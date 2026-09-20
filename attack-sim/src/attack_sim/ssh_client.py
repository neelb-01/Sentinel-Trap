"""The per-campaign SSH client for the Cowrie decoy.

Cowrie has no ``X-Forwarded-For`` — it records the TCP source of the connection,
which for a locally-published container is always the Docker gateway. So one
campaign would not equal one source, and the one-IP-one-label-one-session
invariant the manifest join depends on would collapse.

The SSH analogue is the **PROXY protocol**: Cowrie, when its listener is prefixed
``haproxy:`` (set only in ``docker-compose.yml`` for the local sim, never in the
committed ``cowrie.cfg`` — a real VPS must keep the plain ``tcp:`` endpoint or it
would drop every real scanner that doesn't speak PROXY), reads a PROXY v1 header
as the first bytes of the connection and attributes the whole session to the
address in it. We send that header on a raw socket, then hand the socket to
paramiko, so every campaign presents its own synthetic RFC 5737 source exactly
like the web classes do over XFF.

That header is also a safety interlock: a server that does *not* expect the PROXY
protocol (a real ``sshd``) rejects ``PROXY TCP4 ...`` as a bad identification
string before any credential is offered, so a mispointed run tries nothing.

paramiko is blocking; every network op runs under ``asyncio.to_thread`` so the
runner's semaphore still bounds concurrency and inter-op jitter stays on the loop.
Errors are counted, never raised — one reset connection must not abort a campaign.
"""

from __future__ import annotations

import asyncio
import logging
import random
import socket
import time
from collections.abc import Iterable
from dataclasses import dataclass, field

import paramiko

from .sources import Source

# paramiko is chatty on stderr about missing host keys and auth failures — all
# expected here. Silence it so a run's output stays readable.
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

_CONNECT_TIMEOUT = 15.0


def _open_proxied_socket(host: str, port: int, spoof_ip: str, rng: random.Random) -> socket.socket:
    """Connect, then send the PROXY v1 header naming ``spoof_ip`` as the source.

    The header must be the very first bytes on the wire, before paramiko sends
    its SSH banner — writing it synchronously here, before the ``Transport`` is
    built, guarantees that ordering.
    """
    sock = socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT)
    src_port = rng.randint(1024, 65535)
    header = f"PROXY TCP4 {spoof_ip} 127.0.0.1 {src_port} {port}\r\n".encode()
    sock.sendall(header)
    return sock


@dataclass(slots=True)
class SSHCampaign:
    """One synthetic SSH attacker: a fixed spoofed source, jittered timing."""

    source: Source
    host: str
    port: int
    rng: random.Random
    min_gap: float
    max_gap: float
    client_version: str
    sent: int = 0  # login attempts + commands that reached the decoy
    failed: int = 0  # connection / transport errors
    _first: bool = field(default=True, repr=False)

    async def _jitter(self) -> None:
        if not self._first:
            await asyncio.sleep(self.rng.uniform(self.min_gap, self.max_gap))
        self._first = False

    async def try_login(self, user: str, password: str) -> bool:
        """One connection, one password guess, closed immediately (brute force).

        Returns whether the guess authenticated (Cowrie's AuthRandom lets some
        through). Either way Cowrie logs one credential event for the session.
        """
        await self._jitter()
        return await asyncio.to_thread(self._blocking_login, user, password)

    async def run_dropper(self, guesses: list[tuple[str, str]], commands: Iterable[str]) -> bool:
        """Walk distinct ``guesses`` until Cowrie lets us in, then run ``commands``.

        Returns whether a shell was obtained. Each guess is its own connection and
        credential event (so a dropper also contributes login attempts to its
        session); the guesses MUST be distinct or Cowrie's AuthRandom never counts
        them toward a grant.
        """
        await self._jitter()
        return await asyncio.to_thread(self._blocking_dropper, guesses, list(commands))

    # --- blocking bodies, run in a worker thread ---------------------------

    def _blocking_login(self, user: str, password: str) -> bool:
        sock = None
        transport = None
        try:
            sock = _open_proxied_socket(self.host, self.port, self.source.ip, self.rng)
            transport = paramiko.Transport(sock)
            transport.local_version = self.client_version
            transport.start_client(timeout=_CONNECT_TIMEOUT)
            try:
                transport.auth_password(user, password)
                authed = True
            except paramiko.AuthenticationException:
                authed = False
            self.sent += 1
            return authed
        except (paramiko.SSHException, OSError, EOFError):
            self.failed += 1
            return False
        finally:
            _quiet_close(transport, sock)

    def _blocking_dropper(self, guesses: list[tuple[str, str]], commands: list[str]) -> bool:
        for user, password in guesses:
            sock = None
            transport = None
            try:
                sock = _open_proxied_socket(self.host, self.port, self.source.ip, self.rng)
                transport = paramiko.Transport(sock)
                transport.local_version = self.client_version
                transport.start_client(timeout=_CONNECT_TIMEOUT)
                try:
                    transport.auth_password(user, password)
                except paramiko.AuthenticationException:
                    self.sent += 1  # a recorded (failed) login attempt
                    _quiet_close(transport, sock)
                    time.sleep(self.rng.uniform(self.min_gap, self.max_gap))
                    continue
                self.sent += 1  # the successful login
                self._run_commands(transport, commands)
                _quiet_close(transport, sock)
                return True
            except (paramiko.SSHException, OSError, EOFError):
                self.failed += 1
                _quiet_close(transport, sock)
                time.sleep(self.rng.uniform(self.min_gap, self.max_gap))
        return False

    def _run_commands(self, transport: paramiko.Transport, commands: list[str]) -> None:
        # One exec channel per command on the shared transport. Cowrie logs the
        # command the moment it receives the exec request, then closes the channel
        # without the clean reply paramiko waits for — so exec_command / recv
        # routinely raise EOFError *after* the command has already landed. Counting
        # on paramiko's success would mislabel every delivered command a failure
        # (seen live). So count once the channel is open — the point past which the
        # command reliably reaches Cowrie — and treat exec/recv as best-effort. The
        # channel is never closed from our side (that tears the transport down and
        # drops the rest of the transcript); transport.close() at the end reaps all.
        for cmd in commands:
            try:
                chan = transport.open_session(timeout=_CONNECT_TIMEOUT)
            except (paramiko.SSHException, OSError, EOFError):
                self.failed += 1
                continue
            self.sent += 1
            try:
                chan.exec_command(cmd)
                chan.settimeout(_CONNECT_TIMEOUT)
                chan.recv(4096)
            except (TimeoutError, paramiko.SSHException, OSError, EOFError):
                pass
            time.sleep(self.rng.uniform(self.min_gap, self.max_gap))


def _quiet_close(transport: paramiko.Transport | None, sock: socket.socket | None) -> None:
    if transport is not None:
        try:
            transport.close()
        except (paramiko.SSHException, OSError, EOFError):
            pass
    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass
