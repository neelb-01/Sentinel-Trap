"""sentinel-web — the web decoy.

Serves believable-looking login pages, an endpoint that looks injectable, and a
robots.txt full of bait. Nothing here touches a database or executes anything;
every request is recorded as a normalised event and answered with a plausible
failure.

Writes newline-delimited JSON to ST_LOG_PATH. The tailer picks it up from there —
this process has no network path to Redis or Postgres.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import re
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

LOG_PATH = Path(os.environ.get("ST_LOG_PATH", "/logs/events.jsonl"))
TARPIT_MIN = float(os.environ.get("ST_TARPIT_MIN_SECONDS", "3"))
TARPIT_MAX = float(os.environ.get("ST_TARPIT_MAX_SECONDS", "8"))
TARPIT_AFTER = int(os.environ.get("ST_TARPIT_AFTER_HITS", "5"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("sentinel-web")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOG_PATH.touch(exist_ok=True)
    logger.info("sentinel-web logging to %s", LOG_PATH)
    yield


# docs/openapi disabled: a real target does not advertise a FastAPI schema.
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

_ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_hits: dict[str, int] = defaultdict(int)
_time_wasted: dict[str, float] = defaultdict(float)
_write_lock = asyncio.Lock()


def ulid() -> str:
    value = (int(time.time() * 1000) << 80) | int.from_bytes(os.urandom(10), "big")
    return "".join(_ULID_ALPHABET[(value >> shift) & 0x1F] for shift in range(125, -5, -5))


# ------------------------------------------------------------------ fingerprinting

_UA_PATTERNS = [
    ("scanner", re.compile(r"nmap|masscan|nikto|sqlmap|nuclei|zgrab|dirbuster|gobuster|wpscan", re.I)),
    ("library", re.compile(r"python-requests|curl|wget|libwww|go-http-client|okhttp|axios", re.I)),
    ("crawler", re.compile(r"googlebot|bingbot|yandex|baiduspider|ahrefs|semrush", re.I)),
    ("browser", re.compile(r"mozilla.*(chrome|firefox|safari|edge)", re.I)),
]


def classify_ua(ua: str) -> str:
    for label, pattern in _UA_PATTERNS:
        if pattern.search(ua):
            return label
    return "unknown" if ua else "absent"


def fingerprint(request: Request) -> dict[str, Any]:
    """Cheap per-request signals that become ML features later."""
    names = [k.decode("latin-1").lower() for k, _ in request.scope.get("headers", [])]
    ua = request.headers.get("user-agent", "")
    return {
        "ua": ua[:512],
        "ua_class": classify_ua(ua),
        "header_order": ",".join(names)[:512],
        "header_count": len(names),
        "accept_language": request.headers.get("accept-language", "")[:128],
        "referer": request.headers.get("referer", "")[:256],
    }


# ------------------------------------------------------------------------ logging


async def record(request: Request, action: str, payload: dict[str, Any] | None = None) -> None:
    """Append one normalised event. Never raises into the request path."""
    src_ip = request.client.host if request.client else "0.0.0.0"
    body = {
        "event_id": ulid(),
        "ts": datetime.now(timezone.utc).isoformat(),
        "decoy": "sentinel-web",
        "protocol": "http",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": int(request.url.port or 8080),
        "action": action,
        "payload": {
            "method": request.method,
            "path": str(request.url.path)[:512],
            "query": str(request.url.query)[:512],
            **fingerprint(request),
            **(payload or {}),
        },
    }
    line = json.dumps(body, separators=(",", ":"), default=str)

    try:
        async with _write_lock:
            with LOG_PATH.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
    except OSError:
        logger.exception("could not write event; dropping")


async def tarpit(request: Request) -> float:
    """Delay repeat offenders. Costs nothing, wastes scanner time, and the
    accumulated seconds make a satisfying dashboard metric."""
    src_ip = request.client.host if request.client else "0.0.0.0"
    _hits[src_ip] += 1
    if _hits[src_ip] < TARPIT_AFTER:
        return 0.0
    delay = random.uniform(TARPIT_MIN, TARPIT_MAX)
    _time_wasted[src_ip] += delay
    await asyncio.sleep(delay)
    return delay


# -------------------------------------------------------------------- login bait

LOGIN_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{title}</title>
<style>body{{font-family:system-ui,sans-serif;background:#f0f0f1;margin:0;padding:80px 20px}}
.box{{max-width:320px;margin:0 auto;background:#fff;border:1px solid #c3c4c7;padding:26px 24px}}
h1{{font-size:20px;margin:0 0 18px}}label{{display:block;font-size:14px;margin:12px 0 4px}}
input{{width:100%;padding:8px;border:1px solid #8c8f94;box-sizing:border-box}}
button{{margin-top:18px;width:100%;padding:9px;background:#2271b1;color:#fff;border:0;cursor:pointer}}
.err{{background:#fcf0f1;border-left:4px solid #d63638;padding:10px;font-size:13px;margin-bottom:14px}}
</style></head><body><div class="box">{error}<h1>{title}</h1>
<form method="post"><label>Username</label><input name="{userfield}" autofocus>
<label>Password</label><input name="{passfield}" type="password">
<button type="submit">Log In</button></form></div></body></html>"""


def login_page(title: str, userfield: str = "username", passfield: str = "password",
               error: bool = False) -> HTMLResponse:
    err = '<div class="err">The password you entered is incorrect.</div>' if error else ""
    return HTMLResponse(
        LOGIN_HTML.format(title=title, error=err, userfield=userfield, passfield=passfield),
        status_code=200,
        headers={"Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4.3"},
    )


@app.get("/wp-login.php", response_class=HTMLResponse)
@app.get("/wp-admin", response_class=HTMLResponse)
async def wp_login_get(request: Request):
    await record(request, "login_page_view", {"target": "wordpress"})
    return login_page("WordPress")


@app.post("/wp-login.php")
async def wp_login_post(request: Request, log: str = Form(""), pwd: str = Form("")):
    await record(request, "login_attempt", {"target": "wordpress", "user": log[:128], "pass": pwd[:128]})
    await tarpit(request)
    return login_page("WordPress", "log", "pwd", error=True)


@app.get("/admin", response_class=HTMLResponse)
@app.get("/administrator", response_class=HTMLResponse)
async def admin_get(request: Request):
    await record(request, "login_page_view", {"target": "admin"})
    return login_page("Administration")


@app.post("/admin")
@app.post("/administrator")
async def admin_post(request: Request, username: str = Form(""), password: str = Form("")):
    await record(request, "login_attempt",
                 {"target": "admin", "user": username[:128], "pass": password[:128]})
    await tarpit(request)
    return login_page("Administration", error=True)


@app.get("/phpmyadmin", response_class=HTMLResponse)
@app.get("/pma", response_class=HTMLResponse)
async def pma_get(request: Request):
    await record(request, "login_page_view", {"target": "phpmyadmin"})
    return login_page("phpMyAdmin", "pma_username", "pma_password")


@app.post("/phpmyadmin")
async def pma_post(request: Request, pma_username: str = Form(""), pma_password: str = Form("")):
    await record(request, "login_attempt",
                 {"target": "phpmyadmin", "user": pma_username[:128], "pass": pma_password[:128]})
    await tarpit(request)
    return login_page("phpMyAdmin", "pma_username", "pma_password", error=True)


@app.post("/api/v1/auth")
async def api_auth(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    await record(request, "login_attempt", {
        "target": "api",
        "user": str(body.get("username", ""))[:128],
        "pass": str(body.get("password", ""))[:128],
    })
    await tarpit(request)
    return JSONResponse({"error": "invalid_credentials"}, status_code=401)


# --------------------------------------------------------------- juicy artefacts


@app.get("/.env", response_class=PlainTextResponse)
async def dotenv(request: Request):
    """Looks like a leaked .env. Every credential in it is fake and unused."""
    await record(request, "sensitive_file_probe", {"target": ".env"})
    await tarpit(request)
    return PlainTextResponse(
        "APP_ENV=production\n"
        "APP_KEY=base64:VGhpc0lzTm90QVJlYWxLZXlBdEFsbA==\n"
        "DB_CONNECTION=mysql\n"
        "DB_HOST=127.0.0.1\n"
        "DB_DATABASE=app_prod\n"
        "DB_USERNAME=app\n"
        "DB_PASSWORD=hunter2\n"
    )


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots(request: Request):
    """Bait. A crawler that visits exactly what it was told not to identifies itself."""
    await record(request, "robots_fetch")
    return PlainTextResponse(
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /backup/\n"
        "Disallow: /db_dump.sql\n"
        "Disallow: /internal/api-keys.json\n"
        "Disallow: /.git/\n"
    )


@app.get("/search")
async def search(request: Request, q: str = ""):
    """Looks injectable. Records the payload and touches no database."""
    await record(request, "search_query", {"q": q[:1024], "length": len(q)})
    if q:
        await tarpit(request)
    return JSONResponse({"query": q, "results": [], "took_ms": random.randint(8, 40)})


# -------------------------------------------------------------------- catch-all


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
async def catch_all(request: Request, path: str):
    await record(request, "path_probe", {"probed": "/" + path[:256]})
    await tarpit(request)
    return HTMLResponse(
        "<!doctype html><html><head><title>404 Not Found</title></head>"
        "<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p>"
        "<hr><address>Apache/2.4.41 (Ubuntu) Server at localhost Port 80</address></body></html>",
        status_code=404,
        headers={"Server": "Apache/2.4.41 (Ubuntu)"},
    )
