# attack-sim — phase 3

Traffic generator. This is a first-class deliverable, not a test fixture: running
locally means there are no real attackers, so this module produces everything the
detection layer trains and demos on.

Target corpus:

| Class | Generated with | Volume |
|---|---|---|
| `recon_scan` | `nmap -sV`, `masscan`, `nikto`, curl sweeps | ~1200 |
| `credential_bruteforce` | `hydra` against SSH and the web login | ~1500 |
| `web_exploit` | `sqlmap`, hand-written LFI / traversal / Log4Shell / Shellshock | ~1000 |
| `malware_dropper` | scripted Cowrie sessions replaying public Mirai-style transcripts | ~600 |
| `benign` | crawlers, health checks, monitoring probes, stray browser visits | ~800 |

Vary timing, wordlists and source addresses so the model learns behaviour rather
than memorising one machine.

**Hold out a slice that is never trained on and hand-label it.** That set is the
only thing metrics may be quoted from — see the labelling note in the root README.
