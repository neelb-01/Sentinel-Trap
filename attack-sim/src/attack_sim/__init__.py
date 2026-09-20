"""attack-sim — synthetic attack-traffic generator for SentinelTrap.

Runs locally, so there are no real attackers: this module manufactures the
traffic the detection layer trains and demos on. It drives the live decoys over
HTTP exactly as a real client would, presenting many synthetic source addresses
via ``X-Forwarded-For`` (the decoy honours it when ``ST_TRUST_XFF=1``) so the
sessioniser splits traffic by origin the same way it would for real sources.

No class label is ever written into an event — that would be label leakage, the
fatal flaw of this project class. Labels live only in the run manifest, keyed to
the synthetic source IP and time window, to be joined against ``sessions`` after
the fact. See ``manifest.py``.
"""

__version__ = "0.1.0"
