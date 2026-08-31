# GeoIP database

Enrichment needs MaxMind's `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` here.

They are **not** committed — the licence requires you to fetch them under your own
account, and they are far too large for git. `*.mmdb` is gitignored.

1. Create a free MaxMind account and generate a licence key.
2. Download `GeoLite2-City` and `GeoLite2-ASN` in **MMDB** format.
3. Drop both `.mmdb` files in this directory.

They are read from disk at runtime. The enricher never calls a geolocation API:
a demo that needs the network to render its own map is a demo that fails when it
matters.
