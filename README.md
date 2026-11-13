# safe-url-guard

[![tests](https://github.com/kaboucha-dev/safe-url-guard/actions/workflows/tests.yml/badge.svg)](https://github.com/kaboucha-dev/safe-url-guard/actions/workflows/tests.yml) ![python](https://img.shields.io/badge/python-3.11%2B-blue) ![license](https://img.shields.io/badge/license-MIT-green)

**Stop SSRF in Python apps that fetch URLs given by users.**

A "paste a link and we download it" feature lets anyone make your server request *any* address — including its own internals: `127.0.0.1`, your Redis on `6379`, the cloud metadata service `169.254.169.254`. Attackers hide those addresses behind tricks. This small library refuses them.

## What it blocks

| Attack | Example | Result |
|---|---|---|
| Loopback / localhost | `http://127.0.0.1/` | ❌ refused |
| Decimal / hex / octal / short IPs | `http://2130706433/`, `http://0x7f000001/`, `http://0177.0.0.1/`, `http://127.1/` | ❌ refused |
| IPv6 + IPv4-mapped IPv6 | `http://[::1]/`, `http://[::ffff:127.0.0.1]/` | ❌ refused |
| Cloud metadata | `http://169.254.169.254/latest/meta-data/` | ❌ refused |
| Public name → internal IP | `http://localtest.me/`, `http://127.0.0.1.nip.io/` | ❌ refused |
| `user@host` trick | `http://www.tiktok.com@127.0.0.1/` | ❌ refused |
| Other schemes | `file://`, `gopher://` | ❌ refused |
| Internal service ports | `http://example.com:6379/` | ❌ refused |
| Look-alike domains (with allowlist) | `tiktok.com.evil.com`, `eviltiktok.com` | ❌ refused |
| Clean link that **redirects** inside | `302 → http://169.254.169.254/` | ❌ refused, the internal address is never fetched |

## Usage

```python
from safe_url_guard import UnsafeURL, extract_url, safe_get, validate_url

try:
    url = validate_url(extract_url(user_text), allowed_hosts=["tiktok.com", "youtube.com"])
    resp = safe_get(url, timeout=15, stream=True)   # follows redirects, checks every hop
except UnsafeURL as err:
    return {"error": str(err)}
```

- `validate_url` — scheme, port, credentials, length, optional host allowlist (sub-domains allowed, look-alikes refused), and **every** address the host resolves to must be public.
- `safe_get` — like `requests.get`, but redirects are followed by hand and each hop is validated again.

## Install & test

```bash
pip install -e .            # add "requests" if you use safe_get
python -m unittest discover -s tests -v
```

The tests run offline with a fake DNS resolver, so every trick is checked the same way on any machine.

## Limits

DNS can change between the check and the request (DNS rebinding). An allowlist of hosts, or connecting to the checked IP directly, closes that gap — use `allowed_hosts` whenever you know which sites you accept.

## License

MIT
