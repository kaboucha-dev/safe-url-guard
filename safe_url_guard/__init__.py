"""Stop SSRF in Python apps that fetch URLs given by users.

A "download this link" feature lets anyone make your server request any address,
including its own internals (127.0.0.1, the cloud metadata service 169.254.169.254,
your Redis on 6379...). Attackers hide those addresses behind tricks: decimal or hex
IPs, IPv6-mapped IPv4, DNS names that resolve to 127.0.0.1, user@host, redirects.

`validate_url` checks the URL the user gave; `safe_get` follows redirects BY HAND and
re-checks every hop, so a clean public link cannot bounce to an internal address.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from typing import Callable, Iterable, List, Optional
from urllib.parse import urljoin, urlsplit

__all__ = ["UnsafeURL", "is_public_ip", "extract_url", "validate_url", "safe_get"]
__version__ = "0.1.0"

_URL_IN_TEXT = re.compile(r"https?://[^\s/$.?#][^\s]*", re.IGNORECASE)
Resolver = Callable[[str], List[str]]


class UnsafeURL(ValueError):
    """The URL is not allowed (internal address, bad scheme/port, not in the allowlist...)."""


def _system_resolver(host: str) -> List[str]:
    return list({info[4][0] for info in socket.getaddrinfo(host, None)})


def is_public_ip(ip_str: str) -> bool:
    """True only for globally routable addresses (IPv4-mapped IPv6 is unwrapped first)."""
    try:
        ip = ipaddress.ip_address(ip_str.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return is_public_ip(str(ip.ipv4_mapped))
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                or ip.is_reserved or ip.is_unspecified)


def extract_url(text: str) -> str:
    """First http(s) URL inside pasted text ("look at this https://vm.tiktok.com/abc lol")."""
    match = _URL_IN_TEXT.search((text or "").strip())
    if not match:
        raise UnsafeURL("no http(s) URL found")
    return match.group(0).rstrip(")(")


def validate_url(
    url: str,
    *,
    allowed_hosts: Optional[Iterable[str]] = None,
    allowed_ports: Iterable[int] = (80, 443),
    max_length: int = 2048,
    resolve: Resolver = _system_resolver,
) -> str:
    """Return the URL if it is safe to fetch, else raise UnsafeURL.

    allowed_hosts: e.g. ["tiktok.com", "youtube.com"] — sub-domains included, look-alikes
    such as "tiktok.com.evil.com" or "eviltiktok.com" refused. None = any public host.
    """
    if not url or not isinstance(url, str):
        raise UnsafeURL("empty URL")
    url = url.strip()
    if len(url) > max_length:
        raise UnsafeURL("URL too long")
    parts = urlsplit(url)
    if parts.scheme.lower() not in ("http", "https"):
        raise UnsafeURL("only http/https URLs are allowed")
    if parts.username or parts.password:
        raise UnsafeURL("credentials inside the URL are not allowed")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise UnsafeURL("URL has no host")
    try:
        port = parts.port
    except ValueError:
        raise UnsafeURL("invalid port")
    if port is not None and port not in set(allowed_ports):
        raise UnsafeURL(f"port {port} is not allowed")
    if allowed_hosts is not None:
        allowed = [h.lower().rstrip(".") for h in allowed_hosts]
        if not any(host == h or host.endswith("." + h) for h in allowed):
            raise UnsafeURL("host is not in the allowlist")
    try:
        candidates = [str(ipaddress.ip_address(host))]
    except ValueError:
        try:
            candidates = resolve(host)
        except (OSError, UnicodeError):
            raise UnsafeURL("host could not be resolved")
    if not candidates:
        raise UnsafeURL("host could not be resolved")
    for addr in candidates:
        if not is_public_ip(addr):
            raise UnsafeURL("host resolves to a private/internal address")
    return url


def safe_get(url: str, *, session=None, max_redirects: int = 5, resolve: Resolver = _system_resolver, **kwargs):
    """requests.get that follows redirects itself and validates EVERY hop.

    The first URL should already have passed validate_url (with your allowlist); the
    hops (CDNs...) may be on other hosts but never on internal addresses."""
    if session is None:
        import requests  # optional dependency, only needed here
        session = requests
    kwargs["allow_redirects"] = False
    current = url
    for _ in range(max_redirects + 1):
        validate_url(current, resolve=resolve)
        resp = session.get(current, **kwargs)
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            resp.close()
            if not location:
                raise UnsafeURL("redirect without Location header")
            current = urljoin(current, location)
            continue
        return resp
    raise UnsafeURL("too many redirects")
