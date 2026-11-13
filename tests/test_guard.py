"""Every attack below must be refused — tested offline with a fake DNS resolver."""
import unittest

from safe_url_guard import UnsafeURL, extract_url, is_public_ip, safe_get, validate_url

FAKE_DNS = {
    "www.tiktok.com": ["93.184.216.34"],
    "vm.tiktok.com": ["93.184.216.34"],
    "example.com": ["93.184.216.34"],
    "cdn.example.net": ["93.184.216.35"],
    "localtest.me": ["127.0.0.1"],          # public name -> loopback
    "127.0.0.1.nip.io": ["127.0.0.1"],
    "2130706433": ["127.0.0.1"],            # decimal IP (glibc resolves it)
    "0x7f000001": ["127.0.0.1"],            # hex IP
    "0177.0.0.1": ["127.0.0.1"],            # octal IP
    "127.1": ["127.0.0.1"],                 # short form
    "evil.example": ["10.0.0.5"],           # public name -> private LAN
}


def resolver(host):
    if host not in FAKE_DNS:
        raise OSError("not found")
    return FAKE_DNS[host]


def check(url, **kw):
    return validate_url(url, resolve=resolver, **kw)


class Blocked(unittest.TestCase):
    ATTACKS = {
        "loopback": "http://127.0.0.1/",
        "localhost name": "http://localtest.me/",
        "nip.io loopback": "http://127.0.0.1.nip.io/",
        "decimal IP": "http://2130706433/",
        "hex IP": "http://0x7f000001/",
        "octal IP": "http://0177.0.0.1/",
        "short IP": "http://127.1/",
        "IPv6 loopback": "http://[::1]/",
        "IPv6-mapped IPv4": "http://[::ffff:127.0.0.1]/",
        "cloud metadata": "http://169.254.169.254/latest/meta-data/",
        "private LAN": "http://192.168.1.1/",
        "name to private LAN": "http://evil.example/",
        "unspecified": "http://0.0.0.0/",
        "user@host trick": "http://www.tiktok.com@127.0.0.1/",
        "file scheme": "file:///etc/passwd",
        "gopher scheme": "gopher://127.0.0.1:6379/_FLUSHALL",
        "Redis port": "http://example.com:6379/",
        "too long": "https://example.com/" + "a" * 5000,
        "unknown host": "http://does-not-exist.invalid/",
    }

    def test_attacks_are_refused(self):
        for name, url in self.ATTACKS.items():
            with self.subTest(name):
                with self.assertRaises(UnsafeURL):
                    check(url)

    def test_allowlist_refuses_look_alikes(self):
        allow = ["tiktok.com"]
        for url in ("https://tiktok.com.evil.com/x", "https://eviltiktok.com/x", "https://example.com/"):
            with self.subTest(url), self.assertRaises(UnsafeURL):
                check(url, allowed_hosts=allow)


class Allowed(unittest.TestCase):
    def test_normal_links_pass(self):
        self.assertTrue(check("https://www.tiktok.com/@user/video/1", allowed_hosts=["tiktok.com"]))
        self.assertTrue(check("https://vm.tiktok.com/ZMabc/", allowed_hosts=["tiktok.com"]))
        self.assertTrue(check("https://example.com/video.mp4"))

    def test_extract_from_share_text(self):
        self.assertEqual(extract_url("look at this https://vm.tiktok.com/ZMabc/ lol"), "https://vm.tiktok.com/ZMabc/")

    def test_public_ip_helper(self):
        self.assertTrue(is_public_ip("93.184.216.34"))
        self.assertFalse(is_public_ip("::ffff:10.0.0.1"))


class FakeResponse:
    def __init__(self, status, location=""):
        self.status_code, self.headers = status, {"Location": location} if location else {}

    def close(self):
        pass


class FakeSession:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def get(self, url, **kw):
        self.calls.append(url)
        return self.routes[url]


class Redirects(unittest.TestCase):
    def test_redirect_to_internal_address_is_refused(self):
        s = FakeSession({"https://example.com/v": FakeResponse(302, "http://169.254.169.254/latest")})
        with self.assertRaises(UnsafeURL):
            safe_get("https://example.com/v", session=s, resolve=resolver)
        self.assertEqual(s.calls, ["https://example.com/v"])  # the internal address was never fetched

    def test_redirect_to_public_cdn_is_followed(self):
        s = FakeSession({
            "https://example.com/v": FakeResponse(302, "https://cdn.example.net/file.mp4"),
            "https://cdn.example.net/file.mp4": FakeResponse(200),
        })
        self.assertEqual(safe_get("https://example.com/v", session=s, resolve=resolver).status_code, 200)

    def test_redirect_loop_stops(self):
        s = FakeSession({"https://example.com/a": FakeResponse(302, "https://example.com/a")})
        with self.assertRaises(UnsafeURL):
            safe_get("https://example.com/a", session=s, resolve=resolver, max_redirects=3)


if __name__ == "__main__":
    unittest.main()
