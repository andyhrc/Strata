"""local: allowed_ips_file - only listed clients (and this PC) are answered; the list is re-read when it changes."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serve.frontend import ChatTemplate  # noqa: E402
from serve.server import AllowedIPs, ByteTokenizer, MockEngine, Service, serve  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


class AllowedIPsFile(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "allowed")
        self.write("# who may use the model\n192.168.8.20  andy laptop\n10.1.0.0/16 lab  # the lab\n\n100.64.1.2\n")

    def tearDown(self):
        self.dir.cleanup()

    def write(self, text):
        Path(self.path).write_text(text, encoding="utf-8")

    def changed(self, allowed):
        """Rewrite the list and let the next request look at it (no RECHECK_S wait in a test)."""
        self.write(text=allowed)
        os.utime(self.path, ns=(0, os.stat(self.path).st_mtime_ns + 1))

    def test_listed_addresses_and_networks(self):
        acl = AllowedIPs(self.path)
        self.assertEqual(len(acl.nets), 3)
        for ip in ("192.168.8.20", "10.1.200.3", "100.64.1.2", "::ffff:192.168.8.20"):
            self.assertTrue(acl.allows(ip), ip)
        for ip in ("192.168.8.21", "10.2.0.1", "100.64.1.3", "2001:db8::1", "not an address"):
            self.assertFalse(acl.allows(ip), ip)

    def test_this_pc_always(self):
        self.write("")
        acl = AllowedIPs(self.path)
        for ip in ("127.0.0.1", "127.0.1.1", "::1", "::ffff:127.0.0.1"):
            self.assertTrue(acl.allows(ip), ip)

    def test_a_changed_file_applies_to_the_next_request(self):
        acl = AllowedIPs(self.path)
        self.changed("192.168.8.21 someone else\n")
        acl.checked -= acl.RECHECK_S
        self.assertTrue(acl.allows("192.168.8.21"))
        self.assertFalse(acl.allows("192.168.8.20"))

    def test_a_broken_or_missing_file_keeps_the_last_list(self):
        acl = AllowedIPs(self.path)
        self.changed("192.168.8.300 typo\n")
        acl.checked -= acl.RECHECK_S
        self.assertTrue(acl.allows("192.168.8.20"))
        os.remove(self.path)
        acl.checked -= acl.RECHECK_S
        self.assertTrue(acl.allows("192.168.8.20"))
        self.assertFalse(acl.allows("192.168.8.21"))

    def test_a_list_that_cannot_be_read_stops_the_start(self):
        self.write("192.168.8.0/16\n")                    # host bits set: a typo, not a network
        with self.assertRaisesRegex(ValueError, "line 1"):
            AllowedIPs(self.path)
        with self.assertRaisesRegex(ValueError, "cannot read"):
            AllowedIPs(self.path + ".missing")

    def test_a_refused_address_is_logged_once_a_minute(self):
        acl = AllowedIPs(self.path)
        self.assertTrue(acl.log_refusal("192.0.2.1"))
        self.assertFalse(acl.log_refusal("192.0.2.1"))
        self.assertTrue(acl.log_refusal("192.0.2.2"))
        acl.refused["192.0.2.1"] -= acl.REFUSAL_LOG_S
        self.assertTrue(acl.log_refusal("192.0.2.1"))


class AllowedIPsOverHttp(unittest.TestCase):
    """The check runs before anything else, for every method; a test client is always 127.0.0.1, so it is faked."""

    def test_an_address_not_on_the_list_gets_403(self):
        tok = ByteTokenizer()
        svc = Service(MockEngine(tok, "</think>\n\nok", max_context=0), tok,
                      ChatTemplate(ROOT / "serve/chat_template.jinja"))
        httpd = serve(svc, port=0)
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        try:
            self.assertEqual(urllib.request.urlopen(base + "/v1/models", timeout=10).status, 200)
            with tempfile.TemporaryDirectory() as d:
                Path(d, "allowed").write_text("192.168.8.20\n", encoding="utf-8")
                svc.allowed_ips = AllowedIPs(str(Path(d, "allowed")))
                self.assertEqual(urllib.request.urlopen(base + "/v1/models", timeout=10).status, 200)  # this PC
                with mock.patch.object(AllowedIPs, "allows", return_value=False):
                    for method, body in (("GET", None), ("POST", b"{}")):
                        req = urllib.request.Request(base + "/v1/chat/completions", data=body, method=method)
                        with self.assertRaises(urllib.error.HTTPError) as caught:
                            urllib.request.urlopen(req, timeout=10)
                        with caught.exception as e:
                            self.assertEqual(e.code, 403)
                            self.assertEqual(json.loads(e.read())["error"]["type"], "forbidden")
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
