"""
Unit tests for ZSV. Uses only the standard library's unittest + a throwaway
http.server test fixture, so `python3 -m unittest discover tests` works with
no extra dependencies. (These also run fine under pytest, if installed.)
"""
from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch
from urllib.parse import urlparse, parse_qs

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from zsv.config import Target
from zsv.database.db import Database
from zsv.cve.nvd_client import NVDClient
from zsv.report import html_report
from zsv.scanners import headers_scanner, xss_scanner


class VulnerableHandler(BaseHTTPRequestHandler):
    """Deliberately reflects input unescaped -- used to prove detection works."""

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if parsed.path == "/":
            body = '<html><body><a href="/search?q=test">search</a></body></html>'
        elif parsed.path == "/search":
            q = qs.get("q", [""])[0]
            body = f"<html><body>Results for: {q}</body></html>"  # unescaped on purpose
        else:
            body = "<html><body>not found</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


class SafeHandler(BaseHTTPRequestHandler):
    """Properly escapes input -- used to prove the scanner has no false positives."""

    def log_message(self, format, *args):  # noqa: A002
        pass

    def do_GET(self):
        import html as htmllib
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if parsed.path == "/search":
            q = qs.get("q", [""])[0]
            body = f"<html><body>Results for: {htmllib.escape(q)}</body></html>"
        else:
            body = '<html><body><a href="/search?q=test">search</a></body></html>'
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


def _start_server(handler_cls) -> tuple[HTTPServer, threading.Thread, str]:
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/"
    return server, thread, url


class TargetTests(unittest.TestCase):
    def test_ip_target(self):
        t = Target("203.0.113.10")
        self.assertTrue(t.is_ip)
        self.assertEqual(t.host, "203.0.113.10")
        self.assertEqual(t.url, "https://203.0.113.10")

    def test_hostname_target(self):
        t = Target("example.com")
        self.assertFalse(t.is_ip)
        self.assertEqual(t.host, "example.com")

    def test_url_target(self):
        t = Target("http://example.com/path")
        self.assertEqual(t.host, "example.com")
        self.assertEqual(t.url, "http://example.com/path")


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.db = Database(Path(self.tmpdir.name) / "test.db")

    def tearDown(self):
        self.db.close()
        self.tmpdir.cleanup()

    def test_target_scan_finding_roundtrip(self):
        tid = self.db.upsert_target("example.com", "https://example.com", False)
        sid = self.db.start_scan(tid, ["xss"])
        self.db.add_finding(sid, "xss", "Reflected XSS", severity="high",
                             location="/search?q=", cve_ids=["CVE-2024-0001"])
        self.db.finish_scan(sid)

        findings = self.db.findings_for_scan(sid)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["cve_ids"], ["CVE-2024-0001"])

    def test_cve_cache_upsert_is_idempotent(self):
        self.db.upsert_cve("CVE-2024-0001", "nginx 1.18", "desc", 7.5, "HIGH",
                            "2024-01-01", ["http://x"], {"a": 1})
        self.db.upsert_cve("CVE-2024-0001", "nginx 1.18", "updated desc", 8.1, "HIGH",
                            "2024-01-01", ["http://x"], {"a": 1})
        rows = self.db.cached_cves_for_service("nginx 1.18")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["description"], "updated desc")


class XSSScannerTests(unittest.TestCase):
    def test_detects_reflected_xss(self):
        server, thread, url = _start_server(VulnerableHandler)
        try:
            findings, crawl = xss_scanner.scan(url, max_pages=5, timeout=5)
            self.assertGreater(len(findings), 0)
            self.assertTrue(any(f.parameter == "q" for f in findings))
        finally:
            server.shutdown()
            thread.join(timeout=2)

    def test_no_false_positive_on_escaped_output(self):
        server, thread, url = _start_server(SafeHandler)
        try:
            findings, crawl = xss_scanner.scan(url, max_pages=5, timeout=5)
            self.assertEqual(len(findings), 0)
        finally:
            server.shutdown()
            thread.join(timeout=2)


class HeadersScannerTests(unittest.TestCase):
    def test_flags_missing_headers_and_plain_http(self):
        server, thread, url = _start_server(SafeHandler)
        try:
            findings = headers_scanner.check_headers(url, timeout=5)
            titles = [f.title for f in findings]
            self.assertTrue(any("Content-Security-Policy" in t for t in titles))
            self.assertTrue(any("not served over HTTPS" in t for t in titles))
        finally:
            server.shutdown()
            thread.join(timeout=2)


class NVDClientTests(unittest.TestCase):
    def test_parses_and_caches_response(self):
        sample = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2016-0777",
                    "descriptions": [{"lang": "en", "value": "Leaks private key material."}],
                    "published": "2016-01-14T20:59:00.000",
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.9, "baseSeverity": "MEDIUM"}}]},
                    "references": [{"url": "https://example.com/advisory"}],
                }
            }]
        }
        with TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "test.db")
            client = NVDClient(db, max_results=3)
            mock_resp = MagicMock()
            mock_resp.json.return_value = sample
            mock_resp.raise_for_status.return_value = None
            with patch("zsv.cve.nvd_client.requests.get", return_value=mock_resp):
                results = client.lookup("OpenSSH 7.2")
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["cve_id"], "CVE-2016-0777")

            cached = db.cached_cves_for_service("OpenSSH 7.2")
            self.assertEqual(len(cached), 1)
            db.close()


class ReportTests(unittest.TestCase):
    def test_report_autoescapes_evidence(self):
        with TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "test.db")
            tid = db.upsert_target("example.com", "https://example.com", False)
            sid = db.start_scan(tid, ["xss"])
            db.add_finding(sid, "xss", "Reflected XSS", severity="high",
                            location="https://example.com/search?q=",
                            evidence="Results for: <script>alert(1)</script>")
            db.finish_scan(sid)

            out_path = Path(tmp) / "report.html"
            html_report.generate(db, sid, out_path)
            html = out_path.read_text()

            self.assertNotIn("<script>alert(1)</script>", html)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
            db.close()


if __name__ == "__main__":
    unittest.main()
