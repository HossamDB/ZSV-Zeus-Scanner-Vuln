#!/usr/bin/env python3
"""
Minimal scripted example: use ZSV's modules directly (instead of the CLI)
to scan a target you own/are authorized to test, and print a quick summary.

Usage:
    python3 examples/run_example_scan.py https://your-authorized-target.example
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from zsv.config import Target
from zsv.database.db import Database
from zsv.report import html_report
from zsv.scanners import headers_scanner, xss_scanner


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <authorized-target-url>")
        return 1

    # This script does not prompt for authorization -- that's the CLI's job
    # (see zsv/main.py --authorized). Only point this at a target you own
    # or have explicit written permission to test.
    target = Target(sys.argv[1])

    db = Database(Path.home() / ".zsv" / "zsv.db")
    target_id = db.upsert_target(target.host, target.url, target.is_ip)
    scan_id = db.start_scan(target_id, ["headers", "xss"])

    print(f"Scanning {target.url} ...")

    for f in headers_scanner.check_headers(target.url):
        db.add_finding(scan_id, "headers", f.title, severity=f.severity,
                        detail=f.detail, location=f.location)

    findings, crawl = xss_scanner.scan(target.url, max_pages=10)
    print(f"Crawled {len(crawl.pages_visited)} page(s), tested {crawl.forms_found} form(s)")
    for f in findings:
        db.add_finding(scan_id, "xss", f"Reflected XSS via {f.method} '{f.parameter}'",
                        severity="high", location=f.url, evidence=f.evidence)

    db.finish_scan(scan_id)
    report_path = html_report.generate(db, scan_id, Path(f"zsv_report_{target.host}.html"))
    print(f"Report written to: {report_path}")

    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
