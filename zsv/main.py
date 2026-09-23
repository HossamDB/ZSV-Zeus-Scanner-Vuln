"""
ZSV - Zeus Scanner Vuln
CLI entry point: ties Nmap, Nikto, the custom XSS/header checks, and the
free NVD CVE lookups together into one scan -> SQLite -> HTML report flow.

    python -m zsv.main --target 203.0.113.10 --authorized
    python -m zsv.main --target https://my-webapp.example --authorized --nikto

Only scan systems you own or have explicit written authorization to test.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __full_name__, __project__, __version__
from .config import DEFAULT_DB_PATH, ScanConfig, Target
from .database.db import Database
from .cve.nvd_client import NVDClient
from .report import html_report
from .scanners import headers_scanner, nikto_scanner, nmap_scanner, xss_scanner
from .utils.logger import get_logger

BANNER = r"""
 _____ ______      __
|__  /|   ____|\  / |
  / / |__|  \  \/  /   ZSV - Zeus Scanner Vuln
 / /_ ___   |  \  /    Defensive security scanner
/____|______|   \/     Nmap * Nikto * XSS/header checks * free NVD CVE data
"""


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="zsv",
        description=f"{__full_name__} ({__project__}) v{__version__} - "
                     "defensive vulnerability scanner for a static IP, "
                     "website, or web app you are authorized to test.",
    )
    p.add_argument("--target", "-t", required=True,
                    help="Target: an IP, hostname, or full URL "
                         "(e.g. 203.0.113.10, example.com, https://app.example.com)")
    p.add_argument("--authorized", action="store_true",
                    help="REQUIRED. Confirms you own this target or have explicit "
                         "written authorization to scan it.")

    scope = p.add_argument_group("modules")
    scope.add_argument("--no-nmap", action="store_true", help="Skip Nmap port/service scan")
    scope.add_argument("--nikto", action="store_true",
                        help="Enable Nikto web vuln scan (opt-in; requires nikto installed)")
    scope.add_argument("--no-xss", action="store_true", help="Skip the custom XSS scan")
    scope.add_argument("--no-headers", action="store_true", help="Skip security-header/TLS checks")
    scope.add_argument("--no-cve", action="store_true", help="Skip NVD CVE lookups")

    nmap_g = p.add_argument_group("nmap options")
    nmap_g.add_argument("--ports", default="1-1000", help="Port range for Nmap (default: 1-1000)")
    nmap_g.add_argument("--nmap-args", default="-sV -T4",
                         help="Extra Nmap arguments (default: '-sV -T4')")

    web_g = p.add_argument_group("web scan options")
    web_g.add_argument("--max-pages", type=int, default=25,
                        help="Max pages to crawl for the XSS scan (default: 25)")
    web_g.add_argument("--timeout", type=int, default=10,
                        help="HTTP request timeout in seconds (default: 10)")

    cve_g = p.add_argument_group("CVE / NVD options")
    cve_g.add_argument("--nvd-api-key", default=None,
                        help="Optional free NVD API key (raises the rate limit)")

    out_g = p.add_argument_group("output")
    out_g.add_argument("--db", default=str(DEFAULT_DB_PATH),
                        help=f"Path to the SQLite database (default: {DEFAULT_DB_PATH})")
    out_g.add_argument("--output", "-o", default=None,
                        help="Path to write the HTML report (default: ./zsv_report_<host>.html)")
    out_g.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")

    return p


def severity_for_cvss(score: float | None) -> str:
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def run(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    log = get_logger("zsv", verbose=args.verbose)
    print(BANNER)

    if not args.authorized:
        log.error(
            "Refusing to scan: pass --authorized to confirm you own this target "
            "or have explicit written permission to test it. Unauthorized "
            "scanning may be illegal in your jurisdiction."
        )
        return 2

    try:
        target = Target(args.target)
    except ValueError as exc:
        log.error("Invalid target: %s", exc)
        return 2

    cfg = ScanConfig(
        target=target,
        db_path=Path(args.db),
        run_nmap=not args.no_nmap,
        run_nikto=args.nikto,
        run_xss=not args.no_xss,
        run_headers=not args.no_headers,
        run_cve_lookup=not args.no_cve,
        nmap_ports=args.ports,
        nmap_args=args.nmap_args,
        request_timeout=args.timeout,
        max_crawl_pages=args.max_pages,
        nvd_api_key=args.nvd_api_key,
        verbose=args.verbose,
        authorized=True,
    )

    modules = []
    if cfg.run_nmap:
        modules.append("nmap")
    if cfg.run_nikto:
        modules.append("nikto")
    if cfg.run_xss:
        modules.append("xss")
    if cfg.run_headers:
        modules.append("headers")

    db = Database(cfg.db_path)
    target_id = db.upsert_target(target.host, target.url, target.is_ip)
    scan_id = db.start_scan(target_id, modules)
    log.info("Scan #%s started for %s", scan_id, target.host)

    open_ports: list[dict] = []
    cve_client = NVDClient(db, api_key=cfg.nvd_api_key) if cfg.run_cve_lookup else None

    # -- Nmap ---------------------------------------------------------
    if cfg.run_nmap:
        try:
            services = nmap_scanner.run_scan(
                target.host, ports=cfg.nmap_ports, extra_args=cfg.nmap_args
            )
            for svc in services:
                open_ports.append({
                    "port": svc.port, "protocol": svc.protocol,
                    "service": svc.service, "product": svc.product, "version": svc.version,
                })
                db.add_finding(
                    scan_id, "nmap", f"Open port {svc.port}/{svc.protocol}: {svc.service}",
                    severity="info",
                    detail=svc.extrainfo,
                    location=f"{svc.port}/{svc.protocol}",
                )
                if cve_client and svc.service_string:
                    cpe = svc.cpe[0] if svc.cpe else None
                    cves = cve_client.lookup(svc.service_string, cpe=cpe)
                    if cves:
                        top = max((c.get("cvss_v3_score") or 0 for c in cves), default=0)
                        db.add_finding(
                            scan_id, "nmap",
                            f"Known CVEs for {svc.service_string} (port {svc.port})",
                            severity=severity_for_cvss(top),
                            detail=f"{len(cves)} CVE(s) found in the NVD database for this "
                                   f"service/version.",
                            location=f"{svc.port}/{svc.protocol}",
                            cve_ids=[c["cve_id"] for c in cves],
                        )
        except nmap_scanner.NmapNotFoundError as exc:
            log.warning(str(exc))
            db.add_finding(scan_id, "nmap", "Nmap not available", severity="info", detail=str(exc))
        except Exception as exc:  # noqa: BLE001
            log.error("Nmap module failed: %s", exc)
            db.add_finding(scan_id, "nmap", "Nmap scan failed", severity="info", detail=str(exc))

    # -- Headers / TLS --------------------------------------------------
    if cfg.run_headers:
        try:
            for f in headers_scanner.check_headers(target.url, timeout=cfg.request_timeout):
                db.add_finding(scan_id, "headers", f.title, severity=f.severity,
                                detail=f.detail, location=f.location)
        except Exception as exc:  # noqa: BLE001
            log.error("Headers module failed: %s", exc)

    # -- XSS --------------------------------------------------------------
    if cfg.run_xss:
        try:
            findings, crawl_res = xss_scanner.scan(
                target.url, max_pages=cfg.max_crawl_pages, timeout=cfg.request_timeout
            )
            log.info("XSS crawl visited %d page(s), %d form(s)",
                      len(crawl_res.pages_visited), crawl_res.forms_found)
            for f in findings:
                db.add_finding(
                    scan_id, "xss", f"Reflected XSS via {f.method} parameter '{f.parameter}'",
                    severity="high",
                    detail="Unescaped reflection of an injected marker was found in the "
                           "response, indicating the app does not sanitize/encode this input "
                           "before rendering it back into the page.",
                    location=f.url,
                    evidence=f.evidence,
                )
            if not findings:
                db.add_finding(scan_id, "xss", "No reflected XSS found", severity="info",
                                detail=f"Crawled {len(crawl_res.pages_visited)} page(s), "
                                       f"tested {crawl_res.forms_found} form(s) and URL "
                                       "parameters with marker payloads; none reflected unescaped.")
        except Exception as exc:  # noqa: BLE001
            log.error("XSS module failed: %s", exc)

    # -- Nikto (opt-in, free Nessus alternative) ---------------------------
    if cfg.run_nikto:
        try:
            for nf in nikto_scanner.run_scan(target.url):
                db.add_finding(scan_id, "nikto", nf.message or f"Nikto finding {nf.id}",
                                severity="medium", location=nf.url)
        except nikto_scanner.NiktoNotFoundError as exc:
            log.warning(str(exc))
            db.add_finding(scan_id, "nikto", "Nikto not available", severity="info", detail=str(exc))
        except Exception as exc:  # noqa: BLE001
            log.error("Nikto module failed: %s", exc)

    db.finish_scan(scan_id)

    output_path = Path(args.output) if args.output else Path.cwd() / f"zsv_report_{target.host}.html"
    report_path = html_report.generate(db, scan_id, output_path, open_ports=open_ports)

    findings_count = len(db.findings_for_scan(scan_id))
    log.info("Scan complete: %d finding(s) recorded.", findings_count)
    log.info("Database updated: %s", cfg.db_path)
    log.info("HTML report written: %s", report_path)

    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(run())
