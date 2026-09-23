"""
ZSV configuration and target model.

Everything here is plain data / stdlib — no paid services, no license keys
required. All third-party scan engines ZSV shells out to (Nmap, Nikto) are
free and open source.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse


DEFAULT_DB_PATH = Path.home() / ".zsv" / "zsv.db"
DEFAULT_REPORT_DIR = Path.cwd()

# Benign, non-destructive default XSS marker. Chosen so a positive match is
# unambiguous and cannot itself execute anything harmful if it slips into a
# real page (no external resource, no data exfiltration, no obfuscation).
XSS_MARKER = "zsv_xss_probe_9f3c"

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

IPV4_RE = re.compile(
    r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"
)


@dataclass
class Target:
    """A normalized scan target: a static IP, hostname, or web app URL."""

    raw: str
    host: str = field(init=False)
    url: str | None = field(init=False, default=None)
    is_ip: bool = field(init=False, default=False)

    def __post_init__(self) -> None:
        raw = self.raw.strip()
        if "://" in raw:
            parsed = urlparse(raw)
            if not parsed.hostname:
                raise ValueError(f"Could not parse host from URL: {raw!r}")
            self.host = parsed.hostname
            self.url = raw.rstrip("/")
        else:
            self.host = raw
            # Assume http(s) reachable web app checks are opt-in via --web;
            # default to https for convenience when a URL wasn't given.
            self.url = f"https://{raw}"
        self.is_ip = bool(IPV4_RE.match(self.host))

    def __str__(self) -> str:
        return self.host


@dataclass
class ScanConfig:
    target: Target
    db_path: Path = DEFAULT_DB_PATH
    report_path: Path | None = None
    run_nmap: bool = True
    run_nikto: bool = False
    run_xss: bool = True
    run_headers: bool = True
    run_cve_lookup: bool = True
    nmap_ports: str = "1-1000"
    nmap_args: str = "-sV -T4"
    request_timeout: int = 10
    max_crawl_pages: int = 25
    nvd_api_key: str | None = None
    verbose: bool = False
    authorized: bool = False
