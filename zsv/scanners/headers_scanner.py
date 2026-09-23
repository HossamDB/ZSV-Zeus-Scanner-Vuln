"""
Security headers + basic TLS/cert checker.

Pure-Python, uses only `requests` and the standard `ssl`/`socket` modules
(no paid services). Flags missing common security headers and looks at the
TLS certificate's expiry for HTTPS targets.
"""
from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from ..config import SECURITY_HEADERS
from ..utils.logger import get_logger

log = get_logger(__name__)

DEFAULT_HEADERS = {
    "User-Agent": "ZSV-ZeusScannerVuln/0.1 (authorized-security-scan)"
}


@dataclass
class HeaderFinding:
    title: str
    severity: str
    detail: str
    location: str


def check_headers(url: str, timeout: int = 10) -> list[HeaderFinding]:
    findings: list[HeaderFinding] = []
    try:
        resp = requests.get(url, timeout=timeout, headers=DEFAULT_HEADERS, allow_redirects=True)
    except requests.RequestException as exc:
        return [HeaderFinding(
            title="Could not connect to target",
            severity="info",
            detail=str(exc),
            location=url,
        )]

    present = {k.lower(): v for k, v in resp.headers.items()}
    for header in SECURITY_HEADERS:
        if header.lower() not in present:
            findings.append(HeaderFinding(
                title=f"Missing security header: {header}",
                severity=_severity_for_header(header),
                detail=_advice_for_header(header),
                location=url,
            ))

    server_hdr = present.get("server")
    if server_hdr:
        findings.append(HeaderFinding(
            title="Server header discloses software/version",
            severity="low",
            detail=f"Server: {server_hdr} -- consider suppressing/generalizing this header.",
            location=url,
        ))

    weak_cookies = []
    for cookie in resp.cookies:
        missing = []
        if not cookie.secure:
            missing.append("Secure")
        if not (cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly")):
            missing.append("HttpOnly")
        if missing:
            weak_cookies.append(f"{cookie.name} (missing {', '.join(missing)})")
    if weak_cookies:
        findings.append(HeaderFinding(
            title="Cookie(s) set without Secure/HttpOnly flags",
            severity="medium",
            detail="Cookies missing recommended flags, which increases session-hijack "
                   "risk: " + "; ".join(weak_cookies),
            location=url,
        ))

    findings.extend(check_tls(url, timeout=timeout))
    return findings


def check_tls(url: str, timeout: int = 10) -> list[HeaderFinding]:
    findings: list[HeaderFinding] = []
    parsed = urlparse(url)
    if parsed.scheme != "https":
        findings.append(HeaderFinding(
            title="Site not served over HTTPS",
            severity="high",
            detail="Traffic to this target is unencrypted; use TLS (HTTPS) for any "
                   "site handling logins, sessions, or sensitive data.",
            location=url,
        ))
        return findings

    host = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except Exception as exc:  # noqa: BLE001 - report any TLS/connect issue as a finding
        findings.append(HeaderFinding(
            title="TLS certificate could not be validated",
            severity="high",
            detail=str(exc),
            location=f"{host}:{port}",
        ))
        return findings

    not_after = cert.get("notAfter")
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            days_left = (expiry - datetime.now(timezone.utc)).days
            if days_left < 0:
                findings.append(HeaderFinding(
                    title="TLS certificate has expired",
                    severity="critical",
                    detail=f"Certificate expired on {not_after}.",
                    location=f"{host}:{port}",
                ))
            elif days_left < 14:
                findings.append(HeaderFinding(
                    title="TLS certificate expiring soon",
                    severity="medium",
                    detail=f"Certificate expires on {not_after} ({days_left} days left).",
                    location=f"{host}:{port}",
                ))
        except ValueError:
            pass

    return findings


def _severity_for_header(header: str) -> str:
    high_impact = {"Content-Security-Policy", "Strict-Transport-Security"}
    return "high" if header in high_impact else "medium"


def _advice_for_header(header: str) -> str:
    advice = {
        "Content-Security-Policy": "Add a CSP to mitigate XSS/data-injection by "
                                    "restricting allowed script/style/resource sources.",
        "Strict-Transport-Security": "Add HSTS to force browsers to use HTTPS for "
                                      "this domain and prevent SSL-stripping attacks.",
        "X-Frame-Options": "Add X-Frame-Options (or frame-ancestors in CSP) to "
                            "prevent clickjacking via iframes.",
        "X-Content-Type-Options": "Add 'nosniff' to stop browsers from MIME-sniffing "
                                   "responses away from the declared Content-Type.",
        "Referrer-Policy": "Set a Referrer-Policy to avoid leaking full URLs "
                            "(possibly including sensitive query params) to third parties.",
        "Permissions-Policy": "Set a Permissions-Policy to explicitly disable "
                               "browser features (camera, mic, geolocation, etc.) you don't use.",
    }
    return advice.get(header, "Add this header to improve the site's security posture.")
