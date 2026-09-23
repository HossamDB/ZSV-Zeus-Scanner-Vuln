"""
Lightweight, pure-Python reflected-XSS detector.

This is a detection-only heuristic scanner: it crawls same-origin pages of
the target webapp, finds URL query parameters and HTML forms, submits a
unique, inert marker string as the value, and checks whether that marker
comes back UNESCAPED in the response HTML. Unescaped reflection of
attacker-controlled input is the signature of a reflected XSS vulnerability
-- this module never attempts to actually execute script, exfiltrate data,
or touch anything outside the single target host, and it never follows
links off that host.

Intended for authorized, defensive self-testing of your own web apps.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl, urlunparse

import requests
from bs4 import BeautifulSoup

from ..config import XSS_MARKER
from ..utils.logger import get_logger

log = get_logger(__name__)

# Benign payload variants covering the common reflection contexts (raw HTML
# body text, an HTML attribute, and inside an existing <script> block).
# None of these load external resources or exfiltrate anything -- they only
# exist to prove that special characters survive into the response unescaped.
PAYLOAD_VARIANTS = [
    f"<{XSS_MARKER}>",
    f"\"'><{XSS_MARKER}>",
    f"'-{XSS_MARKER}-'",
]

DEFAULT_HEADERS = {
    "User-Agent": "ZSV-ZeusScannerVuln/0.1 (authorized-security-scan)"
}


@dataclass
class XSSFinding:
    url: str
    parameter: str
    method: str  # GET or POST
    payload: str
    evidence: str


@dataclass
class CrawlResult:
    pages_visited: list[str] = field(default_factory=list)
    forms_found: int = 0


def _same_host(url: str, host: str) -> bool:
    try:
        return urlparse(url).hostname == host
    except ValueError:
        return False


def crawl(base_url: str, session: requests.Session, max_pages: int = 25,
          timeout: int = 10) -> list[str]:
    """Breadth-first same-origin crawl. Returns list of visited page URLs."""
    host = urlparse(base_url).hostname
    seen = {base_url}
    queue = [base_url]
    visited: list[str] = []

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        try:
            resp = session.get(url, timeout=timeout, headers=DEFAULT_HEADERS)
        except requests.RequestException as exc:
            log.debug("Crawl fetch failed for %s: %s", url, exc)
            continue

        visited.append(url)
        content_type = resp.headers.get("Content-Type", "")
        if "html" not in content_type and not resp.text.lstrip().startswith("<"):
            continue

        soup = BeautifulSoup(resp.text, "html.parser")
        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"]).split("#")[0]
            if link not in seen and _same_host(link, host) and len(seen) < max_pages * 4:
                seen.add(link)
                queue.append(link)

    return visited


def _extract_get_params(url: str) -> list[str]:
    return [k for k, _ in parse_qsl(urlparse(url).query)]


def _test_get_param(session: requests.Session, url: str, param: str,
                     timeout: int) -> XSSFinding | None:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query))

    for payload in PAYLOAD_VARIANTS:
        test_query = dict(query)
        test_query[param] = payload
        test_url = urlunparse(parsed._replace(query=urlencode(test_query)))
        try:
            resp = session.get(test_url, timeout=timeout, headers=DEFAULT_HEADERS)
        except requests.RequestException:
            continue

        finding = _check_reflection(resp.text, payload, test_url, param, "GET")
        if finding:
            return finding
    return None


def _test_form(session: requests.Session, page_url: str, form,
                timeout: int) -> list[XSSFinding]:
    findings: list[XSSFinding] = []
    action = urljoin(page_url, form.get("action") or page_url)
    method = (form.get("method") or "get").upper()

    inputs = form.find_all(["input", "textarea"])
    field_names = [
        i.get("name") for i in inputs
        if i.get("name") and i.get("type", "text").lower()
        not in ("submit", "button", "hidden", "file", "image", "checkbox", "radio")
    ]
    if not field_names:
        return findings

    for target_field in field_names:
        for payload in PAYLOAD_VARIANTS:
            data = {name: (payload if name == target_field else "zsv_test")
                     for name in field_names}
            try:
                if method == "POST":
                    resp = session.post(action, data=data, timeout=timeout,
                                         headers=DEFAULT_HEADERS)
                else:
                    resp = session.get(action, params=data, timeout=timeout,
                                        headers=DEFAULT_HEADERS)
            except requests.RequestException:
                continue

            finding = _check_reflection(resp.text, payload, action, target_field, method)
            if finding:
                findings.append(finding)
                break  # one confirmed payload per field is enough
    return findings


def _check_reflection(body: str, payload: str, url: str, param: str,
                       method: str) -> XSSFinding | None:
    # The payload appearing verbatim (with its raw <, >, ' characters
    # intact) means the app did NOT HTML-encode the output -- that's the
    # unescaped-reflection signature of a reflected XSS bug. If the app
    # encoded it correctly, the escaped form (e.g. &lt;...&gt;) would be in
    # the body instead and this exact-match check would not fire.
    if payload not in body:
        return None

    idx = body.find(payload)
    start = max(0, idx - 40)
    evidence = body[start:idx + len(payload) + 40].replace("\n", " ")
    return XSSFinding(url=url, parameter=param, method=method,
                       payload=payload, evidence=evidence)


def scan(base_url: str, max_pages: int = 25, timeout: int = 10) -> tuple[list[XSSFinding], CrawlResult]:
    session = requests.Session()
    session.verify = True

    visited = crawl(base_url, session, max_pages=max_pages, timeout=timeout)
    findings: list[XSSFinding] = []
    forms_count = 0

    for page_url in visited:
        for param in _extract_get_params(page_url):
            result = _test_get_param(session, page_url, param, timeout)
            if result:
                findings.append(result)

        try:
            resp = session.get(page_url, timeout=timeout, headers=DEFAULT_HEADERS)
        except requests.RequestException:
            continue
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        forms_count += len(forms)
        for form in forms:
            findings.extend(_test_form(session, page_url, form, timeout))

    return findings, CrawlResult(pages_visited=visited, forms_found=forms_count)
