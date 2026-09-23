"""HTML report generation for ZSV, using Jinja2 with autoescaping enabled.

Autoescaping matters here specifically: scan evidence can legitimately
contain raw HTML/script-like strings (that's the point of the XSS module),
so the report template MUST escape them on output or the report itself
could reflect them unsafely.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import __version__
from ..database.db import Database

TEMPLATE_DIR = Path(__file__).parent / "templates"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )


def generate(db: Database, scan_id: int, output_path: Path,
             open_ports: list[dict[str, Any]] | None = None) -> Path:
    summary = db.all_scan_summary(scan_id)
    findings = db.findings_for_scan(scan_id)

    # attach cached CVE detail to each finding that references CVE IDs
    for f in findings:
        cves = []
        seen_ids = set(f.get("cve_ids") or [])
        if seen_ids:
            # cve rows are cached per source_service string, not per finding
            # directly, so we scan the finding's own recorded cve_ids and
            # pull matching cached rows by id across all cached services.
            with db.cursor() as cur:
                cur.execute(
                    "SELECT * FROM cves WHERE cve_id IN ({})".format(
                        ",".join("?" for _ in seen_ids)
                    ),
                    tuple(seen_ids),
                )
                rows = [dict(r) for r in cur.fetchall()]
            cves = rows
        f["cves"] = cves

    severity_counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "info")
        if sev not in severity_counts:
            sev = "info"
        severity_counts[sev] += 1

    env = _env()
    template = env.get_template("report.html")
    html = template.render(
        target_host=summary.get("host", "unknown"),
        target_url=summary.get("url", ""),
        started_at=summary.get("started_at", ""),
        finished_at=summary.get("finished_at", "in progress"),
        modules=_safe_json_list(summary.get("modules", "[]")),
        findings=findings,
        severity_counts=severity_counts,
        open_ports=open_ports or [],
        zsv_version=__version__,
    )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path


def _safe_json_list(raw: str) -> list[str]:
    import json
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return []
