"""
Nikto-based web server vulnerability scanner.

Nikto (https://github.com/sullo/nikto) is a free, open-source web server
scanner used here as the free alternative to commercial scanners like
Nessus/Tenable (which require a paid license outside its very limited
"Essentials" tier). ZSV does not bundle Nikto; install it separately (see
README) and ZSV will shell out to it and parse its results.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ..utils.logger import get_logger

log = get_logger(__name__)


class NiktoNotFoundError(RuntimeError):
    pass


@dataclass
class NiktoFinding:
    id: str
    url: str
    method: str
    message: str


def is_available() -> bool:
    return shutil.which("nikto") is not None


def run_scan(url: str, timeout: int = 600) -> list[NiktoFinding]:
    """
    Run `nikto -h <url> -Format json -output <tmpfile>` and parse results.
    Raises NiktoNotFoundError if nikto isn't installed.
    """
    if not is_available():
        raise NiktoNotFoundError(
            "nikto binary not found on PATH. Install it (e.g. `apt install "
            "nikto`, or clone github.com/sullo/nikto) or run with --no-nikto "
            "to skip this module."
        )

    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = Path(tmpdir) / "nikto_out.json"
        cmd = ["nikto", "-h", url, "-Format", "json", "-output", str(out_path)]
        log.info("Running: %s", " ".join(cmd))
        try:
            subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"nikto scan timed out after {timeout}s") from exc

        if not out_path.exists():
            return []

        try:
            data = json.loads(out_path.read_text())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return []

    findings: list[NiktoFinding] = []
    vulns = data.get("vulnerabilities", data) if isinstance(data, dict) else data
    if isinstance(vulns, list):
        for v in vulns:
            findings.append(
                NiktoFinding(
                    id=str(v.get("id", "")),
                    url=v.get("url", url),
                    method=v.get("method", "GET"),
                    message=v.get("msg", v.get("message", "")),
                )
            )
    return findings
