"""
Nmap-based port/service scanner.

Nmap (https://nmap.org) is free and open source. This module shells out to
the system `nmap` binary (it is NOT bundled/installed by ZSV — see README
for install instructions) and parses its XML output (`-oX -`) with the
standard library, so no extra third-party nmap wrapper package is required.
"""
from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from ..utils.logger import get_logger

log = get_logger(__name__)


class NmapNotFoundError(RuntimeError):
    pass


@dataclass
class ServiceResult:
    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str
    extrainfo: str
    cpe: list[str] = field(default_factory=list)

    @property
    def service_string(self) -> str:
        """Best-effort 'product version' string, for CVE/CPE lookups."""
        parts = [p for p in (self.product, self.version) if p]
        return " ".join(parts) if parts else self.service


def is_available() -> bool:
    return shutil.which("nmap") is not None


def run_scan(host: str, ports: str = "1-1000", extra_args: str = "-sV -T4",
             timeout: int = 300) -> list[ServiceResult]:
    """
    Run `nmap <extra_args> -p <ports> -oX - <host>` and return parsed
    service results. Raises NmapNotFoundError if nmap isn't installed.
    Never scans beyond the single host it's given.
    """
    if not is_available():
        raise NmapNotFoundError(
            "nmap binary not found on PATH. Install it (e.g. `apt install "
            "nmap`, `brew install nmap`) or run with --no-nmap to skip "
            "port/service scanning."
        )

    cmd = ["nmap", *extra_args.split(), "-p", ports, "-oX", "-", host]
    log.info("Running: %s", " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"nmap scan timed out after {timeout}s") from exc

    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"nmap failed (rc={proc.returncode}): {proc.stderr.strip()}")

    return _parse_xml(proc.stdout)


def _parse_xml(xml_text: str) -> list[ServiceResult]:
    results: list[ServiceResult] = []
    if not xml_text.strip():
        return results

    root = ET.fromstring(xml_text)
    for host_el in root.findall("host"):
        for ports_el in host_el.findall("ports"):
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                state = state_el.get("state") if state_el is not None else "unknown"
                if state != "open":
                    continue

                svc_el = port_el.find("service")
                service = svc_el.get("name", "") if svc_el is not None else ""
                product = svc_el.get("product", "") if svc_el is not None else ""
                version = svc_el.get("version", "") if svc_el is not None else ""
                extrainfo = svc_el.get("extrainfo", "") if svc_el is not None else ""
                cpes = []
                if svc_el is not None:
                    cpes = [c.text for c in svc_el.findall("cpe") if c.text]

                results.append(
                    ServiceResult(
                        port=int(port_el.get("portid")),
                        protocol=port_el.get("protocol", "tcp"),
                        state=state,
                        service=service,
                        product=product,
                        version=version,
                        extrainfo=extrainfo,
                        cpe=cpes,
                    )
                )
    return results
