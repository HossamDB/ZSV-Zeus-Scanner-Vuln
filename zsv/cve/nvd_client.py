"""
Free NVD (National Vulnerability Database, NIST) CVE lookup client.

Uses the public NVD REST API 2.0 (https://nvd.nist.gov/developers/vulnerabilities)
-- no cost, no license, optional free API key just raises your rate limit.
Results are cached into the local SQLite `cves` table so repeat scans of the
same service don't need to re-hit the API, and so the database always holds
a local, queryable record of "which CVEs apply to what we found."
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

from ..database.db import Database
from ..utils.logger import get_logger

log = get_logger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Without an API key NVD allows ~5 requests / rolling 30s; with a free key,
# ~50 requests / rolling 30s. We rate-limit conservatively either way.
NO_KEY_DELAY = 6.5
WITH_KEY_DELAY = 0.7

CACHE_FRESHNESS = timedelta(days=7)


class NVDClient:
    def __init__(self, db: Database, api_key: str | None = None,
                 timeout: int = 15, max_results: int = 10):
        self.db = db
        self.api_key = api_key
        self.timeout = timeout
        self.max_results = max_results
        self._last_request_at = 0.0

    def _throttle(self) -> None:
        delay = WITH_KEY_DELAY if self.api_key else NO_KEY_DELAY
        elapsed = time.monotonic() - self._last_request_at
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_request_at = time.monotonic()

    def lookup(self, service_string: str, cpe: str | None = None,
               use_cache: bool = True) -> list[dict[str, Any]]:
        """
        Look up CVEs for a given service (e.g. "OpenSSH 8.9p1") or CPE
        string. Checks the local cache first; falls back to a live NVD API
        query and writes results back into the cache ("updates the
        database about CVEs").
        """
        if not service_string:
            return []

        if use_cache:
            cached = self.db.cached_cves_for_service(service_string)
            if cached and self._is_fresh(cached):
                log.debug("Using cached CVEs for %r", service_string)
                return cached

        try:
            results = self._query_nvd(service_string, cpe)
        except requests.RequestException as exc:
            log.warning("NVD lookup failed for %r: %s", service_string, exc)
            # Fall back to whatever we have cached, even if stale.
            return self.db.cached_cves_for_service(service_string)

        for r in results:
            self.db.upsert_cve(
                cve_id=r["cve_id"],
                source_service=service_string,
                description=r["description"],
                cvss_v3_score=r["cvss_v3_score"],
                cvss_v3_severity=r["cvss_v3_severity"],
                published=r["published"],
                refs_json=r["references"],
                raw=r["raw"],
            )
        return results

    @staticmethod
    def _is_fresh(cached_rows: list[dict[str, Any]]) -> bool:
        if not cached_rows:
            return False
        try:
            fetched = datetime.fromisoformat(cached_rows[0]["fetched_at"])
        except (KeyError, ValueError):
            return False
        if fetched.tzinfo is None:
            fetched = fetched.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - fetched < CACHE_FRESHNESS

    def _query_nvd(self, service_string: str, cpe: str | None) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"resultsPerPage": self.max_results}
        if cpe:
            params["cpeName"] = cpe
        else:
            params["keywordSearch"] = service_string

        headers = {"apiKey": self.api_key} if self.api_key else {}

        self._throttle()
        log.info("Querying NVD for: %s", service_string)
        resp = requests.get(NVD_BASE_URL, params=params, headers=headers,
                             timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()

        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            score, severity = self._extract_cvss(cve.get("metrics", {}))
            references = [ref.get("url") for ref in cve.get("references", []) if ref.get("url")]

            results.append({
                "cve_id": cve_id,
                "description": description,
                "cvss_v3_score": score,
                "cvss_v3_severity": severity,
                "published": cve.get("published"),
                "references": references,
                "raw": item,
            })
        return results

    @staticmethod
    def _extract_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity") or entries[0].get("baseSeverity")
                return score, severity
        return None, None
