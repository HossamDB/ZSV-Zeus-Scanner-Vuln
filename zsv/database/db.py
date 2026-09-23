"""
SQLite persistence layer for ZSV.

Tables
------
targets  - one row per distinct scan target (IP / hostname / webapp URL)
scans    - one row per scan run against a target
findings - individual findings from any module (nmap/nikto/xss/headers)
cves     - local cache of CVE records pulled from the free NVD API, keyed
           by CVE ID plus the CPE/service string that produced the hit
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host        TEXT NOT NULL,
    url         TEXT,
    is_ip       INTEGER NOT NULL DEFAULT 0,
    first_seen  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(host)
);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    started_at  TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT,
    modules     TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    module      TEXT NOT NULL,             -- nmap | nikto | xss | headers
    severity    TEXT NOT NULL DEFAULT 'info',  -- info|low|medium|high|critical
    title       TEXT NOT NULL,
    detail      TEXT,
    location    TEXT,                      -- port, URL, param name, etc.
    evidence    TEXT,
    cve_ids     TEXT NOT NULL DEFAULT '[]', -- JSON list of related CVE IDs
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS cves (
    cve_id          TEXT NOT NULL,
    source_service  TEXT NOT NULL,   -- e.g. "openssh 8.9p1" or cpe string
    description     TEXT,
    cvss_v3_score   REAL,
    cvss_v3_severity TEXT,
    published       TEXT,
    refs_json      TEXT,            -- JSON list of URLs
    raw             TEXT,            -- full JSON blob from NVD, for audit
    fetched_at      TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (cve_id, source_service)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_id);
"""


class Database:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON;")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @contextmanager
    def cursor(self) -> Iterator[sqlite3.Cursor]:
        cur = self._conn.cursor()
        try:
            yield cur
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        finally:
            cur.close()

    # -- targets -----------------------------------------------------
    def upsert_target(self, host: str, url: str | None, is_ip: bool) -> int:
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO targets (host, url, is_ip) VALUES (?, ?, ?) "
                "ON CONFLICT(host) DO UPDATE SET url=excluded.url",
                (host, url, int(is_ip)),
            )
            cur.execute("SELECT id FROM targets WHERE host = ?", (host,))
            return cur.fetchone()["id"]

    # -- scans ---------------------------------------------------------
    def start_scan(self, target_id: int, modules: Iterable[str]) -> int:
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO scans (target_id, modules) VALUES (?, ?)",
                (target_id, json.dumps(list(modules))),
            )
            return cur.lastrowid

    def finish_scan(self, scan_id: int) -> None:
        with self.cursor() as cur:
            cur.execute(
                "UPDATE scans SET finished_at = datetime('now') WHERE id = ?",
                (scan_id,),
            )

    # -- findings --------------------------------------------------------
    def add_finding(
        self,
        scan_id: int,
        module: str,
        title: str,
        severity: str = "info",
        detail: str = "",
        location: str = "",
        evidence: str = "",
        cve_ids: list[str] | None = None,
    ) -> int:
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO findings
                   (scan_id, module, severity, title, detail, location, evidence, cve_ids)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    module,
                    severity,
                    title,
                    detail,
                    location,
                    evidence,
                    json.dumps(cve_ids or []),
                ),
            )
            return cur.lastrowid

    def findings_for_scan(self, scan_id: int) -> list[dict[str, Any]]:
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM findings WHERE scan_id = ? "
                "ORDER BY CASE severity "
                "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
                "WHEN 'low' THEN 3 ELSE 4 END, id",
                (scan_id,),
            )
            rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            r["cve_ids"] = json.loads(r["cve_ids"] or "[]")
        return rows

    # -- CVE cache ("update database about CVEs") -------------------------
    def upsert_cve(
        self,
        cve_id: str,
        source_service: str,
        description: str,
        cvss_v3_score: float | None,
        cvss_v3_severity: str | None,
        published: str | None,
        refs_json: list[str],
        raw: dict[str, Any],
    ) -> None:
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO cves
                   (cve_id, source_service, description, cvss_v3_score,
                    cvss_v3_severity, published, refs_json, raw, fetched_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                   ON CONFLICT(cve_id, source_service) DO UPDATE SET
                       description=excluded.description,
                       cvss_v3_score=excluded.cvss_v3_score,
                       cvss_v3_severity=excluded.cvss_v3_severity,
                       published=excluded.published,
                       refs_json=excluded.refs_json,
                       raw=excluded.raw,
                       fetched_at=datetime('now')""",
                (
                    cve_id,
                    source_service,
                    description,
                    cvss_v3_score,
                    cvss_v3_severity,
                    published,
                    json.dumps(refs_json),
                    json.dumps(raw),
                ),
            )

    def cached_cves_for_service(self, source_service: str) -> list[dict[str, Any]]:
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM cves WHERE source_service = ? ORDER BY cvss_v3_score DESC",
                (source_service,),
            )
            rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            r["refs_json"] = json.loads(r["refs_json"] or "[]")
        return rows

    def all_scan_summary(self, scan_id: int) -> dict[str, Any]:
        with self.cursor() as cur:
            cur.execute(
                """SELECT scans.*, targets.host, targets.url, targets.is_ip
                   FROM scans JOIN targets ON targets.id = scans.target_id
                   WHERE scans.id = ?""",
                (scan_id,),
            )
            row = cur.fetchone()
            return dict(row) if row else {}
