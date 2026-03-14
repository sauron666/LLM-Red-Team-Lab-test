from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional


class LabDB:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._conn() as c:
            c.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS projects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT DEFAULT '',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    connector_type TEXT NOT NULL,
                    base_url TEXT NOT NULL,
                    model TEXT NOT NULL,
                    api_key TEXT DEFAULT '',
                    extra_headers_json TEXT DEFAULT '{}',
                    timeout_sec INTEGER DEFAULT 30,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,

                    FOREIGN KEY(project_id) REFERENCES projects(id)
                );

                CREATE TABLE IF NOT EXISTS runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    target_id INTEGER NOT NULL,
                    mode TEXT NOT NULL,
                    safe_mode INTEGER NOT NULL,
                    intensity INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    finished_at TEXT,
                    summary_json TEXT DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER NOT NULL,
                    attack_id TEXT NOT NULL,
                    attack_title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    status TEXT DEFAULT 'vulnerable',
                    evidence_type TEXT DEFAULT 'general_signal',
                    severity TEXT NOT NULL,
                    confidence INTEGER NOT NULL,
                    risk_score INTEGER NOT NULL,
                    recommendation TEXT DEFAULT '',
                    evidence_json TEXT DEFAULT '{}',
                    transcript_json TEXT DEFAULT '{}',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            self._migrate_db(c)

    def _migrate_db(self, c: sqlite3.Connection) -> None:
        # Schema migrations (add missing columns safely)
        self._ensure_column(c, "findings", "status", "TEXT DEFAULT 'vulnerable'")
        self._ensure_column(c, "findings", "evidence_type", "TEXT DEFAULT 'general_signal'")
        self._ensure_column(c, "targets", "updated_at", "TEXT DEFAULT CURRENT_TIMESTAMP")

    def _ensure_column(self, c: sqlite3.Connection, table: str, column: str, decl: str) -> None:
        cols = {str(r[1]) for r in c.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in cols:
            # SQLite does not allow ALTER TABLE ... ADD COLUMN with a non-constant DEFAULT
            # (e.g., CURRENT_TIMESTAMP). Add the column without DEFAULT and backfill.
            decl_upper = str(decl).upper()
            if "DEFAULT CURRENT_TIMESTAMP" in decl_upper or "DEFAULT (CURRENT_TIMESTAMP)" in decl_upper:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {column} TEXT")
                try:
                    c.execute(f"UPDATE {table} SET {column}=CURRENT_TIMESTAMP WHERE {column} IS NULL")
                except Exception:
                    pass
                return
            c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")

    # Projects
    def list_projects(self) -> List[Dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM projects ORDER BY name COLLATE NOCASE").fetchall()
            return [dict(r) for r in rows]

    def create_project(self, name: str, description: str = "") -> int:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO projects(name, description) VALUES(?, ?)",
                (name.strip(), description.strip()),
            )
            return int(cur.lastrowid)

    # Targets
    def list_targets(self, project_id: Optional[int] = None) -> List[Dict[str, Any]]:
        with self._conn() as c:
            if project_id:
                rows = c.execute(
                    "SELECT * FROM targets WHERE project_id = ? ORDER BY id DESC", (project_id,)
                ).fetchall()
            else:
                rows = c.execute("SELECT * FROM targets ORDER BY id DESC").fetchall()
            results = []
            for r in rows:
                d = dict(r)
                try:
                    d["extra_headers"] = json.loads(d.pop("extra_headers_json") or "{}")
                except Exception:
                    d["extra_headers"] = {}
                results.append(d)
            return results

    def create_target(
        self,
        project_id: int,
        name: str,
        connector_type: str,
        base_url: str,
        model: str,
        api_key: str = "",
        extra_headers: Optional[Dict[str, str]] = None,
        timeout_sec: int = 30,
    ) -> int:
        with self._conn() as c:
            cur = c.execute(
                """
                INSERT INTO targets(project_id, name, connector_type, base_url, model, api_key, extra_headers_json, timeout_sec)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    project_id,
                    name.strip(),
                    connector_type,
                    base_url.strip(),
                    model.strip(),
                    api_key.strip(),
                    json.dumps(extra_headers or {}, ensure_ascii=False),
                    int(timeout_sec),
                ),
            )
            return int(cur.lastrowid)

    def get_target(self, target_id: int) -> Dict[str, Any]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
            if not row:
                raise KeyError(f"Target {target_id} not found")
            d = dict(row)
            d["extra_headers"] = json.loads(d.pop("extra_headers_json") or "{}")
            return d
    def update_target(
        self,
        target_id: int,
        *,
        name: str,
        connector_type: str,
        base_url: str,
        model: str,
        api_key: str = "",
        extra_headers: Optional[Dict[str, str]] = None,
        timeout_sec: int = 30,
    ) -> None:
        with self._conn() as c:
            c.execute(
                """
                UPDATE targets
                SET name=?, connector_type=?, base_url=?, model=?, api_key=?, extra_headers_json=?, timeout_sec=?, updated_at=CURRENT_TIMESTAMP
                WHERE id=?
                """,
                (
                    name.strip(),
                    connector_type,
                    base_url.strip(),
                    model.strip(),
                    api_key.strip(),
                    json.dumps(extra_headers or {}, ensure_ascii=False),
                    int(timeout_sec),
                    int(target_id),
                ),
            )



    # Runs
    def create_run(
        self, project_id: int, target_id: int, mode: str, safe_mode: bool, intensity: int, status: str = "running"
    ) -> int:
        with self._conn() as c:
            cur = c.execute(
                """
                INSERT INTO runs(project_id, target_id, mode, safe_mode, intensity, status)
                VALUES(?, ?, ?, ?, ?, ?)
                """,
                (project_id, target_id, mode, 1 if safe_mode else 0, intensity, status),
            )
            return int(cur.lastrowid)

    def finish_run(self, run_id: int, status: str, summary: Dict[str, Any]) -> None:
        with self._conn() as c:
            c.execute(
                "UPDATE runs SET status=?, finished_at=CURRENT_TIMESTAMP, summary_json=? WHERE id=?",
                (status, json.dumps(summary, ensure_ascii=False), run_id),
            )

    def list_runs(self, project_id: Optional[int] = None) -> List[Dict[str, Any]]:
        with self._conn() as c:
            if project_id:
                rows = c.execute("SELECT * FROM runs WHERE project_id=? ORDER BY id DESC", (project_id,)).fetchall()
            else:
                rows = c.execute("SELECT * FROM runs ORDER BY id DESC").fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["summary"] = json.loads(d.pop("summary_json") or "{}")
                out.append(d)
            return out

    def get_run(self, run_id: int) -> Dict[str, Any]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
            if not row:
                raise KeyError(f"Run {run_id} not found")
            d = dict(row)
            d["summary"] = json.loads(d.pop("summary_json") or "{}")
            return d

    # Findings
    def add_finding(
        self,
        run_id: int,
        attack_id: str,
        attack_title: str,
        category: str,
        severity: str,
        confidence: int,
        risk_score: int,
        recommendation: str,
        evidence: Dict[str, Any],
        transcript: Dict[str, Any],
        status: str = "vulnerable",
        evidence_type: str = "general_signal",
    ) -> int:
        with self._conn() as c:
            cur = c.execute(
                """
                INSERT INTO findings(run_id, attack_id, attack_title, category, status, evidence_type, severity, confidence, risk_score, recommendation, evidence_json, transcript_json)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    attack_id,
                    attack_title,
                    category,
                    status,
                    evidence_type,
                    severity,
                    int(confidence),
                    int(risk_score),
                    recommendation,
                    json.dumps(evidence, ensure_ascii=False),
                    json.dumps(transcript, ensure_ascii=False),
                ),
            )
            return int(cur.lastrowid)

    def list_findings(self, run_id: Optional[int] = None) -> List[Dict[str, Any]]:
        with self._conn() as c:
            if run_id:
                rows = c.execute("SELECT * FROM findings WHERE run_id=? ORDER BY risk_score DESC, id DESC", (run_id,)).fetchall()
            else:
                rows = c.execute("SELECT * FROM findings ORDER BY id DESC").fetchall()
            results = []
            for r in rows:
                d = dict(r)
                d["evidence"] = json.loads(d.pop("evidence_json") or "{}")
                d["transcript"] = json.loads(d.pop("transcript_json") or "{}")
                results.append(d)
            return results

    def get_finding(self, finding_id: int) -> Dict[str, Any]:
        with self._conn() as c:
            r = c.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
            if not r:
                raise KeyError(f"Finding {finding_id} not found")
            d = dict(r)
            d["evidence"] = json.loads(d.pop("evidence_json") or "{}")
            d["transcript"] = json.loads(d.pop("transcript_json") or "{}")
            return d
