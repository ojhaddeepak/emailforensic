from __future__ import annotations

import json
import hashlib
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from config import DATABASE_PATH, DATA_DIR, EVIDENCE_DIR
from modules.evidence_import import identify_evidence, sha256_bytes, utc_now, validate_eml
from modules.email_parser import parse_email
from modules.url_analysis import redact_url


@contextmanager
def _connect():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database() -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY, created_at TEXT NOT NULL, analyst TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL REFERENCES investigations(id),
                filename TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL,
                imported_at TEXT NOT NULL, evidence_path TEXT NOT NULL, parsed_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS custody_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, investigation_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL, event TEXT NOT NULL, details TEXT NOT NULL, timestamp TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS url_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checked_at TEXT NOT NULL,
                url_hash TEXT NOT NULL,
                display_url TEXT NOT NULL,
                action TEXT NOT NULL,
                outcome TEXT NOT NULL,
                malicious INTEGER NOT NULL DEFAULT 0,
                suspicious INTEGER NOT NULL DEFAULT 0,
                harmless INTEGER NOT NULL DEFAULT 0,
                undetected INTEGER NOT NULL DEFAULT 0,
                report_url TEXT NOT NULL DEFAULT ''
            );
            CREATE TRIGGER IF NOT EXISTS custody_no_update BEFORE UPDATE ON custody_events
            BEGIN SELECT RAISE(ABORT, 'custody events are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS custody_no_delete BEFORE DELETE ON custody_events
            BEGIN SELECT RAISE(ABORT, 'custody events are append-only'); END;
            """
        )


def create_investigation(analyst: str = "") -> str:
    import uuid

    initialize_database()
    investigation_id = str(uuid.uuid4())
    with _connect() as conn:
        conn.execute("INSERT INTO investigations(id, created_at, analyst) VALUES (?, ?, ?)", (investigation_id, utc_now(), analyst.strip()[:100]))
        _event(conn, investigation_id, "", "Investigation created", "Investigation initialized.")
    return investigation_id


def _event(conn: sqlite3.Connection, investigation_id: str, evidence_id: str, event: str, details: str) -> None:
    conn.execute(
        "INSERT INTO custody_events(investigation_id, evidence_id, event, details, timestamp) VALUES (?, ?, ?, ?, ?)",
        (investigation_id, evidence_id, event, details[:500], utc_now()),
    )


def record_event(investigation_id: str, evidence_id: str, event: str, details: str = "") -> None:
    initialize_database()
    with _connect() as conn:
        _event(conn, investigation_id, evidence_id, event, details)


def import_evidence(investigation_id: str, filename: str, content: bytes) -> dict[str, Any]:
    validate_eml(filename, content)
    evidence_id, sha256 = identify_evidence(content)
    parsed = parse_email(content)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    evidence_path = EVIDENCE_DIR / f"{evidence_id}.eml"
    with evidence_path.open("xb") as evidence_file:
        evidence_file.write(content)
    timestamp = utc_now()
    try:
        with _connect() as conn:
            conn.execute(
                """INSERT INTO evidence(id, investigation_id, filename, size, sha256, imported_at, evidence_path, parsed_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (evidence_id, investigation_id, Path(filename).name[:255], len(content), sha256, timestamp, str(evidence_path), json.dumps(parsed.to_dict(), ensure_ascii=True)),
            )
            _event(conn, investigation_id, evidence_id, "Evidence imported", f"{Path(filename).name[:255]}; SHA-256 {sha256}")
    except Exception:
        evidence_path.unlink(missing_ok=True)
        raise
    return get_evidence(evidence_id)


def verify_evidence(evidence_id: str) -> dict[str, str]:
    record = get_evidence(evidence_id)
    path = Path(record["evidence_path"])
    if not path.is_file():
        return {"expected": record["sha256"], "actual": "", "status": "Evidence file is missing"}
    actual = sha256_bytes(path.read_bytes())
    status = "Verified: hash matches" if actual == record["sha256"] else "WARNING: hash mismatch"
    record_event(record["investigation_id"], evidence_id, "Evidence integrity verified", status)
    return {"expected": record["sha256"], "actual": actual, "status": status}


def get_evidence(evidence_id: str) -> dict[str, Any]:
    initialize_database()
    with _connect() as conn:
        row = conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
    if row is None:
        raise KeyError("Evidence record was not found.")
    result = dict(row)
    result["parsed"] = json.loads(result.pop("parsed_json"))
    return result


def list_evidence(investigation_id: str | None = None) -> list[dict[str, Any]]:
    initialize_database()
    with _connect() as conn:
        if investigation_id:
            rows = conn.execute("SELECT * FROM evidence WHERE investigation_id = ? ORDER BY imported_at DESC", (investigation_id,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM evidence ORDER BY imported_at DESC").fetchall()
    results = []
    for row in rows:
        item = dict(row)
        item["parsed"] = json.loads(item.pop("parsed_json"))
        results.append(item)
    return results


def list_investigations() -> list[dict[str, Any]]:
    initialize_database()
    with _connect() as conn:
        rows = conn.execute(
            """SELECT i.id, i.created_at, i.analyst, COUNT(e.id) AS evidence_count
               FROM investigations i LEFT JOIN evidence e ON e.investigation_id = i.id
               GROUP BY i.id ORDER BY i.created_at DESC"""
        ).fetchall()
    return [dict(row) for row in rows]


def list_custody_events(investigation_id: str | None = None, evidence_id: str | None = None) -> list[dict[str, Any]]:
    initialize_database()
    clauses, values = [], []
    if investigation_id:
        clauses.append("investigation_id = ?")
        values.append(investigation_id)
    if evidence_id:
        clauses.append("evidence_id = ?")
        values.append(evidence_id)
    query = "SELECT * FROM custody_events"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY id DESC"
    with _connect() as conn:
        rows = conn.execute(query, values).fetchall()
    return [dict(row) for row in rows]


def record_url_check(url: str, action: str, result: dict[str, Any]) -> None:
    initialize_database()
    stats = result.get("stats", {})
    with _connect() as conn:
        conn.execute(
            """INSERT INTO url_checks
               (checked_at, url_hash, display_url, action, outcome, malicious, suspicious,
                harmless, undetected, report_url)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                utc_now(),
                hashlib.sha256(url.encode("utf-8")).hexdigest(),
                redact_url(url),
                action[:80],
                str(result.get("outcome", "unknown"))[:80],
                int(stats.get("malicious", 0) or 0),
                int(stats.get("suspicious", 0) or 0),
                int(stats.get("harmless", 0) or 0),
                int(stats.get("undetected", 0) or 0),
                "",
            ),
        )


def list_url_checks(limit: int = 500) -> list[dict[str, Any]]:
    initialize_database()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM url_checks ORDER BY id DESC LIMIT ?",
            (max(1, min(limit, 2000)),),
        ).fetchall()
    return [dict(row) for row in rows]
