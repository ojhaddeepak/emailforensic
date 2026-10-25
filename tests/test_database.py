import sqlite3

import pytest

import modules.database as database


def test_chain_of_custody_append_only_and_hash_verify(tmp_path, monkeypatch, sample_eml):
    monkeypatch.setattr(database, "DATA_DIR", tmp_path)
    monkeypatch.setattr(database, "EVIDENCE_DIR", tmp_path / "evidence")
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "test.sqlite3")
    investigation = database.create_investigation("fictional analyst")
    record = database.import_evidence(investigation, "sample.eml", sample_eml)
    assert database.verify_evidence(record["id"])["status"] == "Verified: hash matches"
    assert database.list_custody_events(evidence_id=record["id"])
    with pytest.raises(sqlite3.IntegrityError):
        with database._connect() as conn:
            conn.execute("DELETE FROM custody_events WHERE evidence_id = ?", (record["id"],))


def test_url_history_redacts_query_and_stores_aggregate_result(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATA_DIR", tmp_path)
    monkeypatch.setattr(database, "EVIDENCE_DIR", tmp_path / "evidence")
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "test.sqlite3")
    url = "https://example.org/path?token=private-value&view=full"
    database.record_url_check(
        url,
        "existing_report",
        {
            "outcome": "suspicious",
            "stats": {"malicious": 0, "suspicious": 1, "harmless": 4, "undetected": 3},
            "report_url": "https://www.virustotal.com/gui/url/example",
        },
    )
    row = database.list_url_checks()[0]
    assert "private-value" not in row["display_url"]
    assert row["url_hash"]
    assert row["outcome"] == "suspicious"
    assert row["suspicious"] == 1
    assert row["report_url"] == ""
