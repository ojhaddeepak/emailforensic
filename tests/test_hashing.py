import hashlib

import pytest

from modules.evidence_import import identify_evidence, validate_eml


def test_sha256_and_evidence_id():
    content = b"From: synthetic@example.com\r\n\r\nbody"
    evidence_id, digest = identify_evidence(content)
    assert len(evidence_id) == 36
    assert digest == hashlib.sha256(content).hexdigest()


def test_reimporting_identical_bytes_keeps_hash_but_assigns_new_evidence_id():
    content = b"From: synthetic@example.com\r\nSubject: same fixture\r\n\r\nhttps://example.org/\r\n"
    first_id, first_hash = identify_evidence(content)
    second_id, second_hash = identify_evidence(content)

    assert first_id != second_id
    assert first_hash == second_hash == hashlib.sha256(content).hexdigest()


def test_one_changed_byte_changes_sha256():
    _, first_hash = identify_evidence(b"same synthetic message")
    _, second_hash = identify_evidence(b"same synthetic messagE")
    assert first_hash != second_hash


def test_upload_validation():
    validate_eml("sample.eml", b"content")
    with pytest.raises(ValueError):
        validate_eml("sample.txt", b"content")
