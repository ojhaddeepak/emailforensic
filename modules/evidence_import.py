from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

from config import MAX_UPLOAD_MB


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def validate_eml(filename: str, content: bytes) -> None:
    if not filename.lower().endswith(".eml"):
        raise ValueError("Only .eml evidence files are accepted.")
    if not content:
        raise ValueError("The uploaded email is empty.")
    if len(content) > MAX_UPLOAD_MB * 1024 * 1024:
        raise ValueError(f"Email exceeds the {MAX_UPLOAD_MB} MB upload limit.")


def identify_evidence(content: bytes) -> tuple[str, str]:
    return str(uuid.uuid4()), hashlib.sha256(content).hexdigest()


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()
