from __future__ import annotations

import hashlib

from config import MAX_ATTACHMENT_MB

RISKY_EXTENSIONS = {".exe", ".dll", ".scr", ".js", ".jse", ".vbs", ".vbe", ".ps1", ".bat", ".cmd", ".com", ".hta", ".msi"}


def attachment_metadata(filename: str, mime_type: str, payload: bytes) -> dict[str, object]:
    if len(payload) > MAX_ATTACHMENT_MB * 1024 * 1024:
        return {"filename": filename, "mime_type": mime_type, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest(), "md5": hashlib.md5(payload, usedforsecurity=False).hexdigest(), "signature": "Not inspected: size limit exceeded", "flags": ["Attachment exceeds configured analysis limit."]}
    from modules.email_parser import _signature

    import os

    flags: list[str] = []
    ext = os.path.splitext(filename.lower())[1]
    signature = _signature(payload)
    if ext in RISKY_EXTENSIONS:
        flags.append(f"Potentially risky extension: {ext}")
    if signature.startswith(("DOS/Windows executable", "ELF executable")) and ext not in {".exe", ".dll", ".com"}:
        flags.append("Executable signature does not match the filename extension.")
    expected_mime = {
        "PDF signature": "application/pdf",
        "PNG image signature": "image/png",
        "JPEG image signature": "image/jpeg",
        "GIF image signature": "image/gif",
        "ZIP/archive signature": "application/zip",
    }.get(signature)
    if expected_mime and mime_type.lower() != expected_mime:
        flags.append(f"File signature suggests {expected_mime}, but declared MIME type is {mime_type}.")
    return {
        "filename": filename,
        "mime_type": mime_type,
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "md5": hashlib.md5(payload, usedforsecurity=False).hexdigest(),
        "signature": signature,
        "flags": flags,
    }
