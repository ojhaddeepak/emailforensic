from email.message import EmailMessage

from modules.email_parser import parse_email


def test_parses_headers_and_timezone(sample_eml):
    parsed = parse_email(sample_eml)
    assert parsed.headers["From"].startswith("Example Sender")
    assert parsed.date_utc == "2024-10-01T10:00:00+00:00"
    assert len(parsed.received) == 1


def test_malformed_and_missing_headers_are_reported():
    parsed = parse_email(b"From: not-an-address\r\nSubject: broken\r\n\r\nbody")
    assert "Message-ID" not in parsed.headers
    assert any("Message-ID" in warning for warning in parsed.warnings)


def test_duplicate_header_values_are_preserved():
    parsed = parse_email(b"From: one@example.com\r\nFrom: two@example.net\r\nSubject: x\r\n\r\nbody")
    assert "one@example.com" in parsed.headers["From"]
    assert "two@example.net" in parsed.headers["From"]
    assert any("Duplicate From" in warning for warning in parsed.warnings)


def test_mime_attachment_is_hashed_without_export():
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message.set_content("Synthetic attachment test")
    message.add_attachment(b"harmless bytes", maintype="application", subtype="octet-stream", filename="notes.txt")
    parsed = parse_email(message.as_bytes())
    item = parsed.attachments[0]
    assert item["filename"] == "notes.txt"
    assert len(item["sha256"]) == 64
    assert item["size"] == len(b"harmless bytes")
