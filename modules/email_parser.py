from __future__ import annotations

from dataclasses import asdict, dataclass
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from typing import Any

from modules.attachment_analysis import attachment_metadata


class _LinkTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            self._href = next((value for key, value in attrs if key.lower() == "href"), None)
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._href is not None:
            self.links.append({"text": " ".join(" ".join(self._text).split()), "href": self._href})
            self._href = None
            self._text = []


@dataclass
class ParsedEmail:
    headers: dict[str, str]
    raw_headers: str
    received: list[str]
    authentication_results: list[str]
    body_text: str
    body_html: str
    links: list[dict[str, str]]
    attachments: list[dict[str, Any]]
    warnings: list[str]
    date_utc: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _decode_part(part: Any) -> str:
    try:
        value = part.get_content()
        return value if isinstance(value, str) else ""
    except (LookupError, UnicodeError, ValueError):
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            return ""
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except (LookupError, UnicodeError):
            return payload.decode("utf-8", errors="replace")


def parse_email(content: bytes) -> ParsedEmail:
    warnings: list[str] = []
    try:
        message = BytesParser(policy=policy.default).parsebytes(content)
    except (ValueError, TypeError) as exc:
        raise ValueError("The uploaded file could not be parsed as an email.") from exc

    headers: dict[str, str] = {}
    for name in ("From", "To", "Cc", "Reply-To", "Subject", "Date", "Message-ID", "Return-Path"):
        values = message.get_all(name, [])
        if values:
            headers[name] = "\n".join(str(value) for value in values)
            if len(values) > 1:
                warnings.append(f"Duplicate {name} headers were found.")
    if not headers.get("From"):
        warnings.append("The From header is missing.")
    if not headers.get("Date"):
        warnings.append("The Date header is missing.")
    if not headers.get("Message-ID"):
        warnings.append("The Message-ID header is missing.")

    raw_header_lines: list[str] = []
    for name, value in message.raw_items():
        if name.lower() in {"received", "authentication-results"}:
            raw_header_lines.append(f"{name}: {value}")
        elif name.lower() in {"from", "to", "cc", "reply-to", "subject", "date", "message-id", "return-path"}:
            raw_header_lines.append(f"{name}: {value}")

    received = [str(value) for value in message.get_all("Received", [])]
    auth_results = [str(value) for value in message.get_all("Authentication-Results", [])]
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict[str, Any]] = []

    for part in message.walk():
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        if disposition == "attachment" or filename:
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                attachment_metadata(
                    str(filename or "unnamed-attachment"),
                    part.get_content_type(),
                    payload,
                )
            )
            continue
        if part.get_content_type() == "text/plain":
            text_parts.append(_decode_part(part))
        elif part.get_content_type() == "text/html":
            html_parts.append(_decode_part(part))

    links: list[dict[str, str]] = []
    for html_content in html_parts:
        parser = _LinkTextParser()
        try:
            parser.feed(html_content)
            parser.close()
            links.extend(parser.links)
        except (ValueError, AssertionError):
            warnings.append("An HTML body fragment could not be fully inspected.")

    date_utc = None
    raw_date = headers.get("Date")
    if raw_date:
        try:
            parsed_date = parsedate_to_datetime(raw_date.splitlines()[0])
            if parsed_date.tzinfo is None:
                warnings.append("The Date header has no timezone information.")
            else:
                from datetime import timezone

                date_utc = parsed_date.astimezone(timezone.utc).isoformat()
        except (TypeError, ValueError, OverflowError):
            warnings.append("The Date header could not be parsed.")

    if message.defects:
        warnings.append("The parser reported structural defects in the email.")

    return ParsedEmail(
        headers=headers,
        raw_headers="\n".join(raw_header_lines),
        received=received,
        authentication_results=auth_results,
        body_text="\n".join(text_parts),
        body_html="\n".join(html_parts),
        links=links,
        attachments=attachments,
        warnings=warnings,
        date_utc=date_utc,
    )


def _signature(payload: bytes) -> str:
    signatures = (
        (b"MZ", "DOS/Windows executable signature"),
        (b"\x7fELF", "ELF executable signature"),
        (b"PK\x03\x04", "ZIP/archive signature"),
        (b"%PDF-", "PDF signature"),
        (b"\x89PNG\r\n\x1a\n", "PNG image signature"),
        (b"\xff\xd8\xff", "JPEG image signature"),
        (b"GIF87a", "GIF image signature"),
        (b"GIF89a", "GIF image signature"),
    )
    return next((label for prefix, label in signatures if payload.startswith(prefix)), "Unknown or unrecognized")
