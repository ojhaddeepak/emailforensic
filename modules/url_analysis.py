from __future__ import annotations

import ipaddress
import re
from html import unescape
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

URL_RE = re.compile(
    r"""(?ix)
    (?:
        \b(?:https?|ftp|file|javascript|data):[^\s<>'""]+
        |
        (?<![\w@.-])
        (?:www\.)?
        (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}
        (?::\d{1,5})?
        (?:/[^\s<>'""]*)?
        (?:\?[^\s<>'""]*)?
        (?:\#[^\s<>'""]*)?
    )
    """
)
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "is.gd", "buff.ly", "ow.ly", "rebrand.ly", "goo.gl"}
RISKY_TLDS = {"zip", "mov", "top", "click", "work"}
SENSITIVE_PARAMETER = re.compile(
    r"(?:pass(?:word)?|token|access.?token|refresh.?token|auth(?:entication|orization)?|"
    r"secret|api.?key|client.?secret|session|cookie|reset|verification|verify|"
    r"one.?time.?pass|otp|credential|signature|private.?key|email|code|nonce|state|ticket|sid)",
    re.IGNORECASE,
)
SENSITIVE_PATH = re.compile(
    r"(?:password|reset|verify|verification|token|authenticate|authorization|one.?time|otp)",
    re.IGNORECASE,
)
SENSITIVE_VALUE = re.compile(
    r"(?:eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|"
    r"[A-Fa-f0-9]{32,}|[A-Za-z0-9_-]{32,})"
)
JWT_VALUE = re.compile(
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
)
BRAND_DOMAINS = {
    "amazon": "amazon.com",
    "apple": "apple.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "paypal": "paypal.com",
}


def analyze_urls(body_text: str, body_html: str = "", html_links: list[dict[str, str]] | None = None) -> list[dict[str, object]]:
    entries: list[tuple[str, str]] = []
    for match in URL_RE.findall(body_text):
        entries.append(("", _normalize_extracted_url(match)))
    for link in html_links or []:
        href = link.get("href", "")
        if href and _is_supported_link(href.strip()):
            entries.append((link.get("text", ""), _normalize_extracted_url(href.strip())))
    for match in URL_RE.findall(unescape(body_html)):
        entries.append(("", _normalize_extracted_url(match)))

    results: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for visible, url in entries:
        if (visible, url) in seen:
            continue
        seen.add((visible, url))
        reasons: list[str] = []
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower().rstrip(".")
        except ValueError:
            parts = urlsplit("")
            host = ""
            reasons.append("URL structure could not be parsed safely.")
        if parts.scheme.lower() in {"javascript", "data"}:
            reasons.append(f"Suspicious non-web scheme: {parts.scheme}.")
        if parts.scheme.lower() not in {"http", "https"}:
            reasons.append("Non-standard or missing web scheme.")
        try:
            ipaddress.ip_address(host)
            reasons.append("Destination uses a raw IP address.")
        except ValueError:
            pass
        if host in SHORTENERS:
            reasons.append("Known URL-shortening domain obscures the final destination.")
        if host.startswith("xn--") or ".xn--" in host:
            reasons.append("Punycode hostname may represent a Unicode lookalike.")
        for brand, canonical_domain in BRAND_DOMAINS.items():
            if brand in host.split(".") and host != canonical_domain and not host.endswith(f".{canonical_domain}"):
                reasons.append(f"Hostname uses the brand term '{brand}' outside {canonical_domain}; possible lookalike (heuristic).")
        if unquote(url) != url:
            reasons.append("Percent-encoded characters may obscure the URL.")
        if "@" in parts.netloc:
            reasons.append("User information in the URL authority may disguise its destination.")
        if host and host.rsplit(".", 1)[-1] in RISKY_TLDS:
            reasons.append("Uses a top-level domain sometimes associated with abuse; context matters.")
        if visible:
            visible_candidate = visible if "://" in visible else f"//{visible}"
            visible_host = (urlsplit(visible_candidate).hostname or "").lower()
            if visible_host and visible_host != host:
                reasons.append("Visible link text points to a different host than its destination.")
        if re.search(r"(?i)(login|verify|password|account|secure)[-_]", host):
            reasons.append("Hostname contains account-action wording.")
        results.append(
            {
                "visible_text": visible,
                "url": url,
                "host": host or "Not parsed",
                "flagged": bool(reasons),
                "reasons": reasons,
            }
        )
    return results


def _normalize_extracted_url(value: str) -> str:
    cleaned = value.strip().rstrip(".,;:!?)]}")
    if cleaned.startswith("//"):
        return f"https:{cleaned}"
    if re.match(r"(?i)^[a-z][a-z0-9+.-]*:", cleaned):
        return cleaned
    return f"https://{cleaned}"


def _is_supported_link(value: str) -> bool:
    if value.startswith("//") or re.match(r"(?i)^(?:https?|ftp|file|javascript|data):", value):
        return True
    return bool(
        re.match(
            r"(?i)^(?:www\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?::\d{1,5})?(?:[/;?#]|$)",
            value,
        )
    )


def validate_http_url(url: str) -> str:
    """Validate and normalize an HTTP(S) URL without making a network request."""
    candidate = url.strip()
    if not candidate or len(candidate) > 8192:
        raise ValueError("Enter a URL between 1 and 8192 characters.")
    try:
        parts = urlsplit(candidate)
        hostname = parts.hostname
        _ = parts.port
    except ValueError as exc:
        raise ValueError("The URL structure or port is invalid.") from exc
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc or not hostname:
        raise ValueError("Enter a complete HTTP or HTTPS URL with a hostname.")
    if any(character.isspace() for character in candidate):
        raise ValueError("The URL cannot contain unescaped whitespace.")
    if any(ord(character) < 32 or ord(character) == 127 for character in candidate):
        raise ValueError("The URL cannot contain control characters.")
    try:
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            ascii_host = hostname.encode("idna").decode("ascii").rstrip(".")
            labels = ascii_host.split(".")
            if len(ascii_host) > 253 or any(
                not label
                or len(label) > 63
                or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
                for label in labels
            ):
                raise ValueError
    except (UnicodeError, ValueError) as exc:
        raise ValueError("The URL hostname is invalid.") from exc
    return candidate


def sensitive_url_reasons(url: str) -> list[str]:
    """Return reasons a URL should not be sent to a third-party reputation service."""
    reasons: list[str] = []
    try:
        parts = urlsplit(url)
    except ValueError:
        return ["URL could not be safely parsed."]
    if parts.username is not None or parts.password is not None:
        reasons.append("URL contains user information or a password.")
    if SENSITIVE_VALUE.search(unquote(parts.hostname or "")):
        reasons.append("The hostname contains a value resembling an opaque credential or token.")
    query_pairs = parse_qsl(parts.query, keep_blank_values=True)
    for key, value in query_pairs:
        if SENSITIVE_PARAMETER.search(unquote(key)):
            reasons.append(f"Query parameter name may contain sensitive data: {key[:60]}.")
        elif SENSITIVE_VALUE.search(unquote(value)):
            reasons.append("A query value resembles a credential or opaque token.")
    fragment_pairs = parse_qsl(parts.fragment, keep_blank_values=True)
    for key, value in fragment_pairs:
        if SENSITIVE_PARAMETER.search(unquote(key)):
            reasons.append(f"Fragment parameter name may contain sensitive data: {key[:60]}.")
        elif SENSITIVE_VALUE.search(unquote(value)):
            reasons.append("A fragment value resembles a credential or opaque token.")
    if not fragment_pairs and SENSITIVE_VALUE.fullmatch(unquote(parts.fragment)):
        reasons.append("The URL fragment resembles an opaque token.")
    if SENSITIVE_PATH.search(unquote(parts.path)):
        reasons.append("URL path appears to contain a credential, reset, verification, or authentication flow.")
    if JWT_VALUE.search(unquote(parts.path)):
        reasons.append("A JWT-like value appears in the URL path.")
    return reasons


def redact_url(url: str) -> str:
    """Mask query values and user information before local history or CSV export."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if SENSITIVE_VALUE.search(unquote(host)):
            host = "[REDACTED]"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        if parts.port:
            host = f"{host}:{parts.port}"
        redacted_query = urlencode(
            [(key, "[REDACTED]" if value else "") for key, value in parse_qsl(parts.query, keep_blank_values=True)]
        )
        redacted_path = (
            "/[REDACTED]"
            if SENSITIVE_PATH.search(unquote(parts.path)) or JWT_VALUE.search(unquote(parts.path))
            else parts.path
        )
        redacted_fragment = "[REDACTED]" if parts.fragment else ""
        return urlunsplit((parts.scheme, host, redacted_path, redacted_query, redacted_fragment))
    except ValueError:
        return "[invalid URL]"


def analyze_url(url: str, visible_text: str = "") -> dict[str, object]:
    """Apply offline structural heuristics to one manually entered URL."""
    normalized = validate_http_url(url)
    result = analyze_urls("", html_links=[{"text": visible_text, "href": normalized}])[0]
    reasons = list(result["reasons"])
    privacy_reasons = sensitive_url_reasons(normalized)
    for reason in privacy_reasons:
        if reason not in reasons:
            reasons.append(reason)
    return {
        **result,
        "url": normalized,
        "flagged": bool(reasons),
        "reasons": reasons,
        "sensitive": bool(privacy_reasons),
        "sensitive_reasons": privacy_reasons,
        "redacted_url": redact_url(normalized),
    }
