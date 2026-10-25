from __future__ import annotations

import re
from email.utils import parseaddr


def _domain(address: str) -> str | None:
    parsed = parseaddr(address)[1]
    return parsed.rsplit("@", 1)[1].lower().rstrip(".") if "@" in parsed else None


def analyze_headers(headers: dict[str, str], auth_results: list[str] | None = None) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    sender = headers.get("From", "")
    reply_to = headers.get("Reply-To", "")
    sender_domain = _domain(sender)
    reply_domain = _domain(reply_to)

    if not sender:
        findings.append({"rule": "Missing From", "evidence": "No From header", "reason": "The apparent sender is unavailable.", "action": "Inspect the original message and source context."})
    if not headers.get("Message-ID"):
        findings.append({"rule": "Missing Message-ID", "evidence": "No Message-ID header", "reason": "A common identifying header is absent.", "action": "Compare with the source mailbox or gateway records."})
    if reply_to and sender_domain and reply_domain and sender_domain != reply_domain:
        findings.append({"rule": "Reply-To domain differs", "evidence": f"{sender_domain} vs {reply_domain}", "reason": "Replies may be directed to a different domain than the apparent sender.", "action": "Verify the reply destination through a trusted channel."})
    display_name, sender_address = parseaddr(sender.splitlines()[0] if sender else "")
    if display_name and sender_address and sender_domain:
        display_domain = re.search(r"@([A-Za-z0-9.-]+)", display_name)
        if display_domain and display_domain.group(1).lower() != sender_domain:
            findings.append({"rule": "Possible display-name impersonation", "evidence": display_name, "reason": "The display name contains a different email domain.", "action": "Treat the display name as unverified and inspect the raw header."})
    if headers.get("Date") and not _date_looks_parseable(headers["Date"]):
        findings.append({"rule": "Unusual Date header", "evidence": headers["Date"], "reason": "The date value could not be interpreted consistently.", "action": "Compare it with trusted receipt timestamps."})

    for result in auth_results or []:
        lowered = result.lower()
        for method in ("spf", "dkim", "dmarc"):
            match = re.search(rf"\b{method}\s*=\s*(fail|softfail|neutral|none|temperror|permerror)\b", lowered)
            if match:
                findings.append({"rule": f"{method.upper()} reports {match.group(1)}", "evidence": result, "reason": f"The supplied Authentication-Results text reports {match.group(1)} for {method.upper()}.", "action": "Validate independently using trusted receiving-system records."})
    return findings


def _date_looks_parseable(value: str) -> bool:
    from email.utils import parsedate_to_datetime

    try:
        parsedate_to_datetime(value.splitlines()[0])
        return True
    except (TypeError, ValueError, OverflowError):
        return False
