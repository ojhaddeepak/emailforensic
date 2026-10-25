from __future__ import annotations

import ipaddress
import re
from email.utils import parsedate_to_datetime


def analyze_routing(received: list[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for index, raw in enumerate(received):
        ips: list[str] = []
        for candidate in re.findall(r"(?<![A-Za-z0-9])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9])|(?<![A-Za-z0-9:])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:]{0,4}(?![A-Za-z0-9:])", raw):
            try:
                normalized = str(ipaddress.ip_address(candidate))
                if normalized not in ips:
                    ips.append(normalized)
            except ValueError:
                pass
        hosts = re.findall(r"(?i)\b(?:from|by)\s+([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)", raw)
        timestamp = ""
        date_candidate = raw.rsplit(";", 1)[-1].strip()
        try:
            parsed = parsedate_to_datetime(date_candidate)
            timestamp = parsed.isoformat()
        except (TypeError, ValueError, OverflowError):
            pass
        malformed = not timestamp or not (hosts or ips)
        rows.append(
            {
                "header_position": str(index + 1),
                "chronological_position": str(len(received) - index),
                "hosts": ", ".join(dict.fromkeys(hosts)) or "Not confidently parsed",
                "ips": ", ".join(ips) or "Not confidently parsed",
                "timestamp": timestamp or "Not confidently parsed",
                "status": "Unusual or incomplete; inspect raw header" if malformed else "Parsed conservatively",
                "raw": raw,
            }
        )
    return rows
