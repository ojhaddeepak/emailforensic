from __future__ import annotations

DEFAULT_WEIGHTS = {
    "reply_to": 20,
    "link_mismatch": 20,
    "raw_ip": 15,
    "encoded_or_punycode": 15,
    "risky_attachment": 20,
    "authentication_failure": 20,
}


def assess_risk(header_findings: list[dict], urls: list[dict], attachments: list[dict], auth_results: list[str], weights: dict[str, int] | None = None) -> dict:
    weights = weights or DEFAULT_WEIGHTS
    findings: list[dict[str, object]] = []

    def add(rule: str, evidence: str, reason: str, action: str, key: str) -> None:
        findings.append({"rule": rule, "evidence": evidence, "reason": reason, "points": max(0, int(weights.get(key, 0))), "action": action})

    for finding in header_findings:
        if finding["rule"] == "Reply-To domain differs":
            add(finding["rule"], finding["evidence"], finding["reason"], finding["action"], "reply_to")
    for item in urls:
        reasons = item.get("reasons", [])
        if any("different host" in reason for reason in reasons):
            add("Visible link differs from destination", str(item.get("url", "")), "; ".join(reasons), "Verify the destination without opening the link.", "link_mismatch")
        if any("raw IP address" in reason for reason in reasons):
            add("URL uses raw IP address", str(item.get("url", "")), "; ".join(reasons), "Review the host using trusted offline analysis.", "raw_ip")
        if any("Percent-encoded" in reason or "Punycode" in reason for reason in reasons):
            add("URL encoding or punycode", str(item.get("url", "")), "; ".join(reasons), "Inspect the decoded hostname and destination manually.", "encoded_or_punycode")
    risky_exts = (".exe", ".dll", ".scr", ".js", ".jse", ".vbs", ".vbe", ".ps1", ".bat", ".cmd", ".com", ".hta", ".msi")
    for item in attachments:
        filename = str(item.get("filename", "")).lower()
        if filename.endswith(risky_exts):
            add("Potentially executable attachment", filename, "The filename extension is commonly associated with executable or script content.", "Do not open; follow your organization's malware-handling process.", "risky_attachment")
    failed = [result for result in auth_results if any(f"{method}=fail" in result.lower() or f"{method}=softfail" in result.lower() for method in ("spf", "dkim", "dmarc"))]
    if failed:
        add("Authentication result reports failure", " | ".join(failed), "The supplied header text indicates an authentication failure; it is not independently verified.", "Check trusted receiver-side authentication logs.", "authentication_failure")

    total_possible = sum(max(0, int(value)) for value in weights.values())
    raw_total = sum(int(item["points"]) for item in findings)
    score = min(100, round(raw_total / total_possible * 100)) if total_possible else 0
    label = "Lower observed risk" if score < 25 else "Moderate observed risk" if score < 50 else "High observed risk" if score < 75 else "Very high observed risk"
    return {"score": score, "label": label, "findings": findings, "unknown_authentication": not bool(auth_results)}
