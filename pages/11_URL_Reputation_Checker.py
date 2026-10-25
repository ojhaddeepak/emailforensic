from __future__ import annotations

import hashlib
import os
import time
from datetime import datetime, timezone

import pandas as pd
import plotly.express as px
import streamlit as st

from config import MAX_UPLOAD_MB
from modules.database import list_evidence, list_url_checks, record_url_check
from modules.email_parser import parse_email
from modules.url_analysis import analyze_url, analyze_urls
from modules.virustotal_client import (
    VirusTotalError,
    lookup_url_report,
    submit_url_for_scanning,
)

st.title("URL Reputation Checker")
st.caption("Offline inspection  /  Optional VirusTotal reputation lookup")
SUBMISSION_COOLDOWN_SECONDS = 15
st.markdown(
    "**PRIVACY NOTICE**  /  External checks disclose the selected URL to VirusTotal. "
    "Sensitive-looking URLs are blocked; review links for private data before requesting a report."
)

api_configured = bool(os.getenv("VIRUSTOTAL_API_KEY"))
if api_configured:
    st.caption("VIRUSTOTAL API  /  CONFIGURED")
else:
    st.caption("VIRUSTOTAL API  /  NOT CONFIGURED — set the key in .env and restart")

st.subheader("Email evidence")
st.caption("Choose an imported message or upload a working copy. Extraction is local; no content is submitted.")
saved_records = list_evidence()
record_by_label = {
    f"{record['filename']} · {record['id'][:8]}": record for record in saved_records
}
saved_choice = st.selectbox(
    "Select previously imported evidence",
    ["No stored evidence"] + list(record_by_label),
)
email_upload = st.file_uploader(
    "Or inspect an .eml file for URL extraction",
    type=["eml"],
    accept_multiple_files=False,
    help=f"Maximum file size: {MAX_UPLOAD_MB} MB. Email content is parsed locally only.",
)

source_records: list[tuple[str, dict]] = []
if saved_choice != "No stored evidence":
    source_records.append((record_by_label[saved_choice]["filename"], record_by_label[saved_choice]["parsed"]))
if email_upload is not None:
    try:
        source_records.append((email_upload.name, parse_email(email_upload.getvalue()).to_dict()))
    except (ValueError, OSError) as exc:
        st.error(f"Email could not be parsed for URL extraction: {exc}")

extracted: list[dict] = []
for filename, parsed in source_records:
    for item in analyze_urls(parsed["body_text"], parsed["body_html"], parsed["links"]):
        extracted.append({"source": filename, **item})

if extracted:
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "Source email": item["source"],
                    "Visible link text": item["visible_text"],
                    "URL": item["url"],
                    "Hostname": item["host"],
                    "Offline indicators": "; ".join(item["reasons"]) or "None observed",
                }
                for item in extracted
            ]
        ),
        use_container_width=True,
        hide_index=True,
    )
    extracted_options = {
        f"{item['host']} — {item['url']}": item["url"] for item in extracted
    }
    selected_extracted = st.selectbox(
        "Choose an extracted URL to inspect",
        list(extracted_options),
        key="selected_email_url",
    )
    if st.button("Use selected email URL"):
        st.session_state["reputation_url_input"] = extracted_options[selected_extracted]
        st.rerun()
else:
    st.caption("No URLs extracted yet. Select imported evidence or upload an .eml file.")

st.divider()
st.subheader("URL inspection")
manual_url = st.text_input(
    "URL to inspect",
    key="reputation_url_input",
    placeholder="https://example.org/path",
    help="Only HTTP and HTTPS URLs are accepted. Inspection does not open the destination.",
)
visible_text = st.text_input(
    "Visible link text (optional)",
    help="If provided, compare a displayed URL/hostname with the actual destination.",
)

analysis = None
validation_error = None
if manual_url.strip():
    try:
        analysis = analyze_url(manual_url, visible_text=visible_text)
    except ValueError as exc:
        validation_error = str(exc)

if validation_error:
    st.error(validation_error)
elif analysis:
    url_fingerprint = hashlib.sha256(analysis["url"].encode("utf-8")).hexdigest()[:16]
    st.markdown(f"**Parsed hostname:** `{analysis['host']}`")
    if analysis["sensitive"]:
        st.error("Manual review required. This URL appears to contain sensitive information; VirusTotal actions are disabled.")
        for reason in analysis["sensitive_reasons"]:
            st.write(f"- {reason}")
    else:
        st.success("No obvious credential/reset-token indicators detected. This is a heuristic check, not a privacy guarantee.")

    with st.expander("Offline structure and heuristic findings", expanded=True):
        st.write(
            {
                "Scheme": analysis["url"].split(":", 1)[0].lower(),
                "Hostname": analysis["host"],
                "Looks suspicious": analysis["flagged"],
            }
        )
        if analysis["reasons"]:
            for reason in analysis["reasons"]:
                st.write(f"- {reason}")
        else:
            st.write("No listed structure heuristic was triggered. This does not establish that the URL is safe.")

    if st.button("Record local analysis in history"):
        record_url_check(
            analysis["url"],
            "local_analysis",
            {
                "outcome": "local_indicators" if analysis["flagged"] else "no_local_indicators",
                "stats": {},
            },
        )
        st.success("Local analysis recorded. Query values are redacted in history.")

    st.subheader("External reputation check")
    st.caption("First check for an existing report. Submit for scanning only when a cached report is unavailable and after reviewing the privacy warning.")
    consent = st.checkbox(
        "I reviewed this URL and consent to sending it to VirusTotal.",
        key=f"vt_url_privacy_consent_{url_fingerprint}",
        disabled=bool(analysis["sensitive"]),
    )
    check_col, submit_col = st.columns(2)
    external_allowed = api_configured and not analysis["sensitive"] and consent
    last_submission = st.session_state.get("vt_last_submission_at", 0.0)
    cooldown_remaining = max(
        0.0,
        SUBMISSION_COOLDOWN_SECONDS - (time.monotonic() - last_submission),
    )
    with check_col:
        if st.button(
            "Check Existing Report",
            type="primary",
            disabled=not external_allowed,
            use_container_width=True,
        ):
            try:
                result = lookup_url_report(analysis["url"])
                record_url_check(analysis["url"], "existing_report", result)
                st.session_state["vt_url_result"] = result
                st.session_state["vt_url_result_fingerprint"] = url_fingerprint
                st.session_state.pop("vt_url_error", None)
                st.session_state.pop("vt_url_error_fingerprint", None)
            except VirusTotalError as exc:
                outcome = "quota_exceeded" if exc.status_code == 429 else "api_error"
                record_url_check(analysis["url"], "existing_report", {"outcome": outcome})
                st.session_state["vt_url_error"] = str(exc)
                st.session_state["vt_url_error_fingerprint"] = url_fingerprint
                st.session_state.pop("vt_url_result", None)
                st.session_state.pop("vt_url_result_fingerprint", None)
    with submit_col:
        submit_confirm = st.checkbox(
            "I understand this submits the URL for a new scan, not just a report lookup.",
            key=f"vt_url_submit_confirm_{url_fingerprint}",
            disabled=bool(analysis["sensitive"]),
        )
        if st.button(
            "Submit URL for Scanning",
            disabled=not (external_allowed and submit_confirm) or cooldown_remaining > 0,
            use_container_width=True,
        ):
            st.session_state["vt_last_submission_at"] = time.monotonic()
            try:
                result = submit_url_for_scanning(analysis["url"])
                record_url_check(analysis["url"], "submitted_for_scanning", result)
                st.session_state["vt_url_result"] = result
                st.session_state["vt_url_result_fingerprint"] = url_fingerprint
                st.session_state.pop("vt_url_error", None)
                st.session_state.pop("vt_url_error_fingerprint", None)
            except VirusTotalError as exc:
                outcome = "quota_exceeded" if exc.status_code == 429 else "api_error"
                record_url_check(analysis["url"], "submitted_for_scanning", {"outcome": outcome})
                st.session_state["vt_url_error"] = str(exc)
                st.session_state["vt_url_error_fingerprint"] = url_fingerprint
                st.session_state.pop("vt_url_result", None)
                st.session_state.pop("vt_url_result_fingerprint", None)

    if cooldown_remaining > 0:
        st.caption(f"Please wait {cooldown_remaining:.0f}s before another scan submission in this session.")
    if not analysis["sensitive"] and not consent:
        st.caption("Confirm the privacy notice to enable either VirusTotal action.")

current_fingerprint = (
    hashlib.sha256(analysis["url"].encode("utf-8")).hexdigest()[:16]
    if analysis
    else None
)
if (
    st.session_state.get("vt_url_error")
    and current_fingerprint
    and st.session_state.get("vt_url_error_fingerprint") == current_fingerprint
):
    error_text = st.session_state["vt_url_error"]
    if "quota" in error_text.lower() or "rate limit" in error_text.lower():
        st.error(f"API error or quota exceeded: {error_text}")
    else:
        st.error(f"API error: {error_text}")

result = (
    st.session_state.get("vt_url_result")
    if current_fingerprint
    and st.session_state.get("vt_url_result_fingerprint") == current_fingerprint
    else None
)
if result:
    st.divider()
    st.subheader(result.get("label", "VirusTotal result"))
    if result["outcome"] in {"malicious", "suspicious"}:
        st.error("Detections were reported by VirusTotal engines. This is a reputation signal, not definitive proof.")
    elif result["outcome"] == "no_detections":
        st.success("No malicious or suspicious detections were reported. This does not prove that the URL is safe.")
    elif result["outcome"] in {"no_report", "no_scan"}:
        st.info("No scan results are currently available for this URL.")
    elif result["outcome"] == "pending":
        st.info("The submitted URL is still being analyzed. Use Check Existing Report later to retrieve the completed report.")
    elif result["outcome"] in {"api_error", "quota_exceeded"}:
        st.error("API error or quota exceeded.")

    stats = result.get("stats", {})
    metric_cols = st.columns(4)
    metric_cols[0].metric("Malicious", stats.get("malicious", 0))
    metric_cols[1].metric("Suspicious", stats.get("suspicious", 0))
    metric_cols[2].metric("Harmless", stats.get("harmless", 0))
    metric_cols[3].metric("Undetected", stats.get("undetected", 0))
    if any(stats.values()):
        chart = px.bar(
            pd.DataFrame([{"Engine result": name.title(), "Engines": count} for name, count in stats.items()]),
            x="Engine result",
            y="Engines",
            color="Engine result",
            color_discrete_map={
                "Malicious": "#c6404e",
                "Suspicious": "#d47b26",
                "Harmless": "#23845e",
                "Undetected": "#68778b",
            },
        )
        chart.update_layout(showlegend=False, plot_bgcolor="white", paper_bgcolor="white")
        st.plotly_chart(chart, use_container_width=True)

    for timestamp_name, label in (
        ("scan_date", "Last scan"),
        ("first_submission_date", "First submitted"),
        ("last_submission_date", "Last submitted"),
    ):
        timestamp = result.get(timestamp_name)
        if timestamp:
            try:
                rendered = datetime.fromtimestamp(int(timestamp), tz=timezone.utc).isoformat()
            except (ValueError, TypeError, OverflowError, OSError):
                rendered = str(timestamp)
            st.caption(f"{label} (UTC): {rendered}")
    if result.get("reputation") is not None:
        st.caption(f"VirusTotal community reputation: {result['reputation']}")
    if result.get("poll_warning"):
        st.warning(result["poll_warning"])
    if result.get("report_url"):
        st.link_button("Open VirusTotal report", result["report_url"])
    st.caption("Provider data can be incomplete or outdated. No detection does not mean safe; detections are not definitive proof of maliciousness.")

st.divider()
st.subheader("URL reputation history")
history = list_url_checks()
if history:
    history_frame = pd.DataFrame(history)
    st.dataframe(history_frame, use_container_width=True, hide_index=True)
    st.download_button(
        "Download URL history CSV",
        history_frame.to_csv(index=False).encode("utf-8"),
        file_name="url-reputation-history.csv",
        mime="text/csv",
    )
    st.caption("Query values are redacted in history and CSV. Only a SHA-256 URL fingerprint, redacted URL, action, outcome, and aggregate counts are retained.")
else:
    st.info("No VirusTotal URL actions have been recorded yet.")
