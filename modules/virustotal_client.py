from __future__ import annotations

import base64
import os
import time
from urllib.parse import quote

import requests

API_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def _api_key(api_key: str | None = None) -> str:
    key = api_key or os.getenv("VIRUSTOTAL_API_KEY") or _streamlit_api_key()
    if not key:
        raise VirusTotalError(
            "VirusTotal is not configured. Set VIRUSTOTAL_API_KEY in your local .env file "
            "or Streamlit Community Cloud secrets."
        )
    return key


def _streamlit_api_key() -> str:
    try:
        import streamlit as st

        return str(st.secrets.get("VIRUSTOTAL_API_KEY", "")).strip()
    except FileNotFoundError:
        return ""


def url_identifier(url: str) -> str:
    """Encode a URL into VirusTotal's unpadded URL-safe base64 identifier."""
    from modules.url_analysis import validate_http_url

    normalized = validate_http_url(url)
    return base64.urlsafe_b64encode(normalized.encode("utf-8")).decode("ascii").rstrip("=")


def classify_url_result(stats: dict[str, object] | None) -> dict[str, object]:
    canonical = {name: 0 for name in ("malicious", "suspicious", "harmless", "undetected")}
    if not stats:
        return {"outcome": "no_scan", "label": "No scan results available", "stats": canonical}
    for name in canonical:
        try:
            canonical[name] = max(0, int(stats.get(name, 0) or 0))
        except (TypeError, ValueError, OverflowError) as exc:
            raise VirusTotalError("VirusTotal returned invalid scan statistics.") from exc
    if canonical["malicious"]:
        outcome, label = "malicious", "Malicious detections"
    elif canonical["suspicious"]:
        outcome, label = "suspicious", "Suspicious detections"
    elif sum(canonical.values()) == 0:
        outcome, label = "no_scan", "No scan results available"
    else:
        outcome, label = "no_detections", "No malicious or suspicious detections"
    return {"outcome": outcome, "label": label, "stats": canonical}


def _request_error(response: requests.Response) -> VirusTotalError:
    messages = {
        401: "VirusTotal rejected the API key (HTTP 401). Check your local configuration.",
        403: "VirusTotal denied this request (HTTP 403). Check API permissions or quota.",
        429: "VirusTotal rate limit or quota exceeded (HTTP 429). Try again later.",
    }
    message = messages.get(response.status_code, f"VirusTotal returned HTTP {response.status_code}.")
    return VirusTotalError(message, response.status_code)


def _json(response: requests.Response) -> dict:
    try:
        data = response.json()
    except (ValueError, requests.exceptions.JSONDecodeError) as exc:
        raise VirusTotalError("VirusTotal returned an unreadable response.") from exc
    if not isinstance(data, dict):
        raise VirusTotalError("VirusTotal returned an unexpected response format.")
    return data


def _url_result(data: dict, url: str) -> dict:
    try:
        report_data = data["data"]
        if not isinstance(report_data, dict):
            raise TypeError
        attributes = report_data["attributes"]
        if not isinstance(attributes, dict):
            raise TypeError
    except (KeyError, TypeError) as exc:
        raise VirusTotalError("VirusTotal response did not contain URL report attributes.") from exc
    stats = attributes.get("last_analysis_stats")
    if stats is not None and not isinstance(stats, dict):
        raise VirusTotalError("VirusTotal returned an unexpected scan-statistics format.")
    classification = classify_url_result(stats)
    report_id = str(report_data.get("id") or url_identifier(url))
    return {
        **classification,
        "url": url,
        "url_id": report_id,
        "report_url": f"https://www.virustotal.com/gui/url/{quote(report_id, safe='')}",
        "scan_date": attributes.get("last_analysis_date"),
        "first_submission_date": attributes.get("first_submission_date"),
        "last_submission_date": attributes.get("last_submission_date"),
        "reputation": attributes.get("reputation"),
        "provider_status": "report_found",
    }


def lookup_url_report(url: str, api_key: str | None = None, timeout: int = 15) -> dict:
    """Retrieve a pre-existing VirusTotal URL report. This does not submit or visit the URL."""
    from modules.url_analysis import sensitive_url_reasons

    normalized = url_identifier(url)
    original_url = base64.urlsafe_b64decode(normalized + "=" * (-len(normalized) % 4)).decode("utf-8")
    sensitive = sensitive_url_reasons(original_url)
    if sensitive:
        raise VirusTotalError("This URL appears to contain sensitive data and must not be sent to VirusTotal. Review it manually.")
    key = _api_key(api_key)
    try:
        response = requests.get(
            f"{API_BASE}/urls/{quote(normalized, safe='')}",
            headers={"x-apikey": key, "accept": "application/json"},
            timeout=timeout,
        )
    except requests.Timeout as exc:
        raise VirusTotalError("VirusTotal request timed out. Try again later.") from exc
    except requests.RequestException as exc:
        raise VirusTotalError("VirusTotal network request failed. Check connectivity and try again.") from exc
    if response.status_code == 404:
        return {
            "outcome": "no_report",
            "label": "No existing report",
            "provider_status": "no_report",
            "stats": classify_url_result(None)["stats"],
            "url": original_url,
            "url_id": normalized,
        }
    if response.status_code >= 400:
        raise _request_error(response)
    return _url_result(_json(response), original_url)


def _analysis_result(data: dict, url: str) -> dict:
    try:
        analysis_data = data["data"]
        if not isinstance(analysis_data, dict):
            raise TypeError
        attributes = analysis_data["attributes"]
        if not isinstance(attributes, dict):
            raise TypeError
        status = attributes.get("status")
    except (KeyError, TypeError) as exc:
        raise VirusTotalError("VirusTotal returned an unexpected analysis response.") from exc
    if status != "completed":
        return {
            "outcome": "pending",
            "label": "Analysis is still in progress",
            "provider_status": status or "pending",
            "stats": classify_url_result(None)["stats"],
            "url": url,
            "analysis_id": analysis_data.get("id"),
        }
    result = classify_url_result(attributes.get("stats"))
    url_id = url_identifier(url)
    return {
        **result,
        "provider_status": "completed",
        "url": url,
        "url_id": url_id,
        "report_url": f"https://www.virustotal.com/gui/url/{url_id}",
        "scan_date": attributes.get("date"),
    }


def submit_url_for_scanning(
    url: str,
    api_key: str | None = None,
    timeout: int = 15,
    poll_attempts: int = 3,
    poll_interval: float = 2.0,
) -> dict:
    """Explicitly submit a URL then poll its analysis a bounded number of times."""
    from modules.url_analysis import sensitive_url_reasons

    url_identifier(url)  # validates before any external request
    sensitive = sensitive_url_reasons(url)
    if sensitive:
        raise VirusTotalError("This URL appears to contain sensitive data and must not be submitted. Review it manually.")
    key = _api_key(api_key)
    try:
        response = requests.post(
            f"{API_BASE}/urls",
            headers={"x-apikey": key, "accept": "application/json"},
            data={"url": url},
            timeout=timeout,
        )
    except requests.Timeout as exc:
        raise VirusTotalError("VirusTotal submission timed out. Check the existing report before retrying.") from exc
    except requests.RequestException as exc:
        raise VirusTotalError("VirusTotal network request failed. Check connectivity and try again.") from exc
    if response.status_code >= 400:
        raise _request_error(response)
    data = _json(response)
    try:
        analysis_id = data["data"]["id"]
    except (KeyError, TypeError) as exc:
        raise VirusTotalError("VirusTotal did not return an analysis identifier.") from exc

    latest: dict = {"data": {"id": analysis_id, "attributes": {"status": "queued"}}}
    poll_warning = ""
    for attempt in range(max(1, min(poll_attempts, 5))):
        if attempt:
            time.sleep(max(0.0, min(poll_interval, 5.0)))
        try:
            poll = requests.get(
                f"{API_BASE}/analyses/{quote(str(analysis_id), safe='')}",
                headers={"x-apikey": key, "accept": "application/json"},
                timeout=timeout,
            )
        except requests.Timeout:
            poll_warning = "The URL was submitted, but polling timed out. Check the existing report later."
            break
        except requests.RequestException:
            poll_warning = "The URL was submitted, but the analysis status could not be retrieved."
            break
        if poll.status_code in {401, 403, 429} or poll.status_code >= 500:
            raise _request_error(poll)
        if poll.status_code == 404:
            continue
        if poll.status_code >= 400:
            raise _request_error(poll)
        latest = _json(poll)
        try:
            if latest["data"]["attributes"].get("status") == "completed":
                break
        except (KeyError, TypeError) as exc:
            raise VirusTotalError("VirusTotal returned an unexpected analysis response.") from exc
    result = _analysis_result(latest, url)
    result["analysis_id"] = analysis_id
    if poll_warning:
        result["poll_warning"] = poll_warning
    return result


def lookup_domain(domain: str, api_key: str | None = None, timeout: int = 10) -> dict:
    key = _api_key(api_key)
    safe_domain = domain.strip().lower().rstrip(".")
    if not safe_domain or any(char in safe_domain for char in "/?#@"):
        raise VirusTotalError("A valid hostname is required for a domain lookup.")
    try:
        response = requests.get(
            f"{API_BASE}/domains/{quote(safe_domain, safe='')}",
            headers={"x-apikey": key, "accept": "application/json"},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise VirusTotalError("VirusTotal request failed; check network connectivity and try again.") from exc
    if response.status_code == 429:
        raise VirusTotalError("VirusTotal rate limit reached. Try again later.")
    if response.status_code >= 400:
        raise VirusTotalError(f"VirusTotal returned HTTP {response.status_code}.")
    try:
        attributes = response.json()["data"]["attributes"]
        stats = attributes["last_analysis_stats"]
        return {
            "domain": safe_domain,
            "stats": {str(key): int(value) for key, value in stats.items()},
            "reputation": int(attributes.get("reputation", 0)),
            "last_analysis_date": attributes.get("last_analysis_date"),
        }
    except (ValueError, KeyError, TypeError) as exc:
        raise VirusTotalError("VirusTotal response did not contain domain analysis statistics.") from exc
