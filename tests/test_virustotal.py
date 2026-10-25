import base64

import pytest
import requests

import modules.virustotal_client as client
from modules.virustotal_client import (
    VirusTotalError,
    classify_url_result,
    lookup_domain,
    lookup_url_report,
    submit_url_for_scanning,
    url_identifier,
)


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self.payload = payload or {}

    def json(self):
        return self.payload


def test_missing_key_is_actionable(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.setattr(client, "_streamlit_api_key", lambda: "")
    with pytest.raises(VirusTotalError, match="not configured"):
        lookup_domain("example.com")


def test_streamlit_secret_is_used_when_environment_key_is_missing(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.setattr(client, "_streamlit_api_key", lambda: "cloud-test-key")
    calls = []
    monkeypatch.setattr(
        client.requests,
        "get",
        lambda *args, **kwargs: calls.append(kwargs["headers"]["x-apikey"])
        or FakeResponse(
            payload={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 1, "undetected": 0}
                    }
                }
            }
        ),
    )

    lookup_domain("example.com")

    assert calls == ["cloud-test-key"]


def test_rate_limit_is_reported_without_exposing_api_key(monkeypatch):
    class Response:
        status_code = 429

    monkeypatch.setattr(client.requests, "get", lambda *args, **kwargs: Response())
    with pytest.raises(VirusTotalError, match="rate limit"):
        lookup_domain("example.com", api_key="private-test-key")


def test_domain_lookup_returns_reputation_snapshot(monkeypatch):
    response = FakeResponse(
        payload={
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 1, "suspicious": 2, "harmless": 15, "undetected": 4},
                    "reputation": -3,
                    "last_analysis_date": 1_750_000_000,
                }
            }
        }
    )

    monkeypatch.setattr(client.requests, "get", lambda *args, **kwargs: response)
    result = lookup_domain("example.com", api_key="private-test-key")
    assert result["stats"]["malicious"] == 1
    assert result["reputation"] == -3
    assert result["domain"] == "example.com"


def test_url_identifier_is_unpadded_url_safe_base64():
    url = "https://example.org/path?q=one%20two"
    expected = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    identifier = url_identifier(url)
    assert identifier == expected
    assert "=" not in identifier


@pytest.mark.parametrize(
    ("stats", "expected"),
    [
        ({"malicious": 2}, "malicious"),
        ({"suspicious": 1}, "suspicious"),
        ({"harmless": 5, "undetected": 3}, "no_detections"),
        (None, "no_scan"),
        ({"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}, "no_scan"),
    ],
)
def test_classifies_reputation_results(stats, expected):
    assert classify_url_result(stats)["outcome"] == expected


def test_existing_url_report_maps_stats_and_uses_url_identifier(monkeypatch):
    url = "https://example.org/page?q=hello"
    identifier = url_identifier(url)
    calls = []
    response = FakeResponse(
        payload={
            "data": {
                "id": identifier,
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 1, "harmless": 20, "undetected": 4},
                    "last_analysis_date": 1_750_000_000,
                    "reputation": -1,
                },
            }
        }
    )
    monkeypatch.setattr(client.requests, "get", lambda *args, **kwargs: calls.append(args[0]) or response)
    result = lookup_url_report(url, api_key="private-test-key")
    assert calls == [f"{client.API_BASE}/urls/{identifier}"]
    assert result["outcome"] == "suspicious"
    assert result["stats"]["undetected"] == 4
    assert result["scan_date"] == 1_750_000_000
    assert result["reputation"] == -1
    assert result["report_url"].endswith(identifier)


def test_missing_existing_url_report_is_not_an_api_failure(monkeypatch):
    monkeypatch.setattr(client.requests, "get", lambda *args, **kwargs: FakeResponse(status_code=404))
    result = lookup_url_report("https://example.org/", api_key="private-test-key")
    assert result["outcome"] == "no_report"
    assert result["label"] == "No existing report"
    assert "report_url" not in result


@pytest.mark.parametrize(
    ("status", "message"),
    [(401, "rejected"), (403, "denied"), (429, "quota exceeded")],
)
def test_existing_report_http_errors_are_actionable(monkeypatch, status, message):
    monkeypatch.setattr(client.requests, "get", lambda *args, **kwargs: FakeResponse(status_code=status))
    with pytest.raises(VirusTotalError, match=message):
        lookup_url_report("https://example.org/", api_key="private-test-key")


def test_sensitive_url_is_never_queried_or_submitted(monkeypatch):
    def unexpected_request(*args, **kwargs):
        pytest.fail("A sensitive URL must not be sent to VirusTotal.")

    monkeypatch.setattr(client.requests, "get", unexpected_request)
    monkeypatch.setattr(client.requests, "post", unexpected_request)
    url = "https://example.org/reset?access_token=private-value"
    with pytest.raises(VirusTotalError, match="sensitive data"):
        lookup_url_report(url, api_key="private-test-key")
    with pytest.raises(VirusTotalError, match="sensitive data"):
        submit_url_for_scanning(url, api_key="private-test-key")


def test_url_report_network_timeout_is_handled(monkeypatch):
    def timeout(*args, **kwargs):
        raise requests.Timeout()

    monkeypatch.setattr(client.requests, "get", timeout)
    with pytest.raises(VirusTotalError, match="timed out"):
        lookup_url_report("https://example.org/", api_key="private-test-key")


def test_url_report_network_failure_is_sanitized(monkeypatch):
    def connection_error(*args, **kwargs):
        raise requests.ConnectionError("detail that should not be shown")

    monkeypatch.setattr(client.requests, "get", connection_error)
    with pytest.raises(VirusTotalError, match="network request failed") as error:
        lookup_url_report("https://example.org/", api_key="private-test-key")
    assert "detail that should not be shown" not in str(error.value)


def test_url_report_missing_key_does_not_make_request(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.setattr(client, "_streamlit_api_key", lambda: "")

    def unexpected_request(*args, **kwargs):
        pytest.fail("A request must not be made without an API key.")

    monkeypatch.setattr(client.requests, "get", unexpected_request)
    with pytest.raises(VirusTotalError, match="not configured"):
        lookup_url_report("https://example.org/")


def test_submit_url_and_poll_bounded_analysis(monkeypatch):
    url = "https://example.org/check"
    responses = iter(
        [
            FakeResponse(payload={"data": {"id": "analysis-123"}}),
            FakeResponse(
                payload={
                    "data": {
                        "id": "analysis-123",
                        "attributes": {"status": "queued"},
                    }
                }
            ),
            FakeResponse(
                payload={
                    "data": {
                        "id": "analysis-123",
                        "attributes": {
                            "status": "completed",
                            "stats": {"malicious": 0, "suspicious": 0, "harmless": 10, "undetected": 2},
                        },
                    }
                }
            ),
        ]
    )
    calls = []

    def mock_post(*args, **kwargs):
        calls.append(("POST", args[0], kwargs.get("data")))
        return next(responses)

    def mock_get(*args, **kwargs):
        calls.append(("GET", args[0], None))
        return next(responses)

    monkeypatch.setattr(client.requests, "post", mock_post)
    monkeypatch.setattr(client.requests, "get", mock_get)
    result = submit_url_for_scanning(
        url,
        api_key="private-test-key",
        poll_attempts=2,
        poll_interval=0,
    )
    assert result["outcome"] == "no_detections"
    assert result["analysis_id"] == "analysis-123"
    assert [call[0] for call in calls] == ["POST", "GET", "GET"]
    assert calls[0][2] == {"url": url}


def test_submit_network_timeout_is_actionable(monkeypatch):
    def timeout(*args, **kwargs):
        raise requests.Timeout()

    monkeypatch.setattr(client.requests, "post", timeout)
    with pytest.raises(VirusTotalError, match="submission timed out"):
        submit_url_for_scanning("https://example.org/", api_key="private-test-key")


def test_unexpected_vt_response_is_reported(monkeypatch):
    monkeypatch.setattr(client.requests, "get", lambda *args, **kwargs: FakeResponse(payload=["unexpected"]))
    with pytest.raises(VirusTotalError, match="unexpected response format"):
        lookup_url_report("https://example.org/", api_key="private-test-key")


def test_unauthorized_and_forbidden_submission_responses(monkeypatch):
    for status in (401, 403, 429):
        monkeypatch.setattr(
            client.requests,
            "post",
            lambda *args, _status=status, **kwargs: FakeResponse(status_code=_status),
        )
        with pytest.raises(VirusTotalError) as error:
            submit_url_for_scanning("https://example.org/", api_key="private-test-key")
        assert error.value.status_code == status


def test_internal_server_error_is_reported(monkeypatch):
    monkeypatch.setattr(client.requests, "get", lambda *args, **kwargs: FakeResponse(status_code=500))
    with pytest.raises(VirusTotalError, match="HTTP 500"):
        lookup_url_report("https://example.org/", api_key="private-test-key")
