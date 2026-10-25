import pytest

from modules.url_analysis import analyze_url, analyze_urls, redact_url, sensitive_url_reasons


def test_extracts_text_and_html_url_and_flags_mismatch():
    found = analyze_urls("Visit https://docs.example.com", "", [{"text": "https://trusted.example", "href": "https://other.example/path"}])
    assert any(item["url"] == "https://docs.example.com" for item in found)
    link = next(item for item in found if item["host"] == "other.example")
    assert any("different host" in reason for reason in link["reasons"])


def test_flags_raw_ip_and_punycode():
    found = analyze_urls("http://192.0.2.50/a https://xn--lookalike.example/ https://paypal.login.example/")
    assert any(any("raw IP" in reason for reason in item["reasons"]) for item in found)
    assert any(any("Punycode" in reason for reason in item["reasons"]) for item in found)
    assert any(any("possible lookalike" in reason for reason in item["reasons"]) for item in found)


def test_manual_url_analysis_checks_ip_and_sensitivity():
    analysis = analyze_url("http://192.0.2.10/path?access_token=secret")
    assert analysis["host"] == "192.0.2.10"
    assert analysis["sensitive"] is True
    assert any("raw IP" in reason for reason in analysis["reasons"])


@pytest.mark.parametrize("url", ["ftp://example.org", "https:///missing-host", "not a url"])
def test_manual_url_rejects_invalid_or_non_http_urls(url):
    with pytest.raises(ValueError):
        analyze_url(url)


def test_redaction_masks_query_values_and_userinfo():
    redacted = redact_url("https://user:pass@example.org/reset/secret/path?token=secret&view=full#access_token=fragment-secret")
    assert "user" not in redacted
    assert "pass" not in redacted
    assert "secret" not in redacted
    assert "%5BREDACTED%5D" in redacted
    assert "fragment-secret" not in redacted
    assert "/reset/" not in redacted
    assert "view=%5BREDACTED%5D" in redacted


def test_sensitive_fragment_is_detected():
    assert sensitive_url_reasons("https://example.org/callback#access_token=secret")


def test_long_ordinary_path_id_is_not_mistaken_for_a_sensitive_token():
    url = "https://chatgpt.com/" + "a" * 48
    analysis = analyze_url(url)
    assert analysis["sensitive"] is False
    assert analysis["sensitive_reasons"] == []


def test_long_id_is_still_blocked_in_sensitive_reset_path():
    url = "https://example.org/account/reset/" + "a" * 48
    reasons = sensitive_url_reasons(url)
    assert any("reset" in reason.lower() for reason in reasons)


def test_jwt_like_path_is_still_blocked():
    url = "https://example.org/" + "eyJabcdefgh.abcdefghijk.abcdefghijk"
    assert any("JWT-like" in reason for reason in sensitive_url_reasons(url))


def test_manual_visible_link_text_mismatch_is_flagged():
    result = analyze_url("https://destination.example/path", "https://shown.example/")
    assert any("different host" in reason for reason in result["reasons"])


def test_extraction_handles_malformed_url_without_crashing():
    result = analyze_urls("https://[invalid-host/path")
    assert result
    assert result[0]["flagged"] is True
    assert any("could not be parsed" in reason for reason in result[0]["reasons"])


def test_extracts_bare_domains_and_www_urls_from_plain_text():
    result = analyze_urls(
        "Please visit www.example.com/help or example.org/path?ref=mail. "
        "Do not treat analyst@example.net as a URL."
    )
    urls = {item["url"] for item in result}
    assert "https://www.example.com/help" in urls
    assert "https://example.org/path?ref=mail" in urls
    assert all("analyst@example.net" not in url for url in urls)


def test_extracts_scheme_less_html_anchor_and_unanchored_html_text():
    result = analyze_urls(
        "",
        "<p>Plain www.docs.example/guide</p><a href='portal.example/help'>Open portal</a>",
        [{"text": "Open portal", "href": "portal.example/help"}],
    )
    urls = {item["url"] for item in result}
    assert "https://www.docs.example/guide" in urls
    assert "https://portal.example/help" in urls


def test_email_parser_and_url_extractor_work_together():
    from modules.email_parser import parse_email

    message = (
        b"From: sender@example.net\r\n"
        b"To: analyst@example.net\r\n"
        b"Subject: Synthetic URL test\r\n"
        b"\r\n"
        b"Open www.example.com/notice and example.org/continue\r\n"
    )
    parsed = parse_email(message)
    found = analyze_urls(parsed.body_text, parsed.body_html, parsed.links)
    assert {item["host"] for item in found} >= {"www.example.com", "example.org"}
