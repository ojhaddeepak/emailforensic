from modules.report_generator import build_analysis, generate_html_report
from modules.email_parser import parse_email


def test_html_report_escapes_untrusted_header_text():
    raw = b"From: <script>alert(1)</script> <sender@example.com>\r\nSubject: <img src=x onerror=alert(1)>\r\nDate: Tue, 01 Oct 2024 10:00:00 +0000\r\nMessage-ID: <id@example.com>\r\n\r\nHello"
    parsed = parse_email(raw).to_dict()
    record = {"id": "id-1", "investigation_id": "inv-1", "filename": "<unsafe>.eml", "imported_at": "2024-10-01T10:00:00+00:00", "sha256": "abc", "parsed": parsed}
    report = generate_html_report(record, build_analysis(record))
    assert "<script>" not in report
    assert "&lt;script&gt;" in report
    assert "<img src=x onerror=alert" not in report
    assert "&lt;img src=x onerror=alert" in report
