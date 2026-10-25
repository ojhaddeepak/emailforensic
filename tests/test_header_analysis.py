from modules.header_analysis import analyze_headers
from modules.routing_analysis import analyze_routing


def test_reply_to_domain_difference_is_flagged():
    findings = analyze_headers({"From": "Sender <sender@example.com>", "Reply-To": "reply@elsewhere.example"})
    assert any(item["rule"] == "Reply-To domain differs" for item in findings)


def test_received_order_is_reversed_for_chronology():
    rows = analyze_routing(["from new.example; Tue, 01 Oct 2024 10:02:00 +0000", "from old.example; Tue, 01 Oct 2024 10:01:00 +0000"])
    assert rows[0]["header_position"] == "1"
    assert rows[0]["chronological_position"] == "2"
    assert rows[1]["chronological_position"] == "1"
