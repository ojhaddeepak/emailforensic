from modules.risk_scoring import assess_risk


def test_risk_score_is_normalized_and_auth_absence_unknown():
    result = assess_risk(
        [{"rule": "Reply-To domain differs", "evidence": "a.example vs b.example", "reason": "different", "action": "verify"}],
        [], [], [],
    )
    assert 0 <= result["score"] <= 100
    assert result["unknown_authentication"] is True
    assert result["findings"][0]["points"] > 0


def test_supplied_authentication_pass_is_not_failure():
    result = assess_risk([], [], [], ["spf=pass"])
    assert result["score"] == 0
