from __future__ import annotations

from email.message import EmailMessage

import pytest


@pytest.fixture
def sample_eml() -> bytes:
    message = EmailMessage()
    message["From"] = "Example Sender <sender@example.com>"
    message["To"] = "Analyst <analyst@example.net>"
    message["Date"] = "Tue, 01 Oct 2024 10:00:00 +0000"
    message["Message-ID"] = "<sample-001@example.com>"
    message["Subject"] = "Synthetic investigation sample"
    message["Reply-To"] = "reply@example.com"
    message["Received"] = "from mx.example.net (192.0.2.10) by inbox.example.org; Tue, 01 Oct 2024 10:01:00 +0000"
    message.set_content("Review this documentation: https://docs.example.com/guide")
    return message.as_bytes()
