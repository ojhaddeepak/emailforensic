from __future__ import annotations

import pandas as pd
import streamlit as st

from modules.database import get_evidence, list_evidence
from modules.report_generator import build_analysis


def selected_evidence(label: str = "Evidence") -> dict | None:
    records = list_evidence()
    if not records:
        st.info("Import an .eml file first to populate this page.")
        return None
    labels = {f"{item['filename']} — {item['id'][:8]}": item["id"] for item in records}
    choice = st.selectbox(label, list(labels))
    return get_evidence(labels[choice])


def show_findings(findings: list[dict]) -> None:
    if not findings:
        st.success("No indicators from these checks. This does not prove the email is safe.")
        return
    st.dataframe(pd.DataFrame(findings), use_container_width=True, hide_index=True)


def analysis_for(record: dict) -> dict:
    return build_analysis(record)
