from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from config import APP_NAME, APP_VERSION
from modules.database import list_evidence
from modules.report_generator import build_analysis

title_col, action_col = st.columns([4, 1.7], vertical_alignment="center")
with title_col:
    st.title("Case overview")
    st.caption(f"LOCAL EVIDENCE WORKSPACE  /  {APP_VERSION}")
with action_col:
    if st.button("Check URL", type="primary", use_container_width=True):
        st.switch_page("pages/11_URL_Reputation_Checker.py")
st.caption("Local analysis only. Email content is untrusted; links are not opened and attachments are not executed.")

records = list_evidence()
analyses = [(record, build_analysis(record)) for record in records]
risks = [(record, analysis["risk"]) for record, analysis in analyses]
url_count = sum(len(analysis["urls"]) for _, analysis in analyses)
col1, col2, col3, col4 = st.columns(4)
col1.metric("Evidence", len(records))
col2.metric("URLs", url_count)
col3.metric("Files", sum(len(record["parsed"]["attachments"]) for record in records))
col4.metric("High risk", sum(risk["score"] >= 50 for _, risk in risks))

if records:
    table = []
    for record, risk in risks:
        table.append({"Filename": record["filename"], "Evidence ID": record["id"], "Imported (UTC)": record["imported_at"], "SHA-256": record["sha256"], "Risk": f"{risk['score']}/100 — {risk['label']}"})
    left, right = st.columns([2, 1])
    with left:
        st.subheader("Evidence register")
        frame = pd.DataFrame(table)
        search = st.text_input("Filter by filename or evidence ID")
        if search:
            frame = frame[frame.astype(str).apply(lambda col: col.str.contains(search, case=False, na=False)).any(axis=1)]
        st.dataframe(frame, use_container_width=True, hide_index=True)
    with right:
        st.subheader("Risk bands")
        risk_bands = [
            "Lower observed risk",
            "Moderate observed risk",
            "High observed risk",
            "Very high observed risk",
        ]
        counts = {band: 0 for band in risk_bands}
        for _, risk in risks:
            counts[risk["label"]] = counts.get(risk["label"], 0) + 1
        chart = pd.DataFrame(
            [{"Risk band": band, "Emails": counts[band]} for band in risk_bands]
        )
        figure = px.bar(
            chart,
            x="Emails",
            y="Risk band",
            color="Risk band",
            orientation="h",
            category_orders={"Risk band": risk_bands[::-1]},
            color_discrete_map={
                "Lower observed risk": "#477b65",
                "Moderate observed risk": "#a17b3e",
                "High observed risk": "#ae6547",
                "Very high observed risk": "#994c50",
            },
        )
        figure.update_layout(
            showlegend=False,
            plot_bgcolor="white",
            paper_bgcolor="white",
            margin=dict(l=8, r=8, t=8, b=8),
            xaxis_title=None,
            yaxis_title=None,
            font=dict(color="#435167"),
            height=230,
        )
        st.plotly_chart(figure, use_container_width=True)
else:
    st.markdown("### Start an investigation")
    st.write("Import one or more `.eml` files to create a local evidence record, compute a baseline SHA-256 hash, and begin reviewing extracted artifacts.")
    if st.button("Go to evidence import", type="primary"):
        st.switch_page("pages/1_Import_Evidence.py")

with st.expander("Interpretation and limitations"):
    st.write("Risk scores are rule-based triage aids, not probabilities or proof that a message is malicious or safe. Authentication headers are not independently verified. Preserve trusted originals, analyze verified working copies, and document analyst conclusions separately.")
