import pandas as pd
import streamlit as st

from modules.ui_helpers import analysis_for, selected_evidence, show_findings

st.title("Phishing Risk Assessment")
st.caption("Rule-based triage, not proof of maliciousness or safety. Thresholds are illustrative and not validated probabilities.")
record = selected_evidence()
if record:
    risk = analysis_for(record)["risk"]
    st.metric("Observed risk score", f"{risk['score']} / 100", risk["label"])
    if risk["unknown_authentication"]:
        st.info("Authentication status is unknown because no Authentication-Results header was supplied; absence is not treated as failure.")
    st.subheader("Findings and recommended actions")
    show_findings(risk["findings"])
    with st.expander("Scoring explanation"):
        st.write("Points are summed from observed rules, then normalized to the 0–100 range using the configured maximum. A score is only a triage aid.")
        st.dataframe(pd.DataFrame(risk["findings"]) if risk["findings"] else pd.DataFrame(columns=["rule", "evidence", "reason", "points", "action"]), use_container_width=True, hide_index=True)
