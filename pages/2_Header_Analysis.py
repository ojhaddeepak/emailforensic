import streamlit as st

from modules.header_analysis import analyze_headers
from modules.ui_helpers import selected_evidence, show_findings

st.title("Email Header Analysis")
record = selected_evidence()
if record:
    parsed = record["parsed"]
    st.subheader("Extracted fields")
    st.dataframe([{"Header": key, "Value": value} for key, value in parsed["headers"].items()], use_container_width=True, hide_index=True)
    st.caption("Duplicate values are preserved as newline-separated values. Authentication results are header text, not independent verification.")
    st.subheader("Raw header comparison")
    st.code(parsed["raw_headers"] or "No selected headers were available.", language="text")
    st.subheader("Investigation leads")
    show_findings(analyze_headers(parsed["headers"], parsed["authentication_results"]))
    if parsed["warnings"]:
        st.warning(" · ".join(parsed["warnings"]))
