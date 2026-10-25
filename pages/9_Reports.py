import streamlit as st

from modules.database import get_evidence, list_evidence, record_event
from modules.report_generator import build_analysis, generate_findings_csv, generate_html_report

st.title("Generate Reports")
st.warning("Reports may include private email metadata and content excerpts. Store and share them only according to your institution's evidence-handling rules.")
records = list_evidence()
if records:
    labels = {f"{item['filename']} — {item['id'][:8]}": item["id"] for item in records}
    choice = st.selectbox("Evidence item", list(labels))
    record = get_evidence(labels[choice])
    analysis = build_analysis(record)
    st.write(f"Risk: **{analysis['risk']['score']}/100 — {analysis['risk']['label']}**")
    if st.button("Prepare report downloads", type="primary"):
        record_event(record["investigation_id"], record["id"], "Reports generated", "HTML report and structured findings CSV prepared.")
        st.download_button("Download HTML report", generate_html_report(record, analysis), file_name=f"forensic-report-{record['id'][:8]}.html", mime="text/html")
        st.download_button("Download findings CSV", generate_findings_csv(record, analysis), file_name=f"findings-{record['id'][:8]}.csv", mime="text/csv")
else:
    st.info("Import evidence before generating reports.")
