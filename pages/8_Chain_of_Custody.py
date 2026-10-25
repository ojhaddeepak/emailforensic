import pandas as pd
import streamlit as st

from modules.database import list_custody_events, list_evidence, verify_evidence

st.title("Chain of Custody")
st.warning("Events are append-only through this application's normal workflow. SQLite controls are not tamper-proof storage or court-certified preservation.")
records = list_evidence()
if records:
    labels = {f"{item['filename']} — {item['id'][:8]}": item for item in records}
    label = st.selectbox("Evidence item", list(labels))
    record = labels[label]
    st.write({"Investigation ID": record["investigation_id"], "Evidence ID": record["id"], "Filename": record["filename"], "Imported UTC": record["imported_at"], "SHA-256": record["sha256"]})
    if st.button("Verify stored evidence hash"):
        result = verify_evidence(record["id"])
        if result["actual"]:
            st.code(f"Expected: {result['expected']}\nActual:   {result['actual']}")
        st.write(result["status"])
    events = list_custody_events(evidence_id=record["id"])
    st.subheader("Recorded events")
    st.dataframe(pd.DataFrame(events), use_container_width=True, hide_index=True)
else:
    st.info("Import evidence to create custody records.")
