import pandas as pd
import streamlit as st

from modules.database import list_evidence, list_investigations

st.title("Investigation History")
investigations = list_investigations()
if investigations:
    st.subheader("Investigations")
    st.dataframe(pd.DataFrame(investigations), use_container_width=True, hide_index=True)
    st.subheader("Evidence records")
    records = list_evidence()
    query = st.text_input("Search filename, evidence ID, or investigation ID")
    if query:
        records = [item for item in records if query.casefold() in item["filename"].casefold() or query.casefold() in item["id"].casefold() or query.casefold() in item["investigation_id"].casefold()]
    st.dataframe(pd.DataFrame([{"Investigation ID": item["investigation_id"], "Evidence ID": item["id"], "Filename": item["filename"], "Imported UTC": item["imported_at"], "Size": item["size"], "SHA-256": item["sha256"]} for item in records]), use_container_width=True, hide_index=True)
else:
    st.info("No investigations have been recorded.")
