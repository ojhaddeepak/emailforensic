import pandas as pd
import streamlit as st

from modules.ui_helpers import selected_evidence

st.title("Attachment Analysis")
st.warning("Attachments are hashed and inspected as data only. They are not executed, previewed, saved out, or extracted from archives.")
record = selected_evidence()
if record:
    attachments = record["parsed"]["attachments"]
    if attachments:
        st.dataframe(pd.DataFrame([{"Filename": item["filename"], "MIME type": item["mime_type"], "Size (bytes)": item["size"], "SHA-256": item["sha256"], "MD5": item["md5"], "Signature": item["signature"], "Indicators": "; ".join(item.get("flags", [])) or "None observed"} for item in attachments]), use_container_width=True, hide_index=True)
    else:
        st.info("No MIME attachments were found.")
    st.caption("Signature checks cover common file types only and are not malware scans. MD5 is included for legacy comparison only; SHA-256 is preferred.")
