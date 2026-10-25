import os

import streamlit as st

from config import APP_NAME, APP_VERSION, MAX_ATTACHMENT_MB, MAX_EMAILS_PER_IMPORT, MAX_IMPORT_TOTAL_MB, MAX_UPLOAD_MB
from modules.database import initialize_database

st.title("Settings and About")
initialize_database()
st.write(f"**{APP_NAME}** · version {APP_VERSION}")
st.subheader("Local processing limits")
st.write({"Maximum email size (MB)": MAX_UPLOAD_MB, "Maximum emails per import": MAX_EMAILS_PER_IMPORT, "Maximum batch size (MB)": MAX_IMPORT_TOTAL_MB, "Attachment inspection threshold (MB)": MAX_ATTACHMENT_MB})
st.subheader("Optional VirusTotal")
st.write("Status:", "API key configured" if os.getenv("VIRUSTOTAL_API_KEY") else "Not configured")
st.caption("The key is read only from VIRUSTOTAL_API_KEY. External queries require a separate explicit user action. Never put the key in source code or share it.")
st.subheader("Forensic limitations")
st.markdown("""
- Preserve trusted originals in a controlled location and analyze verified working copies.
- Hashes support integrity checks against a known reference; they do not prove sender identity or truthful metadata.
- Header and URL rules are conservative heuristics and can produce false positives and false negatives.
- Email authentication headers are not independently verified by this tool.
- SQLite audit events are application-level append-only records, not tamper-proof or court-certified storage.
- The tool does not execute email content, open links, scan files for malware, or attribute messages to a person.
""")
