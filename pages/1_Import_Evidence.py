from __future__ import annotations

import sqlite3

import streamlit as st

from config import MAX_EMAILS_PER_IMPORT, MAX_IMPORT_TOTAL_MB, MAX_UPLOAD_MB
from modules.database import create_investigation, import_evidence

st.title("Import Email Evidence")
st.warning(f"Untrusted content warning: uploaded emails may contain deceptive links or attachments. Nothing is executed or opened. Maximum {MAX_UPLOAD_MB} MB per email.")
st.write("Evidence bytes are preserved in the local evidence store. Analysis uses extracted copies and never modifies the stored original.")
with st.expander("Understand the identifiers and hashes", expanded=True):
    st.markdown(
        """
        - **Evidence ID** is a new record identifier each time you import. It is expected to change on re-import.
        - **Email SHA-256** fingerprints the exact uploaded file bytes. Re-importing the exact same file produces the same SHA-256. If even one byte differs (for example, a changed header or line ending), its SHA-256 changes.
        - **VirusTotal URL identifier** is a URL-safe encoding used for URL report lookup; it is not the email file hash.

        This application does not upload email files to VirusTotal. The VirusTotal `gui/home/upload` page is a file-upload page; it is not a URL reputation report.
        """
    )
analyst = st.text_input("Analyst identifier (optional)", max_chars=100)
uploads = st.file_uploader("Choose .eml files", type=["eml"], accept_multiple_files=True)
if uploads and len(uploads) > MAX_EMAILS_PER_IMPORT:
    st.error(f"Choose no more than {MAX_EMAILS_PER_IMPORT} emails at a time.")
elif uploads and sum(upload.size for upload in uploads) > MAX_IMPORT_TOTAL_MB * 1024 * 1024:
    st.error(f"The combined import exceeds the {MAX_IMPORT_TOTAL_MB} MB batch limit.")
elif st.button("Import selected evidence", type="primary", disabled=not uploads):
    try:
        investigation_id = create_investigation(analyst)
        imported = []
        for upload in uploads or []:
            record = import_evidence(investigation_id, upload.name, upload.getvalue())
            imported.append(record)
        st.session_state["active_investigation_id"] = investigation_id
        st.success(f"Imported {len(imported)} email(s). Investigation ID: {investigation_id}")
        st.dataframe(
            [
                {
                    "New Evidence Record ID": row["id"],
                    "Original filename": row["filename"],
                    "File size (bytes)": row["size"],
                    "Email file SHA-256 (content fingerprint)": row["sha256"],
                    "Imported (UTC)": row["imported_at"],
                }
                for row in imported
            ],
            use_container_width=True,
            hide_index=True,
        )
    except (ValueError, OSError, KeyError, sqlite3.Error) as exc:
        st.error(f"Import could not be completed: {exc}")
