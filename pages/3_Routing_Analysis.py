import pandas as pd
import streamlit as st

from modules.routing_analysis import analyze_routing
from modules.ui_helpers import selected_evidence

st.title("Email Routing Analysis")
st.info("Received headers are normally prepended by receiving systems. The displayed original order is therefore usually newest-to-oldest; chronological reconstruction generally reverses the list. Header values can be forged, and an IP does not by itself identify the real sender.")
record = selected_evidence()
if record:
    rows = analyze_routing(record["parsed"]["received"])
    if rows:
        for row in rows:
            with st.expander(f"Original header position {row['header_position']} · Chronological position {row['chronological_position']}"):
                st.code(row["raw"], language="text")
                st.write({key: row[key] for key in ("hosts", "ips", "timestamp", "status")})
        st.dataframe(pd.DataFrame([{key: row[key] for key in ("header_position", "chronological_position", "hosts", "ips", "timestamp", "status")} for row in rows]), use_container_width=True, hide_index=True)
    else:
        st.info("No Received headers were found.")
