import pandas as pd
import streamlit as st

from modules.ui_helpers import selected_evidence
from modules.url_analysis import analyze_urls

st.title("URL Investigation")
st.warning("URLs are extracted for offline inspection only. This application never opens links, follows redirects, or downloads content.")
record = selected_evidence()
if record:
    parsed = record["parsed"]
    urls = analyze_urls(parsed["body_text"], parsed["body_html"], parsed["links"])
    if urls:
        st.dataframe(pd.DataFrame([{"Visible text": item["visible_text"], "Complete URL": item["url"], "Host": item["host"], "Heuristic indicators": "; ".join(item["reasons"]) or "None observed"} for item in urls]), use_container_width=True, hide_index=True)
        st.caption("For a VirusTotal report lookup, use URL Reputation Checker. No external request is made from this page.")
    else:
        st.info("No supported URL patterns were extracted from the text or HTML body.")
