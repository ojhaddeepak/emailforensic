from __future__ import annotations

import streamlit as st
from dotenv import load_dotenv

from config import APP_NAME
from modules.database import initialize_database

load_dotenv()
st.set_page_config(page_title=APP_NAME, page_icon="🔎", layout="wide")
initialize_database()
st.markdown(
    """
    <style>
      .stApp { background: #f3f5f3; }
      [data-testid="stHeader"] { background: #f3f5f3; }
      [data-testid="stSidebar"] { background: #182826; border-right: 1px solid #263b37; }
      [data-testid="stSidebar"] * { color: #e9efec; }
      [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color: #aabbb5; }
      [data-testid="stSidebar"] a { color: #dce8e2; }
      [data-testid="stSidebar"] a[aria-current="page"] { background: #29413c; }
      [data-testid="stSidebarNavSeparator"] { border-color: #344743; }
      [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h3 {
        color: #f2f5f3; font-size: .82rem; letter-spacing: .08em;
      }
      [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {
        font-size: .68rem; letter-spacing: .075em;
      }
      .block-container { max-width: 1320px; padding-top: 1.65rem; padding-bottom: 2.5rem; }
      h1, h2, h3 { letter-spacing: -.02em; color: #202b2a; }
      h1 { font-size: 1.9rem !important; font-weight: 650 !important; }
      h2 { font-size: 1.35rem !important; font-weight: 620 !important; }
      h3 { font-size: 1.05rem !important; font-weight: 620 !important; }
      [data-testid="stCaptionContainer"] { color: #697773; }
      [data-testid="stMetric"] {
        background: #fff; border: 1px solid #dce3df; border-radius: 6px;
        padding: .75rem 1rem; box-shadow: none;
      }
      [data-testid="stMetricLabel"] { color: #65736e; font-size: .82rem; }
      [data-testid="stMetricValue"] { color: #202b2a; font-size: 1.65rem; }
      [data-testid="stDataFrame"], [data-testid="stPlotlyChart"] {
        border: 1px solid #dce3df; border-radius: 6px; overflow: hidden;
      }
      .stButton > button, .stDownloadButton > button {
        border-radius: 5px; font-weight: 600; min-height: 2.35rem;
      }
      [data-testid="stAlert"] { border-radius: 5px; }
      [data-testid="stTextInput"] input, [data-testid="stSelectbox"] [role="combobox"] {
        border-radius: 5px;
      }
      hr { border-color: #dce3df; }
      [data-testid="stExpander"] { border-color: #dce3df; border-radius: 5px; }
      footer { visibility: hidden; }
    </style>
    """,
    unsafe_allow_html=True,
)

navigation = st.navigation(
    {
        "CASEWORK": [
            st.Page("pages/0_Dashboard.py", title="Case overview", default=True),
            st.Page("pages/1_Import_Evidence.py", title="Import evidence"),
            st.Page("pages/7_Investigation_History.py", title="Investigation history"),
            st.Page("pages/8_Chain_of_Custody.py", title="Chain of custody"),
            st.Page("pages/9_Reports.py", title="Reports"),
        ],
        "ANALYSIS": [
            st.Page("pages/2_Header_Analysis.py", title="Email headers"),
            st.Page("pages/3_Routing_Analysis.py", title="Message routing"),
            st.Page("pages/4_URL_Investigation.py", title="Email URL extraction"),
            st.Page("pages/11_URL_Reputation_Checker.py", title="URL reputation"),
            st.Page("pages/5_Attachment_Analysis.py", title="Attachments"),
            st.Page("pages/6_Risk_Assessment.py", title="Risk assessment"),
        ],
        "PREFERENCES": [
            st.Page("pages/10_Settings.py", title="Settings and limitations"),
        ],
    }
)
navigation.run()
