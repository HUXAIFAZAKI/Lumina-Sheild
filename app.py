import streamlit as st
import os
import json
import hashlib
import tempfile
import re
from urllib.parse import urlparse
import pathlib
import pandas as pd

# dotenv for local dev
from dotenv import load_dotenv
load_dotenv()

# Database init
from data.db import (get_db, log_submission, log_verdict, log_heatmap, log_to_feed, 
                    get_heatmap_data, get_community_feed, upvote_feed_item, init_db,
                    get_all_city_names, GLOBAL_CITY_COORDS, get_community_feed_filtered, 
                    check_feed_duplicate)
init_db()

# Agents
from agents.translator import translate_and_extract
from agents.decomposer import split_into_claims
from agents.misinfo_investigator import verify_claim, check_fake_url
from agents.threat_investigator import investigate_threat, normalize_investigation_input, investigate_threat_cached
from agents.tactic_analyser import analyse_tactics
from agents.narrator import generate_citizen_card, generate_cyber_card, generate_researcher_card
from agents.cartographer import build_genealogy_graph

# Utils
from utils.cache import get_cached_result, submission_hash
from utils.report_generator import generate_pdf

whitelist_path = pathlib.Path(__file__).parent / "data" / "source_whitelist.json"
with open(whitelist_path, "r", encoding="utf-8") as f:
    TRUSTED_SOURCES = json.load(f)

# -------------------- Page Config --------------------
st.set_page_config(
    page_title="Lumina Shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

with st.sidebar:
    st.markdown("### ⚙️ Developer Settings")
    demo_mode = st.toggle("🚀 Demo Mode (Mock APIs)", value=False, help="Enable to bypass API rate limits during pitch.")
    st.session_state.demo_mode = demo_mode

    st.markdown("---")
    st.markdown("### 💾 Disk Cache")
    try:
        from utils.disk_cache import cache_stats, cache_purge_expired
        stats = cache_stats()
        if stats:
            for ns, info in stats.items():
                st.caption(f"**{ns}**: {info['entries']} entries · {info['total_hits']} hits")
        else:
            st.caption("Cache empty")
        if st.button("🗑️ Purge Expired", key="purge_cache"):
            n = cache_purge_expired()
            st.success(f"Removed {n} expired entries")
    except Exception:
        st.caption("Cache unavailable")


# -------------------- Design System CSS --------------------
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500&display=swap');

    /* ── Reset & base ───────────────────────────────────── */
    *, *::before, *::after { box-sizing: border-box; }

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
    }

    /* ── Background ─────────────────────────────────────── */
    .stApp {
        background: #f8f6f0 !important;
        background-image:
            radial-gradient(ellipse 80% 50% at 20% -10%, rgba(229,161,0,0.08) 0%, transparent 60%),
            radial-gradient(ellipse 60% 40% at 80% 110%, rgba(255,140,66,0.07) 0%, transparent 60%) !important;
        min-height: 100vh;
    }

    /* ── Scrollbar ───────────────────────────────────────── */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #f0ede6; border-radius: 10px; }
    ::-webkit-scrollbar-thumb { background: #d4a843; border-radius: 10px; }

    /* ── Streamlit chrome ────────────────────────────────── */
    #MainMenu, footer, header { visibility: hidden !important; }
    .block-container {
        padding-top: 1.5rem !important;
        padding-bottom: 3rem !important;
        max-width: 1280px !important;
    }

    /* ── Typography ──────────────────────────────────────── */
    .stMarkdown h1, .stMarkdown h2, .stMarkdown h3,
    h1, h2, h3, h4, p, label, span, div { color: #1a1714 !important; }
    .stCaption, .stCaption * { color: #7a7268 !important; font-size: 0.82rem !important; }

    /* ── Particles ───────────────────────────────────────── */
    .particles {
        position: fixed; top: 0; left: 0;
        width: 100%; height: 100%;
        z-index: 0; pointer-events: none; overflow: hidden;
    }
    .particle {
        position: absolute;
        border-radius: 50%;
        animation: floatUp linear infinite;
        opacity: 0;
    }
    .particle:nth-child(1) { width:5px; height:5px; left:10%; background:#E5A100; animation-duration:14s; animation-delay:0s; }
    .particle:nth-child(2) { width:4px; height:4px; left:28%; background:#FF8C42; animation-duration:18s; animation-delay:3s; }
    .particle:nth-child(3) { width:6px; height:6px; left:52%; background:#E5A100; animation-duration:12s; animation-delay:6s; }
    .particle:nth-child(4) { width:3px; height:3px; left:71%; background:#FF8C42; animation-duration:16s; animation-delay:9s; }
    .particle:nth-child(5) { width:5px; height:5px; left:88%; background:#d4a843; animation-duration:20s; animation-delay:1s; }
    @keyframes floatUp {
        0%   { transform: translateY(100vh) scale(0); opacity: 0; }
        8%   { opacity: 0.35; }
        92%  { opacity: 0.35; }
        100% { transform: translateY(-8vh) scale(1.2); opacity: 0; }
    }

    /* ── Header ──────────────────────────────────────────── */
    .ls-header {
        background: linear-gradient(135deg, #fffef8 0%, #fff9ed 100%);
        border: 1px solid rgba(229,161,0,0.18);
        border-radius: 24px;
        padding: 2.2rem 2rem 1.8rem;
        text-align: center;
        position: relative;
        overflow: hidden;
        margin-bottom: 1.8rem;
        box-shadow: 0 4px 40px rgba(229,161,0,0.08), 0 1px 0 rgba(255,255,255,0.9) inset;
        animation: fadeDown 0.7s cubic-bezier(.22,1,.36,1) both;
    }
    .ls-header::before {
        content: "";
        position: absolute; top: -60%; left: -30%;
        width: 160%; height: 160%;
        background: radial-gradient(ellipse 60% 50% at 50% 50%, rgba(229,161,0,0.12) 0%, transparent 70%);
        animation: headerGlow 8s ease-in-out infinite alternate;
        pointer-events: none;
    }
    @keyframes headerGlow {
        0%   { transform: scale(1) rotate(0deg); opacity: 0.6; }
        100% { transform: scale(1.15) rotate(8deg); opacity: 1; }
    }
    .ls-header h1 {
        font-size: 2.8rem !important;
        font-weight: 900 !important;
        background: linear-gradient(135deg, #c88b00 0%, #E5A100 40%, #FF8C42 100%);
        -webkit-background-clip: text !important;
        -webkit-text-fill-color: transparent !important;
        background-clip: text !important;
        letter-spacing: -0.5px;
        margin: 0 0 0.4rem !important;
        position: relative;
    }
    .ls-header .tagline {
        color: #6b6156 !important;
        font-size: 1rem;
        font-weight: 500;
        letter-spacing: 0.2px;
        -webkit-text-fill-color: #6b6156 !important;
    }
    .ls-header .badge-row {
        display: flex;
        justify-content: center;
        gap: 8px;
        margin-top: 0.9rem;
        flex-wrap: wrap;
    }
    .ls-badge {
        background: rgba(229,161,0,0.1);
        border: 1px solid rgba(229,161,0,0.25);
        color: #9a6e00 !important;
        -webkit-text-fill-color: #9a6e00 !important;
        font-size: 0.72rem;
        font-weight: 600;
        padding: 3px 10px;
        border-radius: 20px;
        letter-spacing: 0.3px;
    }

    /* ── Tabs ────────────────────────────────────────────── */
    .stTabs [data-baseweb="tab-list"] {
        gap: 4px !important;
        justify-content: center;
        background: rgba(255,252,242,0.95) !important;
        border: 1px solid rgba(229,161,0,0.12) !important;
        backdrop-filter: blur(16px);
        padding: 6px !important;
        border-radius: 18px !important;
        box-shadow: 0 2px 20px rgba(0,0,0,0.05) !important;
        margin-bottom: 1.6rem !important;
    }
    .stTabs [data-baseweb="tab"] {
        background: transparent !important;
        border-radius: 12px !important;
        padding: 0.55rem 1.4rem !important;
        font-weight: 600 !important;
        font-size: 0.88rem !important;
        color: #7a7268 !important;
        border: none !important;
        transition: all 0.25s cubic-bezier(.22,1,.36,1) !important;
    }
    .stTabs [data-baseweb="tab"]:hover {
        background: rgba(229,161,0,0.08) !important;
        color: #c88b00 !important;
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #E5A100, #FF8C42) !important;
        color: #fff !important;
        box-shadow: 0 3px 12px rgba(229,161,0,0.38) !important;
    }
    .stTabs [aria-selected="true"]:hover {
        background: linear-gradient(135deg, #E5A100, #FF8C42) !important;
        color: #fff !important;
    }
    .stTabs [aria-selected="true"] * { color: #fff !important; -webkit-text-fill-color: #fff !important; }
    .stTabs [aria-selected="true"]:hover * { color: #fff !important; -webkit-text-fill-color: #fff !important; }

    /* ── Cards ───────────────────────────────────────────── */
    .ls-card, .verdict-card, .info-card, .tactic-card, .feed-card {
        background: #fffdf5;
        border: 1px solid rgba(229,161,0,0.12);
        border-radius: 18px;
        padding: 1.4rem 1.6rem;
        margin: 0.75rem 0;
        box-shadow: 0 2px 16px rgba(0,0,0,0.04), 0 1px 0 rgba(255,255,255,0.8) inset;
        animation: fadeUp 0.45s cubic-bezier(.22,1,.36,1) both;
        position: relative;
        overflow: hidden;
    }
    .verdict-card { border-left: 4px solid #E5A100; }
    .tactic-card  { border-left: 4px solid #FF8C42; }
    .feed-card    { padding: 1rem 1.2rem; margin: 0.4rem 0; }

    /* shimmer effect on cards */
    .ls-card::after, .verdict-card::after, .info-card::after {
        content: "";
        position: absolute; top: 0; left: -100%;
        width: 60%; height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.45), transparent);
        animation: shimmer 3.5s infinite;
        pointer-events: none;
    }
    @keyframes shimmer {
        0%   { left: -100%; }
        50%  { left: 150%; }
        100% { left: 150%; }
    }

    @keyframes fadeUp {
        from { opacity: 0; transform: translateY(14px); }
        to   { opacity: 1; transform: translateY(0); }
    }
    @keyframes fadeDown {
        from { opacity: 0; transform: translateY(-14px); }
        to   { opacity: 1; transform: translateY(0); }
    }

    /* ── Stat cards ──────────────────────────────────────── */
    .stat-card {
        background: linear-gradient(145deg, #fffef8, #fff8e8);
        border: 1px solid rgba(229,161,0,0.18);
        border-radius: 18px;
        padding: 1.5rem 1rem;
        text-align: center;
        box-shadow: 0 4px 20px rgba(229,161,0,0.08);
        transition: transform 0.2s, box-shadow 0.2s;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        gap: 4px;
        min-height: 110px;
    }
    .stat-card:hover { transform: translateY(-3px); box-shadow: 0 8px 28px rgba(229,161,0,0.14); }
    .stat-num {
        font-size: 3rem !important;
        font-weight: 900 !important;
        line-height: 1 !important;
        margin: 0 !important;
        background: linear-gradient(135deg, #c88b00, #FF8C42) !important;
        -webkit-background-clip: text !important;
        -webkit-text-fill-color: transparent !important;
        background-clip: text !important;
        color: transparent !important;
        display: block;
        width: 100%;
        font-family: 'Inter', sans-serif !important;
    }
    .stat-card p {
        font-size: 0.78rem !important;
        font-weight: 600 !important;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        color: #a09585 !important;
        -webkit-text-fill-color: #a09585 !important;
        margin: 0 !important;
        line-height: 1.3 !important;
    }

    /* ── Overall verdict badge ───────────────────────────── */
    .overall-badge {
        display: inline-flex;
        align-items: center;
        gap: 10px;
        padding: 0.55rem 2rem;
        border-radius: 50px;
        font-weight: 800;
        font-size: 1.3rem;
        margin: 0.8rem 0 1.2rem;
        animation: popIn 0.55s cubic-bezier(.34,1.56,.64,1) both;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        color: #fff !important;
        -webkit-text-fill-color: #fff !important;
        box-shadow: 0 6px 24px rgba(0,0,0,0.15);
    }
    @keyframes popIn {
        0%   { transform: scale(0.5); opacity: 0; }
        70%  { transform: scale(1.05); }
        100% { transform: scale(1); opacity: 1; }
    }

    /* ── Severity pill badges ────────────────────────────── */
    .severity-badge {
        display: inline-block; padding: 3px 12px;
        border-radius: 20px; font-size: 0.72rem; font-weight: 700;
        text-transform: uppercase; letter-spacing: 0.5px;
    }
    .badge-true       { background: #d4f5e0; color: #1a6e3a !important; -webkit-text-fill-color: #1a6e3a !important; }
    .badge-false      { background: #fde0e0; color: #9c1f1f !important; -webkit-text-fill-color: #9c1f1f !important; }
    .badge-fake       { background: #fde0e0; color: #9c1f1f !important; -webkit-text-fill-color: #9c1f1f !important; }
    .badge-scam       { background: #ffe8d6; color: #8a3a00 !important; -webkit-text-fill-color: #8a3a00 !important; }
    .badge-manipulated{ background: #fff0c2; color: #7a5500 !important; -webkit-text-fill-color: #7a5500 !important; }
    .badge-mixture    { background: #fff0c2; color: #7a5500 !important; -webkit-text-fill-color: #7a5500 !important; }

    /* ── Buttons ─────────────────────────────────────────── */
    .stButton > button {
        background: linear-gradient(135deg, #E5A100 0%, #FF8C42 100%) !important;
        color: #fff !important;
        -webkit-text-fill-color: #fff !important;
        border: none !important;
        border-radius: 50px !important;
        padding: 0.55rem 1.8rem !important;
        font-weight: 700 !important;
        font-size: 0.9rem !important;
        letter-spacing: 0.3px;
        transition: transform 0.2s, box-shadow 0.2s !important;
        box-shadow: 0 4px 16px rgba(229,161,0,0.30) !important;
    }
    .stButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 8px 24px rgba(229,161,0,0.45) !important;
    }
    .stButton > button:active { transform: translateY(0px) !important; }

    .stLinkButton > a {
        background: linear-gradient(135deg, #E5A100, #FF8C42) !important;
        color: #fff !important; -webkit-text-fill-color: #fff !important;
        border: none !important; border-radius: 50px !important;
        padding: 0.5rem 1.4rem !important; font-weight: 600 !important;
        font-size: 0.85rem !important;
        box-shadow: 0 3px 12px rgba(229,161,0,0.28) !important;
        transition: all 0.2s !important;
    }
    .stLinkButton > a:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 6px 20px rgba(229,161,0,0.42) !important;
    }

    /* ── Download button – subtle variant ───────────────── */
    [data-testid="stDownloadButton"] > button {
        background: #fff !important;
        color: #c88b00 !important;
        -webkit-text-fill-color: #c88b00 !important;
        border: 2px solid rgba(229,161,0,0.35) !important;
        box-shadow: none !important;
    }
    [data-testid="stDownloadButton"] > button:hover {
        background: linear-gradient(135deg,#E5A100,#FF8C42) !important;
        color: #fff !important; -webkit-text-fill-color: #fff !important;
        border-color: transparent !important;
    }

    /* ── Inputs ──────────────────────────────────────────── */
    .stTextArea textarea, .stTextInput input {
        background: #fff !important;
        border: 1.5px solid rgba(0,0,0,0.1) !important;
        border-radius: 14px !important;
        color: #1a1714 !important;
        font-family: 'Inter', sans-serif !important;
        padding: 0.75rem 1rem !important;
        transition: border-color 0.2s, box-shadow 0.2s !important;
    }
    .stTextArea textarea:focus, .stTextInput input:focus {
        border-color: #E5A100 !important;
        box-shadow: 0 0 0 3px rgba(229,161,0,0.15) !important;
        outline: none !important;
    }

    /* ── Select / radio ──────────────────────────────────── */
    .stSelectbox > div > div {
        border-radius: 12px !important;
        border-color: rgba(0,0,0,0.1) !important;
        background: #fff !important;
    }
    .stRadio [data-testid="stMarkdownContainer"] p { font-weight: 500; }

    /* ── Expanders ───────────────────────────────────────── */
    .streamlit-expanderHeader {
        background: #fffdf5 !important;
        border-radius: 12px !important;
        font-weight: 600 !important;
        color: #1a1714 !important;
        border: 1px solid rgba(229,161,0,0.12) !important;
    }
    .streamlit-expanderContent {
        border: 1px solid rgba(229,161,0,0.08) !important;
        border-top: none !important;
        border-radius: 0 0 12px 12px !important;
        background: #fffdf5 !important;
    }

    /* ── Metrics ─────────────────────────────────────────── */
    [data-testid="stMetricValue"] {
        color: #1a1714 !important; font-weight: 700 !important; font-size: 1.5rem !important;
    }
    [data-testid="stMetricLabel"] { color: #7a7268 !important; font-size: 0.78rem !important; }

    /* ── Alerts & info boxes ─────────────────────────────── */
    .stAlert {
        border-radius: 14px !important;
        border: none !important;
    }
    [data-testid="stInfoBox"]    { background: rgba(229,161,0,0.07) !important; border-left: 4px solid #E5A100 !important; }
    [data-testid="stWarningBox"] { background: rgba(255,140,66,0.07) !important; border-left: 4px solid #FF8C42 !important; }
    [data-testid="stErrorBox"]   { background: rgba(244,67,54,0.07)  !important; border-left: 4px solid #f44336 !important; }
    [data-testid="stSuccessBox"] { background: rgba(76,175,80,0.07)  !important; border-left: 4px solid #4CAF50 !important; }

    /* ── Spinner ─────────────────────────────────────────── */
    .stSpinner > div { border-top-color: #E5A100 !important; }

    /* ── Code blocks ─────────────────────────────────────── */
    .stCodeBlock, code, pre {
        font-family: 'JetBrains Mono', monospace !important;
        background: #fff8ec !important;
        border: 1px solid rgba(229,161,0,0.14) !important;
        border-radius: 12px !important;
        font-size: 0.84rem !important;
    }

    /* ── Dataframe ───────────────────────────────────────── */
    [data-testid="stDataFrame"] { border-radius: 14px !important; overflow: hidden; }
    [data-testid="stDataFrame"] table th {
        background: #fff9ed !important; color: #7a7268 !important;
        font-weight: 600 !important; font-size: 0.78rem !important; text-transform: uppercase; letter-spacing: 0.5px;
    }

    /* ── Progress bars (Streamlit native) ───────────────── */
    .stProgress > div > div > div {
        background: linear-gradient(90deg, #E5A100, #FF8C42) !important;
        border-radius: 10px !important;
        animation: progressShimmer 1.5s ease infinite;
    }
    @keyframes progressShimmer {
        0%   { filter: brightness(1); }
        50%  { filter: brightness(1.2); }
        100% { filter: brightness(1); }
    }

    /* ── Loading step list ───────────────────────────────── */
    .ls-steps { list-style: none; padding: 0; margin: 0.5rem 0; }
    .ls-step  {
        display: flex; align-items: center; gap: 10px;
        padding: 8px 12px; border-radius: 10px; margin: 4px 0;
        font-size: 0.88rem; font-weight: 500; transition: all 0.3s;
    }
    .ls-step.done    { background: rgba(76,175,80,0.08);  color: #2e7d32 !important; -webkit-text-fill-color: #2e7d32 !important; }
    .ls-step.running { background: rgba(229,161,0,0.1);   color: #8a5f00 !important; -webkit-text-fill-color: #8a5f00 !important; animation: stepPulse 1s ease infinite; }
    .ls-step.pending { background: rgba(0,0,0,0.03);      color: #a09585 !important; -webkit-text-fill-color: #a09585 !important; }
    @keyframes stepPulse {
        0%, 100% { opacity: 1; } 50% { opacity: 0.65; }
    }

    /* ── Risk gauge bar ──────────────────────────────────── */
    .risk-gauge {
        background: #f0ede6; border-radius: 20px; height: 12px;
        overflow: hidden; margin: 8px 0;
        box-shadow: inset 0 2px 6px rgba(0,0,0,0.08);
    }
    .risk-fill {
        height: 100%; border-radius: 20px;
        transition: width 1s cubic-bezier(.22,1,.36,1);
        animation: riseFill 1.2s cubic-bezier(.22,1,.36,1) both;
    }
    @keyframes riseFill { from { width: 0 !important; } }

    /* ── Section dividers ────────────────────────────────── */
    .ls-divider {
        height: 1px; background: linear-gradient(90deg, transparent, rgba(229,161,0,0.2), transparent);
        margin: 1.5rem 0; border: none;
    }
    .ls-section-header {
        display: flex; align-items: center; gap: 10px;
        margin: 1.4rem 0 0.8rem; font-weight: 700; font-size: 1.05rem;
        color: #1a1714 !important;
    }
    .ls-section-header .icon-box {
        width: 32px; height: 32px; border-radius: 8px;
        background: linear-gradient(135deg, rgba(229,161,0,0.15), rgba(255,140,66,0.15));
        display: flex; align-items: center; justify-content: center;
        font-size: 1rem;
    }

    /* ── Redirect chain ──────────────────────────────────── */
    .redirect-step {
        background: #fff; border-left: 3px solid #1f78b4;
        border-radius: 8px; padding: 10px 14px;
        font-family: 'JetBrains Mono', monospace; font-size: 0.8rem;
        word-break: break-all; color: #2c5f8a !important;
    }
    .redirect-arrow { text-align: center; color: #b0a99c !important; font-size: 1rem; margin: 2px 0; }

    /* ── Feature grid (researcher landing) ──────────────── */
    .feature-grid {
        display: grid; grid-template-columns: repeat(3, 1fr);
        gap: 14px; margin-top: 1rem;
    }
    .feature-card {
        background: #fffdf5; border: 1px solid rgba(229,161,0,0.13);
        border-radius: 16px; padding: 1.3rem 1.1rem;
        text-align: center; transition: transform 0.2s, box-shadow 0.2s;
    }
    .feature-card:hover { transform: translateY(-4px); box-shadow: 0 8px 28px rgba(229,161,0,0.12); }
    .feature-card .icon { font-size: 2rem; margin-bottom: 0.5rem; }
    .feature-card strong { color: #1a1714 !important; font-size: 0.95rem; }
    .feature-card p { color: #7a7268 !important; -webkit-text-fill-color: #7a7268 !important; font-size: 0.8rem; margin: 4px 0 0; }

    /* ── Footer ──────────────────────────────────────────── */
    .ls-footer {
        text-align: center; padding: 1.2rem;
        color: #a09585 !important; font-size: 0.78rem; font-weight: 500;
        border-top: 1px solid rgba(229,161,0,0.1); margin-top: 2rem;
        letter-spacing: 0.2px;
    }
    .ls-footer a { color: #c88b00 !important; text-decoration: none; }

    /* ── Sidebar ─────────────────────────────────────────── */
    [data-testid="stSidebar"] {
        background: #fffef8 !important;
        border-right: 1px solid rgba(229,161,0,0.12) !important;
    }

    /* ── st.subheader / st.header typography polish ─────── */
    [data-testid="stHeadingWithActionElements"] h2,
    [data-testid="stHeadingWithActionElements"] h3 {
        font-weight: 700 !important;
        font-size: 1.05rem !important;
        color: #1a1714 !important;
        display: flex;
        align-items: center;
        gap: 8px;
        margin: 1.4rem 0 0.7rem !important;
        padding-bottom: 0.5rem;
        border-bottom: 2px solid rgba(229,161,0,0.15);
    }

    /* ── Toggle ─────────────────────────────────────────── */
    [data-testid="stToggle"] [role="switch"][aria-checked="true"] {
        background-color: #E5A100 !important;
    }

    @media (max-width: 768px) {
        .ls-header h1 { font-size: 2rem !important; }
        .feature-grid { grid-template-columns: 1fr 1fr; }
        .stTabs [data-baseweb="tab"] { padding: 0.5rem 0.9rem !important; font-size: 0.78rem !important; }
    }
</style>

<div class="particles">
    <div class="particle"></div><div class="particle"></div>
    <div class="particle"></div><div class="particle"></div>
    <div class="particle"></div>
</div>
""", unsafe_allow_html=True)

# -------------------- Header --------------------
st.markdown("""
<div class="ls-header">
    <h1>🛡️ Lumina Shield</h1>
    <div class="tagline">Global AI-Powered Misinformation &amp; Cyber Threat Defense Platform</div>
    <div class="badge-row">
        <span class="ls-badge">🤖 Llama 3.3/Gemini 2.5</span>
        <span class="ls-badge">🌐 Real-Time OSINT</span>
        <span class="ls-badge">🔬 20+ Intel Sources</span>
        <span class="ls-badge">🧬 MITRE ATT&amp;CK</span>
        <span class="ls-badge">📧 Email Phishing AI</span>
        <span class="ls-badge">🇵🇰 Multilingual</span>
    </div>
</div>
""", unsafe_allow_html=True)

# -------------------- Tabs --------------------
tab1, tab2, tab3, tab4 = st.tabs(["🌍 Basic Mode", "🔍 Cyber Analyst", "🔬 Researcher", "📊 Global Dashboard"])


def get_mock_threat_result(url):
    return {
        "ips": ["192.168.1.100", "10.0.0.5"],
        "domains": [url.split("/")[2] if "://" in url else url, "malicious-cdn.net"],
        "hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        "emails": ["admin@phishing.com"],
        "risk_score": 9.5,
        "details": {
            "whois": {"registrar": "Namecheap", "creation_date": "2024-01-01"},
            "domain_age_days": 15,
            "phishtank": "known phishing",
            "safe_browsing": "flagged",
            "abuseipdb": {"abuseConfidenceScore": 100}
        },
        "vt_vendors": {
            "Kaspersky": {"category": "malicious", "result": "phishing"},
            "BitDefender": {"category": "malicious", "result": "malware"}
        },
        "vt_categories": {"Forcepoint ThreatSeeker": "phishing"},
        "vt_reputation": -50,
        "vt_stats": {"malicious": 15, "suspicious": 5, "harmless": 60, "undetected": 10},
        "geo": {"country": "Russia", "city": "Moscow", "isp": "BadHost LLC"},
        "tech_stack": {"server": "nginx", "powered_by": "PHP", "security_headers": []},
        "dns_records": {"A": ["192.168.1.100"], "MX": ["10 mail.phishing.com"]},
        "threatfox": [{"ioc_value": "192.168.1.100", "threat_type": "botnet_cc"}],
        "dom_heuristics": "Detected highly obfuscated JavaScript and a hidden iframe loading an external credential-harvesting form from a suspicious Russian IP. This is a severe Zero-Day phishing heuristic.",
        "redirect_chain": [url, "http://bit.ly/3xyz22", "http://compromised-site.com/redirect", "http://attacker-login.ru/fb/login.php"],
        "subdomains": ["login." + (url.split("/")[2] if "://" in url else url)]
    }

# ===============================
# TAB 1: CITIZEN MODE
# ===============================
with tab1:
    st.markdown("""
    <div class='info-card'>
        <div class='ls-section-header' style='margin:0 0 0.3rem;'>
            <div class='icon-box'>🌍</div>
            <span>Basic Mode — Real-Time Misinformation Verdict</span>
        </div>
        <p style='margin:0; color:#7a7268; font-size:0.88rem;'>
            Paste a message, upload a screenshot, or record a voice note.
            Lumina checks every claim, detects manipulation tactics, and warns you about dangerous links.
        </p>
    </div>
    """, unsafe_allow_html=True)

    col_input, col_loc = st.columns([0.72, 0.28])
    with col_input:
        input_mode = st.radio("Input type", ["📝 Text paste", "🖼️ Screenshot", "🎙️ Voice note", "📧 Email Phishing"], horizontal=True, key="citizen_input")
    with col_loc:
        _all_cities = get_all_city_names()  # 100+ cities from db.py
        user_location = st.selectbox("📍 Your Location", _all_cities,
                                     index=_all_cities.index("Karachi") if "Karachi" in _all_cities else 0,
                                     key="user_location")

    if "raw_text" not in st.session_state:
        st.session_state.raw_text = ""

    # ---- Input handling ----
    if input_mode == "📝 Text paste":
        raw_text = st.text_area(
            "Paste your message here",
            value=st.session_state.raw_text,
            height=160,
            placeholder="Paste any message in Urdu, Arabic, Spanish, or English — WhatsApp forwards, SMS scams, news...",
            key="text_area"
        )
        if raw_text != st.session_state.raw_text:
            st.session_state.raw_text = raw_text

    elif input_mode == "🖼️ Screenshot":
        img_file = st.file_uploader("Upload a screenshot", type=["png","jpg","jpeg"], key="screenshot_upload")
        if img_file:
            from PIL import Image
            img = Image.open(img_file)
            st.image(img, caption="Uploaded Screenshot", width=300)
            if st.button("🔮 Analyze with AI Vision"):
                with st.spinner("AI is analyzing image forensics and extracting text..."):
                    img_bytes = img_file.getvalue()
                    from agents.misinfo_investigator import analyze_image_with_vision
                    vision_result = analyze_image_with_vision(img_bytes)
                    st.session_state.raw_text = vision_result.get("extracted_text", "")
                    st.session_state.vision_forensics = vision_result.get("forensic_analysis", "")
                st.rerun()

        if st.session_state.get("vision_forensics"):
            st.info(f"**🔍 Visual Forensics:** {st.session_state.vision_forensics}")

        if st.session_state.raw_text:
            st.text_area("Extracted Text", value=st.session_state.raw_text, height=100, key="screenshot_text_area")
            if st.session_state.screenshot_text_area != st.session_state.raw_text:
                st.session_state.raw_text = st.session_state.screenshot_text_area

    elif input_mode == "🎙️ Voice note":
        audio_file = st.file_uploader("Upload audio (wav, mp3)", type=["wav","mp3"], key="voice_upload")
        if audio_file:
            st.audio(audio_file)
            if st.button("🎙️ Transcribe with AI"):
                with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as tmp:
                    tmp.write(audio_file.read())
                    tmp_path = tmp.name
                with st.spinner("Whisper AI is transcribing your audio..."):
                    import whisper
                    model = whisper.load_model("base")
                    result = model.transcribe(tmp_path)
                    st.session_state.raw_text = result["text"]
                    st.rerun()
        if st.session_state.raw_text:
            st.text_area("Transcribed Text", value=st.session_state.raw_text, height=100, key="voice_text_area")
            if st.session_state.voice_text_area != st.session_state.raw_text:
                st.session_state.raw_text = st.session_state.voice_text_area

    elif input_mode == "📧 Email Phishing":
        st.markdown("""
        <div class='info-card' style='padding:0.85rem 1.2rem; margin-bottom:0.9rem;'>
            <strong>📧 AI-Powered Email Phishing Scanner</strong>
            <p style='margin:4px 0 0; color:#7a7268; font-size:0.86rem;'>
                Paste the full email text below — headers, body, links and all.
                Lumina uses a <strong>RAG index of 18,650 real phishing samples</strong> combined with
                an LLM to classify the email, fingerprint the campaign, dissect every link,
                and generate your personalised safety guide.
            </p>
        </div>
        """, unsafe_allow_html=True)

        if "email_phishing_text" not in st.session_state:
            st.session_state.email_phishing_text = ""

        email_input = st.text_area(
            "Paste email content here",
            value=st.session_state.email_phishing_text,
            height=220,
            placeholder="From: support@paypa1-secure.tk\nSubject: URGENT: Your account has been suspended\n\nDear Customer, We noticed unusual activity...",
            key="email_phishing_area",
        )
        if email_input != st.session_state.email_phishing_text:
            st.session_state.email_phishing_text = email_input

        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🔍 Scan Email for Phishing", key="scan_email_btn", width='content'):
            if not st.session_state.email_phishing_text.strip():
                st.warning("⚠️ Please paste the email content first.")
            else:
                _email_txt = st.session_state.email_phishing_text
                _ep_progress = st.progress(0, text="Initialising RAG index…")
                _ep_status   = st.empty()

                def _ep_step(n, total, label):
                    _ep_progress.progress(n / total, text=label)
                    _ep_status.markdown(f"""
                    <div class='info-card' style='padding:0.75rem 1.1rem; margin:0;'>
                        <ul class='ls-steps'>
                            {"".join([
                                f"<li class='ls-step done'>✅ {s}</li>" if i < n
                                else f"<li class='ls-step running'>⏳ {s}</li>" if i == n - 1
                                else f"<li class='ls-step pending'>○ {s}</li>"
                                for i, s in enumerate([
                                    "Loading RAG index",
                                    "Classifying email — LLM + RAG",
                                    "Phishing DNA fingerprinting",
                                    "Header & link forensics",
                                    "Generating safety report",
                                ])
                            ])}
                        </ul>
                    </div>
                    """, unsafe_allow_html=True)

                from agents.email_phishing_agent import (
                    classify_email, analyse_phishing_dna,
                    analyse_email_forensics, generate_safety_report,
                )

                _ep_step(1, 5, "Loading RAG index…")
                _ep_classification = classify_email(_email_txt)

                _ep_step(2, 5, "Classifying with LLM + RAG…")
                _ep_dna = analyse_phishing_dna(_email_txt, _ep_classification.get("rag_examples"))

                _ep_step(3, 5, "Fingerprinting phishing campaign…")
                _ep_forensics = analyse_email_forensics(_email_txt)

                _ep_step(4, 5, "Running header & link forensics…")
                _ep_safety = generate_safety_report(_email_txt, _ep_classification, _ep_dna)

                _ep_step(5, 5, "Building safety report…")
                _ep_progress.empty()
                _ep_status.empty()

                st.session_state["email_phishing_result"] = {
                    "classification": _ep_classification,
                    "dna": _ep_dna,
                    "forensics": _ep_forensics,
                    "safety": _ep_safety,
                    "email_text": _email_txt,
                }
                st.rerun()

    # ---- Render Email Phishing Results (persists across reruns) ----
    if input_mode == "📧 Email Phishing" and "email_phishing_result" in st.session_state:
        _ep = st.session_state["email_phishing_result"]
        _cls = _ep["classification"]
        _dna = _ep["dna"]
        _fors = _ep["forensics"]
        _safe = _ep["safety"]

        # ─── Top verdict banner ───────────────────────────────────────
        _ep_verdict = _cls.get("verdict", "Unknown")
        _ep_conf    = _cls.get("confidence", 0)
        _ep_risk    = _cls.get("risk_level", "Unknown")
        _is_phishing = "Phishing" in _ep_verdict

        _verdict_grad = (
            "linear-gradient(135deg,#b71c1c,#e53935)" if _is_phishing
            else "linear-gradient(135deg,#2e7d32,#43a047)"
        )
        _verdict_emoji = "🚨" if _is_phishing else "✅"
        _risk_color = {
            "Critical": "#b71c1c", "High": "#e65100",
            "Medium": "#f57f17", "Low": "#2e7d32"
        }.get(_ep_risk, "#9E9E9E")

        st.markdown(f"""
        <div style='text-align:center; padding:0.6rem 0 1.2rem;'>
            <div class="overall-badge" style="background:{_verdict_grad}; font-size:1.3rem; padding:0.7rem 2.2rem;">
                {_verdict_emoji}&nbsp; {_ep_verdict}
            </div>
            <div style='margin-top:0.6rem; display:flex; justify-content:center; gap:16px; flex-wrap:wrap;'>
                <span style='font-size:0.85rem; font-weight:700; color:{_risk_color};
                             background:{_risk_color}18; padding:4px 14px; border-radius:20px;'>
                    ⚠️ Risk: {_ep_risk}
                </span>
                <span style='font-size:0.85rem; font-weight:700; color:#4a4540;
                             background:#f0ede6; padding:4px 14px; border-radius:20px;'>
                    🎯 Confidence: {_ep_conf}%
                </span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown(f"<div class='info-card'><p style='margin:0; font-size:0.93rem; line-height:1.6;'>💡 {_cls.get('summary','')}</p></div>", unsafe_allow_html=True)

        # ─── 4 Feature Sub-tabs ────────────────────────────────────────
        _ep_t1, _ep_t2, _ep_t3, _ep_t4 = st.tabs([
            "🎯 Classifier",
            "🧬 Phishing DNA",
            "🔬 Header & Link Forensics",
            "🛡️ Safety Report",
        ])

        # ── Tab 1: Classifier ──────────────────────────────────────────
        with _ep_t1:
            st.markdown("<div class='ls-section-header'><div class='icon-box'>🎯</div><span>AI Email Classifier — LLM + RAG</span></div>", unsafe_allow_html=True)
            st.markdown(f"<p style='font-size:0.93rem;color:#7a7268;margin:0 0 0.9rem;'>RAG index searched <strong>{len(_cls.get('rag_examples', []))}</strong> nearest training emails from <strong>18,650</strong> worldwide samples.</p>", unsafe_allow_html=True)

            _flags = _cls.get("red_flags", [])
            _safe_sigs = _cls.get("safe_signals", [])

            if _flags:
                _flags_html = " ".join(
                    f"<span style='background:#fde0e0;color:#9c1f1f;padding:4px 13px;border-radius:20px;font-size:0.88rem;font-weight:600;'>🚩 {f}</span>"
                    for f in _flags
                )
                st.markdown(f"<p style='font-size:0.95rem;font-weight:700;margin:0.6rem 0 0.4rem;'>Red Flags Detected:</p>{_flags_html}", unsafe_allow_html=True)

            if _safe_sigs:
                _sigs_html = " ".join(
                    f"<span style='background:#e8f5e9;color:#1b5e20;padding:4px 13px;border-radius:20px;font-size:0.88rem;font-weight:600;'>✅ {s}</span>"
                    for s in _safe_sigs
                )
                st.markdown(f"<p style='font-size:0.95rem;font-weight:700;margin:0.8rem 0 0.4rem;'>Safe Signals:</p>{_sigs_html}", unsafe_allow_html=True)

            # RAG examples
            st.markdown("<p style='font-size:0.95rem;font-weight:700;margin:1rem 0 0.5rem;'>📚 Most Similar Training Emails (RAG Retrieved):</p>", unsafe_allow_html=True)
            for ex in _cls.get("rag_examples", [])[:4]:
                _ex_color = "#fde0e0" if "Phishing" in ex["label"] else "#e8f5e9"
                _ex_badge_color = "#9c1f1f" if "Phishing" in ex["label"] else "#1b5e20"
                _ex_emoji = "🚨" if "Phishing" in ex["label"] else "✅"
                st.markdown(f"""
                <div style='background:{_ex_color};border-radius:10px;padding:0.75rem 1.1rem;margin:0.4rem 0;'>
                    <span style='font-size:0.88rem;font-weight:700;color:{_ex_badge_color};'>{_ex_emoji} {ex["label"]} — similarity {ex["score"]:.3f}</span>
                    <p style='margin:6px 0 0;font-size:0.92rem;color:#4a4540;line-height:1.6;'>{ex["text"][:200]}…</p>
                </div>
                """, unsafe_allow_html=True)

        # ── Tab 2: Phishing DNA ────────────────────────────────────────
        with _ep_t2:
            st.markdown("<div class='ls-section-header'><div class='icon-box'>🧬</div><span>Phishing DNA — Campaign Fingerprint</span></div>", unsafe_allow_html=True)

            _arch = _dna.get("archetype", "Unknown")
            _camp = _dna.get("campaign_name", "Unknown")
            _regions = _dna.get("global_regions", [])
            _region_str = "  •  ".join(f"🌍 {r}" for r in _regions)

            st.markdown(f"""
            <div class="tactic-card" style="border-left:4px solid #FF8C42;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:8px;">
                    <strong style="font-size:1.05rem;">🧬 {_camp}</strong>
                    <span style="background:#fff0c2;color:#7a5500;padding:3px 12px;border-radius:20px;font-size:0.78rem;font-weight:700;">{_arch}</span>
                </div>
                <p style="margin:0 0 8px;color:#4a4540;font-size:0.88rem;line-height:1.6;">{_dna.get("why_dangerous","")}</p>
                <p style="margin:0 0 4px;font-size:0.83rem;color:#7a7268;">👤 Target: <strong>{_dna.get("target_profile","General users")}</strong></p>
                <p style="margin:0;font-size:0.82rem;color:#7a7268;">{_region_str}</p>
            </div>
            """, unsafe_allow_html=True)

            _tactics = _dna.get("tactics", [])
            if _tactics:
                st.markdown("**🎭 Psychological Tactics Used:**")
                for t in _tactics:
                    st.markdown(f"""
                    <div class="tactic-card">
                        <strong style="font-size:0.9rem;">🎭 {t.get("name","")}</strong>
                        <p style="margin:5px 0 0;color:#7a7268;font-size:0.86rem;line-height:1.5;">{t.get("explanation","")}</p>
                    </div>
                    """, unsafe_allow_html=True)

        # ── Tab 3: Forensics ───────────────────────────────────────────
        with _ep_t3:
            st.markdown("<div class='ls-section-header'><div class='icon-box'>🔬</div><span>Header & Link Forensics</span></div>", unsafe_allow_html=True)

            _headers = _fors.get("headers", {})
            _overall_risk = _fors.get("overall_risk", 0)
            _trust = _fors.get("sender_trust_score", 100)
            _risk_fill_color = "#e53935" if _overall_risk > 70 else "#FF9800" if _overall_risk > 40 else "#4CAF50"

            _hdr_col1, _hdr_col2 = st.columns(2)
            with _hdr_col1:
                st.markdown(f"""
                <div class="info-card" style="padding:1rem 1.2rem;">
                    <p style="margin:0 0 6px;font-weight:700;font-size:0.88rem;">📨 Extracted Headers</p>
                    <p style="margin:2px 0;font-size:0.83rem;"><strong>From:</strong> {_headers.get("from","—") or "—"}</p>
                    <p style="margin:2px 0;font-size:0.83rem;"><strong>Reply-To:</strong> {_headers.get("reply_to","—") or "—"}</p>
                    <p style="margin:2px 0;font-size:0.83rem;"><strong>Subject:</strong> {_headers.get("subject","—") or "—"}</p>
                    <p style="margin:2px 0;font-size:0.83rem;"><strong>To:</strong> {_headers.get("to","—") or "—"}</p>
                </div>
                """, unsafe_allow_html=True)
            with _hdr_col2:
                st.markdown(f"""
                <div class="info-card" style="padding:1rem 1.2rem;">
                    <p style="margin:0 0 6px;font-weight:700;font-size:0.88rem;">🛡️ Trust Scores</p>
                    <p style="margin:2px 0 8px;font-size:0.83rem;">Sender Trust: <strong style="color:{'#2e7d32' if _trust>70 else '#e65100' if _trust>40 else '#b71c1c'};">{_trust}/100</strong></p>
                    <div class="risk-gauge"><div class="risk-fill" style="width:{_trust}%;background:{'#4CAF50' if _trust>70 else '#FF9800' if _trust>40 else '#e53935'};"></div></div>
                    <p style="margin:10px 0 4px;font-size:0.83rem;">Overall Risk: <strong style="color:{_risk_fill_color};">{_overall_risk}/100</strong></p>
                    <div class="risk-gauge"><div class="risk-fill" style="width:{_overall_risk}%;background:{_risk_fill_color};"></div></div>
                </div>
                """, unsafe_allow_html=True)

            # Keyword hits
            _kw_hits = _fors.get("keyword_hits", [])
            if _kw_hits:
                _kw_html = " ".join(
                    f"<span style='background:#fff0c2;color:#7a5500;padding:2px 9px;border-radius:20px;font-size:0.73rem;font-weight:600;'>⚡ {k}</span>"
                    for k in _kw_hits
                )
                st.markdown(f"**⚡ Suspicious Keywords Found:**<br>{_kw_html}", unsafe_allow_html=True)

            # URL analysis
            _urls = _fors.get("url_analysis", [])
            if _urls:
                st.markdown("**🔗 Link Analysis:**")
                for ua in _urls:
                    _u_risk = ua.get("suspicion_score", 0)
                    _u_color = "#e53935" if _u_risk > 60 else "#FF9800" if _u_risk > 30 else "#4CAF50"
                    _u_flags_html = " ".join(
                        f"<span style='background:#fde0e0;color:#9c1f1f;padding:2px 8px;border-radius:20px;font-size:0.7rem;font-weight:600;'>⚠️ {fl}</span>"
                        for fl in ua.get("flags", [])
                    )
                    st.markdown(f"""
                    <div class="verdict-card" style="border-left:4px solid {_u_color}; padding:0.8rem 1rem; margin:0.4rem 0;">
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                            <span style="font-size:0.82rem;font-weight:700;color:{_u_color};">Suspicion {_u_risk}/100</span>
                        </div>
                        <div class="risk-gauge"><div class="risk-fill" style="width:{_u_risk}%;background:{_u_color};"></div></div>
                        <p style="margin:6px 0 2px;font-size:0.8rem;font-family:monospace;color:#4a4540;">{ua.get("url","")[:80]}</p>
                        <div style="margin-top:5px;">{_u_flags_html}</div>
                    </div>
                    """, unsafe_allow_html=True)
            elif not _headers.get("urls"):
                st.info("No URLs detected in this email.")

            # LLM assessment
            if _fors.get("llm_assessment"):
                st.markdown("**🤖 AI Forensic Assessment:**")
                st.info(_fors["llm_assessment"])

        # ── Tab 4: Safety Report ───────────────────────────────────────
        with _ep_t4:
            st.markdown("<div class='ls-section-header'><div class='icon-box'>🛡️</div><span>Your Personalised Safety Report</span></div>", unsafe_allow_html=True)

            st.markdown(f"""
            <div class="ls-card" style="border-left:4px solid {'#e53935' if _is_phishing else '#2e7d32'};">
                <p style="margin:0 0 6px;font-weight:700;font-size:0.95rem;">🎯 What the Attacker Wants</p>
                <p style="margin:0;font-size:0.9rem;color:#4a4540;line-height:1.6;">{_safe.get("attacker_goal","")}</p>
            </div>
            """, unsafe_allow_html=True)

            st.markdown(f"""
            <div class="ls-card" style="border-left:4px solid #e65100;">
                <p style="margin:0 0 6px;font-weight:700;font-size:0.95rem;">⚠️ If You Follow These Instructions…</p>
                <p style="margin:0;font-size:0.9rem;color:#4a4540;line-height:1.6;">{_safe.get("if_you_comply","")}</p>
            </div>
            """, unsafe_allow_html=True)

            _actions = _safe.get("immediate_actions", [])
            if _actions:
                st.markdown("**✅ What To Do Right Now:**")
                for i, act in enumerate(_actions, 1):
                    st.markdown(f"""
                    <div style='display:flex;align-items:flex-start;gap:10px;padding:6px 0;'>
                        <span style='background:linear-gradient(135deg,#E5A100,#FF8C42);color:#fff;font-weight:700;
                                     border-radius:50%;width:24px;height:24px;display:flex;align-items:center;
                                     justify-content:center;font-size:0.78rem;flex-shrink:0;'>{i}</span>
                        <span style='font-size:0.9rem;color:#1a1714;line-height:1.5;'>{act}</span>
                    </div>
                    """, unsafe_allow_html=True)

            # Full report
            if _safe.get("report_text"):
                st.markdown("**📄 Full Safety Summary:**")
                st.info(_safe["report_text"])

            # Shareable warning
            st.markdown("<div class='ls-section-header'><div class='icon-box'>📤</div><span>Forward This Warning to Your Contacts</span></div>", unsafe_allow_html=True)
            st.caption("Copy this message and send it to anyone who may receive the same email.")
            st.code(_safe.get("warning_message", ""), language="text")

        # ─── Community Reporting for Email Scams ───────────────────────
        st.markdown("<hr class='ls-divider'>", unsafe_allow_html=True)
        st.markdown("<div class='ls-section-header'><div class='icon-box'>🌍</div><span>Report This Email Scam to Community</span></div>", unsafe_allow_html=True)
        _ep_share = st.checkbox("📢 Share this email scam verdict with the community map", key="ep_share_consent")
        if _ep_share:
            _ep_cities = get_all_city_names()
            _ep_city = st.selectbox("📍 Report from city", _ep_cities, key="ep_report_city",
                                    index=_ep_cities.index("Karachi") if "Karachi" in _ep_cities else 0)
            if st.button("📤 Submit Email Scam Report", key="ep_submit_report"):
                sub_id = log_submission(_ep["email_text"], "EmailPhishing", "app")
                _ep_verdict_val = "SCAM" if _is_phishing else "TRUE"
                log_heatmap(_ep_city, "email_phishing", _ep_verdict_val)
                if _is_phishing and not check_feed_duplicate(_ep["email_text"][:100]):
                    log_to_feed(sub_id, "SCAM", _ep["email_text"][:100] + "…")
                st.success(f"✅ Email scam reported from **{_ep_city}**. Thank you!")

    # ---- Analyze Button (non-email modes) ----
    if input_mode != "📧 Email Phishing":
        st.markdown("<br>", unsafe_allow_html=True)
    if input_mode != "📧 Email Phishing" and st.button("🔍 Analyze this message", key="analyze_citizen", width='content'):
        if not st.session_state.raw_text.strip():
            st.warning("⚠️ Please paste or upload some content first.")
        else:
            raw_text = st.session_state.raw_text
            sub_hash = submission_hash(raw_text)
            demo = get_cached_result(sub_hash)
            
            context_data = {}
            claims = []
            _research_text = ""

            if demo:
                verdicts = demo["verdicts"]
                tactics = demo["tactics"]
                url_checks = demo.get("url_checks", [])
                entities = {}
            else:
                # ── Step-by-step loading feedback ──
                progress_bar = st.progress(0, text="Starting analysis…")
                status_box = st.empty()

                def _step(n, total, label):
                    progress_bar.progress(n / total, text=label)
                    status_box.markdown(f"""
                    <div class='info-card' style='padding:0.9rem 1.2rem; margin:0;'>
                        <ul class='ls-steps'>
                            {"".join([
                                f"<li class='ls-step done'>✅ {s}</li>" if i < n
                                else f"<li class='ls-step running'>⏳ {s}</li>" if i == n-1
                                else f"<li class='ls-step pending'>○ {s}</li>"
                                for i, s in enumerate([
                                    "Translating & extracting entities",
                                    "Decomposing claims",
                                    "Verifying each claim",
                                    "Detecting manipulation tactics",
                                    "Checking URLs for phishing",
                                    "Generating verdict card",
                                ])
                            ])}
                        </ul>
                    </div>
                    """, unsafe_allow_html=True)

                _step(1, 6, "Translating & extracting entities…")
                trans = translate_and_extract(raw_text)
                norm = trans.get("normalised_text", raw_text)
                detected_language = trans.get("detected_language", "English")
                entities = trans.get("entities", {})

                _step(2, 6, "Decomposing into individual claims…")
                context_data = split_into_claims(norm)
                context_data["full_message"] = norm
                claims = context_data.get("claims", [])

                _step(3, 6, "Verifying message against live web…")
                from agents.searcher import verify_message as _verify_message

                # Fast local fake-URL pre-check — skip Gemini if already busted
                all_cta_urls = [c["text"] for c in context_data.get("ctas", []) if c.get("type") == "url"]
                fake_url_result = None
                for _u in all_cta_urls:
                    _r = check_fake_url(_u)
                    if _r["verdict"] == "FAKE_SITE":
                        fake_url_result = _r
                        break

                if fake_url_result:
                    _fake_ev = (
                        f"🚨 FAKE LINK DETECTED: '{fake_url_result.get('real_url', '')}' is NOT a legitimate site. "
                        f"Risk score: {fake_url_result.get('risk_score', 'N/A')}/100."
                    )
                    msg_result = {
                        "overall_verdict": "FALSE",
                        "overall_confidence": 99,
                        "overall_evidence": _fake_ev,
                        "breakdown": [{"point": "Fake URL detected", "verdict": "FALSE", "explanation": _fake_ev}],
                        "source_urls": [],
                    }
                else:
                    # ONE Gemini call — full message in, Gemini searches + self-breaks-down
                    msg_result = _verify_message(norm, context_data)

                # Map Gemini's self-generated breakdown into (claim, verdict) pairs for the card
                _ov = msg_result.get("overall_verdict", "UNVERIFIABLE")
                _oc = msg_result.get("overall_confidence", 50)
                _src = msg_result.get("source_urls", [])
                _research_text = msg_result.get("gemini_research", "")
                breakdown = msg_result.get("breakdown", [])
                if breakdown:
                    verdicts = [
                        (
                            {"text": b.get("point", ""), "type": "general"},
                            {
                                "verdict": _ov,
                                "confidence": _oc,
                                "evidence": b.get("explanation", b.get("evidence", "")),
                                "source_urls": _src,
                                "source_tier": 3,
                            },
                        )
                        for b in breakdown
                    ]
                else:
                    verdicts = [(
                        {"text": norm[:200], "type": "general"},
                        {"verdict": _ov, "confidence": _oc,
                         "evidence": msg_result.get("overall_evidence", ""), "source_urls": _src, "source_tier": 3},
                    )]

                _step(4, 6, "Detecting psychological manipulation tactics…")
                tactics = analyse_tactics(norm)

                _step(5, 6, "Checking URLs for phishing / scam patterns…")
                url_checks = []
                for u in entities.get("urls", []):
                    url_checks.append(check_fake_url(u))

                _step(6, 6, "Building your verdict card…")
                card = generate_citizen_card(verdicts, tactics, url_checks, entities, detected_language)

                progress_bar.empty()
                status_box.empty()

            if demo:
                card = generate_citizen_card(verdicts, tactics, url_checks, entities, "English")

            # ── Persist results so the display survives chat reruns ──
            st.session_state["citizen_result"] = {
                "card": card, "verdicts": verdicts, "tactics": tactics,
                "url_checks": url_checks, "entities": entities,
                "context_data": context_data, "_research_text": _research_text,
                "sub_hash": sub_hash, "raw_text": raw_text, "claims": claims,
            }
            st.rerun()

            # ---------- Verdict Display ----------  (unreachable — rerun called above)
            st.markdown("<hr class='ls-divider'>", unsafe_allow_html=True)
            badge_color = {
                "TRUE": "linear-gradient(135deg,#2e7d32,#43a047)",
                "FALSE": "linear-gradient(135deg,#b71c1c,#e53935)",
                "FAKE": "linear-gradient(135deg,#b71c1c,#e53935)",
                "SCAM": "linear-gradient(135deg,#e65100,#ff6d00)",
                "MANIPULATED": "linear-gradient(135deg,#f57f17,#fbc02d)",
                "MIXTURE": "linear-gradient(135deg,#c88b00,#E5A100)",
            }.get(card["overall_label"], "linear-gradient(135deg,#9E9E9E,#bdbdbd)")
            overall_emoji = {
                "TRUE": "✅", "FALSE": "❌", "FAKE": "🚫",
                "SCAM": "🚨", "MANIPULATED": "⚠️", "MIXTURE": "🟡",
            }.get(card["overall_label"], "❓")
            st.markdown(f"""
            <div style='text-align:center; padding: 0.5rem 0 1rem;'>
                <div class="overall-badge" style="background:{badge_color};">
                    {overall_emoji}&nbsp; {card['overall_label']}
                </div>
            </div>
            """, unsafe_allow_html=True)

            # ---------- Metadata & CTA Scrutiny ----------
            if context_data and (context_data.get("ctas") or context_data.get("metadata", {}).get("locations")):
                with st.expander("🔍 Deep Inspection — Locations, Dates & CTAs"):
                    cols = st.columns(2)
                    with cols[0]:
                        st.markdown("**📍 Locations & Dates mentioned**")
                        for loc in context_data.get("metadata", {}).get("locations", []):
                            st.write(f"- {loc}")
                        for dt in context_data.get("metadata", {}).get("dates", []):
                            st.write(f"- 🗓️ {dt}")
                    with cols[1]:
                        st.markdown("**🔗 Call-to-Action links detected**")
                        for cta in context_data.get("ctas", []):
                            st.write(f"- {cta['text']} `({cta['type']})`")

            # ---------- Individual Claim Verdicts ----------
            if _research_text:
                st.markdown("<div class='ls-section-header'><div class='icon-box'>🔍</div><span>What We Found</span></div>", unsafe_allow_html=True)
                st.info(_research_text)

            st.markdown("<div class='ls-section-header'><div class='icon-box'>📋</div><span>Claim Breakdown</span></div>", unsafe_allow_html=True)
            for item in card["verdicts"]:
                label = item["label"]
                emoji = "✅" if label == "TRUE" else "❌" if label in ("FALSE","FAKE") else "🚨" if label == "SCAM" else "⚠️" if label == "MANIPULATED" else "🟡"
                conf = item.get("confidence", 0)
                conf_color = "#4CAF50" if conf > 70 else "#FF9800" if conf > 40 else "#f44336"
                badge_cls = f"badge-{label.lower()}"
                st.markdown(f"""
                <div class="verdict-card">
                    <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:8px;">
                        <span class="severity-badge {badge_cls}">{emoji} {label}</span>
                        <span style="font-size:0.78rem; color:#7a7268; font-weight:600;">Confidence {conf}%</span>
                    </div>
                    <div class="risk-gauge"><div class="risk-fill" style="width:{conf}%; background:linear-gradient(90deg,{conf_color},{conf_color}cc);"></div></div>
                    <p style="margin:10px 0 4px; font-weight:600; font-size:0.92rem;">{item['claim'][:180]}</p>
                    <p style="margin:0; color:#7a7268; font-size:0.85rem; line-height:1.5;">{item["evidence"]}</p>
                </div>
                """, unsafe_allow_html=True)

            # ---------- URL Danger Warnings ----------
            for uw in card["url_warnings"]:
                flags_html = " ".join(
                    f"<span style='background:#fde0e0;color:#9c1f1f;padding:2px 9px;border-radius:20px;font-size:0.72rem;font-weight:600;'>⚠️ {flag}</span>"
                    for flag in uw.get("flags", [])
                )
                risk_pct = min(100, uw.get("risk_score", 0))
                st.markdown(f"""
                <div class="tactic-card" style="border-left:4px solid #e53935;">
                    <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
                        <span style="font-size:1.4rem;">🚨</span>
                        <div>
                            <strong style="font-size:0.95rem;">Dangerous Link — Risk {risk_pct}/100</strong><br>
                            <span style="font-size:0.8rem;color:#7a7268;">Real site: <strong>{uw['url']}</strong></span>
                        </div>
                    </div>
                    <div class="risk-gauge"><div class="risk-fill" style="width:{risk_pct}%;background:linear-gradient(90deg,#e53935,#ff6d00);"></div></div>
                    <div style="margin:10px 0 6px;">{flags_html}</div>
                    <p style="margin:6px 0 3px;font-size:0.88rem;">🔍 {uw.get('why_dangerous','')}</p>
                    <p style="margin:0;font-size:0.85rem;color:#7a7268;">⚠️ {uw.get('what_can_happen','')}</p>
                </div>
                """, unsafe_allow_html=True)

            # ---------- Community Alert ----------
            try:
                from data.db import get_heatmap_data
                h_data = get_heatmap_data()
                city_count = sum(1 for row in h_data if row["city"] == user_location and row["verdict"] in ["FAKE", "SCAM", "FALSE", "MANIPULATED"])
                if city_count > 0:
                    st.warning(f"📍 **Community Alert:** {city_count} similar scams reported in **{user_location}** recently. Stay vigilant!")
            except:
                pass

            # ---------- Manipulation Tactics ----------
            if card["tactics"]:
                st.markdown("<div class='ls-section-header'><div class='icon-box'>🎭</div><span>How You're Being Manipulated</span></div>", unsafe_allow_html=True)
                for t in card["tactics"]:
                    st.markdown(f"""
                    <div class="tactic-card">
                        <strong style="font-size:0.9rem;">🎭 {t['tactic']}</strong>
                        <p style="margin:6px 0 0; color:#7a7268; font-size:0.87rem; line-height:1.5;">{t['explanation']}</p>
                    </div>
                    """, unsafe_allow_html=True)

            # ---------- AI Narrative Attribution (fingerprinting) ----------
            if card["overall_label"] in ("FALSE", "FAKE", "SCAM", "MANIPULATED", "MIXTURE"):
                st.markdown("<div class='ls-section-header'><div class='icon-box'>🧬</div><span>Narrative Fingerprint — Which Campaign Is This?</span></div>", unsafe_allow_html=True)
                _narr_key = f"narrative_cluster_{sub_hash}"
                if _narr_key not in st.session_state:
                    with st.spinner("🧠 Matching against known disinformation campaigns…"):
                        from agents.narrator import identify_narrative_cluster
                        _ev_sum = verdicts[0][1].get("evidence", "") if verdicts else ""
                        st.session_state[_narr_key] = identify_narrative_cluster(
                            raw_text, card["overall_label"], _ev_sum
                        )
                nc = st.session_state[_narr_key]
                _nc_conf_color = {"High": "#b71c1c", "Medium": "#e65100", "Low": "#4CAF50"}.get(nc.get("confidence", "Low"), "#9E9E9E")
                _tactics_html = " ".join(
                    f"<span style='background:#fff0c2;color:#7a5500;padding:2px 10px;border-radius:20px;font-size:0.72rem;font-weight:600;'>{t}</span>"
                    for t in nc.get("tactics_used", [])
                )
                _geo_html = ", ".join(f"🌍 {g}" for g in nc.get("geographic_spread", []))
                st.markdown(f"""
                <div class="tactic-card" style="border-left:4px solid {_nc_conf_color};">
                    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
                        <strong style="font-size:1rem;color:#1a1714;">🧬 {nc.get('cluster_name','Unknown Cluster')}</strong>
                        <span style="font-size:0.75rem;font-weight:700;color:{_nc_conf_color};background:{_nc_conf_color}18;
                                     padding:3px 12px;border-radius:20px;">{nc.get('confidence','?')} Confidence Match</span>
                    </div>
                    <p style="margin:0 0 8px;font-size:0.88rem;color:#4a4540;line-height:1.6;">{nc.get('description','')}</p>
                    <div style="display:flex;gap:20px;font-size:0.82rem;color:#7a7268;margin-bottom:8px;flex-wrap:wrap;">
                        <span>📊 Seen ~<strong style="color:{_nc_conf_color};">{nc.get('similar_count',0)}</strong> times</span>
                        <span>🗓️ First seen: <strong>{nc.get('first_seen','?')}</strong></span>
                        <span>{_geo_html}</span>
                    </div>
                    <div style="margin-bottom:6px;">{_tactics_html}</div>
                    <p style="margin:4px 0 0;font-size:0.82rem;color:#9c1f1f;">⚠️ {nc.get('why_dangerous','')}</p>
                </div>
                """, unsafe_allow_html=True)
            st.markdown("<div class='ls-section-header'><div class='icon-box'>📤</div><span>Share This Correction</span></div>", unsafe_allow_html=True)
            st.caption("Copy and forward this fact-checked reply to whoever sent you this message:")
            st.code(card["whatsapp_reply"], language="text")

            # ---------- Action Guide ----------
            st.info(f"💡 **What to do:** {card['action_guide']}")

            # ---------- Multilingual Explainer Bot ----------
            st.markdown("<div class='ls-section-header'><div class='icon-box'>💬</div><span>Ask Lumina — Follow-Up Questions</span></div>", unsafe_allow_html=True)
            st.caption('Ask anything: "Why is this fake?", "What should I tell my parents?", "Is there any truth in it?" — answered in plain language.')

            _chat_key = f"explainer_chat_{sub_hash}"
            _ctx_key   = f"explainer_ctx_{sub_hash}"
            if _chat_key not in st.session_state:
                st.session_state[_chat_key] = []
            if _ctx_key not in st.session_state:
                _ev_ctx = verdicts[0][1].get("evidence", "") if verdicts else ""
                st.session_state[_ctx_key] = (
                    f"You are Lumina Shield, a friendly AI fact-checker. "
                    f"The user just had a message verified. "
                    f"Verdict: {card['overall_label']} (confidence {verdicts[0][1].get('confidence',75) if verdicts else '?'}%). "
                    f"Key evidence: {_ev_ctx[:400]}. "
                    f"Original message snippet: {raw_text[:300]}. "
                    f"Answer follow-up questions in simple, friendly language. "
                    f"If the user writes in Urdu or Roman Urdu, reply in Roman Urdu. "
                    f"Keep answers under 4 sentences."
                )

            # Render chat history
            for _msg in st.session_state[_chat_key]:
                with st.chat_message(_msg["role"]):
                    st.markdown(_msg["content"])

            if _user_q := st.chat_input("Ask a follow-up question…", key=f"chat_input_{sub_hash}"):
                st.session_state[_chat_key].append({"role": "user", "content": _user_q})
                with st.chat_message("user"):
                    st.markdown(_user_q)

                with st.chat_message("assistant"):
                    _placeholder = st.empty()
                    _full_resp = ""
                    try:
                        import groq as _groq_sdk
                        _groq_client = _groq_sdk.Groq(api_key=os.getenv("GROQ_API_KEY"), max_retries=0, timeout=20.0)
                        _messages = [{"role": "system", "content": st.session_state[_ctx_key]}]
                        for _m in st.session_state[_chat_key][-8:]:   # keep last 8 turns
                            _messages.append({"role": _m["role"], "content": _m["content"]})
                        _stream = _groq_client.chat.completions.create(
                            model="llama-3.1-8b-instant",
                            messages=_messages,
                            stream=True,
                            max_tokens=400,
                            temperature=0.6,
                        )
                        for _chunk in _stream:
                            _delta = (_chunk.choices[0].delta.content or "")
                            _full_resp += _delta
                            _placeholder.markdown(_full_resp + "▌")
                        _placeholder.markdown(_full_resp)
                    except Exception as _ce:
                        _full_resp = f"Sorry, I couldn't respond right now: {_ce}"
                        _placeholder.markdown(_full_resp)
                    st.session_state[_chat_key].append({"role": "assistant", "content": _full_resp})

            # ---------- Reporting Buttons ----------
            st.markdown("<div class='ls-section-header'><div class='icon-box'>📞</div><span>Report This to Authorities</span></div>", unsafe_allow_html=True)
            col1, col2, col3, col4 = st.columns(4)
            with col1: st.link_button("🚨 FIA Cybercrime", "https://complaint.fia.gov.pk")
            with col2: st.link_button("📡 PTA Complaint", "https://pta.gov.pk/en/consumer-support/complaints")
            with col3: st.link_button("🏦 SECP Fraud", "https://www.secp.gov.pk/complaint/")
            with col4: st.link_button("🛡️ NCERT", "https://ncart.gov.pk/report/")

            # ---------- Shareable Verdict Card (PNG) ----------
            st.markdown("<div class='ls-section-header'><div class='icon-box'>🖼️</div><span>Shareable Verdict Card</span></div>", unsafe_allow_html=True)
            st.caption("Download a beautiful PNG card to share on WhatsApp, Twitter/X, or any social platform.")
            _top_claim_text = verdicts[0][0].get("text", "") if verdicts else raw_text[:120]
            _top_evidence   = verdicts[0][1].get("evidence", "") if verdicts else ""
            try:
                from utils.report_generator import generate_verdict_card_png
                _card_png = generate_verdict_card_png(
                    verdict_label=card["overall_label"],
                    confidence=verdicts[0][1].get("confidence", 75) if verdicts else 75,
                    claim_snippet=_top_claim_text,
                    evidence_snippet=_top_evidence,
                    report_url="https://luminashield.app",
                )
                _png_col1, _png_col2 = st.columns([0.5, 0.5])
                with _png_col1:
                    st.image(_card_png, caption="Preview — right-click to copy", width='stretch')
                with _png_col2:
                    st.download_button(
                        "⬇️ Download Verdict Card (PNG)",
                        data=_card_png,
                        file_name=f"lumina_verdict_{card['overall_label'].lower()}.png",
                        mime="image/png",
                        width='stretch',
                    )
                    st.caption("Share this card on WhatsApp, Twitter/X, or Instagram Stories to spread awareness and protect others.")
            except Exception as _e:
                st.info(f"Card generation unavailable: {_e}")

            # ---------- Opt-in Community Reporting ----------
            st.markdown("<hr class='ls-divider'>", unsafe_allow_html=True)
            st.markdown("<div class='ls-section-header'><div class='icon-box'>🌍</div><span>Help Others — Report to Community</span></div>", unsafe_allow_html=True)

            _rpt_col1, _rpt_col2 = st.columns([0.55, 0.45])
            with _rpt_col1:
                share_consent = st.checkbox(
                    "📢 Share this verdict anonymously with the community map",
                    value=False, key="share_consent",
                    help="Adds this report to the Global Dashboard heatmap and feed so others in your city can be warned."
                )
            with _rpt_col2:
                # Dynamic city — pre-select user_location chosen at top
                _cities = get_all_city_names()
                report_city = st.selectbox(
                    "📍 Report city",
                    _cities,
                    index=_cities.index(user_location) if user_location in _cities else 0,
                    key="report_city",
                    help="Which city should this report be attributed to on the heatmap?"
                )

            if share_consent:
                if st.button("📤 Submit Community Report", key="submit_report_btn"):
                    sub_id = log_submission(raw_text, "Citizen", "app")
                    for idx, (_, v) in enumerate(verdicts):
                        log_verdict(sub_id, idx, v["verdict"], v.get("confidence", 0),
                                    v.get("evidence", ""),
                                    json.dumps([t["tactic"] for t in tactics]))
                    _cat = claims[0].get("type", "general") if claims else "general"
                    _verdict_val = verdicts[0][1]["verdict"] if verdicts else card["overall_label"]
                    log_heatmap(report_city, _cat, _verdict_val)
                    if card["overall_label"] in ["FAKE", "SCAM", "FALSE", "MANIPULATED"]:
                        if not check_feed_duplicate(raw_text[:100]):
                            log_to_feed(sub_id, card["overall_label"], raw_text[:100] + "…")
                    st.success(f"✅ Reported anonymously from **{report_city}**. Thank you for protecting others!")
            else:
                st.caption("Your analysis is private by default. Tick the checkbox above to contribute to the community map.")

    # ---- Render citizen results (persists across chat reruns) ----
    if "citizen_result" in st.session_state:
        _cr = st.session_state["citizen_result"]
        card           = _cr["card"]
        verdicts       = _cr["verdicts"]
        tactics        = _cr["tactics"]
        url_checks     = _cr["url_checks"]
        entities       = _cr["entities"]
        context_data   = _cr["context_data"]
        _research_text = _cr["_research_text"]
        sub_hash       = _cr["sub_hash"]
        raw_text       = _cr["raw_text"]
        claims         = _cr["claims"]

        # ---------- Verdict Display ----------
        st.markdown("<hr class='ls-divider'>", unsafe_allow_html=True)
        badge_color = {
            "TRUE": "linear-gradient(135deg,#2e7d32,#43a047)",
            "FALSE": "linear-gradient(135deg,#b71c1c,#e53935)",
            "FAKE": "linear-gradient(135deg,#b71c1c,#e53935)",
            "SCAM": "linear-gradient(135deg,#e65100,#ff6d00)",
            "MANIPULATED": "linear-gradient(135deg,#f57f17,#fbc02d)",
            "MIXTURE": "linear-gradient(135deg,#c88b00,#E5A100)",
        }.get(card["overall_label"], "linear-gradient(135deg,#9E9E9E,#bdbdbd)")
        overall_emoji = {
            "TRUE": "✅", "FALSE": "❌", "FAKE": "🚫",
            "SCAM": "🚨", "MANIPULATED": "⚠️", "MIXTURE": "🟡",
        }.get(card["overall_label"], "❓")
        st.markdown(f"""
        <div style='text-align:center; padding: 0.5rem 0 1rem;'>
            <div class="overall-badge" style="background:{badge_color};">
                {overall_emoji}&nbsp; {card['overall_label']}
            </div>
        </div>
        """, unsafe_allow_html=True)

        # ---------- Metadata & CTA Scrutiny ----------
        if context_data and (context_data.get("ctas") or context_data.get("metadata", {}).get("locations")):
            with st.expander("🔍 Deep Inspection — Locations, Dates & CTAs"):
                cols = st.columns(2)
                with cols[0]:
                    st.markdown("**📍 Locations & Dates mentioned**")
                    for loc in context_data.get("metadata", {}).get("locations", []):
                        st.write(f"- {loc}")
                    for dt in context_data.get("metadata", {}).get("dates", []):
                        st.write(f"- 🗓️ {dt}")
                with cols[1]:
                    st.markdown("**🔗 Call-to-Action links detected**")
                    for cta in context_data.get("ctas", []):
                        st.write(f"- {cta['text']} `({cta['type']})`")

        # ---------- Individual Claim Verdicts ----------
        if _research_text:
            st.markdown("<div class='ls-section-header'><div class='icon-box'>🔍</div><span>What We Found</span></div>", unsafe_allow_html=True)
            st.info(_research_text)

        st.markdown("<div class='ls-section-header'><div class='icon-box'>📋</div><span>Claim Breakdown</span></div>", unsafe_allow_html=True)
        for item in card["verdicts"]:
            label = item["label"]
            emoji = "✅" if label == "TRUE" else "❌" if label in ("FALSE","FAKE") else "🚨" if label == "SCAM" else "⚠️" if label == "MANIPULATED" else "🟡"
            conf = item.get("confidence", 0)
            conf_color = "#4CAF50" if conf > 70 else "#FF9800" if conf > 40 else "#f44336"
            badge_cls = f"badge-{label.lower()}"
            st.markdown(f"""
            <div class="verdict-card">
                <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:8px;">
                    <span class="severity-badge {badge_cls}">{emoji} {label}</span>
                    <span style="font-size:0.78rem; color:#7a7268; font-weight:600;">Confidence {conf}%</span>
                </div>
                <div class="risk-gauge"><div class="risk-fill" style="width:{conf}%; background:linear-gradient(90deg,{conf_color},{conf_color}cc);"></div></div>
                <p style="margin:10px 0 4px; font-weight:600; font-size:0.92rem;">{item['claim'][:180]}</p>
                <p style="margin:0; color:#7a7268; font-size:0.85rem; line-height:1.5;">{item["evidence"]}</p>
            </div>
            """, unsafe_allow_html=True)

        # ---------- URL Danger Warnings ----------
        for uw in card["url_warnings"]:
            flags_html = " ".join(
                f"<span style='background:#fde0e0;color:#9c1f1f;padding:2px 9px;border-radius:20px;font-size:0.72rem;font-weight:600;'>⚠️ {flag}</span>"
                for flag in uw.get("flags", [])
            )
            risk_pct = min(100, uw.get("risk_score", 0))
            st.markdown(f"""
            <div class="tactic-card" style="border-left:4px solid #e53935;">
                <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
                    <span style="font-size:1.4rem;">🚨</span>
                    <div>
                        <strong style="font-size:0.95rem;">Dangerous Link — Risk {risk_pct}/100</strong><br>
                        <span style="font-size:0.8rem;color:#7a7268;">Real site: <strong>{uw['url']}</strong></span>
                    </div>
                </div>
                <div class="risk-gauge"><div class="risk-fill" style="width:{risk_pct}%;background:linear-gradient(90deg,#e53935,#ff6d00);"></div></div>
                <div style="margin:10px 0 6px;">{flags_html}</div>
                <p style="margin:6px 0 3px;font-size:0.88rem;">🔍 {uw.get('why_dangerous','')}</p>
                <p style="margin:0;font-size:0.85rem;color:#7a7268;">⚠️ {uw.get('what_can_happen','')}</p>
            </div>
            """, unsafe_allow_html=True)

        # ---------- Community Alert ----------
        try:
            from data.db import get_heatmap_data
            h_data = get_heatmap_data()
            city_count = sum(1 for row in h_data if row["city"] == user_location and row["verdict"] in ["FAKE", "SCAM", "FALSE", "MANIPULATED"])
            if city_count > 0:
                st.warning(f"📍 **Community Alert:** {city_count} similar scams reported in **{user_location}** recently. Stay vigilant!")
        except:
            pass

        # ---------- Manipulation Tactics ----------
        if card["tactics"]:
            st.markdown("<div class='ls-section-header'><div class='icon-box'>🎭</div><span>How You're Being Manipulated</span></div>", unsafe_allow_html=True)
            for t in card["tactics"]:
                st.markdown(f"""
                <div class="tactic-card">
                    <strong style="font-size:0.9rem;">🎭 {t['tactic']}</strong>
                    <p style="margin:6px 0 0; color:#7a7268; font-size:0.87rem; line-height:1.5;">{t['explanation']}</p>
                </div>
                """, unsafe_allow_html=True)

        # ---------- AI Narrative Attribution (fingerprinting) ----------
        if card["overall_label"] in ("FALSE", "FAKE", "SCAM", "MANIPULATED", "MIXTURE"):
            st.markdown("<div class='ls-section-header'><div class='icon-box'>🧬</div><span>Narrative Fingerprint — Which Campaign Is This?</span></div>", unsafe_allow_html=True)
            _narr_key = f"narrative_cluster_{sub_hash}"
            if _narr_key not in st.session_state:
                with st.spinner("🧠 Matching against known disinformation campaigns…"):
                    from agents.narrator import identify_narrative_cluster
                    _ev_sum = verdicts[0][1].get("evidence", "") if verdicts else ""
                    st.session_state[_narr_key] = identify_narrative_cluster(
                        raw_text, card["overall_label"], _ev_sum
                    )
            nc = st.session_state[_narr_key]
            _nc_conf_color = {"High": "#b71c1c", "Medium": "#e65100", "Low": "#4CAF50"}.get(nc.get("confidence", "Low"), "#9E9E9E")
            _tactics_html = " ".join(
                f"<span style='background:#fff0c2;color:#7a5500;padding:2px 10px;border-radius:20px;font-size:0.72rem;font-weight:600;'>{t}</span>"
                for t in nc.get("tactics_used", [])
            )
            _geo_html = ", ".join(f"🌍 {g}" for g in nc.get("geographic_spread", []))
            st.markdown(f"""
            <div class="tactic-card" style="border-left:4px solid {_nc_conf_color};">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
                    <strong style="font-size:1rem;color:#1a1714;">🧬 {nc.get('cluster_name','Unknown Cluster')}</strong>
                    <span style="font-size:0.75rem;font-weight:700;color:{_nc_conf_color};background:{_nc_conf_color}18;
                                 padding:3px 12px;border-radius:20px;">{nc.get('confidence','?')} Confidence Match</span>
                </div>
                <p style="margin:0 0 8px;font-size:0.88rem;color:#4a4540;line-height:1.6;">{nc.get('description','')}</p>
                <div style="display:flex;gap:20px;font-size:0.82rem;color:#7a7268;margin-bottom:8px;flex-wrap:wrap;">
                    <span>📊 Seen ~<strong style="color:{_nc_conf_color};">{nc.get('similar_count',0)}</strong> times</span>
                    <span>🗓️ First seen: <strong>{nc.get('first_seen','?')}</strong></span>
                    <span>{_geo_html}</span>
                </div>
                <div style="margin-bottom:6px;">{_tactics_html}</div>
                <p style="margin:4px 0 0;font-size:0.82rem;color:#9c1f1f;">⚠️ {nc.get('why_dangerous','')}</p>
            </div>
            """, unsafe_allow_html=True)
        st.markdown("<div class='ls-section-header'><div class='icon-box'>📤</div><span>Share This Correction</span></div>", unsafe_allow_html=True)
        st.caption("Copy and forward this fact-checked reply to whoever sent you this message:")
        st.code(card["whatsapp_reply"], language="text")

        # ---------- Action Guide ----------
        st.info(f"💡 **What to do:** {card['action_guide']}")

        # ---------- Multilingual Explainer Bot ----------
        st.markdown("<div class='ls-section-header'><div class='icon-box'>💬</div><span>Ask Lumina — Follow-Up Questions</span></div>", unsafe_allow_html=True)
        st.caption('Ask anything: "Why is this fake?", "What should I tell my parents?", "Is there any truth in it?" — answered in plain language.')

        _chat_key = f"explainer_chat_{sub_hash}"
        _ctx_key   = f"explainer_ctx_{sub_hash}"
        if _chat_key not in st.session_state:
            st.session_state[_chat_key] = []
        if _ctx_key not in st.session_state:
            _ev_ctx = verdicts[0][1].get("evidence", "") if verdicts else ""
            st.session_state[_ctx_key] = (
                f"You are Lumina Shield, a friendly AI fact-checker. "
                f"The user just had a message verified. "
                f"Verdict: {card['overall_label']} (confidence {verdicts[0][1].get('confidence',75) if verdicts else '?'}%). "
                f"Key evidence: {_ev_ctx[:400]}. "
                f"Original message snippet: {raw_text[:300]}. "
                f"Answer follow-up questions in simple, friendly language. "
                f"If the user writes in Urdu, Roman Urdu, reply in Roman Urdu or in the same language as of the original message else in english"
                f"Keep answers under 4 sentences."
            )

        # Render chat history
        for _msg in st.session_state[_chat_key]:
            with st.chat_message(_msg["role"]):
                st.markdown(_msg["content"])

        if _user_q := st.chat_input("Ask a follow-up question…", key=f"chat_input_{sub_hash}"):
            st.session_state[_chat_key].append({"role": "user", "content": _user_q})
            with st.chat_message("user"):
                st.markdown(_user_q)

            with st.chat_message("assistant"):
                _placeholder = st.empty()
                _full_resp = ""
                try:
                    import groq as _groq_sdk
                    _groq_client = _groq_sdk.Groq(api_key=os.getenv("GROQ_API_KEY"), max_retries=0, timeout=20.0)
                    _messages = [{"role": "system", "content": st.session_state[_ctx_key]}]
                    for _m in st.session_state[_chat_key][-8:]:   # keep last 8 turns
                        _messages.append({"role": _m["role"], "content": _m["content"]})
                    _stream = _groq_client.chat.completions.create(
                        model="llama-3.1-8b-instant",
                        messages=_messages,
                        stream=True,
                        max_tokens=400,
                        temperature=0.6,
                    )
                    for _chunk in _stream:
                        _delta = (_chunk.choices[0].delta.content or "")
                        _full_resp += _delta
                        _placeholder.markdown(_full_resp + "▌")
                    _placeholder.markdown(_full_resp)
                except Exception as _ce:
                    _full_resp = f"Sorry, I couldn't respond right now: {_ce}"
                    _placeholder.markdown(_full_resp)
                st.session_state[_chat_key].append({"role": "assistant", "content": _full_resp})

        # ---------- Reporting Buttons ----------
        st.markdown("<div class='ls-section-header'><div class='icon-box'>📞</div><span>Report This to Authorities</span></div>", unsafe_allow_html=True)
        col1, col2, col3, col4 = st.columns(4)
        with col1: st.link_button("🚨 FIA Cybercrime", "https://complaint.fia.gov.pk")
        with col2: st.link_button("📡 PTA Complaint", "https://pta.gov.pk/en/consumer-support/complaints")
        with col3: st.link_button("🏦 SECP Fraud", "https://www.secp.gov.pk/complaint/")
        with col4: st.link_button("🛡️ NCERT", "https://ncart.gov.pk/report/")

        # ---------- Shareable Verdict Card (PNG) ----------
        st.markdown("<div class='ls-section-header'><div class='icon-box'>🖼️</div><span>Shareable Verdict Card</span></div>", unsafe_allow_html=True)
        st.caption("Download a beautiful PNG card to share on WhatsApp, Twitter/X, or any social platform.")
        _top_claim_text = verdicts[0][0].get("text", "") if verdicts else raw_text[:120]
        _top_evidence   = verdicts[0][1].get("evidence", "") if verdicts else ""
        try:
            from utils.report_generator import generate_verdict_card_png
            _card_png = generate_verdict_card_png(
                verdict_label=card["overall_label"],
                confidence=verdicts[0][1].get("confidence", 75) if verdicts else 75,
                claim_snippet=_top_claim_text,
                evidence_snippet=_top_evidence,
                report_url="https://luminashield.app",
            )
            _png_col1, _png_col2 = st.columns([0.5, 0.5])
            with _png_col1:
                st.image(_card_png, caption="Preview — right-click to copy", width='stretch')
            with _png_col2:
                st.download_button(
                    "⬇️ Download Verdict Card (PNG)",
                    data=_card_png,
                    file_name=f"lumina_verdict_{card['overall_label'].lower()}.png",
                    mime="image/png",
                    width='stretch',
                )
                st.caption("Share this card on WhatsApp, Twitter/X, or Instagram Stories to spread awareness and protect others.")
        except Exception as _e:
            st.info(f"Card generation unavailable: {_e}")

        # ---------- Opt-in Community Reporting ----------
        st.markdown("<hr class='ls-divider'>", unsafe_allow_html=True)
        st.markdown("<div class='ls-section-header'><div class='icon-box'>🌍</div><span>Help Others — Report to Community</span></div>", unsafe_allow_html=True)

        _rpt_col1, _rpt_col2 = st.columns([0.55, 0.45])
        with _rpt_col1:
            share_consent = st.checkbox(
                "📢 Share this verdict anonymously with the community map",
                value=False, key="share_consent",
                help="Adds this report to the Global Dashboard heatmap and feed so others in your city can be warned."
            )
        with _rpt_col2:
            # Dynamic city — pre-select user_location chosen at top
            _cities = get_all_city_names()
            report_city = st.selectbox(
                "📍 Report city",
                _cities,
                index=_cities.index(user_location) if user_location in _cities else 0,
                key="report_city",
                help="Which city should this report be attributed to on the heatmap?"
            )

        if share_consent:
            if st.button("📤 Submit Community Report", key="submit_report_btn"):
                sub_id = log_submission(raw_text, "Citizen", "app")
                for idx, (_, v) in enumerate(verdicts):
                    log_verdict(sub_id, idx, v["verdict"], v.get("confidence", 0),
                                v.get("evidence", ""),
                                json.dumps([t["tactic"] for t in tactics]))
                _cat = claims[0].get("type", "general") if claims else "general"
                _verdict_val = verdicts[0][1]["verdict"] if verdicts else card["overall_label"]
                log_heatmap(report_city, _cat, _verdict_val)
                if card["overall_label"] in ["FAKE", "SCAM", "FALSE", "MANIPULATED"]:
                    if not check_feed_duplicate(raw_text[:100]):
                        log_to_feed(sub_id, card["overall_label"], raw_text[:100] + "…")
                st.success(f"✅ Reported anonymously from **{report_city}**. Thank you for protecting others!")
        else:
            st.caption("Your analysis is private by default. Tick the checkbox above to contribute to the community map.")

# ===============================
# TAB 2: CYBER ANALYST
# ===============================
with tab2:
    st.markdown("""
    <div class='info-card'>
        <div class='ls-section-header' style='margin:0 0 0.3rem;'>
            <div class='icon-box'>🔬</div>
            <span>Cyber Analyst — Deep Forensics & Threat Intelligence</span>
        </div>
        <p style='margin:0; color:#7a7268; font-size:0.88rem;'>
            Submit any URL, domain, IP address, or file hash for multi-engine enrichment:
            VirusTotal, AbuseIPDB, WHOIS, Shodan, BGP, passive DNS, SSL analysis, and AI threat profiling.
        </p>
    </div>
    """, unsafe_allow_html=True)
    url = st.text_input("🎯 Target — URL, domain, IP, or file hash", key="cyber_input",
                        placeholder="e.g. malware-site.ru · 192.168.1.1 · d41d8cd98f00b204e9800998ecf8427e")
    cyber_target = normalize_investigation_input(url, {"url", "domain", "ip", "hash"}) if url.strip() else None
    if cyber_target and cyber_target["extracted"]:
        st.info(cyber_target["message"])

    if st.button("🔍 Run Investigation", key="cyber_btn"):
        if not url.strip():
            st.warning("⚠️ Please enter a URL, domain, IP, or file hash first.")
        elif not cyber_target or not cyber_target["value"]:
            st.warning(cyber_target["message"] if cyber_target else "No valid target found.")
        else:
            target_value = cyber_target["value"]
            target_kind = cyber_target["kind"]

            _progress = st.progress(0, text="Initializing threat scan…")
            _status = st.empty()
            _steps_ca = [
                "Initializing multi-engine threat scan",
                "Querying global threat intelligence",
                "Cross-referencing reputation databases",
                "Mapping network topology & IP data",
                "Enriching with network intelligence",
                "Gathering passive DNS & subdomain data",
                "Running AI-powered forensic analysis",
            ]
            def _ca_step(n, total=7, label=""):
                step_idx = min(n, len(_steps_ca) - 1)
                frac = min(1.0, n / len(_steps_ca))
                _progress.progress(frac, text=_steps_ca[step_idx])
                items = "".join([
                    "<li class='ls-step done'>✅ " + s + "</li>" if i < n
                    else "<li class='ls-step running'>⏳ " + s + "</li>" if i == n
                    else "<li class='ls-step pending'>○ " + s + "</li>"
                    for i, s in enumerate(_steps_ca)
                ])
                _status.markdown("<div class='info-card' style='padding:0.9rem 1.2rem;margin:0;'><ul class='ls-steps'>" + items + "</ul></div>", unsafe_allow_html=True)

            _ca_step(0)
            if st.session_state.get('demo_mode'):
                result = get_mock_threat_result(target_value)
                _ca_step(len(_steps_ca))
            else:
                result = investigate_threat_cached(
                    file_hash=target_value if target_kind == "hash" else None,
                    url=target_value if target_kind != "hash" else None,
                    progress_callback=_ca_step,
                )
            _progress.empty()
            _status.empty()

            if result.get("_from_cache"):
                st.toast("⚡ Result loaded from disk cache (12h TTL)", icon="💾")
            st.session_state.cyber_result = result
            st.session_state.cyber_target = target_value

            try:
                from data.db import log_ioc
                sub_id = log_submission(target_value, "Cyber", "app")
                for ip in result.get("ips", []):
                    log_ioc(sub_id, "IP", ip)
                for d in result.get("domains", []):
                    log_ioc(sub_id, "Domain", d)
            except Exception:
                pass

    # ---- Display results if we have them ----
    if "cyber_result" in st.session_state:
        result = st.session_state.cyber_result
        current_target = st.session_state.get("cyber_target", url)
        from datetime import datetime
        import concurrent.futures as _cf
        from agents.threat_investigator import generate_threat_summary, generate_narrative_intelligence

        # ===== RISK SCORE + AI SUMMARY TOP ROW =====
        risk = result.get("risk_score", 0)
        severity = "LOW" if risk < 3 else "MEDIUM" if risk < 6 else "HIGH" if risk < 8 else "CRITICAL"
        sev_emoji = "🟢" if risk < 3 else "🟡" if risk < 6 else "🔴" if risk < 8 else "🚨"
        risk_color = "#4CAF50" if risk < 3 else "#FF9800" if risk < 6 else "#f44336" if risk < 8 else "#b71c1c"
        risk_pct = risk * 10

        # AI summary/narrative — cached per target so the spinner doesn't fire on every re-render
        _ai_cache_key = f"cyber_ai_{current_target}"
        if _ai_cache_key not in st.session_state:
            with st.spinner("🔬 Finalising threat analysis…"):
                with _cf.ThreadPoolExecutor(max_workers=2) as _ai_ex:
                    _fut_summary   = _ai_ex.submit(generate_threat_summary,         current_target, result)
                    _fut_narrative = _ai_ex.submit(generate_narrative_intelligence,  current_target, result)
                    st.session_state[_ai_cache_key] = {
                        "summary":   _fut_summary.result(),
                        "narrative": _fut_narrative.result(),
                    }
        summary_text   = st.session_state[_ai_cache_key]["summary"]
        narrative_data = st.session_state[_ai_cache_key]["narrative"]

        # Convert AI markdown bold (**text**) and newlines to HTML so they render correctly
        def _md_to_html(text: str) -> str:
            import re as _re
            text = _re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
            text = text.replace('\n', '<br>')
            return text

        c_risk, c_summary = st.columns([0.35, 0.65])
        with c_risk:
            # Confidence interval from narrative (if available)
            ci_low  = narrative_data.get("risk_confidence_low",  round(max(0, risk - 1.0), 1)) if narrative_data else round(max(0, risk - 1.0), 1)
            ci_high = narrative_data.get("risk_confidence_high", round(min(10, risk + 1.0), 1)) if narrative_data else round(min(10, risk + 1.0), 1)
            st.markdown(f"""
            <div class='verdict-card' style='text-align:center; border-left:4px solid {risk_color};'>
                <div style='font-size:0.78rem;font-weight:600;color:#7a7268;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;'>Risk Score</div>
                <div style='font-size:3rem;font-weight:900;color:{risk_color};line-height:1;'>{risk}<span style='font-size:1.2rem;color:#b0a99c;'>/10</span></div>
                <div style='font-size:1rem;font-weight:700;color:{risk_color};margin:4px 0 6px;'>{sev_emoji} {severity}</div>
                <div class='risk-gauge'><div class='risk-fill' style='width:{risk_pct}%;background:{risk_color};'></div></div>
                <div style='font-size:0.74rem;color:#a09585;margin-top:8px;font-weight:600;'>
                    Confidence range: <span style='color:{risk_color};'>{ci_low}–{ci_high}</span>/10
                </div>
            </div>
            """, unsafe_allow_html=True)

        with c_summary:
            st.markdown("<div class='ls-section-header'><div class='icon-box'>🤖</div><span>AI Executive Summary</span></div>", unsafe_allow_html=True)
            st.markdown(f"<div class='info-card' style='margin-top:0;'><p style='margin:0;line-height:1.65;font-size:0.9rem;'>{_md_to_html(summary_text)}</p></div>", unsafe_allow_html=True)

        # ===== NARRATIVE INTELLIGENCE SCORE =====
        if narrative_data and not narrative_data.get("error") and narrative_data.get("scenarios"):
            st.markdown("<div class='ls-section-header'><div class='icon-box'>🧠</div><span>Narrative Intelligence Score</span></div>", unsafe_allow_html=True)

            scenarios = narrative_data.get("scenarios", [])
            top_scenario = scenarios[0] if scenarios else {}
            top_prob = top_scenario.get("probability", 0)
            archetype = narrative_data.get("campaign_archetype", "Unknown")
            target_profile = narrative_data.get("target_profile", "Unknown")
            narrative_text = narrative_data.get("narrative", "")

            # Headline narrative banner
            arch_color = (
                "#b71c1c" if any(k in archetype.lower() for k in ["credential", "phishing", "malware", "c2", "botnet", "espionage"])
                else "#e65100" if any(k in archetype.lower() for k in ["fraud", "scam", "impersonation"])
                else "#4CAF50"
            )
            st.markdown(f"""
            <div style='background:linear-gradient(135deg,{arch_color}11,{arch_color}06);
                        border:1.5px solid {arch_color}33; border-left:5px solid {arch_color};
                        border-radius:16px; padding:1.2rem 1.5rem; margin:0.5rem 0 1rem;
                        position:relative; overflow:hidden;'>
                <div style='font-size:0.72rem;font-weight:700;text-transform:uppercase;
                            letter-spacing:1px;color:{arch_color};margin-bottom:6px;'>
                    🧠 AI NARRATIVE INTELLIGENCE
                </div>
                <div style='font-size:1.05rem;font-weight:700;color:#1a1714;line-height:1.5;'>
                    {narrative_text}
                </div>
                <div style='margin-top:8px;font-size:0.8rem;color:#7a7268;'>
                    Campaign Archetype: <strong style='color:{arch_color};'>{archetype}</strong>
                    &nbsp;·&nbsp; Target: <strong>{target_profile}</strong>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Scenario probability bars
            sc_col, tp_col = st.columns([0.65, 0.35])
            with sc_col:
                st.markdown("<div style='font-size:0.85rem;font-weight:700;color:#1a1714;margin-bottom:10px;'>Attack Scenario Probabilities</div>", unsafe_allow_html=True)
                bars_html = ""
                for sc in scenarios:
                    sc_prob  = sc.get("probability", 0)
                    sc_name  = sc.get("name", "Unknown")
                    sc_desc  = sc.get("description", "")
                    _raw_icon = sc.get("icon", "❓")
                    try:
                        _raw_icon.encode("utf-8")
                        sc_icon = _raw_icon
                    except (UnicodeEncodeError, UnicodeDecodeError):
                        sc_icon = "❓"
                    sc_color = (
                        "#b71c1c" if sc_prob == top_prob and arch_color == "#b71c1c"
                        else "#e65100" if sc_prob == top_prob and arch_color == "#e65100"
                        else "#4CAF50" if "benign" in sc_name.lower()
                        else "#E5A100" if sc_prob == top_prob
                        else "#9E9E9E"
                    )
                    bar_w = max(2, sc_prob)
                    bars_html += f"""
                    <div style='margin-bottom:10px;'>
                        <div style='display:flex;align-items:center;justify-content:space-between;margin-bottom:3px;'>
                            <span style='font-size:0.85rem;font-weight:600;color:#1a1714;'>{sc_icon} {sc_name}</span>
                            <span style='font-size:0.85rem;font-weight:800;color:{sc_color};'>{sc_prob}%</span>
                        </div>
                        <div style='background:#f0ede6;border-radius:20px;height:10px;overflow:hidden;'>
                            <div style='width:{bar_w}%;height:100%;border-radius:20px;
                                        background:{sc_color};
                                        transition:width 1s cubic-bezier(.22,1,.36,1);'></div>
                        </div>
                        <div style='font-size:0.75rem;color:#a09585;margin-top:2px;'>{sc_desc}</div>
                    </div>"""
                st.markdown(bars_html, unsafe_allow_html=True)

            with tp_col:
                st.markdown(f"""
                <div style='background:#fffdf5;border:1px solid rgba(229,161,0,0.15);border-radius:14px;
                            padding:1rem 1.1rem;height:100%;'>
                    <div style='font-size:0.72rem;font-weight:700;text-transform:uppercase;
                                letter-spacing:1px;color:#a09585;margin-bottom:10px;'>Target Profile</div>
                    <div style='font-size:0.88rem;font-weight:600;color:#1a1714;line-height:1.5;
                                margin-bottom:14px;'>{target_profile}</div>
                    <div style='font-size:0.72rem;font-weight:700;text-transform:uppercase;
                                letter-spacing:1px;color:#a09585;margin-bottom:6px;'>Risk Confidence Range</div>
                    <div style='font-size:1.4rem;font-weight:900;color:{risk_color};'>
                        {ci_low}–{ci_high}<span style='font-size:0.85rem;color:#b0a99c;font-weight:500;'>/10</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

        # ===== VIRUSTOTAL DETECTION OVERVIEW =====
        vt_stats = result.get("vt_stats", {})
        if vt_stats:
            st.markdown("<div class='ls-section-header'><div class='icon-box'>🛡️</div><span>VirusTotal Detection Overview</span></div>", unsafe_allow_html=True)
            mal = vt_stats.get("malicious", 0)
            sus = vt_stats.get("suspicious", 0)
            harm = vt_stats.get("harmless", 0)
            undet = vt_stats.get("undetected", 0)
            total = mal + sus + harm + undet
            flagged = mal + sus

            # Detection ratio bar
            det_color = "#4CAF50" if flagged == 0 else "#FF9800" if flagged < 5 else "#f44336"
            st.markdown(f"""
            <div class="info-card">
                <div style="display:flex; align-items:center; gap:20px;">
                    <div style="text-align:center; min-width:120px;">
                        <div style="font-size:2.5rem; font-weight:800; color:{det_color};">{flagged}/{total}</div>
                        <div style="font-size:0.85rem; color:#666;">vendors flagged</div>
                    </div>
                    <div style="flex:1;">
                        <div style="display:flex; gap:4px; height:18px; border-radius:9px; overflow:hidden;">
                            <div style="width:{mal/max(total,1)*100}%; background:#f44336;" title="Malicious: {mal}"></div>
                            <div style="width:{sus/max(total,1)*100}%; background:#FF9800;" title="Suspicious: {sus}"></div>
                            <div style="width:{harm/max(total,1)*100}%; background:#4CAF50;" title="Harmless: {harm}"></div>
                            <div style="width:{undet/max(total,1)*100}%; background:#9E9E9E;" title="Undetected: {undet}"></div>
                        </div>
                        <div style="display:flex; gap:16px; margin-top:8px; font-size:0.8rem; color:#666;">
                            <span>🔴 Malicious: {mal}</span>
                            <span>🟠 Suspicious: {sus}</span>
                            <span>🟢 Harmless: {harm}</span>
                            <span>⚪ Undetected: {undet}</span>
                        </div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)


        # ===== ZERO-DAY DOM HEURISTICS =====
        if result.get("dom_heuristics"):
            st.markdown("<div class='ls-section-header'><div class='icon-box'>🧠</div><span>Zero-Day DOM Heuristics</span></div>", unsafe_allow_html=True)
            st.info(f"**AI Code Review:** {result['dom_heuristics']}")

        # ===== REDIRECT CHAIN =====
        if result.get("redirect_chain"):
            st.markdown("<div class='ls-section-header'><div class='icon-box'>🔀</div><span>Redirect Chain</span></div>", unsafe_allow_html=True)
            chain_html = "<div style='display:flex; flex-direction:column; gap:6px; margin-bottom:16px;'>"
            for idx, link in enumerate(result["redirect_chain"]):
                chain_html += f"<div class='redirect-step'>{link}</div>"
                if idx < len(result["redirect_chain"]) - 1:
                    chain_html += "<div class='redirect-arrow'>↓</div>"
            chain_html += "</div>"
            st.markdown(chain_html, unsafe_allow_html=True)

        # ===== PER-VENDOR VERDICTS TABLE (like VT website) =====

        vt_vendors = result.get("vt_vendors", {})
        if vt_vendors:
            with st.expander(f"🔬 Per-Vendor Verdicts ({len(vt_vendors)} engines)", expanded=True):
                vendor_rows = []
                for vendor, info in sorted(vt_vendors.items()):
                    cat = info.get("category", "undetected")
                    vendor_rows.append({
                        "Engine": info.get("engine_name", vendor),
                        "Category": cat.upper(),
                        "Result": info.get("result", "clean"),
                        "Method": info.get("method", ""),
                    })
                vdf = pd.DataFrame(vendor_rows)

                # Color-code the dataframe
                def color_category(val):
                    colors = {
                        "MALICIOUS": "background-color: #ffcdd2; color: #b71c1c;",
                        "SUSPICIOUS": "background-color: #ffe0b2; color: #e65100;",
                        "PHISHING": "background-color: #ffcdd2; color: #b71c1c;",
                        "HARMLESS": "background-color: #c8e6c9; color: #1b5e20;",
                        "UNDETECTED": "background-color: #f5f5f5; color: #757575;",
                    }
                    return colors.get(val, "")

                styled = vdf.style.map(color_category, subset=["Category"])
                st.dataframe(styled, use_container_width=True, height=400)

        # ===== CATEGORIES & REPUTATION =====
        col1, col2 = st.columns(2)
        with col1:
            cats = result.get("vt_categories", {})
            if cats:
                st.markdown("**📂 Site Categories**")
                for vendor, category in cats.items():
                    st.markdown(f"- **{vendor}**: {category}")
            else:
                st.info("No category data from VirusTotal.")

        with col2:
            rep = result.get("vt_reputation", 0)
            votes = result.get("details", {}).get("vt_votes", {})
            st.markdown("**🏆 Community Reputation**")
            st.metric("Reputation Score", rep)
            if votes:
                st.caption(f"👍 Harmless: {votes.get('harmless', 0)}  |  👎 Malicious: {votes.get('malicious', 0)}")

        # ===== HTTP RESPONSE INFO =====
        http_info = result.get("vt_http_response", {})
        if http_info and http_info.get("status_code"):
            with st.expander("🌍 Last HTTP Response"):
                hcol1, hcol2, hcol3, hcol4 = st.columns(4)
                hcol1.metric("Status", http_info.get("status_code", "N/A"))
                hcol2.metric("Server", http_info.get("server", "N/A") or "N/A")
                hcol3.metric("Content-Type", (http_info.get("content_type", "") or "N/A")[:30])
                hcol4.metric("Size", f"{http_info.get('content_length', 'N/A')} bytes" if http_info.get("content_length") else "N/A")

        # ===== VT METADATA =====
        details = result.get("details", {})
        first_sub = details.get("vt_first_submission")
        last_anal = details.get("vt_last_analysis")
        times_sub = details.get("vt_times_submitted")
        if first_sub or last_anal:
            with st.expander("📅 VirusTotal History"):
                mcol1, mcol2, mcol3 = st.columns(3)
                if first_sub:
                    try:
                        mcol1.metric("First Submitted", datetime.fromtimestamp(first_sub).strftime("%Y-%m-%d"))
                    except:
                        mcol1.metric("First Submitted", str(first_sub))
                if last_anal:
                    try:
                        mcol2.metric("Last Analysis", datetime.fromtimestamp(last_anal).strftime("%Y-%m-%d"))
                    except:
                        mcol2.metric("Last Analysis", str(last_anal))
                if times_sub:
                    mcol3.metric("Times Submitted", times_sub)

        # ===== IOC TABLE =====
        st.markdown("<div class='ls-section-header'><div class='icon-box'>📋</div><span>Extracted IOCs</span></div>", unsafe_allow_html=True)
        df_rows = []
        abuse_data = result.get("details", {}).get("abuseipdb", {})
        for ip in result.get("ips", []):
            abuse_score = str(abuse_data.get("abuseConfidenceScore", "N/A")) if abuse_data else "N/A"
            df_rows.append({"Type": "IP", "Value": ip, "AbuseIPDB Score": abuse_score})
        for d in result.get("domains", []):
            df_rows.append({"Type": "Domain", "Value": d, "AbuseIPDB Score": "N/A"})
        for h in result.get("hashes", []):
            df_rows.append({"Type": "Hash", "Value": h, "AbuseIPDB Score": "N/A"})
        for e in result.get("emails", []):
            df_rows.append({"Type": "Email", "Value": e, "AbuseIPDB Score": "N/A"})

        if df_rows:
            st.dataframe(pd.DataFrame(df_rows), use_container_width=True)
        else:
            st.info("No IOCs extracted.")

        # ===== WHOIS & OSINT DETAILS =====
        with st.expander("🌐 WHOIS & OSINT Raw Details"):
            st.json(result.get("details", {}))

        # ===== SSL CERTIFICATE DETAILS =====
        ssl_info = result.get("ssl_info", {})
        if ssl_info:
            with st.expander("🔒 SSL Certificate Details"):
                st.write(f"**Issuer:** {ssl_info.get('issuer')}")
                st.write(f"**Subject:** {ssl_info.get('subject')}")
                st.write(f"**Valid From:** {ssl_info.get('validity_not_before')}")
                st.write(f"**Valid To:** {ssl_info.get('validity_not_after')}")
                st.write(f"**Serial Number:** {ssl_info.get('serial_number')}")
                st.write(f"**Thumbprint:** {ssl_info.get('thumbprint')}")
                st.write("**SAN Domains:**")
                st.write(", ".join(ssl_info.get('san_domains', [])))

        # ===== THREATFOX IOC DATABASE =====
        tf_hits = result.get("threatfox", [])
        if tf_hits:
            st.markdown("<div class='ls-section-header'><div class='icon-box'>🕵️</div><span>ThreatFox IOC Intelligence</span></div>", unsafe_allow_html=True)
            st.error(f"🚨 Found in **{len(tf_hits)}** ThreatFox entries!")
            for hit in tf_hits[:10]:
                c1, c2, c3, c4 = st.columns([2, 2, 2, 1])
                c1.markdown(f"**IOC:** `{hit.get('ioc_value','N/A')}`")
                c2.markdown(f"**Type:** {hit.get('threat_type','N/A')}")
                c3.markdown(f"**Malware:** {hit.get('malware','N/A')}")
                c4.markdown(f"**Confidence:** {hit.get('confidence_level','N/A')}")
        else:
            with st.expander("🕵️ ThreatFox IOC Database"):
                st.success("✅ Not found in ThreatFox IOC database.")

        # ===== ALIENVAULT OTX =====
        otx_data = result.get("details", {}).get("alienvault_otx", {})
        if otx_data:
            pulse_count = otx_data.get("pulse_info", {}).get("count", 0) or 0
            st.markdown("<div class='ls-section-header'><div class='icon-box'>🛸</div><span>AlienVault OTX Intelligence</span></div>", unsafe_allow_html=True)
            if pulse_count:
                st.error(f"🚨 **{pulse_count} threat intelligence pulses** reference this domain on AlienVault OTX!")
                pulses = otx_data.get("pulse_info", {}).get("pulses", [])[:5]
                for p in pulses:
                    with st.expander(f"📌 {p.get('name', 'Unnamed pulse')}  |  {p.get('created', '')[:10]}"):
                        st.write(f"**Description:** {p.get('description', 'N/A')}")
                        st.write(f"**Tags:** {', '.join(p.get('tags', [])[:8]) or 'None'}")
                        mf_raw = p.get('malware_families', [])[:5]
                        mf_names = [m.get('display_name', str(m)) if isinstance(m, dict) else str(m) for m in mf_raw]
                        st.write(f"**Malware Families:** {', '.join(mf_names) or 'None'}")
                        st.write(f"**TLP:** {p.get('tlp', 'white').upper()}")
            else:
                with st.expander("🛸 AlienVault OTX Intelligence"):
                    st.success("✅ No OTX pulses reference this target.")
        else:
            with st.expander("🛸 AlienVault OTX Intelligence"):
                st.info("OTX data not yet available for this target.")

        # ===== PDF EXPORT =====
        if st.button("📄 Generate PDF Report", key="pdf_btn"):
            pdf_path = generate_pdf(
                current_target, result,
                summary_text=summary_text,
                narrative_data=narrative_data,
            )
            with open(pdf_path, "rb") as f:
                st.download_button("⬇️ Download Report", f, file_name="forensic_report.pdf", mime="application/pdf")

# ===== TAB 3: RESEARCHER =====
with tab3:
    st.markdown("""
    <div class='info-card'>
        <div class='ls-section-header' style='margin:0 0 0.3rem;'>
            <div class='icon-box'>🔭</div>
            <span>Researcher Workbench — Advanced OSINT Intelligence</span>
        </div>
        <p style='margin:0; color:#7a7268; font-size:0.88rem;'>
            Advanced OSINT pivoting &nbsp;·&nbsp; Passive DNS history &nbsp;·&nbsp; BGP / ASN intelligence &nbsp;·&nbsp;
            AI threat actor profiling &nbsp;·&nbsp; MITRE ATT&amp;CK mapping &nbsp;·&nbsp; Snort / YARA rule forge
        </p>
    </div>
    """, unsafe_allow_html=True)

    r_url = st.text_input("Enter domain or URL to analyze", key="researcher_url",
                          placeholder="e.g. malicious-site.com or https://phishing.example/login")
    researcher_target = normalize_investigation_input(r_url, {"url", "domain"}) if r_url.strip() else None
    if researcher_target and researcher_target["extracted"]:
        st.info(researcher_target["message"])

    if r_url and researcher_target and researcher_target["value"]:
        r_target = researcher_target["value"]
        r_domain = urlparse(r_target).hostname if researcher_target["kind"] == "url" else r_target

        # --- Prefetch screenshot in background so OSINT Pivot loads instantly ---
        _ss_prefetch_key = f"_ss_prefetch_{r_domain}"
        if _ss_prefetch_key not in st.session_state:
            st.session_state[_ss_prefetch_key] = True
            import threading as _th_ss
            def _bg_screenshot_fetch():
                try:
                    from utils.api_clients import urlscan_latest_screenshot as _uss
                    _uss(r_domain)   # populates @st.cache_data; result fetched when rtab3 opens
                except Exception:
                    pass
            _th_ss.Thread(target=_bg_screenshot_fetch, daemon=True).start()

        # ---------- Sub-tabs ----------
        rtab1, rtab2, rtab3, rtab4, rtab5, rtab6 = st.tabs([
            "🕸️ Threat Graph",
            "📡 DNS & Passive History",
            "🔎 OSINT Pivot",
            "🦠 Campaign Intel",
            "🎯 Threat Actor Profile",
            "📝 Notes & Export",
        ])

        # ── rtab1: Threat Genealogy Graph ──────────────────────────────────
        with rtab1:
            st.subheader("🕸️ Threat Genealogy Graph")
            with st.spinner("🕸️ Mapping threat infrastructure graph…"):
                try:
                    gh, gx = build_genealogy_graph(r_domain)
                    st.components.v1.html(gh, height=580)
                    st.session_state.current_gexf = gx
                except Exception as e:
                    st.error(f"Graph error: {e}")
            st.markdown(
                '<div class="info-card" style="padding:0.8rem;">'
                '<strong>Legend:</strong> 🔵 Domain &nbsp; 🟢 IP &nbsp; 🟠 MX &nbsp;'
                '🟣 NS &nbsp; 🔴 Registrar &nbsp; 🩷 Subdomain &nbsp; 🟡 SPF/DMARC'
                '</div>',
                unsafe_allow_html=True,
            )

        # ── rtab2: DNS + CIRCL Passive History ─────────────────────────────
        with rtab2:
            from utils.api_clients import dns_resolve_all, crt_sh_subdomains, circl_pdns, email_security_check

            col_dns, col_email = st.columns([0.6, 0.4])

            with col_dns:
                st.subheader("📡 Live DNS Records")
                with st.spinner("📡 Looking up live DNS records…"):
                    dns_d = dns_resolve_all(r_domain)
                if any(dns_d.values()):
                    for rt in ["A", "AAAA", "MX", "NS", "CNAME", "TXT"]:
                        recs = dns_d.get(rt, [])
                        if recs:
                            st.markdown(f"**{rt} Records** ({len(recs)})")
                            for r in recs:
                                st.code(r, language="text")
                else:
                    st.info("No DNS records resolved.")

            with col_email:
                st.subheader("📧 Email Security")
                with st.spinner("📧 Checking email security posture…"):
                    email_sec = email_security_check(r_domain)
                spf = email_sec.get("spf")
                dmarc = email_sec.get("dmarc")
                if spf:
                    st.success("✅ SPF Record Found")
                    st.caption(spf[:120])
                else:
                    st.error("❌ No SPF Record (spoofing risk!)")
                if dmarc:
                    st.success("✅ DMARC Record Found")
                    st.caption(dmarc[:120])
                else:
                    st.error("❌ No DMARC (email forgery possible!)")

            st.markdown("---")
            st.subheader("🕰️ Passive DNS History (CIRCL)")
            with st.spinner("🕰️ Loading passive DNS history…"):
                pdns_records = circl_pdns(r_domain)
            if pdns_records:
                st.success(f"Found **{len(pdns_records)}** historical DNS entries")
                pdns_rows = []
                for rec in pdns_records[:50]:
                    import datetime as _dt
                    first = _dt.datetime.fromtimestamp(rec.get("time_first", 0)).strftime("%Y-%m-%d") if rec.get("time_first") else "?"
                    last  = _dt.datetime.fromtimestamp(rec.get("time_last",  0)).strftime("%Y-%m-%d") if rec.get("time_last")  else "?"
                    pdns_rows.append({
                        "Type": rec.get("rrtype", "?"),
                        "Value": rec.get("rdata", "?"),
                        "First Seen": first,
                        "Last Seen": last,
                        "Count": rec.get("count", 1),
                    })
                st.dataframe(pd.DataFrame(pdns_rows), use_container_width=True, height=300)
                st.caption("Source: CIRCL Passive DNS — historical resolution records, updated hourly.")
            else:
                st.info("No passive DNS history found for this domain.")

            st.markdown("---")
            st.subheader("🌍 Subdomains (crt.sh Certificate Transparency)")
            with st.spinner("🌍 Scanning certificate transparency logs…"):
                subs = crt_sh_subdomains(r_domain)
            if subs:
                st.success(f"Found **{len(subs)}** subdomains in certificate logs!")
                st.dataframe(pd.DataFrame(subs, columns=["Subdomain"]), use_container_width=True, height=300)
            else:
                st.info("No subdomains found in certificate logs.")

        # ── rtab3: OSINT Pivot ──────────────────────────────────────────────
        with rtab3:
            from utils.api_clients import (
                dns_resolve_all as _dns_all, ip_geolocation,
                shodan_internetdb, bgpview_ip_info, bgpview_asn_info,
                hackertarget_reverse_ip, otx_domain_report, otx_ip_report,
                urlscan_latest_screenshot,
            )
            import socket as _sock

            st.subheader("🔎 OSINT Pivot — Infrastructure Intelligence")
            st.caption("Pivot from a domain → IPs → ASN → sibling domains → open ports → OTX pulses")

            # Resolve IPs
            with st.spinner("🔍 Resolving IP addresses…"):
                dns_res = _dns_all(r_domain)
                ips = dns_res.get("A", [])
                try:
                    direct_ip = _sock.gethostbyname(r_domain)
                    if direct_ip not in ips:
                        ips.insert(0, direct_ip)
                except Exception:
                    pass

            if not ips:
                st.warning("Could not resolve any IP for this domain.")
            else:
                for ip in ips[:3]:
                    with st.expander(f"🖥️ IP: {ip}", expanded=(ips.index(ip) == 0)):
                        c1, c2, c3 = st.columns(3)

                        # Geolocation
                        with st.spinner("📍 Pinpointing server location…"):
                            geo = ip_geolocation(ip)
                        with c1:
                            st.markdown("**📍 Geolocation**")
                            if geo:
                                st.write(f"🌍 {geo.get('country','?')} / {geo.get('city','?')}")
                                st.write(f"🏢 ISP: {geo.get('isp','?')}")
                                st.write(f"📡 ASN: {geo.get('as','?')}")
                                st.write(f"🕐 TZ: {geo.get('timezone','?')}")
                            else:
                                st.write("Geo unavailable")

                        # BGPView ASN details
                        with c2:
                            st.markdown("**📡 BGP / ASN Intel**")
                            with st.spinner("📡 Mapping network routing & ASN…"):
                                bgp = bgpview_ip_info(ip)
                            prefixes = bgp.get("data", {}).get("prefixes", [])
                            if prefixes:
                                p = prefixes[0]
                                asn_num = p.get("asn", {}).get("asn")
                                st.write(f"🔢 ASN: AS{asn_num}")
                                st.write(f"🏷️ Org: {p.get('asn', {}).get('name','?')}")
                                st.write(f"📦 Prefix: {p.get('prefix','?')}")
                                st.write(f"🌐 CC: {p.get('asn', {}).get('country_code','?')}")
                            else:
                                st.write("BGP data unavailable")

                        # Shodan InternetDB (free)
                        with c3:
                            st.markdown("**🔌 Open Ports & CVEs**")
                            with st.spinner("🔌 Scanning exposed ports & CVEs…"):
                                idb = shodan_internetdb(ip)
                            if idb and not idb.get("detail"):
                                ports = idb.get("ports", [])
                                cves = idb.get("vulns", [])
                                tags = idb.get("tags", [])
                                hostnames = idb.get("hostnames", [])
                                if ports:
                                    st.write(f"🔓 Ports: {', '.join(str(p) for p in ports[:10])}")
                                if cves:
                                    st.error(f"🚨 {len(cves)} CVE(s): {', '.join(list(cves)[:4])}")
                                if tags:
                                    st.write(f"🏷️ Tags: {', '.join(tags)}")
                                if hostnames:
                                    st.write(f"🖧 Hostnames: {', '.join(hostnames[:3])}")
                            else:
                                st.write("No port/CVE data (clean or private IP)")

                        # Reverse IP — sibling domains
                        st.markdown("**🏘️ Sibling Domains (same IP)**")
                        with st.spinner("🏘️ Discovering co-hosted domains…"):
                            siblings = hackertarget_reverse_ip(ip)
                        if siblings:
                            st.info(f"Found **{len(siblings)}** domains on the same IP")
                            st.dataframe(
                                pd.DataFrame(siblings, columns=["Domain"]),
                                use_container_width=True, height=200,
                            )
                        else:
                            st.write("No sibling domains found (or API limit reached).")

            st.markdown("---")
            st.subheader("🛸 AlienVault OTX Intelligence")
            with st.spinner("🛸 Searching global threat intelligence feeds…"):
                otx = otx_domain_report(r_domain)
            pulse_count = otx.get("pulse_info", {}).get("count", 0)
            if pulse_count:
                st.error(f"🚨 **{pulse_count} threat intelligence pulses** reference this domain on AlienVault OTX!")
                pulses = otx.get("pulse_info", {}).get("pulses", [])[:5]
                for pulse in pulses:
                    st.markdown(f"""
                    <div class='tactic-card'>
                        <strong>{pulse.get('name','Unnamed Pulse')}</strong><br/>
                        <small>Tags: {', '.join(pulse.get('tags', [])) or 'None'} &nbsp;|&nbsp;
                        TLP: {pulse.get('tlp','?')} &nbsp;|&nbsp;
                        Modified: {pulse.get('modified','?')[:10]}</small>
                    </div>""", unsafe_allow_html=True)
            else:
                st.success("✅ No OTX pulses reference this domain.")

            st.markdown("---")
            st.subheader("📸 Web Screenshot (URLScan.io)")
            with st.spinner("📸 Loading site screenshot…"):
                ss = urlscan_latest_screenshot(r_domain)
            if ss and ss.get("screenshot_bytes"):
                source = ss.get("source", "urlscan")
                if source == "urlscan":
                    scanned = ss.get("scanned_at", "")[:10] or "Unknown"
                    is_mal = ss.get("malicious", False)
                    score = ss.get("score", 0)
                    st.caption(
                        f"Scanned: {scanned} | URLScan Score: {score} | "
                        f"{'🚨 Flagged malicious' if is_mal else '✅ Not flagged'}"
                    )
                    st.image(ss["screenshot_bytes"], caption="Latest URLScan.io snapshot", width='stretch')
                    st.link_button("🔗 View Full URLScan Report", ss.get("scan_url", "#"))
                else:
                    st.caption("Live screenshot via thum.io (no URLScan history found)")
                    st.image(ss["screenshot_bytes"], caption=f"Live render of https://{r_domain}", width='stretch')
            else:
                st.info("Screenshot unavailable — the domain may block automated rendering.")

            st.markdown("---")
            st.subheader("🏘️ Typosquatting Detection")
            from agents.cartographer import generate_typosquatting
            if st.button("🔍 Check Typosquatting", key="typo_btn"):
                with st.spinner("🔄 Generating typosquat permutations & probing DNS…"):
                    active_typos = generate_typosquatting(r_domain)
                if active_typos:
                    st.warning(f"🚨 Found **{len(active_typos)}** active typosquatting domains!")
                    st.dataframe(pd.DataFrame(active_typos), width="stretch")
                else:
                    st.success("✅ No active typosquatting domains found.")

        # ── rtab4: Campaign & Malware Intel ─────────────────────────────────
        with rtab4:
            from agents.cartographer import campaign_similarity
            from utils.api_clients import urlhaus_check, threatfox_domain_check

            st.subheader("🔗 Campaign Attribution")
            matches = campaign_similarity({"domains": [r_domain]})
            if matches:
                st.warning(f"⚠️ **{len(matches)}** infrastructure overlaps with previous submissions!")
                st.dataframe(pd.DataFrame(matches), width="stretch")
            else:
                st.info("No overlaps found in local submission history.")

            st.markdown("---")
            st.subheader("🦠 URLHaus Malware Feed")
            with st.spinner("🦠 Scanning malware distribution databases…"):
                uh = urlhaus_check(r_domain)
            if uh and uh.get("query_status") == "ok" and uh.get("urls"):
                st.error(f"🚨 **{len(uh['urls'])} malware campaigns** used this domain!")
                try:
                    st.dataframe(
                        pd.DataFrame(uh["urls"])[["url", "url_status", "date_added", "threat"]],
                        width="stretch",
                    )
                except Exception:
                    st.dataframe(pd.DataFrame(uh["urls"]))
            else:
                st.success("✅ Clean on URLHaus.")

            st.markdown("---")
            st.subheader("🕵️ ThreatFox IOC Database")
            with st.spinner("🕵️ Cross-referencing IOC threat databases…"):
                tf_hits = threatfox_domain_check(r_domain)
            if tf_hits:
                st.error(f"🚨 Found in **{len(tf_hits)}** ThreatFox entries!")
                tf_rows = []
                for hit in tf_hits[:20]:
                    tf_rows.append({
                        "IOC": hit.get("ioc_value","?"),
                        "Threat Type": hit.get("threat_type","?"),
                        "Malware": hit.get("malware_printable","?"),
                        "Confidence": hit.get("confidence_level","?"),
                        "First Seen": hit.get("first_seen","?")[:10] if hit.get("first_seen") else "?",
                    })
                st.dataframe(pd.DataFrame(tf_rows), width='stretch')
            else:
                st.success("✅ Not found in ThreatFox IOC database.")

            st.markdown("---")
            st.subheader("📈 Community Threat Timeline")
            try:
                import plotly.express as px
                fi = get_community_feed(limit=1000)
                if fi:
                    df_f = pd.DataFrame(fi, columns=["id", "verdict", "snippet", "upvotes", "timestamp"])
                    df_f["timestamp"] = pd.to_datetime(df_f["timestamp"], errors="coerce")
                    df_f = df_f.dropna(subset=["timestamp"])
                    df_f["date"] = df_f["timestamp"].dt.date
                    td = df_f.groupby(["date", "verdict"]).size().reset_index(name="count")
                    fig = px.bar(td, x="date", y="count", color="verdict", title="Community Reports Timeline",
                                 template="plotly_white")
                    st.plotly_chart(fig, width="stretch")
                else:
                    st.info("No community data yet.")
            except Exception as e:
                st.error(f"Timeline error: {e}")

        # ── rtab5: Threat Actor Profile ──────────────────────────────────────
        with rtab5:
            from agents.threat_investigator import generate_threat_actor_profile

            st.subheader("🎯 AI Threat Actor Profiling")
            st.caption(
                "Lumina correlates IOCs with known threat groups, maps TTPs to MITRE ATT&CK, "
                "and reconstructs the attack narrative. Results are cached for 6 hours."
            )

            # Check if we already have a cached result for this domain
            _cached_key = f"actor_{r_domain}"
            _already_cached = _cached_key in st.session_state

            if _already_cached:
                st.success("⚡ Profile loaded from session cache — click **Refresh** to re-run.")
                _btn_label = "🔄 Refresh Threat Actor Analysis"
            else:
                _btn_label = "🔮 Run Threat Actor Analysis"

            if st.button(_btn_label, key="actor_btn"):
                _prog = st.progress(0, text="Gathering IOCs…")
                actor_iocs = st.session_state.get("cyber_result") or {}
                if not actor_iocs:
                    from agents.threat_investigator import investigate_threat_cached
                    actor_iocs = (
                        get_mock_threat_result(r_target)
                        if st.session_state.get("demo_mode")
                        else investigate_threat_cached(url=r_target)
                    )
                _prog.progress(40, text="AI profiling threat actor…")
                try:
                    profile = generate_threat_actor_profile(r_domain, actor_iocs)
                    _prog.progress(100, text="Done!")
                    _prog.empty()
                    if profile.get("_from_cache"):
                        st.toast("⚡ Loaded from 6-hour disk cache", icon="💾")
                    else:
                        st.toast("✅ Fresh profile generated", icon="🎯")
                    st.session_state[_cached_key] = profile
                except RuntimeError as _rle:
                    _prog.empty()
                    if "RATE_LIMIT" in str(_rle):
                        st.warning(
                            "⏳ **Groq rate limit reached** (free-tier: 6,000 tokens/min). "
                            "Please wait ~60 seconds then try again. "
                            "Results for previously analysed domains load instantly from cache."
                        )
                    else:
                        st.error(f"Profile error: {_rle}")
                except Exception as _exc:
                    _prog.empty()
                    st.error(f"Unexpected error: {_exc}")

            profile = st.session_state.get(_cached_key)
            if profile:
                # Threat Level banner
                threat_level = profile.get("threat_level", "Unknown")
                tl_color = {
                    "Nation-State": "#b71c1c",
                    "Cybercriminal": "#e65100",
                    "Hacktivist": "#f57f17",
                    "Script Kiddie": "#4CAF50",
                    "Unknown": "#9E9E9E",
                }.get(threat_level, "#9E9E9E")
                st.markdown(f"""
                <div class="overall-badge" style="background:{tl_color}; color:white; margin-bottom:1rem;">
                    ⚔️ {threat_level} &nbsp;|&nbsp; 🎯 {profile.get('motivation','Unknown')}
                </div>
                """, unsafe_allow_html=True)

                # Campaign narrative
                st.markdown("### 📖 Campaign Narrative")
                st.info(profile.get("campaign_narrative", "N/A"))

                # Threat actor candidates
                st.markdown("### 🕵️ Threat Actor Candidates")
                candidates = profile.get("threat_actor_candidates", [])
                for cand in candidates:
                    conf = cand.get("confidence","?")
                    conf_color = {"High": "#f44336", "Medium": "#FF9800", "Low": "#4CAF50"}.get(conf, "#9E9E9E")
                    st.markdown(f"""
                    <div class="verdict-card" style="border-left:5px solid {conf_color};">
                        <h4>🎭 {cand.get('name','?')} <span style='float:right;font-size:0.85rem;color:{conf_color};'>{conf} Confidence</span></h4>
                        <p style='margin:0;color:#555;'>{cand.get('reasoning','')}</p>
                    </div>""", unsafe_allow_html=True)

                # MITRE ATT&CK Heatmap
                st.markdown("### 🗺️ MITRE ATT&CK Tactics")
                tactics = profile.get("mitre_tactics", [])
                if tactics:
                    ALL_TACTICS = [
                        "Reconnaissance", "Resource Development", "Initial Access", "Execution",
                        "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
                        "Discovery", "Lateral Movement", "Collection", "Command & Control",
                        "Exfiltration", "Impact",
                    ]
                    tactic_html = "<div style='display:flex;flex-wrap:wrap;gap:8px;margin:12px 0;'>"
                    for t in ALL_TACTICS:
                        active = any(t.lower() in tac.lower() or tac.lower() in t.lower() for tac in tactics)
                        bg = "linear-gradient(135deg,#b71c1c,#e53935)" if active else "#eeeeee"
                        color = "white" if active else "#999"
                        tactic_html += f"<div style='background:{bg};color:{color};padding:6px 14px;border-radius:20px;font-size:0.8rem;font-weight:600;'>{t}</div>"
                    tactic_html += "</div>"
                    st.markdown(tactic_html, unsafe_allow_html=True)

                # MITRE Techniques
                techniques = profile.get("mitre_techniques", [])
                if techniques:
                    st.markdown("### 🔧 MITRE ATT&CK Techniques")
                    for tech in techniques:
                        st.markdown(f"""
                        <div class="tactic-card">
                            <strong><code>{tech.get('id','?')}</code> – {tech.get('name','?')}</strong><br/>
                            <small>{tech.get('relevance','')}</small>
                        </div>""", unsafe_allow_html=True)

                # Recommended detections
                detections = profile.get("recommended_detections", [])
                if detections:
                    st.markdown("### 🛡️ Recommended Detections")
                    for d in detections:
                        st.markdown(f"- {d}")

                # ── Kill-Chain Timeline Reconstruction ───────────────────────
                st.markdown("---")
                st.markdown("### ⛓️ Behavioral Kill-Chain Reconstruction")
                st.caption(
                    "AI maps your IOC evidence to each Cyber Kill Chain phase — "
                    "Reconnaissance → Exfiltration — with specific data references."
                )
                _kc_key = f"kill_chain_{r_domain}"
                if _kc_key not in st.session_state:
                    _kc_btn_label = "⛓️ Reconstruct Kill Chain"
                else:
                    _kc_btn_label = "🔄 Refresh Kill Chain"

                if st.button(_kc_btn_label, key="kc_btn"):
                    _kc_prog = st.progress(0, text="Loading IOC evidence…")
                    _kc_iocs = st.session_state.get("cyber_result") or {}
                    if not _kc_iocs:
                        from agents.threat_investigator import investigate_threat_cached as _itc
                        _kc_iocs = (
                            get_mock_threat_result(r_target)
                            if st.session_state.get("demo_mode")
                            else _itc(url=r_target)
                        )
                    _kc_prog.progress(50, text="AI reconstructing kill chain…")
                    try:
                        from agents.threat_investigator import generate_kill_chain_timeline
                        _kc_result = generate_kill_chain_timeline(r_domain, _kc_iocs, profile)
                        _kc_prog.progress(100, text="Done!")
                        _kc_prog.empty()
                        if _kc_result.get("_from_cache"):
                            st.toast("⚡ Kill chain loaded from cache", icon="💾")
                        st.session_state[_kc_key] = _kc_result
                    except RuntimeError as _kc_rle:
                        _kc_prog.empty()
                        if "RATE_LIMIT" in str(_kc_rle):
                            st.warning("⏳ Groq rate limit. Wait ~60 s then retry.")
                        else:
                            st.error(f"Kill chain error: {_kc_rle}")
                    except Exception as _kc_exc:
                        _kc_prog.empty()
                        st.error(f"Kill chain error: {_kc_exc}")

                _kc_data = st.session_state.get(_kc_key)
                if _kc_data:
                    # Narrative banner
                    if _kc_data.get("narrative"):
                        st.markdown(f"""
                        <div style='background:linear-gradient(135deg,#b71c1c11,#e5390006);
                                    border:1.5px solid #b71c1c33;border-left:5px solid #b71c1c;
                                    border-radius:16px;padding:1.1rem 1.4rem;margin:0.5rem 0 1rem;'>
                            <div style='font-size:0.72rem;font-weight:700;text-transform:uppercase;
                                        letter-spacing:1px;color:#b71c1c;margin-bottom:6px;'>
                                ⛓️ ATTACK TIMELINE
                            </div>
                            <div style='font-size:0.92rem;color:#1a1714;line-height:1.6;'>{_kc_data['narrative']}</div>
                            <div style='margin-top:8px;font-size:0.8rem;color:#7a7268;'>
                                Estimated duration: <strong style='color:#b71c1c;'>{_kc_data.get('attack_duration_estimate','?')}</strong>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)

                    # Phase cards — vertical timeline
                    phases = _kc_data.get("phases", [])
                    conf_colors = {"High": "#b71c1c", "Medium": "#e65100", "Low": "#4CAF50"}
                    for _idx, _ph in enumerate(phases):
                        _ph_conf  = _ph.get("confidence", "Low")
                        _ph_color = conf_colors.get(_ph_conf, "#9E9E9E")
                        _ioc_tags = " ".join(
                            f"<code style='background:#fff8ec;color:#c88b00;padding:1px 7px;border-radius:8px;"
                            f"font-size:0.75rem;border:1px solid rgba(229,161,0,0.2);'>{ir}</code>"
                            for ir in _ph.get("ioc_refs", [])[:4]
                        )
                        _connector = (
                            "<div style='width:2px;height:20px;background:#dee2e6;margin:0 0 0 19px;'></div>"
                            if _idx < len(phases) - 1 else ""
                        )
                        st.markdown(f"""
                        <div style='display:flex;gap:14px;align-items:flex-start;'>
                            <div style='display:flex;flex-direction:column;align-items:center;min-width:40px;'>
                                <div style='width:40px;height:40px;border-radius:50%;
                                            background:{_ph_color}22;border:2px solid {_ph_color};
                                            display:flex;align-items:center;justify-content:center;
                                            font-size:1.2rem;flex-shrink:0;'>{_ph.get('icon','⚙️')}</div>
                                {_connector}
                            </div>
                            <div style='flex:1;background:#fffdf5;border:1px solid rgba(229,161,0,0.12);
                                        border-left:3px solid {_ph_color};border-radius:12px;
                                        padding:0.9rem 1.1rem;margin-bottom:4px;'>
                                <div style='display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;'>
                                    <strong style='font-size:0.95rem;color:#1a1714;'>{_ph.get('phase','?')}</strong>
                                    <span style='font-size:0.72rem;font-weight:700;color:{_ph_color};
                                                 background:{_ph_color}18;padding:2px 10px;border-radius:20px;'>
                                        {_ph_conf}
                                    </span>
                                </div>
                                <p style='margin:0 0 8px;font-size:0.87rem;color:#4a4540;line-height:1.55;'>{_ph.get('evidence','')}</p>
                                <div style='display:flex;flex-wrap:wrap;gap:4px;'>{_ioc_tags}</div>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.info("Click **Reconstruct Kill Chain** above to map IOC evidence to the attack lifecycle.")

            else:
                st.info("Click **Run Threat Actor Analysis** above to generate an AI-powered threat profile.")

        # ── rtab6: Notes, Citations & Export ────────────────────────────────
        with rtab6:
            from data.db import add_annotation, get_annotations
            from utils.api_clients import dns_resolve_all as _dns_r, crt_sh_subdomains as _crt

            st.subheader("📝 Research Annotations")
            with st.form("ann_form", clear_on_submit=True):
                note = st.text_area("Research notes", placeholder="Observations, hypotheses, pivots...")
                tags = st.text_input("Tags", placeholder="phishing, apt29, c2")
                if st.form_submit_button("💾 Save Note") and note:
                    add_annotation(r_domain, note, tags)
                    st.success("Note saved.")
            anns = get_annotations(r_domain)
            for a in anns:
                st.markdown(
                    f'<div class="feed-card"><strong>{a["timestamp"]}</strong> | '
                    f'🏷️ {a["tags"]}<br><em>{a["note"]}</em></div>',
                    unsafe_allow_html=True,
                )

            st.markdown("---")
            st.subheader("🎓 Academic Citation")
            import datetime as dtm
            st.code(
                f'Lumina Shield. ({dtm.datetime.now().strftime("%Y, %B %d")}). '
                f"Threat Intelligence Report for \'{r_domain}\'. "
                "LuminaAI Research Workbench. https://luminashield.app",
                language="text",
            )

            st.markdown("---")
            st.subheader("📥 Artifact Export")

            # YARA Rule
            if st.button("🛡️ Generate YARA Rule", key="yara_btn"):
                with st.spinner("AI is forging YARA rule..."):
                    from agents.threat_investigator import generate_yara_rule
                    iocs_for_rule = st.session_state.get("cyber_result") or {}
                    if not iocs_for_rule:
                        from agents.threat_investigator import investigate_threat_cached
                        iocs_for_rule = (
                            get_mock_threat_result(r_target)
                            if st.session_state.get("demo_mode")
                            else investigate_threat_cached(url=r_target)
                        )
                    yara_rule = generate_yara_rule(iocs_for_rule)
                    st.session_state.r_yara_rule = yara_rule
            if st.session_state.get("r_yara_rule"):
                st.code(st.session_state.r_yara_rule, language="text")
                st.download_button("⬇️ Download YARA", st.session_state.r_yara_rule, f"{r_domain}.yar")

            # Snort Rule
            if st.button("🚨 Generate Snort/Suricata Rule", key="snort_btn"):
                with st.spinner("AI is forging Snort rules..."):
                    from agents.threat_investigator import generate_snort_rule
                    iocs_for_snort = st.session_state.get("cyber_result") or {}
                    if not iocs_for_snort:
                        from agents.threat_investigator import investigate_threat_cached
                        iocs_for_snort = (
                            get_mock_threat_result(r_target)
                            if st.session_state.get("demo_mode")
                            else investigate_threat_cached(url=r_target)
                        )
                    snort_rule = generate_snort_rule(iocs_for_snort)
                    st.session_state.r_snort_rule = snort_rule
            if st.session_state.get("r_snort_rule"):
                st.code(st.session_state.r_snort_rule, language="text")
                st.download_button("⬇️ Download Snort Rules", st.session_state.r_snort_rule, f"{r_domain}.rules")

            # Standard exports
            st.markdown("---")
            e1, e2, e3 = st.columns(3)
            with e1:
                dns_export = _dns_r(r_domain)
                e1.download_button(
                    "📋 IOC JSON",
                    json.dumps({"domain": r_domain, "dns": dns_export}, indent=2, default=str),
                    f"{r_domain}_iocs.json",
                )
            with e2:
                e2.download_button(
                    "🕸️ Graph GEXF",
                    st.session_state.get("current_gexf", "<gexf/>"),
                    f"{r_domain}_graph.gexf",
                )
            with e3:
                subs_export = _crt(r_domain)
                e3.download_button(
                    "🌍 Subdomains CSV",
                    "\n".join(subs_export),
                    f"{r_domain}_subdomains.csv",
                )

    elif r_url:
        st.warning(researcher_target["message"] if researcher_target else "Please enter a URL or domain.")
    else:
        # Landing state — show feature highlights
        st.markdown("""
        <div style='display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-top:1rem;'>
            <div class='info-card' style='text-align:center;'>
                <div style='font-size:2rem;'>🕰️</div>
                <strong>Passive DNS History</strong>
                <p style='color:#666;font-size:0.85rem;margin:0;'>CIRCL PDNS — see every IP this domain ever pointed to</p>
            </div>
            <div class='info-card' style='text-align:center;'>
                <div style='font-size:2rem;'>📡</div>
                <strong>BGP / ASN Intelligence</strong>
                <p style='color:#666;font-size:0.85rem;margin:0;'>BGPView — autonomous system, prefix, org attribution</p>
            </div>
            <div class='info-card' style='text-align:center;'>
                <div style='font-size:2rem;'>🏘️</div>
                <strong>Reverse IP Pivoting</strong>
                <p style='color:#666;font-size:0.85rem;margin:0;'>Find all domains co-hosted on the same IP server</p>
            </div>
            <div class='info-card' style='text-align:center;'>
                <div style='font-size:2rem;'>🎯</div>
                <strong>Threat Actor Profiling</strong>
                <p style='color:#666;font-size:0.85rem;margin:0;'>AI matches IOCs to APT groups + MITRE ATT&CK heatmap</p>
            </div>
            <div class='info-card' style='text-align:center;'>
                <div style='font-size:2rem;'>📸</div>
                <strong>Web Screenshot</strong>
                <p style='color:#666;font-size:0.85rem;margin:0;'>URLScan.io visual snapshot of the live page</p>
            </div>
            <div class='info-card' style='text-align:center;'>
                <div style='font-size:2rem;'>🚨</div>
                <strong>Snort / YARA Forge</strong>
                <p style='color:#666;font-size:0.85rem;margin:0;'>AI-generated IDS rules ready to deploy in your SOC</p>
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.info("Enter a domain above to begin research.")

# ===== TAB 4: DASHBOARD =====
with tab4:
    st.markdown("""
    <div class='info-card'>
        <div class='ls-section-header' style='margin:0 0 0.3rem;'>
            <div class='icon-box'>🌐</div>
            <span>Global Dashboard — Live Threat Intelligence</span>
        </div>
        <p style='margin:0; color:#7a7268; font-size:0.88rem;'>
            Real-time heatmap, trending threats by verdict, community submissions, and shared intelligence feed.
        </p>
    </div>
    """, unsafe_allow_html=True)
    try: hm_rows = get_heatmap_data()
    except: hm_rows = []
    if hm_rows:
        import plotly.express as px; import folium; from streamlit_folium import st_folium
        df = pd.DataFrame(hm_rows, columns=["city","category","verdict","date"])
        s1,s2,s3,s4 = st.columns(4)
        s1.markdown(f'<div class="stat-card"><span class="stat-num">{len(df)}</span><p>Total Reports</p></div>', unsafe_allow_html=True)
        s2.markdown(f'<div class="stat-card"><span class="stat-num">{len(df[df["verdict"].isin(["FAKE","FALSE"])])}</span><p>Fake / False</p></div>', unsafe_allow_html=True)
        s3.markdown(f'<div class="stat-card"><span class="stat-num">{len(df[df["verdict"]=="SCAM"])}</span><p>Scams Detected</p></div>', unsafe_allow_html=True)
        s4.markdown(f'<div class="stat-card"><span class="stat-num">{df["city"].nunique()}</span><p>Cities Reporting</p></div>', unsafe_allow_html=True)
        st.subheader("🗺️ Global Threat Heatmap")
        cc2 = df.groupby("city").size().reset_index(name="n")
        vc = [(GLOBAL_CITY_COORDS[c][0],GLOBAL_CITY_COORDS[c][1]) for c in cc2["city"] if c in GLOBAL_CITY_COORDS]
        clat = sum(c[0] for c in vc)/max(len(vc),1) if vc else 30.37
        clon = sum(c[1] for c in vc)/max(len(vc),1) if vc else 69.34
        m = folium.Map(location=[clat,clon], zoom_start=3, tiles="cartodbpositron")
        for _,row in cc2.iterrows():
            c = row["city"]
            if c in GLOBAL_CITY_COORDS:
                folium.CircleMarker(location=GLOBAL_CITY_COORDS[c], radius=row["n"]*3+4, color="#E5A100", fill=True, fill_color="#E5A100", fill_opacity=0.6, popup=f"{c}: {row['n']}").add_to(m)
        st_folium(m, width='stretch', height=450, returned_objects=[])
        st.subheader("📈 Threats Over Time")
        df["date"] = pd.to_datetime(df["date"], errors="coerce"); df = df.dropna(subset=["date"]); df["d2"] = df["date"].dt.date
        trend = df.groupby(["d2","verdict"]).size().reset_index(name="count")
        if not trend.empty:
            fig = px.area(trend, x="d2", y="count", color="verdict", title="Threat Reports Over Time", template="plotly_white",
                color_discrete_map={"FAKE":"#f44336","SCAM":"#FF9800","MANIPULATED":"#FFB347","FALSE":"#e53935","MIXTURE":"#FFC107","TRUE":"#4CAF50"})
            fig.update_layout(xaxis_title="Date", yaxis_title="Reports", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, width="stretch")
        st.subheader("📊 Breakdown")
        bc1,bc2 = st.columns(2)
        with bc1: st.plotly_chart(px.pie(df.groupby("verdict").size().reset_index(name="n"), names="verdict", values="n", title="By Verdict", template="plotly_white"), width='stretch')
        with bc2: st.plotly_chart(px.bar(df.groupby("category").size().reset_index(name="n"), x="category", y="n", title="By Category", color="n", color_continuous_scale=["#FFF8E7","#E5A100"], template="plotly_white"),  width='stretch')
    else:
        st.info("📭 No data yet. Submit a message from the Citizen tab to populate the dashboard.")
    # Community Feed
    st.markdown("<hr class='ls-divider'>", unsafe_allow_html=True)
    st.subheader("💬 Community Intelligence Feed")
    fc1,fc2,_ = st.columns([0.3,0.3,0.4])
    with fc1: ff = st.selectbox("Filter verdict", ["ALL","FAKE","SCAM","MANIPULATED","FALSE","MIXTURE"], key="ff")
    with fc2: fs = st.selectbox("Sort by", ["Latest","Most Upvoted"], key="fs")
    feed = get_community_feed_filtered(verdict_filter=ff if ff!="ALL" else None, sort_by="upvotes" if fs=="Most Upvoted" else "latest", limit=20)
    if feed:
        for item in feed:
            v = item["verdict"]; bc = f"badge-{v.lower()}" if v.lower() in ["fake","scam","manipulated","false","mixture","true"] else "badge-false"
            try:
                ts = datetime.strptime(item["timestamp"], "%Y-%m-%d %H:%M:%S"); d = datetime.now()-ts
                tstr = f"{d.days}d ago" if d.days>0 else f"{d.seconds//3600}h ago" if d.seconds>3600 else f"{d.seconds//60}m ago"
            except: tstr = item["timestamp"]
            f1,f2 = st.columns([0.85,0.15])
            with f1: st.markdown(f'<div class="feed-card"><span class="severity-badge {bc}">{v}</span> {item["snippet"][:100]} <span style="color:#b0a99c;float:right;font-size:0.78rem;">{tstr}</span></div>', unsafe_allow_html=True)
            with f2:
                if st.button(f"⬆️ {item['upvotes']}", key=f"up_{item['id']}"): upvote_feed_item(item['id']); st.rerun()
    else: st.info("No community items match this filter yet.")

st.markdown('<div class="ls-footer">Lumina Shield &copy; 2026 &nbsp;&middot;&nbsp; GenAI Hackathon &nbsp;&middot;&nbsp; Protecting users worldwide &nbsp;&middot;&nbsp; <a href="#">Privacy</a></div>', unsafe_allow_html=True)

