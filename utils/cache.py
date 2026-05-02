import streamlit as st
import hashlib
import os
import json
from datetime import datetime, timedelta

def submission_hash(raw_input: str) -> str:
    return hashlib.sha256(raw_input.encode()).hexdigest()

DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"   

# Pre-cached demo responses for 5 demo claims
DEMO_CACHE = {
    # Demo 1: Medical Misinformation (Lemon cures Dengue)
    submission_hash("lemon juice cures dengue please share"): {
        "verdicts": [
            {"label": "FALSE", "claim": "Lemon juice cures Dengue", "confidence": 95, "evidence": "Sarkari health department aur WHO dono ne confirm kiya hai ke nimbu (lemon) dengue nahi rokta. Dengue machar se phailta hai aur iska ilaaj doctor se karwana chahiye.", "tactic_flags": ["FAKE_AUTHORITY","FEAR"]}
        ],
        "tactics": [
            {"tactic": "FAKE_AUTHORITY", "explanation": "Doctor ya WHO ka naam jhuta istemal kar ke bharosa dilane ki koshish ki gai hai."},
            {"tactic": "FEAR", "explanation": "Bimari ka dar dikhakar logon ko pareshan kiya ja raha hai."}
        ],
        "url_checks": []
    },
    
    # Demo 2: Phishing Scam (BISP Free Money)
    submission_hash("BISP Ehsaas program is giving Rs 25000 to every citizen. Register here: http://bisp-free-money.com"): {
        "verdicts": [
            {"label": "SCAM", "claim": "BISP Ehsaas program is giving Rs 25000", "confidence": 100, "evidence": "BISP ki official website .gov.pk par hoti hai. Yeh link nakli hai aur sirf fraud ke liye banaya gaya hai.", "tactic_flags": ["URGENCY"]}
        ],
        "tactics": [
            {"tactic": "URGENCY", "explanation": "Jaldi paise milne ka lalach de kar aapka data chori karne ki koshish hai."}
        ],
        "url_checks": [
            {
                "url": "http://bisp-free-money.com",
                "real_url": "https://bisp.gov.pk",
                "verdict": "FAKE_SITE",
                "risk_score": 98,
                "similarity": 0,
                "flags": ["No HTTPS", "Not a .gov.pk domain", "Known phishing pattern"]
            }
        ]
    },

    # Demo 3: Job Scam (Army Recruitment)
    submission_hash("Join Pak Army today! Direct recruitment for Captain. Send Rs 5000 processing fee to this JazzCash number: 03001234567"): {
        "verdicts": [
            {"label": "FAKE", "claim": "Direct recruitment for Captain by sending Rs 5000", "confidence": 99, "evidence": "Pak Army kabhi bhi recruitment ke liye JazzCash par processing fee nahi mangti. Ye aik fraud scheme hai.", "tactic_flags": ["FAKE_AUTHORITY"]}
        ],
        "tactics": [
            {"tactic": "FAKE_AUTHORITY", "explanation": "Fauj ka naam istemal karke logon se paise batore ja rahe hain."}
        ],
        "url_checks": []
    },

    # Demo 4: Mixed News (Real Event, Exaggerated Numbers)
    submission_hash("Heavy rain in Lahore yesterday. 500 people died in flooding."): {
        "verdicts": [
            {"label": "TRUE", "claim": "Heavy rain in Lahore yesterday", "confidence": 100, "evidence": "Haan, pichle din Lahore mein shadeed barish hui hai."},
            {"label": "FALSE", "claim": "500 people died in flooding", "confidence": 90, "evidence": "Kisi bhi official news agency ya NDMA ne 500 logon ki halakat ki tasdeeq nahi ki hai. Yeh figure exaggerate kiya gaya hai."}
        ],
        "tactics": [
            {"tactic": "FEAR", "explanation": "Maut ki jhuti khabrein phaila kar khauf paida kiya ja raha hai."}
        ],
        "url_checks": []
    },

    # Demo 5: True News (Official Announcement)
    submission_hash("State Bank of Pakistan has issued a new 75 rupee note to commemorate the anniversary."): {
        "verdicts": [
            {"label": "TRUE", "claim": "State Bank of Pakistan issued a new 75 rupee note", "confidence": 98, "evidence": "Yeh khabar bilkul sach hai. SBP ki official website aur news channels ne iski tasdeeq ki hai."}
        ],
        "tactics": [],
        "url_checks": []
    }
}

def get_cached_result(key: str):
    """If DEMO_MODE and key in DEMO_CACHE, return it."""
    if DEMO_MODE:
        for demo_key, value in DEMO_CACHE.items():
            # In production, you'd match exact hash. Here simplified.
            if demo_key in key:  # rough matching for demo
                return value
    return None