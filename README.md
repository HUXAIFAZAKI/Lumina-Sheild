<div align="center">

# 🛡️ Lumina Shield

### AI-Powered Misinformation Detection & Cyber Forensics Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.29.0-FF4B4B?logo=streamlit)](https://streamlit.io/)
[![Gemini](https://img.shields.io/badge/Google_Gemini-2.5_Flash_Lite-4285F4?logo=google)](https://ai.google.dev/)
[![Groq](https://img.shields.io/badge/Groq-Llama_3-orange)](https://groq.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

> Detect fake news, phishing scams, manipulated content, and malicious URLs — with multilingual support and real-time threat intelligence for anyone, anywhere.

</div>

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Agent System](#agent-system)
- [Threat Intelligence Integrations](#threat-intelligence-integrations)
- [Verdict System](#verdict-system)
- [Screenshots](#screenshots)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Environment Variables](#environment-variables)
  - [Running the App](#running-the-app)
- [Project Structure](#project-structure)
- [Persona Modes](#persona-modes)
- [Community Features](#community-features)
- [Tech Stack](#tech-stack)
- [Contributing](#contributing)

---

## Overview

**Lumina Shield** is a multi-agent AI platform that analyzes viral messages, suspicious URLs, and social media content to detect misinformation, phishing campaigns, and manipulation tactics. It combines large language model reasoning with real-time threat intelligence feeds and a multi-layer verification pipeline.

Built for a global audience, it supports **English, Urdu (Roman & Nastaliq), Spanish, Arabic and more** — and can be extended to any language Gemini understands.

### What it solves

| Problem                                            | Lumina Shield's Approach                                                    |
| -------------------------------------------------- | --------------------------------------------------------------------------- |
| Viral fake news (WhatsApp, Telegram, social media) | AI decomposition into verifiable claims + LLM fact-checking                 |
| Phishing / scam URLs                               | 12+ concurrent enrichment checks (VirusTotal, AbuseIPDB, WHOIS, DNS, SSL)   |
| Manipulation tactics in content                    | Pattern detection: urgency, fear, fake authority, suppression, social proof |
| Multilingual misinformation                        | Automatic language detection, transliteration, localized verdicts           |
| Domain impersonation                               | Typosquatting detection, domain age checks, DNS genealogy graphs            |

---

## Key Features

- **🔍 Multi-Layer Fact Checking** — 5-layer verification pipeline from whitelist matching to LLM knowledge fallback
- **🦠 IOC Enrichment** — Asynchronous parallel enrichment of IPs, domains, hashes, and emails via 30+ sources
- **🧠 Manipulation Detection** — Identifies 6 psychological manipulation tactics (URGENCY, FEAR, FAKE_AUTHORITY, SUPPRESSION, RELIGIOUS_FRAMING, SOCIAL_PROOF)
- **🌐 Multilingual** — English, Urdu (Roman + Nastaliq), Arabic, Spanish — extensible to any language supported by Gemini
- **🗺️ Domain Genealogy** — Interactive network graph of DNS records, subdomains, registrar, and typosquatting neighbors
- **🌍 Heatmap** — Geographic distribution of detected misinformation by category
- **👥 Community Feed** — Shared, deduplicated verdicts with upvote system
- **📄 PDF Reports** — Full forensic report with branded layout, shareable PNG verdict cards, and QR codes
- **⚡ Demo Mode** — Bypass API rate limits for testing and demonstrations
- **💾 Disk Cache** — Persistent, namespace-based cache with expiry and purge UI

---

## Architecture

```
Viral Message / URL
        │
        ▼
┌───────────────┐
│  Translator   │  Language detection, transliteration, IOC extraction
└───────┬───────┘
        │
        ▼
┌───────────────┐
│  Decomposer   │  Extract claims, CTAs, entities, dates, locations (Gemini)
└───────┬───────┘
        │
   ┌────┴────┐
   │         │
   ▼         ▼
┌──────────────────┐   ┌──────────────────────┐
│ Misinfo          │   │ Threat Investigator   │
│ Investigator     │   │ (12 async tasks)      │
│ (5-layer check)  │   │ VT · WHOIS · DNS      │
│                  │   │ AbuseIPDB · OTX · SSL │
└────────┬─────────┘   └──────────┬───────────┘
         │                        │
         └──────────┬─────────────┘
                    │
                    ▼
         ┌──────────────────┐
         │ Tactic Analyser  │  6 manipulation patterns
         └────────┬─────────┘
                  │
                  ▼
         ┌──────────────────┐
         │    Narrator      │  Persona-specific output cards
         └────────┬─────────┘
                  │
        ┌─────────┼──────────┐
        ▼         ▼          ▼
   Citizen     Cyber     Researcher
    Card        Card       Card
```

---

## Agent System

Lumina Shield is built around **8 specialized agents** that operate in a coordinated pipeline:

### 1. `Translator`

Detects language, transliterates non-Latin scripts to normalized English, and extracts structured artifacts (URLs, IPs, phone numbers, emails) from raw message text.

### 2. `Decomposer`

Uses Gemini with structured JSON prompts to break a viral message into:

- **Claims** — Categorized as factual, statistical, identity, policy, or crisis
- **CTAs** — Links, phone numbers, download instructions
- **Metadata** — Named entities, dates, locations, monetary amounts

### 3. `Misinfo Investigator`

Five-layer verification engine:

1. **Whitelist** — Direct match against a curated list of trusted global sources
2. **Structural red-flags** — Government/brand keyword spoofing, free TLD abuse (`.xyz`, `.tk`, `.ml`)
3. **Similarity scoring** — Levenshtein distance against trusted domains
4. **Domain age** — WHOIS creation date; domains < 30 days old flagged
5. **LLM fallback** — Gemini knowledge-grounded web search with Groq structuring

### 4. `Threat Investigator`

Runs **12 concurrent async enrichment tasks** on every IOC extracted:

- VirusTotal scan, AbuseIPDB score, AlienVault OTX pulses
- WHOIS registration data, passive DNS history (CIRCL PDNS)
- SSL/TLS certificate chain, HTTP response headers
- Geolocation + ASN (BGPView), Shodan open ports & CVEs
- PhishTank lookup, URLhaus check, URLScan live scan
- Certificate transparency subdomains (crt.sh)

### 5. `Tactic Analyser`

Identifies psychological manipulation patterns in message text:

| Tactic              | Example Pattern                                                    |
| ------------------- | ------------------------------------------------------------------ |
| `URGENCY`           | "Act within 24 hours or lose your account"                         |
| `FEAR`              | "Your account will be blocked"                                     |
| `FAKE_AUTHORITY`    | Impersonating government agencies, officials, or well-known brands |
| `SUPPRESSION`       | "Don't tell anyone, limited seats"                                 |
| `RELIGIOUS_FRAMING` | Exploiting religious or cultural sentiment to encourage sharing    |
| `SOCIAL_PROOF`      | "Thousands have already registered"                                |

### 6. `Narrator`

Transforms raw analysis into **persona-appropriate output cards**:

- **Citizen Card** — Plain-language verdict, WhatsApp reply template, action guide
- **Cyber Card** — Risk score (0–10), severity rating, IOC summary table
- **Researcher Card** — Domain genealogy graph, campaign fingerprint, confidence reasoning

### 7. `Cartographer`

Builds an interactive **domain genealogy graph** using Pyvis/NetworkX:

- DNS records: A, AAAA, MX, NS, TXT, CNAME
- Certificate transparency subdomain enumeration
- Registrar, creation date, country node
- Typosquatting neighbor detection

### 8. `Searcher`

Two-pass web verification:

1. **Gemini** performs grounded web searches and returns source metadata
2. **Groq (Llama)** structures results into a JSON verdict with confidence score

---

## Threat Intelligence Integrations

### Paid / API-Keyed

| Service                  | Data Provided                                         |
| ------------------------ | ----------------------------------------------------- |
| **VirusTotal**           | URL/domain/hash scanning, vendor detections, category |
| **AbuseIPDB**            | IP abuse confidence score, country, ISP, reports      |
| **AlienVault OTX**       | Threat intelligence pulses, malware families          |
| **URLScan.io**           | Live site screenshot, DOM snapshot, verdict           |
| **Google Safe Browsing** | Malware / phishing classification                     |
| **Shodan**               | Open ports, banners, CVE references                   |

### Free / No Auth Required

| Service                  | Data Provided                                       |
| ------------------------ | --------------------------------------------------- |
| **WHOIS**                | Domain registrar, creation/expiry dates, registrant |
| **dnspython**            | A, AAAA, MX, NS, TXT, CNAME, SOA records            |
| **crt.sh**               | Certificate transparency subdomain discovery        |
| **ThreatFox** (abuse.ch) | IOC database — malware C2s, botnet infrastructure   |
| **URLhaus** (abuse.ch)   | Malware distribution URLs                           |
| **PhishTank**            | Crowdsourced phishing URL list                      |
| **ip-api.com**           | IP geolocation, ASN, org (45 req/min)               |
| **CIRCL PDNS**           | Passive DNS history                                 |
| **BGPView**              | ASN info, IP prefix, upstream peers                 |
| **HackerTarget**         | Reverse IP lookup                                   |

---

## Verdict System

### Final Verdicts (User-Facing)

| Verdict          | Meaning                                                       |
| ---------------- | ------------------------------------------------------------- |
| ✅ `TRUE`        | Claim is accurate and safe to share                           |
| ❌ `FALSE`       | Completely fabricated content                                 |
| 🚫 `FAKE`        | Fraudulent / scam website                                     |
| ⚠️ `SCAM`        | Real scheme name + fake official link (credential harvesting) |
| 🔶 `MANIPULATED` | True facts wrapped in deceptive framing                       |
| 🔀 `MIXTURE`     | Mix of accurate and false claims                              |

### Risk Score

A composite score (0–10) derived from:

- Structural URL red-flags
- Domain registration age
- VirusTotal vendor detections
- AbuseIPDB confidence score
- Similarity to known-trusted domains

| Score | Severity    |
| ----- | ----------- |
| 0–2   | 🟢 LOW      |
| 3–5   | 🟡 MEDIUM   |
| 6–7   | 🔴 HIGH     |
| 8–10  | 🔴 CRITICAL |

---

## Getting Started

### Prerequisites

- Python 3.10 or higher
- A **Google Gemini API key** (primary LLM)
- A **Groq API key** (fallback LLM + query structuring)
- Optional API keys for enhanced threat intelligence (see [Environment Variables](#environment-variables))

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-username/lumina-shield.git
cd lumina-shield

# 2. Create and activate a virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

### Environment Variables

Create a `.env` file in the root directory. A minimal setup requires only the first two keys:

```env
# ── Required ──────────────────────────────────────────────────────────────────
GEMINI_API_KEY=your_google_gemini_api_key
GROQ_API_KEY=your_groq_api_key

# ── Threat Intelligence (optional but recommended) ────────────────────────────
VIRUSTOTAL_API_KEYS=["your_vt_key_1", "your_vt_key_2"]
ABUSEIPDB_API_KEY=your_abuseipdb_key
ALIENVAULT_OTX_API_KEYS=["your_otx_key"]
URLSCAN_API_KEY=your_urlscan_key
SAFE_BROWSING_API_KEY=your_google_safe_browsing_key
SHODAN_API_KEY=your_shodan_key

# ── Feature Flags (optional) ──────────────────────────────────────────────────
ENABLE_VIRUSTOTAL=true
ENABLE_WHOIS=true
ENABLE_ABUSEIPDB=true
ENABLE_ALIENVAULT_OTX=true
LOG_LEVEL=INFO
```

> **Note:** Multiple API keys can be provided as JSON arrays for automatic rotation to handle rate limits.

### Running the App

```bash
streamlit run app.py
```

The app will be available at `http://localhost:8501` by default.

---

## Project Structure

```
lumina-shield/
│
├── app.py                        # Streamlit application entry point
├── gemini_test.py                # Standalone Gemini search testing
├── requirements.txt
│
├── agents/                       # 8 specialized AI agents
│   ├── translator.py             # Language detection & IOC extraction
│   ├── decomposer.py             # Claim + CTA decomposition
│   ├── misinfo_investigator.py   # 5-layer fact-checking engine
│   ├── threat_investigator.py    # Async IOC enrichment (12 tasks)
│   ├── tactic_analyser.py        # Manipulation pattern detection
│   ├── narrator.py               # Persona-specific output generation
│   ├── cartographer.py           # Domain genealogy graph
│   └── searcher.py               # Web search + LLM structuring
│
├── utils/
│   ├── api_clients.py            # HTTP client wrappers
│   ├── cache.py                  # In-memory cache utilities
│   ├── disk_cache.py             # Persistent namespace-based cache
│   └── report_generator.py       # PDF report + PNG verdict card generation
│
├── data/
│   ├── db.py                     # SQLite database schema & operations
│   └── source_whitelist.json     # Curated trusted global source list
│
├── lib/                          # Bundled frontend libraries
│   ├── vis-9.1.2/                # vis-network (graph visualization)
│   ├── tom-select/               # Tom Select (dropdown UI)
│   └── bindings/
│       └── utils.js
│
└── scripts/                      # Developer utility scripts
    ├── fix_prompt.py
    ├── scratch_dns.py
    └── write_searcher.py
```

---

## Persona Modes

Lumina Shield generates different output views depending on the user's role:

| Persona        | Target Audience         | Output                                                                                     |
| -------------- | ----------------------- | ------------------------------------------------------------------------------------------ |
| **Citizen**    | General public          | Plain-language verdict, emoji indicators, WhatsApp-ready reply, step-by-step action guide  |
| **Cyber**      | Security analysts       | Risk score (0–10), severity badge, full IOC table, flagged engines, WHOIS/SSL details      |
| **Researcher** | Journalists / academics | Domain genealogy graph, campaign archetype, confidence range, source breakdown, PDF report |

---

## Community Features

- **Community Feed** — Anonymized verdict snippets shared across users, deduplicated by content hash
- **Upvote System** — Community validation of verdicts
- **Annotations** — Tag and annotate URLs/domains with researcher notes
- **Heatmap** — Folium-based geographic map showing misinformation density by city and category
- **Trending Campaigns** — Automatically surfaces recurring domains and claim patterns

---

## Tech Stack

| Category                | Technology                              |
| ----------------------- | --------------------------------------- |
| **UI Framework**        | Streamlit 1.29.0                        |
| **Primary LLM**         | Google Gemini 2.5 Flash Lite            |
| **Fallback LLM**        | Groq (Llama 3)                          |
| **Database**            | SQLite (via Python `sqlite3`)           |
| **Async Execution**     | Python `asyncio` + `concurrent.futures` |
| **Graph Visualization** | NetworkX + Pyvis + vis-network.js       |
| **Map Visualization**   | Folium                                  |
| **Data Visualization**  | Plotly                                  |
| **PDF Generation**      | ReportLab                               |
| **Image Generation**    | Pillow (PIL)                            |
| **QR Codes**            | qrcode                                  |
| **Web Scraping**        | requests + BeautifulSoup4               |
| **DNS Resolution**      | dnspython                               |
| **Text Processing**     | regex, textwrap                         |
| **Input Validation**    | validators                              |

---

## Contributing

Contributions are welcome. Please open an issue first to discuss significant changes.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "feat: add your feature"`
4. Push and open a Pull Request

---

<div align="center">

**Lumina Shield** © 2026 · AI-Powered Misinformation Defense  
Built to protect communities from digital deception.

</div>
