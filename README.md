<div align="center">

# 🛡️ Lumina Shield

### AI-Powered Misinformation Detection & Cyber Forensics Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.29.0-FF4B4B?logo=streamlit)](https://streamlit.io/)
[![Gemini](https://img.shields.io/badge/Google_Gemini-2.0_Flash-4285F4?logo=google)](https://ai.google.dev/)
[![Groq](https://img.shields.io/badge/Groq-Llama_3.3_70B-orange)](https://groq.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-RAG_Index-F7931E?logo=scikitlearn)](https://scikit-learn.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

> Detect fake news, phishing scams, manipulated content, and malicious URLs — with multilingual support, real-time threat intelligence, and an AI-powered email phishing scanner trained on 18,650 real-world samples.

</div>

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [App Tabs](#app-tabs)
  - [Basic Mode](#-basic-mode)
  - [Cyber Analyst](#-cyber-analyst)
    - [Basic Mode](#basic-mode-rapid-threat-scan)
    - [Deep Mode](#deep-mode-full-osint--forensics)
  - [Global Dashboard](#-global-dashboard)
- [Email Phishing Scanner](#email-phishing-scanner)
- [Architecture](#architecture)
- [Agent System](#agent-system)
- [Threat Intelligence Integrations](#threat-intelligence-integrations)
- [Verdict System](#verdict-system)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Environment Variables](#environment-variables)
  - [Running the App](#running-the-app)
- [Project Structure](#project-structure)
- [Community Features](#community-features)
- [Tech Stack](#tech-stack)
- [Contributing](#contributing)

---

## Overview

**Lumina Shield** is a multi-agent AI platform that analyzes viral messages, suspicious URLs, and social media content to detect misinformation, phishing campaigns, and manipulation tactics. It combines large language model reasoning with real-time threat intelligence feeds and a multi-layer verification pipeline.

Built for a global audience, it supports **English, Urdu (Roman & Nastaliq), Spanish, Arabic and more** — and can be extended to any language Gemini understands.

### What it solves

| Problem                                            | Lumina Shield's Approach                                                              |
| -------------------------------------------------- | ------------------------------------------------------------------------------------- |
| Viral fake news (WhatsApp, Telegram, social media) | AI decomposition into verifiable claims + LLM fact-checking                           |
| Phishing / scam URLs                               | 12+ concurrent enrichment checks (VirusTotal, AbuseIPDB, WHOIS, DNS, SSL)             |
| Phishing emails                                    | RAG index of 18,650 labeled emails + LLM classifier, forensics & campaign fingerprint |
| Manipulation tactics in content                    | Pattern detection: urgency, fear, fake authority, suppression, social proof           |
| Multilingual misinformation                        | Automatic language detection, transliteration, localized verdicts                     |
| Domain impersonation                               | Typosquatting detection, domain age checks, DNS genealogy graphs                      |

---

## Key Features

- **🔍 Multi-Layer Fact Checking** — 5-layer verification pipeline from whitelist matching to LLM knowledge fallback
- **📧 Email Phishing Scanner** — LLM + RAG classifier trained on 18,650 real phishing emails; 4 analysis features
- **🦠 IOC Enrichment** — Asynchronous parallel enrichment of IPs, domains, hashes, and emails via 30+ sources
- **🧠 Manipulation Detection** — Identifies 6 psychological manipulation tactics (URGENCY, FEAR, FAKE_AUTHORITY, SUPPRESSION, RELIGIOUS_FRAMING, SOCIAL_PROOF)
- **🌐 Multilingual** — English, Urdu (Roman + Nastaliq), Arabic, Spanish — extensible to any language supported by Gemini
- **🗺️ Domain Genealogy** — Interactive network graph of DNS records, subdomains, registrar, and typosquatting neighbors
- **🔬 Deep Mode** — Full OSINT pivot, passive DNS history, BGP/ASN intel, threat actor profiling, MITRE ATT&CK mapping, kill-chain reconstruction, and YARA/Snort rule forge
- **📑 Deep Intelligence PDF** — Comprehensive branded report covering all basic forensics + deep analysis sections
- **🌍 Heatmap** — Geographic distribution of detected misinformation by category
- **👥 Community Feed** — Shared, deduplicated verdicts with upvote system
- **📄 PDF Reports** — Forensic reports with branded layout, shareable PNG verdict cards, and QR codes
- **⚡ Demo Mode** — Bypass API rate limits for testing and demonstrations
- **💾 Disk Cache** — Persistent, namespace-based cache with expiry and purge UI

---

## App Tabs

The app is organized into **3 tabs**:

### 🌍 Basic Mode

Designed for general users, journalists, and anyone who receives a suspicious message:

- Paste any viral message, URL, or social media post
- AI decomposes it into verifiable claims and extracts IOCs
- 5-layer fact-check pipeline produces a plain-language verdict
- Manipulation tactic detection (urgency, fear, fake authority, etc.)
- Multilingual input and output support
- **📧 Email Phishing Scanner** — sub-mode for pasting raw emails

### 🔍 Cyber Analyst

A single unified tab with a **Basic / Deep Mode** toggle at the top:

#### Basic Mode — Rapid Threat Scan

Submit any URL, domain, IP address, or file hash for:

- Multi-engine VirusTotal scan with per-vendor verdict table
- AI executive summary + narrative intelligence score
- Attack scenario probability bars
- Redirect chain visualization
- IOC extraction table (IPs, domains, hashes, emails)
- WHOIS, SSL certificate, HTTP response metadata
- ThreatFox IOC database cross-reference
- AlienVault OTX threat intelligence pulses
- **📄 PDF Report** — branded forensic report

#### Deep Mode — Full OSINT & Forensics

Everything in Basic Mode, plus full infrastructure intelligence:

| Feature                          | Description                                                                   |
| -------------------------------- | ----------------------------------------------------------------------------- |
| **🕸️ Threat Genealogy Graph**    | Interactive vis-network graph of DNS, IPs, subdomains, registrar, SPF/DMARC   |
| **📡 Passive DNS History**       | CIRCL PDNS — every IP this domain ever resolved to                            |
| **🌍 Subdomains**                | crt.sh certificate transparency subdomain enumeration                         |
| **📧 Email Security**            | SPF / DMARC posture check                                                     |
| **🔎 OSINT Pivot**               | Domain → IPs → ASN → sibling domains → open ports (Shodan) → CVEs             |
| **📸 Web Screenshot**            | URLScan.io live snapshot with malice score                                    |
| **🏘️ Typosquatting Detection**   | Active lookalike domain probing                                               |
| **🦠 Campaign Intel**            | URLHaus, ThreatFox, campaign attribution, community timeline                  |
| **🎯 Threat Actor Profile**      | AI-matched APT groups, MITRE ATT&CK tactics & techniques heatmap              |
| **⛓️ Kill-Chain Reconstruction** | Phase-by-phase behavioral mapping to the Cyber Kill Chain                     |
| **🛡️ YARA / Snort Forge**        | AI-generated detection rules ready to deploy in your SOC                      |
| **📝 Research Annotations**      | Tag and note domains; stored in local SQLite                                  |
| **📑 Deep Intelligence PDF**     | Full report: forensics + threat actor + kill chain + YARA/Snort + annotations |

### 📊 Global Dashboard

- **Folium heatmap** — geographic misinformation density by city
- **Threat timeline** — Plotly area chart of reports over time by verdict
- **Verdict breakdown** — pie and bar charts
- **Community Feed** — filterable, sortable shared intelligence feed with upvote system

---

## Email Phishing Scanner

Available as a dedicated **"📧 Email Phishing"** mode inside the Basic Mode tab. Paste any raw email (headers + body) and the pipeline runs four sequential analyses:

### Feature 1 — 🎯 AI Email Classifier (LLM + RAG)

A **TF-IDF RAG index** is built at startup from the full training corpus of **18,650 labeled emails** (7,328 phishing, 11,322 safe). For each new email:

1. The top-6 most similar training emails are retrieved via cosine similarity
2. Retrieved examples + their labels are injected into the LLM context
3. **Groq `llama-3.3-70b-versatile`** classifies the email and returns:
   - **Verdict**: `Phishing Email` or `Safe Email`
   - **Confidence**: 0–100%
   - **Risk Level**: Critical / High / Medium / Low
   - **Red Flags**: specific reasons it looks like phishing
   - **Safe Signals**: reasons it might be legitimate
   - **RAG Examples**: the nearest training emails with similarity scores

### Feature 2 — 🧬 Phishing DNA: Campaign Fingerprint

The LLM matches the email against **12 worldwide phishing archetypes** and identifies:

| Field          | Example                                              |
| -------------- | ---------------------------------------------------- |
| Archetype      | `Credential Harvesting`, `Romance Scam`, `BEC`, etc. |
| Campaign Name  | `Nigerian Prince Variant`, `PayPal Suspension Lure`  |
| Tactics Used   | Urgency, impersonation, fake authority               |
| Target Profile | Elderly users, corporate finance teams, etc.         |
| Global Regions | Countries / regions where this campaign is active    |
| Why Dangerous  | One-sentence real-world harm summary                 |

Supported archetypes: Credential Harvesting · Financial Scam / Advance Fee Fraud · Lottery / Prize Notification · Romance / Emotional Manipulation · Urgent Account Alert · CEO / Executive Impersonation (BEC) · Package / Delivery Scam · Tech Support Scam · Adult / Sextortion · Malware / Attachment Lure · Charity / Disaster Relief Fraud · Job Offer Scam

### Feature 3 — 🔬 Header & Link Forensics

- **Header extraction** — From, Reply-To, Subject, To (mismatch is a strong phishing signal)
- **Sender trust score** (0–100) based on free-domain use, missing sender, reply-to mismatch
- **URL suspicion scoring** — Flags suspicious TLDs, IP-as-domain, URL shorteners, deceptive keywords
- **Keyword hits** — 20+ known phishing trigger words detected in body text
- **LLM forensic assessment** — Plain-language explanation of what the AI sees

### Feature 4 — 🛡️ Personalised Safety Report

- **Attacker Goal** — What the attacker is trying to achieve
- **If You Comply** — Specific harm that would result
- **Immediate Action Steps** — Numbered list of what to do right now
- **WhatsApp Warning Message** — Ready-to-forward warning in the email's own language
- **Full Safety Summary** — Written for non-technical readers

> **LLM Stack:** Groq `llama-3.3-70b-versatile` is the primary inference engine. Gemini `gemini-2.0-flash` is the automatic fallback.

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
        ┌─────────┼──────────────┐
        ▼         ▼              ▼
   Citizen    Cyber Card    Deep Mode
    Card      (Basic)       (OSINT + ATT&CK
                             + Kill Chain
                             + YARA/Snort)
```

---

## Agent System

Lumina Shield is built around **9 specialized agents**:

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

Also provides deep-mode AI functions:

- `generate_threat_actor_profile` — APT attribution + MITRE ATT&CK mapping
- `generate_kill_chain_timeline` — Phase-by-phase Cyber Kill Chain reconstruction
- `generate_yara_rule` / `generate_snort_rule` — AI-generated detection rules

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

Transforms raw analysis into persona-appropriate output cards:

- **Citizen Card** — Plain-language verdict, WhatsApp reply template, action guide
- **Cyber Card** — Risk score (0–10), severity rating, IOC summary table
- **Researcher Card** — Domain genealogy graph, campaign fingerprint, confidence reasoning

### 7. `Cartographer`

Builds an interactive **domain genealogy graph** using Pyvis/NetworkX:

- DNS records: A, AAAA, MX, NS, TXT, CNAME
- Certificate transparency subdomain enumeration
- Registrar, creation date, country node
- Typosquatting neighbor detection and active domain probing

### 8. `Searcher`

Two-pass web verification:

1. **Gemini** performs grounded web searches and returns source metadata
2. **Groq (Llama)** structures results into a JSON verdict with confidence score

### 9. `Email Phishing Agent`

LLM + RAG pipeline for email phishing analysis:

- Builds a **TF-IDF index** (20,000 features, bigrams, sublinear TF) over 18,650 labeled emails at startup
- `classify_email` — RAG retrieval + Groq LLM classification
- `analyse_phishing_dna` — Campaign archetype + psychological tactics
- `analyse_email_forensics` — Header/link heuristics + LLM assessment
- `generate_safety_report` — Personalised action guide + shareable warning

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
| 8–10  | 🚨 CRITICAL |

---

## Getting Started

### Prerequisites

- Python 3.10 or higher
- A **Groq API key** (primary LLM — free tier, no quota issues)
- A **Google Gemini API key** (fallback LLM + web search grounding)
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
GROQ_API_KEY=your_groq_api_key          # Primary LLM (llama-3.3-70b-versatile)
GEMINI_API_KEY=your_google_gemini_api_key  # Fallback LLM + web search grounding

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
├── agents/                       # 9 specialized AI agents
│   ├── translator.py             # Language detection & IOC extraction
│   ├── decomposer.py             # Claim + CTA decomposition
│   ├── misinfo_investigator.py   # 5-layer fact-checking engine
│   ├── threat_investigator.py    # Async IOC enrichment + deep AI analysis
│   ├── tactic_analyser.py        # Manipulation pattern detection
│   ├── narrator.py               # Persona-specific output generation
│   ├── cartographer.py           # Domain genealogy graph + typosquatting
│   ├── searcher.py               # Web search + LLM structuring
│   └── email_phishing_agent.py   # LLM + RAG email phishing scanner (4 features)
│
├── utils/
│   ├── api_clients.py            # HTTP client wrappers for all integrations
│   ├── cache.py                  # In-memory cache utilities
│   ├── disk_cache.py             # Persistent namespace-based cache
│   └── report_generator.py       # PDF reports: basic forensic + deep intelligence
│
├── data/
│   ├── db.py                     # SQLite database schema & operations
│   ├── source_whitelist.json     # Curated trusted global source list
│   └── email_csv/
│       └── Phishing_Email.csv    # 18,650 labeled emails (RAG training corpus)
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

## Community Features

- **Community Feed** — Anonymized verdict snippets shared across users, deduplicated by content hash
- **Upvote System** — Community validation of verdicts
- **Annotations** — Tag and annotate URLs/domains with researcher notes; exported in Deep Intelligence PDF
- **Heatmap** — Folium-based geographic map showing misinformation density by city and category
- **Trending Campaigns** — Automatically surfaces recurring domains and claim patterns

---

## Tech Stack

| Category                | Technology                              |
| ----------------------- | --------------------------------------- |
| **UI Framework**        | Streamlit 1.29.0                        |
| **Primary LLM**         | Groq — Llama 3.3 70B Versatile          |
| **Fallback LLM**        | Google Gemini 2.0 Flash                 |
| **RAG / ML**            | scikit-learn TF-IDF (20k features)      |
| **Database**            | SQLite (via Python `sqlite3`)           |
| **Async Execution**     | Python `asyncio` + `concurrent.futures` |
| **Graph Visualization** | NetworkX + Pyvis + vis-network.js       |
| **Map Visualization**   | Folium                                  |
| **Data Visualization**  | Plotly                                  |
| **PDF Generation**      | ReportLab (basic forensic + deep intel) |
| **Image Generation**    | Pillow (PIL)                            |
| **QR Codes**            | qrcode                                  |
| **Web Scraping**        | requests + BeautifulSoup4               |
| **DNS Resolution**      | dnspython                               |
| **Text Processing**     | regex, textwrap                         |
| **Input Validation**    | validators                              |
| **Email Training Data** | 18,650 labeled phishing/safe emails     |

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

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Email Phishing Scanner](#email-phishing-scanner)
- [Architecture](#architecture)
- [Agent System](#agent-system)
- [Threat Intelligence Integrations](#threat-intelligence-integrations)
- [Verdict System](#verdict-system)
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

| Problem                                            | Lumina Shield's Approach                                                              |
| -------------------------------------------------- | ------------------------------------------------------------------------------------- |
| Viral fake news (WhatsApp, Telegram, social media) | AI decomposition into verifiable claims + LLM fact-checking                           |
| Phishing / scam URLs                               | 12+ concurrent enrichment checks (VirusTotal, AbuseIPDB, WHOIS, DNS, SSL)             |
| Phishing emails                                    | RAG index of 18,650 labeled emails + LLM classifier, forensics & campaign fingerprint |
| Manipulation tactics in content                    | Pattern detection: urgency, fear, fake authority, suppression, social proof           |
| Multilingual misinformation                        | Automatic language detection, transliteration, localized verdicts                     |
| Domain impersonation                               | Typosquatting detection, domain age checks, DNS genealogy graphs                      |

---

## Key Features

- **🔍 Multi-Layer Fact Checking** — 5-layer verification pipeline from whitelist matching to LLM knowledge fallback
- **📧 Email Phishing Scanner** — LLM + RAG classifier trained on 18,650 real phishing emails; 4 analysis features (see below)
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

## Email Phishing Scanner

Available as a dedicated **"📧 Email Phishing"** mode inside the Basic Mode tab. Paste any raw email (headers + body) and the pipeline runs four sequential analyses:

### Feature 1 — 🎯 AI Email Classifier (LLM + RAG)

A **TF-IDF RAG index** is built at startup from the full training corpus of **18,650 labeled emails** (7,328 phishing, 11,322 safe). For each new email:

1. The top-6 most similar training emails are retrieved via cosine similarity
2. Retrieved examples + their labels are injected into the LLM context
3. **Groq `llama-3.3-70b-versatile`** classifies the email and returns:
   - **Verdict**: `Phishing Email` or `Safe Email`
   - **Confidence**: 0–100%
   - **Risk Level**: Critical / High / Medium / Low
   - **Red Flags**: specific reasons it looks like phishing
   - **Safe Signals**: reasons it might be legitimate
   - **RAG Examples**: the nearest training emails with similarity scores, shown in the UI

### Feature 2 — 🧬 Phishing DNA: Campaign Fingerprint

The LLM matches the email against **12 worldwide phishing archetypes** and identifies:

| Field          | Example                                              |
| -------------- | ---------------------------------------------------- |
| Archetype      | `Credential Harvesting`, `Romance Scam`, `BEC`, etc. |
| Campaign Name  | `Nigerian Prince Variant`, `PayPal Suspension Lure`  |
| Tactics Used   | Urgency, impersonation, fake authority               |
| Target Profile | Elderly users, corporate finance teams, etc.         |
| Global Regions | Countries / regions where this campaign is active    |
| Why Dangerous  | One-sentence real-world harm summary                 |

Supported archetypes: Credential Harvesting · Financial Scam / Advance Fee Fraud · Lottery / Prize Notification · Romance / Emotional Manipulation · Urgent Account Alert · CEO / Executive Impersonation (BEC) · Package / Delivery Scam · Tech Support Scam · Adult / Sextortion · Malware / Attachment Lure · Charity / Disaster Relief Fraud · Job Offer Scam

### Feature 3 — 🔬 Header & Link Forensics

Regex-based extraction of email metadata combined with heuristic URL scoring:

- **Header extraction** — From, Reply-To, Subject, To (mismatch between From and Reply-To is a strong phishing signal)
- **Sender trust score** (0–100) based on free-domain use, missing sender, reply-to mismatch
- **URL suspicion scoring** — Flags suspicious TLDs, IP-as-domain, URL shorteners, deceptive keywords, deep subdomains
- **Keyword hits** — 20+ known phishing trigger words detected in body text
- **LLM forensic assessment** — Plain-language explanation of what the AI sees in the metadata

### Feature 4 — 🛡️ Personalised Safety Report

Generates a human-friendly safety guide tailored to the detected campaign:

- **Attacker Goal** — What the attacker is trying to achieve
- **If You Comply** — Specific harm that would result from following the email's instructions
- **Immediate Action Steps** — Numbered list of what to do right now
- **WhatsApp Warning Message** — Ready-to-forward warning in the email's own language
- **Full Safety Summary** — Written for non-technical readers

> **LLM Stack:** Groq `llama-3.3-70b-versatile` is the primary inference engine (generous free tier, no quota issues). Gemini `gemini-2.0-flash` is the automatic fallback if Groq is unavailable.

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

Lumina Shield is built around **9 specialized agents** that operate in a coordinated pipeline:

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

### 9. `Email Phishing Agent`

LLM + RAG pipeline for email phishing analysis. See [Email Phishing Scanner](#email-phishing-scanner) for full details.

- Builds a **TF-IDF index** (20,000 features, bigrams, sublinear TF) over 18,650 labeled emails at startup
- `classify_email` — RAG retrieval + Groq LLM classification
- `analyse_phishing_dna` — Campaign archetype + psychological tactics
- `analyse_email_forensics` — Header/link heuristics + LLM assessment
- `generate_safety_report` — Personalised action guide + shareable warning

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
- A **Groq API key** (primary LLM — free tier, no quota issues)
- A **Google Gemini API key** (fallback LLM + web search grounding)
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
GROQ_API_KEY=your_groq_api_key          # Primary LLM (llama-3.3-70b-versatile)
GEMINI_API_KEY=your_google_gemini_api_key  # Fallback LLM + web search grounding

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
├── agents/                       # 9 specialized AI agents
│   ├── translator.py             # Language detection & IOC extraction
│   ├── decomposer.py             # Claim + CTA decomposition
│   ├── misinfo_investigator.py   # 5-layer fact-checking engine
│   ├── threat_investigator.py    # Async IOC enrichment (12 tasks)
│   ├── tactic_analyser.py        # Manipulation pattern detection
│   ├── narrator.py               # Persona-specific output generation
│   ├── cartographer.py           # Domain genealogy graph
│   ├── searcher.py               # Web search + LLM structuring
│   └── email_phishing_agent.py   # LLM + RAG email phishing scanner (4 features)
│
├── utils/
│   ├── api_clients.py            # HTTP client wrappers
│   ├── cache.py                  # In-memory cache utilities
│   ├── disk_cache.py             # Persistent namespace-based cache
│   └── report_generator.py       # PDF report + PNG verdict card generation
│
├── data/
│   ├── db.py                     # SQLite database schema & operations
│   ├── source_whitelist.json     # Curated trusted global source list
│   └── email_csv/
│       └── Phishing_Email.csv    # 18,650 labeled emails (RAG training corpus)
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
| **Primary LLM**         | Groq — Llama 3.3 70B Versatile          |
| **Fallback LLM**        | Google Gemini 2.0 Flash                 |
| **RAG / ML**            | scikit-learn TF-IDF (20k features)      |
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
| **Email Training Data** | 18,650 labeled phishing/safe emails     |

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
