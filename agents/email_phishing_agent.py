"""
Email Phishing Agent — LLM + RAG pipeline
==========================================
Four features powered by a TF-IDF RAG index built from the training CSV:

1. classify_email          — phishing / safe verdict with confidence
2. analyse_phishing_dna    — campaign fingerprint & tactic breakdown
3. analyse_email_forensics — header/sender/URL heuristics + LLM scoring
4. generate_safety_report  — plain-language "what to do" action guide
"""

import os
import re
import json
import pathlib
import functools
import numpy as np

# ── Lazy RAG index ──────────────────────────────────────────────────────────
_INDEX: dict | None = None   # built once, shared across all calls
_CSV_PATH = pathlib.Path(__file__).parent.parent / "data" / "email_csv" / "Phishing_Email.csv"

def _build_rag_index() -> dict:
    """Load CSV and build a TF-IDF matrix for retrieval. Cached at module level."""
    import pandas as pd
    from sklearn.feature_extraction.text import TfidfVectorizer

    df = pd.read_csv(_CSV_PATH, usecols=["Email Text", "Email Type"])
    df = df.dropna(subset=["Email Text", "Email Type"])
    df["Email Text"] = df["Email Text"].astype(str)

    vectorizer = TfidfVectorizer(
        max_features=20_000,
        ngram_range=(1, 2),
        sublinear_tf=True,
        stop_words="english",
        min_df=2,
    )
    matrix = vectorizer.fit_transform(df["Email Text"])

    return {
        "vectorizer": vectorizer,
        "matrix": matrix,
        "texts": df["Email Text"].tolist(),
        "labels": df["Email Type"].tolist(),
    }


def _get_index() -> dict:
    global _INDEX
    if _INDEX is None:
        _INDEX = _build_rag_index()
    return _INDEX


def _retrieve_similar(email_text: str, k: int = 6) -> list[dict]:
    """Return top-k most similar training examples with their labels."""
    from sklearn.metrics.pairwise import cosine_similarity

    idx = _get_index()
    vec = idx["vectorizer"].transform([email_text])
    scores = cosine_similarity(vec, idx["matrix"]).flatten()
    top_k = np.argsort(scores)[::-1][:k]

    results = []
    for i in top_k:
        results.append({
            "text": idx["texts"][i][:300],
            "label": idx["labels"][i],
            "score": float(scores[i]),
        })
    return results


# ── LLM helper — Groq primary, Gemini fallback ──────────────────────────────

def _llm_generate(prompt: str, temperature: float = 0.2) -> str:
    """Call Groq (llama-3.3-70b) first; fall back to Gemini if unavailable."""
    groq_key = os.getenv("GROQ_API_KEY")
    if groq_key:
        try:
            import groq as _groq_sdk
            client = _groq_sdk.Groq(api_key=groq_key, max_retries=0, timeout=30.0)
            resp = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                temperature=temperature,
                max_tokens=1200,
            )
            return resp.choices[0].message.content.strip()
        except Exception:
            pass  # fall through to Gemini

    # Gemini fallback
    from google import genai
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("Neither GROQ_API_KEY nor GEMINI_API_KEY is set.")
    client = genai.Client(api_key=api_key)
    resp = client.models.generate_content(
        model="gemini-2.0-flash",
        contents=prompt,
        config={"temperature": temperature, "max_output_tokens": 1200},
    )
    return resp.text.strip()


def _parse_json_from_llm(raw: str) -> dict:
    """Strip markdown fences and parse JSON from LLM output."""
    clean = re.sub(r"```(?:json)?", "", raw).strip().strip("`")
    # Try to isolate the first { ... } block
    m = re.search(r"\{.*\}", clean, re.DOTALL)
    if m:
        clean = m.group(0)
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# Feature 1 — Phishing Classifier (LLM + RAG)
# ─────────────────────────────────────────────────────────────────────────────

def classify_email(email_text: str) -> dict:
    """
    Classify an email as Phishing or Safe using RAG + LLM.

    Returns:
        verdict       : "Phishing" | "Safe"
        confidence    : 0-100
        risk_level    : "Critical" | "High" | "Medium" | "Low"
        red_flags     : list[str]
        safe_signals  : list[str]
        summary       : str  (1-2 sentence plain-language explanation)
        rag_examples  : list[dict]  (top similar training samples)
    """
    similar = _retrieve_similar(email_text, k=6)

    # Format RAG context
    rag_ctx = "\n".join(
        f"[Example {i+1} — {ex['label']} | sim={ex['score']:.2f}]\n{ex['text']}\n"
        for i, ex in enumerate(similar)
    )

    phishing_count = sum(1 for ex in similar if "Phishing" in ex["label"])
    safe_count = len(similar) - phishing_count

    prompt = f"""You are a world-class email security analyst combining machine-learning signals with expert reasoning.

TRAINING EXAMPLES (retrieved via TF-IDF similarity from 18,650 labeled emails):
{rag_ctx}

RAG SIGNAL: {phishing_count}/{len(similar)} retrieved examples are phishing, {safe_count}/{len(similar)} are safe.

NEW EMAIL TO CLASSIFY:
\"\"\"
{email_text[:2000]}
\"\"\"

TASK: Classify the new email as "Phishing Email" or "Safe Email". Consider:
- Urgency cues, financial lures, prize claims, romantic bait, credential harvesting
- Suspicious sender patterns, lookalike domains, mismatched reply-to
- Grammar quality, generic greetings, threatening language
- The RAG signal from similar training examples

Respond ONLY with valid JSON (no markdown fences):
{{
  "verdict": "Phishing Email" | "Safe Email",
  "confidence": <integer 0-100>,
  "risk_level": "Critical" | "High" | "Medium" | "Low",
  "red_flags": ["flag1", "flag2", ...],
  "safe_signals": ["signal1", ...],
  "summary": "<1-2 sentence plain-language explanation>"
}}"""

    raw = _llm_generate(prompt, temperature=0.1)
    result = _parse_json_from_llm(raw)

    # Fallbacks
    result.setdefault("verdict", "Phishing Email" if phishing_count > safe_count else "Safe Email")
    result.setdefault("confidence", 70)
    result.setdefault("risk_level", "High" if "Phishing" in result.get("verdict", "") else "Low")
    result.setdefault("red_flags", [])
    result.setdefault("safe_signals", [])
    result.setdefault("summary", "Analysis complete.")
    result["rag_examples"] = similar

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Feature 2 — Phishing DNA: Campaign Fingerprint & Tactic Analysis
# ─────────────────────────────────────────────────────────────────────────────

PHISHING_ARCHETYPES = [
    "Credential Harvesting",
    "Financial Scam / Advance Fee Fraud",
    "Lottery / Prize Notification",
    "Romance / Emotional Manipulation",
    "Urgent Account Alert",
    "CEO / Executive Impersonation (BEC)",
    "Package / Delivery Scam",
    "Tech Support Scam",
    "Adult / Sextortion",
    "Malware / Attachment Lure",
    "Charity / Disaster Relief Fraud",
    "Job Offer Scam",
]

def analyse_phishing_dna(email_text: str, rag_examples: list[dict] | None = None) -> dict:
    """
    Identify the phishing campaign archetype, psychological tactics, and global
    distribution patterns.

    Returns:
        archetype       : str  (one of PHISHING_ARCHETYPES)
        confidence      : int
        tactics         : list[{name, explanation}]
        target_profile  : str  (likely victim demographic)
        global_regions  : list[str]  (where this campaign is common)
        campaign_name   : str  (LLM-assigned campaign label)
        why_dangerous   : str
    """
    if rag_examples is None:
        rag_examples = _retrieve_similar(email_text, k=4)

    rag_ctx = "\n".join(
        f"[{ex['label']}] {ex['text'][:200]}" for ex in rag_examples[:4]
    )
    archetypes_list = "\n".join(f"- {a}" for a in PHISHING_ARCHETYPES)

    prompt = f"""You are a threat intelligence analyst specialising in worldwide phishing campaigns.

KNOWN PHISHING ARCHETYPES:
{archetypes_list}

SIMILAR EMAILS FROM GLOBAL TRAINING CORPUS:
{rag_ctx}

TARGET EMAIL:
\"\"\"
{email_text[:2000]}
\"\"\"

Identify the campaign fingerprint. Respond ONLY with valid JSON:
{{
  "archetype": "<one archetype from the list above>",
  "confidence": <0-100>,
  "campaign_name": "<short memorable name, e.g. 'Nigerian Prince Variant'>",
  "tactics": [
    {{"name": "<tactic name>", "explanation": "<how it's used in this email>"}},
    ...
  ],
  "target_profile": "<likely victim demographic, e.g. 'Elderly internet users unfamiliar with online banking'>",
  "global_regions": ["<region1>", "<region2>", ...],
  "why_dangerous": "<one sentence on the real-world harm this campaign causes>"
}}"""

    raw = _llm_generate(prompt, temperature=0.2)
    result = _parse_json_from_llm(raw)

    result.setdefault("archetype", "Unknown")
    result.setdefault("confidence", 60)
    result.setdefault("campaign_name", "Unknown Campaign")
    result.setdefault("tactics", [])
    result.setdefault("target_profile", "General internet users")
    result.setdefault("global_regions", ["Worldwide"])
    result.setdefault("why_dangerous", "This email attempts to defraud recipients.")

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Feature 3 — Header & Link Forensics
# ─────────────────────────────────────────────────────────────────────────────

_SUSPICIOUS_KEYWORDS = [
    "verify", "confirm", "urgent", "account suspended", "click here",
    "free", "winner", "congratulations", "act now", "limited time",
    "password", "update your", "unusual activity", "validate",
    "claim your", "prize", "lottery", "inheritance", "million",
    "wire transfer", "western union", "gift card", "bitcoin",
]

_SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz",
    ".club", ".icu", ".cam", ".rest", ".surf", ".monster", ".cyou",
    ".ru", ".cn", ".pw", ".cc",
}


def _extract_email_headers(text: str) -> dict:
    """Best-effort extraction of email metadata from raw text."""
    from_match   = re.search(r"(?i)(?:from|sender)\s*[:\-]\s*([^\n\r<]+(?:<[^>]+>)?)", text)
    reply_match  = re.search(r"(?i)reply-to\s*[:\-]\s*([^\n\r]+)", text)
    subject_match = re.search(r"(?i)subject\s*[:\-]\s*([^\n\r]+)", text)
    to_match     = re.search(r"(?i)(?:to|recipient)\s*[:\-]\s*([^\n\r]+)", text)

    urls = list(set(re.findall(r"https?://[^\s\"'<>]+", text, re.IGNORECASE)))
    urls = [u.rstrip(".,;:!?)\"'") for u in urls]

    emails_found = list(set(re.findall(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text
    )))

    return {
        "from": from_match.group(1).strip() if from_match else "",
        "reply_to": reply_match.group(1).strip() if reply_match else "",
        "subject": subject_match.group(1).strip() if subject_match else "",
        "to": to_match.group(1).strip() if to_match else "",
        "urls": urls[:10],
        "emails": emails_found[:8],
    }


def _score_url_suspicion(url: str) -> dict:
    """Heuristic URL danger score."""
    flags = []
    score = 0

    parsed_domain = ""
    m = re.search(r"https?://([^/?\s]+)", url)
    if m:
        parsed_domain = m.group(1).lower()

    tld = "." + parsed_domain.split(".")[-1] if "." in parsed_domain else ""
    if tld in _SUSPICIOUS_TLDS:
        flags.append(f"Suspicious TLD ({tld})")
        score += 30

    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", parsed_domain):
        flags.append("IP address used instead of domain name")
        score += 40

    if len(parsed_domain) > 35:
        flags.append("Unusually long domain (obfuscation attempt)")
        score += 20

    keywords_in_url = [kw for kw in ["login", "verify", "secure", "account", "bank", "paypal", "update"] if kw in url.lower()]
    if keywords_in_url:
        flags.append(f"Deceptive keywords in URL: {', '.join(keywords_in_url)}")
        score += 20

    subdomain_parts = parsed_domain.split(".")
    if len(subdomain_parts) > 4:
        flags.append("Deep subdomain nesting (possible cloaking)")
        score += 15

    if "bit.ly" in url or "tinyurl" in url or "t.co" in url or "rb.gy" in url or "cutt.ly" in url:
        flags.append("URL shortener (hides true destination)")
        score += 25

    return {"url": url, "domain": parsed_domain, "flags": flags, "suspicion_score": min(100, score)}


def analyse_email_forensics(email_text: str) -> dict:
    """
    Extract headers, sender metadata, embedded links and score each for danger.

    Returns:
        headers          : dict
        url_analysis     : list[dict]
        keyword_hits     : list[str]
        sender_trust_score : int (0-100, 100=fully trusted)
        overall_risk     : int (0-100)
        llm_assessment   : str
    """
    headers = _extract_email_headers(email_text)

    url_analysis = [_score_url_suspicion(u) for u in headers["urls"]]

    lower_text = email_text.lower()
    keyword_hits = [kw for kw in _SUSPICIOUS_KEYWORDS if kw in lower_text]

    # Sender trust heuristics
    sender_trust = 100
    sender = headers["from"].lower()
    if any(kw in sender for kw in ["noreply", "service", "support", "help", "team", "info"]):
        sender_trust -= 15
    free_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"]
    if any(fd in sender for fd in free_domains) and len(email_text) < 500:
        sender_trust -= 10  # minor flag only if email is short/suspicious
    if headers["reply_to"] and headers["from"] and headers["reply_to"] != headers["from"]:
        sender_trust -= 25  # reply-to mismatch — classic phishing
    if not headers["from"]:
        sender_trust -= 30

    # Max URL suspicion score
    max_url_risk = max((u["suspicion_score"] for u in url_analysis), default=0)
    keyword_penalty = min(40, len(keyword_hits) * 5)
    overall_risk = min(100, max(max_url_risk, keyword_penalty, 100 - sender_trust))

    # LLM enrichment
    headers_str = json.dumps(headers, indent=2)
    url_str = json.dumps(url_analysis[:5], indent=2)

    prompt = f"""You are an email security expert. Analyse the following forensic data extracted from a suspicious email.

EXTRACTED HEADERS:
{headers_str}

URL ANALYSIS:
{url_str}

SUSPICIOUS KEYWORDS HIT: {keyword_hits}

EMAIL TEXT (first 1200 chars):
\"\"\"
{email_text[:1200]}
\"\"\"

In 3-4 sentences, explain what you observe about the sender identity, link destinations, and psychological pressure tactics used. Focus on what a non-technical person should notice. Be direct and specific."""

    try:
        llm_assessment = _llm_generate(prompt, temperature=0.2)
    except Exception as e:
        llm_assessment = f"Assessment unavailable: {e}"

    return {
        "headers": headers,
        "url_analysis": url_analysis,
        "keyword_hits": keyword_hits,
        "sender_trust_score": max(0, sender_trust),
        "overall_risk": overall_risk,
        "llm_assessment": llm_assessment,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Feature 4 — Personalised Safety Report
# ─────────────────────────────────────────────────────────────────────────────

def generate_safety_report(
    email_text: str,
    classification: dict | None = None,
    dna: dict | None = None,
) -> dict:
    """
    Generate a plain-language personalised safety guide for the analysed email.

    Returns:
        attacker_goal     : str  (what the attacker wants)
        if_you_comply     : str  (what happens if you follow instructions)
        immediate_actions : list[str]  (what to do right now)
        warning_message   : str  (ready-to-forward warning to send contacts)
        detected_language : str
        report_text       : str  (full formatted report)
    """
    verdict = (classification or {}).get("verdict", "Phishing Email")
    archetype = (dna or {}).get("archetype", "Unknown Phishing")
    campaign = (dna or {}).get("campaign_name", "Unknown Campaign")

    prompt = f"""You are Lumina Shield, a friendly cybersecurity assistant helping everyday people stay safe from email scams.

EMAIL (first 1500 chars):
\"\"\"
{email_text[:1500]}
\"\"\"

CLASSIFICATION: {verdict}
CAMPAIGN TYPE: {archetype} — "{campaign}"

Generate a personalised safety report. Respond ONLY with valid JSON:
{{
  "attacker_goal": "<what the attacker is trying to achieve — max 2 sentences>",
  "if_you_comply": "<what bad thing would happen if the victim follows the email instructions — be specific>",
  "immediate_actions": [
    "<action 1>",
    "<action 2>",
    "<action 3>",
    "<action 4>"
  ],
  "warning_message": "<a short WhatsApp/SMS-style message to forward to friends and family warning them about this scam — max 3 sentences, no links>",
  "detected_language": "<primary language of the email, e.g. English, Urdu, Spanish>",
  "report_text": "<a 4-6 sentence plain-language full safety summary — written as if talking to a friend who is not tech-savvy>"
}}"""

    raw = _llm_generate(prompt, temperature=0.3)
    result = _parse_json_from_llm(raw)

    result.setdefault("attacker_goal", "The attacker wants to steal your personal information or money.")
    result.setdefault("if_you_comply", "You risk losing money, having your accounts hacked, or your identity stolen.")
    result.setdefault("immediate_actions", [
        "Do not click any links in this email.",
        "Do not reply to the sender.",
        "Mark it as spam and delete it.",
        "Warn your contacts if you forwarded it.",
    ])
    result.setdefault("warning_message", "⚠️ Warning: A phishing scam email is circulating. Do not click any links or reply. Stay safe!")
    result.setdefault("detected_language", "English")
    result.setdefault("report_text", "This email appears to be a scam. The sender is trying to trick you into giving away sensitive information. Please ignore and delete this email immediately.")

    return result
