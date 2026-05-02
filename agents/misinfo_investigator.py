import groq, os, json, difflib, requests, re, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from bs4 import BeautifulSoup
from datetime import datetime
import whois, pathlib
from urllib.parse import urlparse


def _get_gemini():
    from google import genai
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY not set.")
    return genai.Client(api_key=api_key)


def analyze_image_with_vision(image_bytes: bytes) -> dict:
    import base64
    client = _get_client()
    base64_image = base64.b64encode(image_bytes).decode('utf-8')
    prompt = '''
    You are an expert digital forensics AI analyzing a potentially fake WhatsApp screenshot or news clipping.
    Extract all text clearly.
    Then, provide a brief forensic analysis (e.g., does it look manipulated? Are there obvious fake news templates or suspicious watermarks?).
    Format your response EXACTLY like this:
    TEXT:
    [extracted text here]
    FORENSICS:
    [forensic analysis here]
    '''
    try:
        response = client.chat.completions.create(
            model="meta-llama/llama-4-scout-17b-16e-instruct",
            messages=[
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/jpeg;base64,{base64_image}",
                            },
                        },
                    ],
                }
            ],
            temperature=0.0,
        )
        res = response.choices[0].message.content
        text_part = res.split("FORENSICS:")[0].replace("TEXT:", "").strip()
        forensics_part = res.split("FORENSICS:")[1].strip() if "FORENSICS:" in res else ""
        return {"extracted_text": text_part, "forensic_analysis": forensics_part}
    except Exception as e:
        return {"extracted_text": "", "forensic_analysis": f"Vision analysis failed: {str(e)}"}

def _get_client():
    """Groq client — used only for image/vision analysis."""
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY not set.")
    return groq.Groq(api_key=api_key)

whitelist_path = pathlib.Path(__file__).parent.parent / "data" / "source_whitelist.json"
with open(whitelist_path, "r", encoding="utf-8") as f:
    TRUSTED_SOURCES = json.load(f)

# Build lookup sets once at module load
_TRUSTED_DOMAINS = {s["domain"].lower() for s in TRUSTED_SOURCES}
# Globally credible TLDs (not just Pakistan)
_TRUSTED_OFFICIAL_TLDS = {
    ".gov", ".gov.pk", ".gov.uk", ".gov.au", ".gov.in", ".gc.ca",
    ".edu", ".edu.pk", ".ac.uk", ".ac.in",
    ".org", ".org.pk",
}

# Disposable / free-registration TLDs used heavily in phishing
_SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz",
    ".club", ".icu", ".cam", ".rest", ".surf", ".monster", ".cyou",
    ".uno", ".sbs", ".cfd", ".fun", ".site", ".online", ".store",
    ".click", ".link", ".info", ".work", ".life", ".live",
}

# Government/authority keywords scammers globally love to include
_GOV_KEYWORDS = [
    # Pakistani
    "bisp", "hec", "nadra", "ehsaas", "fbr", "pta", "secp",
    "nha", "nacta", "pmyp", "kamyab", "benazir",
    # Global
    "govt", "gov", "government", "ministry", "official",
    "passport", "visa", "customs", "tax", "irs", "hmrc",
    "scheme", "grant", "relief", "portal", "challan",
]


def _scrape_page(url):
    """Used only as a fallback when Compound + web search isn't triggered."""
    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"}, verify=False)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "html.parser")
            for tag in soup(["script", "style", "nav", "footer"]):
                tag.decompose()
            return soup.get_text(separator=" ", strip=True)[:5000]
    except:
        pass
    return ""


def _extract_urls_from_text(text: str) -> list:
    """Regex-extract every URL and domain-like string from raw text."""
    patterns = [
        r'https?://[^\s\"\'\<\>]+',                        # full URLs
        r'(?<![/@])\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})*(?:/[^\s]*)?',  # bare domains
    ]
    found = set()
    for p in patterns:
        for m in re.findall(p, text, re.IGNORECASE):
            cleaned = m.rstrip(".,;:!?)\"'")
            if "." in cleaned and len(cleaned) > 4:
                found.add(cleaned)
    return list(found)


# =====================================================================
#  ENHANCED FAKE URL DETECTOR  (multi-layer)
# =====================================================================

def _normalize_domain(raw: str) -> str:
    """Strip scheme/path, return just the hostname."""
    if "://" in raw:
        raw = urlparse(raw).netloc
    raw = raw.split("/")[0].split("?")[0].split("#")[0]
    return raw.lower().strip(".")


def _get_tld(domain: str) -> str:
    """Return composite TLD like .gov.pk or .com."""
    parts = domain.split(".")
    if len(parts) >= 3 and parts[-1] == "pk":
        return "." + ".".join(parts[-2:])
    return "." + parts[-1] if parts else ""


def _domain_age_days(domain: str) -> int | None:
    """Return domain age in days, or None if lookup fails."""
    try:
        w = whois.whois(domain)
        cr = w.creation_date
        if isinstance(cr, list):
            cr = cr[0]
        if cr:
            return (datetime.now() - cr).days
    except:
        pass
    return None


def _structural_url_flags(domain: str) -> dict:
    """
    Detect structural red-flags that NO legitimate .gov.pk site has:
    - Hyphenated gov patterns  (bisp-gov-pk.com)
    - Gov keyword in non-.gov.pk TLD  (bisp-fund.xyz)
    - Subdomain spoofing  (bisp.gov.pk.evil.com  ← real TLD is .com)
    - Excessive length / random chars
    """
    flags = {}
    tld = _get_tld(domain)
    parts = domain.split(".")

    # 1 — Hyphen-joined gov patterns  e.g. hec-laptop-gov-pk.com
    if re.search(r'gov[\-\.]pk', domain) and tld not in _TRUSTED_OFFICIAL_TLDS:
        flags["hyphen_gov_spoof"] = True

    # 2 — Gov keyword present but wrong TLD
    base = domain.replace(tld, "").replace(".", "").replace("-", "")
    for kw in _GOV_KEYWORDS:
        if kw in base and tld not in _TRUSTED_OFFICIAL_TLDS:
            flags["gov_keyword_wrong_tld"] = kw
            break

    # 3 — Subdomain spoofing:  something.gov.pk.scam.com
    full = ".".join(parts)
    for trusted_d in _TRUSTED_DOMAINS:
        if trusted_d in full and full != trusted_d and not full.endswith("." + trusted_d):
            flags["subdomain_spoof"] = trusted_d
            break

    # 4 — Suspicious free TLD
    if tld in _SUSPICIOUS_TLDS:
        flags["suspicious_tld"] = tld

    # 5 — Excessive length (most .gov.pk are short)
    if len(domain) > 30:
        flags["excessive_length"] = len(domain)

    # 6 — Multiple hyphens (legitimate Pakistani gov sites almost never have hyphens)
    if domain.count("-") >= 2:
        flags["many_hyphens"] = domain.count("-")

    return flags


def check_fake_url(url: str) -> dict:
    """
    Multi-layer fake-URL detection:
      Layer 1: Exact whitelist match → safe
      Layer 2: Structural red-flag analysis (catches gov-pk.com, bisp.xyz etc.)
      Layer 3: Similarity scoring against whitelist (catches typosquatting)
      Layer 4: Domain age check (young domains are riskier)
    Each layer contributes to a composite risk score.
    """
    domain = _normalize_domain(url)

    # --- Layer 1: Exact match → it's real ---
    if domain in _TRUSTED_DOMAINS:
        return {
            "verdict": "SAFE",
            "similarity": 100,
            "real_url": url,
            "domain_age_days": None,
            "risk": "none",
            "flags": [],
        }

    # --- Layer 2: Structural red-flags ---
    struct_flags = _structural_url_flags(domain)

    # --- Layer 3: Similarity to trusted domains ---
    best_sim = 0.0
    closest = None
    for src in TRUSTED_SOURCES:
        # Compare the "core" (strip TLD) so hec vs hec-laptop still scores high
        src_core = src["domain"].split(".")[0]
        dom_core = domain.split(".")[0].replace("-", "")
        core_sim = difflib.SequenceMatcher(None, dom_core, src_core).ratio()
        full_sim = difflib.SequenceMatcher(None, domain, src["domain"]).ratio()
        sim = max(core_sim, full_sim)
        if sim > best_sim:
            best_sim = sim
            closest = src

    # --- Layer 4: Domain age ---
    age = _domain_age_days(domain)

    # --- Composite decision ---
    risk_score = 0.0
    reasons = []

    # Structural flags are very strong signals
    if struct_flags.get("hyphen_gov_spoof"):
        risk_score += 40
        reasons.append("Uses gov-pk pattern in wrong TLD — classic phishing")
    if struct_flags.get("gov_keyword_wrong_tld"):
        risk_score += 35
        reasons.append(f"Contains govt keyword '{struct_flags['gov_keyword_wrong_tld']}' but TLD is not .gov.pk")
    if struct_flags.get("subdomain_spoof"):
        risk_score += 45
        reasons.append(f"Mimics {struct_flags['subdomain_spoof']} via subdomain spoofing")
    if struct_flags.get("suspicious_tld"):
        risk_score += 20
        reasons.append(f"Uses disposable/free TLD {struct_flags['suspicious_tld']}")
    if struct_flags.get("many_hyphens"):
        risk_score += 10
        reasons.append(f"Unusually many hyphens ({struct_flags['many_hyphens']})")
    if struct_flags.get("excessive_length"):
        risk_score += 5
        reasons.append("Domain name is unusually long")

    # Similarity to a trusted domain (but NOT matching it) is suspicious
    if best_sim > 0.55 and domain not in _TRUSTED_DOMAINS:
        bonus = (best_sim - 0.55) * 80   # 0.55→0, 1.0→36
        risk_score += bonus
        if best_sim > 0.7:
            reasons.append(f"Closely resembles {closest['domain']} (similarity {round(best_sim*100)}%)")

    # Young domain
    if age is not None and age < 90:
        risk_score += 15
        reasons.append(f"Domain only {age} days old")

    # --- Final verdict ---
    risk_score = min(100, risk_score)

    if risk_score >= 40:
        return {
            "verdict": "FAKE_SITE",
            "similarity": round(best_sim * 100),
            "real_url": closest["official_url"] if closest else None,
            "domain_age_days": age,
            "risk": "high" if risk_score >= 60 else "medium",
            "flags": reasons,
            "risk_score": round(risk_score),
        }

    return {
        "verdict": "UNKNOWN",
        "similarity": round(best_sim * 100),
        "real_url": closest["official_url"] if closest else None,
        "domain_age_days": age,
        "risk": "low",
        "flags": reasons,
        "risk_score": round(risk_score),
    }


# =====================================================================
#  MAIN VERIFICATION PIPELINE
# =====================================================================

def verify_claim(claim_data: dict, context_data: dict = None) -> dict:
    """
    Enhanced verification.
    claim_data: The specific claim dict {"type": "...", "text": "..."}
    context_data: The full structured decomposition {"claims": [], "ctas": [], "metadata": {}}
    """
    claim_text = claim_data.get("text", "")
    claim_type = claim_data.get("type", "")

    if claim_type == "religious":
        return {
            "verdict": "UNVERIFIABLE",
            "confidence": 0,
            "source_tier": None,
            "evidence": "SachAI mazhabi fatwe tasdeeq nahi karta.",
            "real_url": None
        }

    # ---- Step 0: Extract ALL URLs from claim text itself ----
    inline_urls = _extract_urls_from_text(claim_text)

    # ---- Step 1: CTA Hijacking & Typosquatting Check ----
    # Gather URLs from decomposer CTAs + inline extraction
    all_urls_to_check = set()
    if context_data and context_data.get("ctas"):
        for cta in context_data["ctas"]:
            if cta["type"] == "url":
                all_urls_to_check.add(cta["text"])
    for u in inline_urls:
        all_urls_to_check.add(u)

    fake_url_results = []
    for url_candidate in all_urls_to_check:
        fake_check = check_fake_url(url_candidate)
        if fake_check["verdict"] == "FAKE_SITE":
            flag_detail = " | ".join(fake_check.get("flags", []))
            return {
                "verdict": "FALSE",
                "confidence": 99,
                "source_tier": 1,
                "evidence": (
                    f"🚨 FAKE LINK DETECTED: '{url_candidate}' is NOT a legitimate site. "
                    f"Real site: {fake_check['real_url']}. "
                    f"Reasons: {flag_detail}. "
                    f"Risk score: {fake_check.get('risk_score', 'N/A')}/100."
                ),
                "real_url": fake_check["real_url"]
            }
        fake_url_results.append(fake_check)

    # ---- Step 2: Metadata Scrutiny (Dates/Locations) ----
    metadata_str = ""
    if context_data and context_data.get("metadata"):
        m = context_data["metadata"]
        metadata_str = f" [Context: Date={m.get('dates')}, Location={m.get('locations')}]"

    # ---- Step 3: Tiered Verification (using new Searcher) ----
    from .searcher import search_and_verify

    # Try searching with context — searcher now does a two-pass verification
    search_result = search_and_verify(claim_text, context_data)

    if search_result["verdict"] != "UNVERIFIABLE":
        verdict = search_result["verdict"]
        if verdict == "TRUE":
            verdict = "VERIFIED"
        return {
            "verdict": verdict,
            "confidence": search_result.get("confidence", 80),
            "source_tier": 3,
            "evidence": search_result.get("evidence", ""),
            "real_url": search_result.get("source_urls", [None])[0] if search_result.get("source_urls") else None
        }

    # ---- Step 4: LLM Knowledge Fallback (Last Resort) ----
    # Build a richer prompt that includes all the context we have
    cta_list = ""
    if all_urls_to_check:
        cta_list = f"\nLinks/CTAs found in message: {', '.join(all_urls_to_check)}"

    knowledge_prompt = (
        f"You are an elite fact-checker specialized in Pakistani misinformation.\n"
        f"Fact-check this claim using your knowledge. Be EXTRA careful about subtle scams.\n\n"
        f"Claim: {claim_text}\n"
        f"Metadata context: {metadata_str}\n"
        f"{cta_list}\n\n"
        f"CRITICAL RULES:\n"
        f"- If the main event is real BUT the link/phone/CTA is NOT the official one, return FALSE.\n"
        f"- If any date, location, or name is wrong, return FALSE.\n"
        f"- If the claim mixes real facts with fabricated details, return MIXTURE.\n"
        f"- Only return TRUE if EVERY detail is accurate.\n\n"
        f"Return JSON: {{\"verdict\": \"TRUE/FALSE/MIXTURE/OUTDATED\", \"confidence\": 0-100, \"explanation\": \"...\"}}"
    )
    try:
        from google.genai import types
        client = _get_gemini()
        response = client.models.generate_content(
            model="gemini-2.5-flash-lite",
            contents=knowledge_prompt,
            config=types.GenerateContentConfig(
                temperature=0.0,
                response_mime_type="application/json",
            ),
        )
        llm = json.loads(response.text)
    except:
        llm = {"verdict": "UNVERIFIABLE", "confidence": 30, "explanation": "LLM check failed."}

    verdict_map = {"TRUE": "VERIFIED", "FALSE": "FALSE", "MIXTURE": "MIXTURE", "OUTDATED": "OUTDATED"}
    return {
        "verdict": verdict_map.get(llm.get("verdict", "").upper(), "UNVERIFIABLE"),
        "confidence": llm.get("confidence", 50),
        "source_tier": 4,
        "evidence": llm.get("explanation", ""),
        "real_url": None
    }