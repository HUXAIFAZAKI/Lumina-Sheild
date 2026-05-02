import os
import json
import re

try:
    from src.extraction.artifact_extractor import extract_artifacts as _extract_src_artifacts
except Exception:
    _extract_src_artifacts = None

def _get_client():
    from google import genai
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY not set.")
    return genai.Client(api_key=api_key)


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        normalized = value.lower().strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(value)
    return deduped


def _regex_extract(text: str) -> dict:
    """
    Hard-coded regex extraction BEFORE LLM — catches URLs/phones
    the LLM might miss or normalize away.
    """
    urls = re.findall(r'https?://[^\s\"\'\<\>]+', text, re.IGNORECASE)
    # Bare domains: word.word.word (at least 2 dots or known TLDs)
    bare = re.findall(
        r'(?<![/@\w])\b([a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|pk|org|net|xyz|top|info|live|online|site|tv|edu|gov|co)(?:\.[a-zA-Z]{2,})?(?:/[^\s]*)?)',
        text, re.IGNORECASE
    )
    urls.extend(bare)

    if _extract_src_artifacts is not None:
        try:
            extracted = _extract_src_artifacts(text)
            urls.extend(extracted.get("urls", []))
            urls.extend(extracted.get("domains", []))
        except Exception:
            pass

    # Clean trailing punctuation
    urls = [u.rstrip(".,;:!?)\"'") for u in urls]
    urls = _dedupe_preserve_order([u for u in urls if len(u) > 4])

    # Pakistani phone patterns
    phones = re.findall(
        r'(?:0\d{3}[\s\-]?\d{7}|(?:\+92|0092)\s?\d{3}[\s\-]?\d{7}|\d{4}[\s\-]?\d{7})',
        text
    )
    phones = _dedupe_preserve_order(phones)

    return {"urls": urls, "phones": phones}


def split_into_claims(normalised_text: str) -> dict:
    """
    Split any message into structured components:
    1. Independent verifiable claims.
    2. CTAs (Call to Actions like URLs, phone numbers, or "Visit X").
    3. Metadata (Dates, Locations, Names).

    Uses regex pre-extraction + LLM decomposition for maximum coverage.
    """
    # Step 1: Hard regex extraction (never misses a URL)
    regex_found = _regex_extract(normalised_text)

    # Step 2: LLM-based deep decomposition
    client = _get_client()
    prompt = f"""You are a precise fact-checking assistant. Analyze the following message and extract structured data for deep verification.

**Extraction Rules:**
1. **Claims**: Independent verifiable statements. (e.g., "Prime Minister announced a scheme").
   - Tag each claim with a category: health / political / financial / scheme / url / malware / deepfake / religious / education / cyber
2. **CTAs (Call to Action)**: Specific instructions, links, or contacts that tell the reader to DO something.
   - URLs (even partial like "visit bisp-pk.com")
   - Phone numbers (even partial)
   - Instructions ("forward to 10 people", "register before May 30")
   - IMPORTANT: Extract the EXACT text of every URL/link/phone as written in the message. Do not fix typos or normalize them.
3. **Metadata**: Specific details that MUST be accurate.
   - `dates`: Any dates, deadlines, or time references mentioned.
   - `locations`: Cities, venues, offices, or addresses.
   - `entities`: Important names, organizations, or official titles.
   - `amounts`: Any monetary amounts, percentages, or numbers mentioned.

**What to ignore:**
- Do NOT decide if it's true or false yet.
- Do NOT rewrite URLs – keep them EXACTLY as written in the message.

Return ONLY a JSON object:
{{
  "claims": [{{"type": "category", "text": "..."}}, ...],
  "ctas": [{{"text": "...", "type": "url/phone/instruction"}}],
  "metadata": {{
    "dates": [],
    "locations": [],
    "entities": [],
    "amounts": []
  }}
}}

Message:
{normalised_text}
"""
    try:
        from google.genai import types
        response = client.models.generate_content(
            model="gemini-2.5-flash-lite",
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.0,
                response_mime_type="application/json",
            ),
        )
        result = json.loads(response.text)
    except Exception:
        result = {
            "claims": [{"type": "general", "text": normalised_text}],
            "ctas": [],
            "metadata": {"dates": [], "locations": [], "entities": [], "amounts": []}
        }

    # Step 3: Merge regex-found URLs/phones into CTAs (deduplicate)
    existing_cta_texts = {c["text"].lower().strip() for c in result.get("ctas", [])}

    for url in regex_found["urls"]:
        if url.lower().strip() not in existing_cta_texts:
            result["ctas"].append({"text": url, "type": "url"})
            existing_cta_texts.add(url.lower().strip())

    for phone in regex_found["phones"]:
        if phone.lower().strip() not in existing_cta_texts:
            result["ctas"].append({"text": phone, "type": "phone"})
            existing_cta_texts.add(phone.lower().strip())

    # Ensure metadata has all keys
    if "metadata" not in result:
        result["metadata"] = {}
    result["metadata"].setdefault("dates", [])
    result["metadata"].setdefault("locations", [])
    result["metadata"].setdefault("entities", [])
    result["metadata"].setdefault("amounts", [])

    return result