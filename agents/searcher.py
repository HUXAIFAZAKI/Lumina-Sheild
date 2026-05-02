"""
searcher.py Gemini 2.5 Flash Lite + Google Search grounding.
Step 1: Gemini searches the web and returns plain-text findings (like gemini_test.py).
Step 2: Groq llama-3.1-8b-instant structures those findings into a JSON verdict.
"""

import json
import os
import time

from google import genai
from google.genai import types


_GEMINI_MODEL     = "gemini-2.5-flash-lite"
_GROQ_FALLBACK    = "compound-beta-mini"     # has built-in web search � used when Gemini is down
_GROQ_STRUCTURE   = "llama-3.1-8b-instant"  # fast, cheap � only structures Gemini's findings into JSON
_MAX_RETRIES      = 3
_RETRY_DELAY      = 2  # seconds, doubles each retry


# -- Gemini client (mirrors gemini_test.py exactly) ---------------------------

def _gemini_ask(question: str, api_key: str) -> tuple[str, object]:
    """
    One chat message to Gemini with Google Search enabled.
    Exactly as in gemini_test.py: client ? chats.create ? send_message.
    Returns (response_text, response_object).
    """
    client = genai.Client(api_key=api_key)
    google_search_tool = types.Tool(google_search=types.GoogleSearch())
    config = types.GenerateContentConfig(tools=[google_search_tool])

    last_exc = None
    delay = _RETRY_DELAY
    for attempt in range(_MAX_RETRIES):
        try:
            chat = client.chats.create(model=_GEMINI_MODEL, config=config)
            response = chat.send_message(question)
            text = (response.text or "").strip()
            print(f"[gemini] attempt={attempt+1} chars={len(text)}")
            if text:
                return text, response, chat
            print(f"[gemini] empty response, retrying in {delay}s...")
            last_exc = RuntimeError("Empty response")
            time.sleep(delay)
            delay *= 2
        except Exception as exc:
            last_exc = exc
            msg = str(exc)
            if "503" in msg or "429" in msg:
                print(f"[gemini] attempt={attempt+1} rate-limited, retrying in {delay}s...")
                time.sleep(delay)
                delay *= 2
            else:
                print(f"[gemini] error: {msg[:120]}")
                break

    raise RuntimeError(f"Gemini failed after {_MAX_RETRIES} attempts. Last: {last_exc}")


# -- Groq fallback web search (when Gemini is fully down) ---------------------

def _groq_ask(question: str, groq_key: str) -> str:
    """compound-beta-mini has built-in web search � used only when Gemini is unavailable."""
    import groq as groq_sdk
    client = groq_sdk.Groq(api_key=groq_key)
    resp = client.chat.completions.create(
        model=_GROQ_FALLBACK,
        messages=[{"role": "user", "content": question}],
        temperature=0.0,
    )
    return (resp.choices[0].message.content or "").strip()

def _extract_search_query(message: str, groq_key: str) -> str:
    """
    Use a small Groq model to condense the message into ONE focused search query.
    This stops Gemini from breaking the message into multiple searches.
    Example: a 10-sentence WhatsApp forward → "BISP 25000 registration portal Pakistan 2024"
    """
    import groq as groq_sdk
    client = groq_sdk.Groq(api_key=groq_key)
    resp = client.chat.completions.create(
        model=_GROQ_STRUCTURE,
        messages=[{
            "role": "user",
            "content": (
                "Extract the single most important claim or topic from this message as a short "
                "Google search query (max 10 words). Return ONLY the search query, nothing else.\n\n"
                f"MESSAGE:\n{message[:1000]}"
            ),
        }],
        temperature=0.0,
    )
    query = (resp.choices[0].message.content or "").strip().strip('"').strip("'")
    print(f"[extract_query] {query}")
    return query or message[:200]

# -- Verdict detection from plain text ----------------------------------------

_VERDICT_PATTERNS = [
    ("MANIPULATED", ["manipulated", "unofficial url", "unofficial link", "not the official", "different from official"]),
    ("MIXTURE",     ["mixture", "some parts true", "partially true", "partly true", "mixed"]),
    ("MISLEADING",  ["misleading", "out of context", "missing context"]),
    ("FALSE",       ["appears to be false", "is false", "message is false", "claim is false",
                     "is incorrect", "is not true", "is untrue", "is a scam", "is fake",
                     "is misinformation", "is disinformation"]),
    ("TRUE",        ["appears to be true", "is true", "message is true", "claim is true",
                     "is accurate", "is correct", "is legitimate", "is real", "is genuine",
                     "is verified", "information is accurate", "confirmed by", "is indeed"]),
    ("UNVERIFIABLE",["cannot verify", "could not verify", "insufficient information",
                     "no information found", "unverifiable", "not enough information"]),
]

def _detect_verdict_from_text(text: str) -> str | None:
    """Parse Gemini's plain-text research to detect what verdict it actually reached."""
    t = text.lower()
    for verdict, patterns in _VERDICT_PATTERNS:
        if any(p in t for p in patterns):
            return verdict
    return None


# -- Gemini JSON formatting (same chat session) --------------------------------

def _gemini_format(chat, message: str, research: str, source_urls: list, context_data: dict = None) -> dict:
    """
    Sends a follow-up message to the SAME Gemini chat asking it to format ITS OWN findings as JSON.
    The verdict is first extracted from the plain-text research so it can never be flipped.
    """
    # Detect the real verdict from Gemini's own words BEFORE asking for JSON
    detected_verdict = _detect_verdict_from_text(research)
    print(f"[gemini_format] detected_verdict_from_text={detected_verdict}")

    ctas = (context_data or {}).get("ctas", [])
    cta_urls   = [c["text"] for c in ctas if c.get("type") == "url"   and c.get("text")]
    cta_phones = [c["text"] for c in ctas if c.get("type") == "phone" and c.get("text")]
    cta_note = ""
    if cta_urls or cta_phones:
        cta_note = (
            f"NOTE: The message tells users to visit {cta_urls} or call {cta_phones}. "
            "If those are NOT the official ones, overall_verdict MUST be MANIPULATED.\n"
        )

    verdict_instruction = (
        f"Your conclusion above was: {detected_verdict}. "
        f"You MUST use overall_verdict: \"{detected_verdict}\".\n"
    ) if detected_verdict else "Use the verdict that YOUR research above supports.\n"

    format_prompt = (
        "Format your research findings above as JSON. "
        f"{verdict_instruction}"
        "Other rules:\n"
        "- overall_confidence: 0-100 integer (e.g. 85, not 0.85)\n"
        "- overall_evidence: your main conclusion in 1-2 sentences in the SAME LANGUAGE as the original message\n"
        "- breakdown: 2-4 specific facts you verified. Each item has only 'point' (the claim) and 'explanation' (what you found).\n"
        f"{cta_note}"
        "Output ONLY valid JSON, no extra text:\n"
        '{"overall_verdict":"...","overall_confidence":85,"overall_evidence":"...","breakdown":[{"point":"...","explanation":"..."}]}'
    )

    try:
        fmt_response = chat.send_message(format_prompt)
        raw = (fmt_response.text or "").strip()
        print(f"[gemini_format] raw={raw[:200]}")
        # strip markdown code fences if present
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        result = json.loads(raw)
    except Exception as exc:
        print(f"[gemini_format] failed ({exc}), falling back to Groq structuring")
        return _groq_structure_fallback(message, research, source_urls, context_data)

    result["source_urls"] = source_urls
    result["gemini_research"] = research

    # Fix float/string confidence (Gemini sometimes returns 0.9 or "0.9" meaning 90%)
    try:
        conf = float(result.get("overall_confidence", 75))
    except (TypeError, ValueError):
        conf = 75.0
    if conf <= 1.0:
        conf = int(conf * 100)
    result["overall_confidence"] = int(conf)

    # Hard-override: if we detected a verdict from the research text, always use it
    if detected_verdict:
        if result.get("overall_verdict") != detected_verdict:
            print(f"[gemini_format] overriding JSON verdict '{result.get('overall_verdict')}' -> '{detected_verdict}' (from research text)")
        result["overall_verdict"] = detected_verdict

    print(f"[gemini_format] verdict={result.get('overall_verdict')} confidence={result.get('overall_confidence')}")
    return result


def _groq_structure_fallback(message: str, research: str, source_urls: list, context_data: dict = None) -> dict:
    """Fallback: used only when Gemini format step fails."""
    groq_key = os.getenv("GROQ_API_KEY")
    if not groq_key:
        return {
            "overall_verdict": "UNVERIFIABLE", "overall_confidence": 0,
            "overall_evidence": research[:500],
            "breakdown": [], "source_urls": source_urls,
        }
    ctas = (context_data or {}).get("ctas", [])
    cta_urls   = [c["text"] for c in ctas if c.get("type") == "url"   and c.get("text")]
    cta_phones = [c["text"] for c in ctas if c.get("type") == "phone" and c.get("text")]
    cta_note = ""
    if cta_urls or cta_phones:
        cta_note = (
            f"\nNOTE: The message tells users to visit {cta_urls} or call {cta_phones}. "
            "If the research shows these are NOT the official ones, verdict MUST be MANIPULATED.\n"
        )
    prompt = f"""You are a JSON formatter. A web researcher already investigated this message. Your ONLY job is to convert their findings into JSON. DO NOT re-evaluate. NEVER contradict the researcher.

WHAT THE RESEARCHER FOUND:
{research[:3000]}
{cta_note}
Convert to JSON — overall_verdict must reflect what the RESEARCHER concluded:
TRUE / FALSE / MANIPULATED / MIXTURE / MISLEADING / UNVERIFIABLE

Output ONLY valid JSON:
{{"overall_verdict":"...","overall_confidence":0,"overall_evidence":"...","breakdown":[{{"point":"...","verdict":"...","explanation":"..."}}]}}"""
    try:
        import groq as groq_sdk
        client = groq_sdk.Groq(api_key=groq_key)
        resp = client.chat.completions.create(
            model=_GROQ_STRUCTURE,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
            response_format={"type": "json_object"},
        )
        result = json.loads(resp.choices[0].message.content or "{}")
        result["source_urls"] = source_urls
        result["gemini_research"] = research
        # Fix float/string confidence
        try:
            conf = float(result.get("overall_confidence", 75))
        except (TypeError, ValueError):
            conf = 75.0
        if conf <= 1.0:
            conf = int(conf * 100)
        result["overall_confidence"] = int(conf)
        return result
    except Exception as exc:
        print(f"[groq_structure_fallback] failed: {exc}")
        return {
            "overall_verdict": "UNVERIFIABLE", "overall_confidence": 0,
            "overall_evidence": research[:500],
            "breakdown": [], "source_urls": source_urls,
            "gemini_research": research,
        }


# -- Public API ----------------------------------------------------------------

def verify_message(full_message: str, context_data: dict = None) -> dict:
    """
    Called by app.py.
    Returns: {overall_verdict, overall_confidence, overall_evidence, breakdown, source_urls}
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return {"overall_verdict": "UNVERIFIABLE", "overall_confidence": 0,
                "overall_evidence": "GEMINI_API_KEY not configured.", "breakdown": [], "source_urls": []}

    question = (
        "I received this message and want to know if it is true or fake. "
        "Please search the web and tell me what you find.\n\n"
        f"MESSAGE:\n{full_message[:2000]}"
    )

    # Extract one focused search query so Gemini doesn't split the message into multiple searches
    search_question = question  # fallback if Groq key missing
    groq_key = os.getenv("GROQ_API_KEY")
    if groq_key:
        try:
            query = _extract_search_query(full_message, groq_key)
            search_question = (
                f"Search the web for: {query}\n\n"
                f"Then tell me: based on what you found, is this message true or fake?\n\n"
                f"FULL MESSAGE FOR CONTEXT:\n{full_message[:2000]}"
            )
        except Exception as exc:
            print(f"[verify_message] query extraction failed, using full message: {exc}")

    research = ""
    source_urls: list = []
    chat_obj = None

    # Step 1 — Gemini searches with ONE focused query
    try:
        research, response_obj, chat_obj = _gemini_ask(search_question, api_key)
        try:
            chunks = response_obj.candidates[0].grounding_metadata.grounding_chunks or []
            source_urls = [c.web.uri for c in chunks if getattr(c, "web", None)]
        except Exception:
            pass
        sep = "-" * 60
        print(f"\n{sep}\n[GEMINI RESEARCH]\n{sep}\n{research}\n{sep}")
        if source_urls:
            print("[SOURCES]")
            for u in source_urls:
                print(f"  - {u}")
        print(sep + "\n")
    except Exception as exc:
        print(f"[verify_message] Gemini failed: {exc}")

    # Groq compound-beta-mini fallback if Gemini produced nothing
    if not research:
        if groq_key:
            try:
                print("[verify_message] falling back to Groq web search...")
                research = _groq_ask(search_question, groq_key)
            except Exception as exc2:
                print(f"[verify_message] Groq fallback also failed: {exc2}")

    if not research:
        return {"overall_verdict": "UNVERIFIABLE", "overall_confidence": 0,
                "overall_evidence": "Verification service unavailable.", "breakdown": [], "source_urls": []}

    # Step 2 — ask Gemini to format ITS OWN findings as JSON (same chat session = no contradiction)
    if chat_obj is not None:
        return _gemini_format(chat_obj, full_message, research, source_urls, context_data)
    # Groq fallback only if Gemini was never reached (used compound-beta-mini above)
    return _groq_structure_fallback(full_message, research, source_urls, context_data)


def search_and_verify(claim_text: str, context_data: dict = None) -> dict:
    """
    Called by misinfo_investigator.py.
    Returns: {verdict, confidence, evidence, source_urls}
    """
    full_message = (context_data or {}).get("full_message", claim_text)
    result = verify_message(full_message, context_data)
    return {
        "verdict": result.get("overall_verdict", "UNVERIFIABLE"),
        "confidence": result.get("overall_confidence", 0),
        "evidence": result.get("overall_evidence", ""),
        "source_urls": result.get("source_urls", []),
    }
