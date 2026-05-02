"""Helper: writes the new searcher.py cleanly."""
import pathlib, textwrap

content = textwrap.dedent("""\
    \"\"\"
    searcher.py - Gemini 2.5 Flash Lite + Google Search grounding.
    Step 1: Gemini searches the web, returns plain-text findings (same as gemini_test.py).
    Step 2: Groq llama-3.1-8b-instant structures those findings into a JSON verdict.
    \"\"\"

    import json
    import os
    import time

    from google import genai
    from google.genai import types


    _GEMINI_MODEL   = "gemini-2.5-flash-lite"
    _GROQ_FALLBACK  = "compound-beta-mini"    # built-in web search - used when Gemini is down
    _GROQ_STRUCTURE = "llama-3.1-8b-instant"  # structures Gemini findings into JSON
    _MAX_RETRIES    = 3
    _RETRY_DELAY    = 2  # seconds, doubles each retry


    def _gemini_ask(question: str, api_key: str) -> tuple[str, object]:
        \"\"\"
        One chat message to Gemini with Google Search enabled.
        Mirrors gemini_test.py exactly: client -> chats.create -> send_message.
        \"\"\"
        client = genai.Client(api_key=api_key)
        config = types.GenerateContentConfig(tools=[types.Tool(google_search=types.GoogleSearch())])

        last_exc = None
        delay = _RETRY_DELAY
        for attempt in range(_MAX_RETRIES):
            try:
                chat = client.chats.create(model=_GEMINI_MODEL, config=config)
                response = chat.send_message(question)
                text = (response.text or "").strip()
                print(f"[gemini] attempt={attempt+1} chars={len(text)}")
                if text:
                    return text, response
                print(f"[gemini] empty, retrying in {delay}s...")
                last_exc = RuntimeError("Empty response")
                time.sleep(delay)
                delay *= 2
            except Exception as exc:
                last_exc = exc
                msg = str(exc)
                if "503" in msg or "429" in msg:
                    print(f"[gemini] rate-limited, retrying in {delay}s...")
                    time.sleep(delay)
                    delay *= 2
                else:
                    print(f"[gemini] error: {msg[:120]}")
                    break

        raise RuntimeError(f"Gemini failed after {_MAX_RETRIES} attempts. Last: {last_exc}")


    def _groq_ask(question: str, groq_key: str) -> str:
        \"\"\"compound-beta-mini fallback - used only when Gemini is unavailable.\"\"\"
        import groq as _groq
        client = _groq.Groq(api_key=groq_key)
        resp = client.chat.completions.create(
            model=_GROQ_FALLBACK,
            messages=[{"role": "user", "content": question}],
            temperature=0.0,
        )
        return (resp.choices[0].message.content or "").strip()


    def _groq_structure(message: str, research: str, source_urls: list, context_data: dict = None) -> dict:
        \"\"\"
        Takes Gemini plain-text research, asks Groq to produce the structured JSON verdict.
        Groq never touches the web - only reads what Gemini found.
        \"\"\"
        groq_key = os.getenv("GROQ_API_KEY")
        if not groq_key:
            return {
                "overall_verdict": "UNVERIFIABLE", "overall_confidence": 0,
                "overall_evidence": research[:500] or "No GROQ_API_KEY set.",
                "breakdown": [], "source_urls": source_urls,
            }

        ctas = (context_data or {}).get("ctas", [])
        cta_urls   = [c["text"] for c in ctas if c.get("type") == "url"   and c.get("text")]
        cta_phones = [c["text"] for c in ctas if c.get("type") == "phone" and c.get("text")]
        cta_note = ""
        if cta_urls or cta_phones:
            cta_note = (
                f"NOTE: The message tells users to visit {cta_urls} or call {cta_phones}. "
                "If the research shows these are NOT the official ones, verdict MUST be MANIPULATED."
            )

        prompt = (
            "You are a fact-checking analyst. A researcher already searched the web about this message. "
            "Use ONLY their findings - do not guess or add new information.\\n\\n"
            f"ORIGINAL MESSAGE:\\n{message[:1500]}\\n"
            f"{cta_note}\\n"
            f"RESEARCH FINDINGS:\\n{research[:3000]}\\n\\n"
            "Rules for overall_verdict: TRUE / FALSE / MANIPULATED / MIXTURE / MISLEADING / UNVERIFIABLE\\n"
            "- MANIPULATED = main story real but URL/phone in message is not the official one\\n"
            "- MIXTURE = some facts true, some false\\n"
            "- TRUE = every detail confirmed\\n"
            "- FALSE = main claim is wrong\\n"
            "- UNVERIFIABLE = not enough evidence\\n"
            "- If FALSE and confidence < 65, change to UNVERIFIABLE\\n"
            "- Write in the SAME LANGUAGE as the original message, Grade 6 level\\n"
            "- breakdown: 2-4 items, each a specific fact checked\\n\\n"
            'Output ONLY valid JSON:\\n'
            '{"overall_verdict":"...","overall_confidence":0,"overall_evidence":"...","breakdown":[{"point":"...","verdict":"...","explanation":"..."}]}'
        )

        try:
            import groq as _groq
            client = _groq.Groq(api_key=groq_key)
            resp = client.chat.completions.create(
                model=_GROQ_STRUCTURE,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                response_format={"type": "json_object"},
            )
            result = json.loads(resp.choices[0].message.content or "{}")
        except Exception as exc:
            print(f"[groq_structure] failed: {exc}")
            return {
                "overall_verdict": "UNVERIFIABLE", "overall_confidence": 0,
                "overall_evidence": research[:500],
                "breakdown": [], "source_urls": source_urls,
            }

        result["source_urls"] = source_urls
        if result.get("overall_verdict") == "FALSE" and result.get("overall_confidence", 100) < 65:
            result["overall_verdict"] = "UNVERIFIABLE"
            result["overall_evidence"] = (result.get("overall_evidence", "") + " Confidence too low.").strip()

        print(f"[groq_structure] verdict={result.get('overall_verdict')} confidence={result.get('overall_confidence')}")
        return result


    def verify_message(full_message: str, context_data: dict = None) -> dict:
        \"\"\"
        Called by app.py.
        Returns: {overall_verdict, overall_confidence, overall_evidence, breakdown, source_urls}
        \"\"\"
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            return {"overall_verdict": "UNVERIFIABLE", "overall_confidence": 0,
                    "overall_evidence": "GEMINI_API_KEY not configured.", "breakdown": [], "source_urls": []}

        question = (
            "I received this message and want to know if it is true or fake. "
            "Please search the web and tell me what you find.\\n\\n"
            f"MESSAGE:\\n{full_message[:2000]}"
        )

        research = ""
        source_urls: list = []
        response_obj = None

        # Step 1 — Gemini searches the web
        try:
            research, response_obj = _gemini_ask(question, api_key)
            try:
                chunks = response_obj.candidates[0].grounding_metadata.grounding_chunks or []
                source_urls = [c.web.uri for c in chunks if getattr(c, "web", None)]
            except Exception:
                pass
            sep = "-" * 60
            print(f"\\n{sep}\\n[GEMINI RESEARCH]\\n{sep}\\n{research}\\n{sep}")
            if source_urls:
                print("[SOURCES]")
                for u in source_urls:
                    print(f"  - {u}")
            print(sep + "\\n")
        except Exception as exc:
            print(f"[verify_message] Gemini failed: {exc}")

        # Groq compound-beta-mini fallback if Gemini produced nothing
        if not research:
            groq_key = os.getenv("GROQ_API_KEY")
            if groq_key:
                try:
                    print("[verify_message] falling back to Groq web search...")
                    research = _groq_ask(question, groq_key)
                except Exception as exc2:
                    print(f"[verify_message] Groq fallback also failed: {exc2}")

        if not research:
            return {"overall_verdict": "UNVERIFIABLE", "overall_confidence": 0,
                    "overall_evidence": "Verification service unavailable.", "breakdown": [], "source_urls": []}

        # Step 2 — Groq structures Gemini's findings into JSON
        return _groq_structure(full_message, research, source_urls, context_data)


    def search_and_verify(claim_text: str, context_data: dict = None) -> dict:
        \"\"\"
        Called by misinfo_investigator.py.
        Returns: {verdict, confidence, evidence, source_urls}
        \"\"\"
        full_message = (context_data or {}).get("full_message", claim_text)
        result = verify_message(full_message, context_data)
        return {
            "verdict": result.get("overall_verdict", "UNVERIFIABLE"),
            "confidence": result.get("overall_confidence", 0),
            "evidence": result.get("overall_evidence", ""),
            "source_urls": result.get("source_urls", []),
        }
""")

dest = pathlib.Path(r"agents\searcher.py")
dest.write_text(content, encoding="utf-8")
print("Written:", dest.stat().st_size, "bytes")
