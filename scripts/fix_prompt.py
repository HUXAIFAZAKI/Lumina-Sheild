import pathlib

p = pathlib.Path("agents/searcher.py")
txt = p.read_text(encoding="utf-8", errors="replace")
lines = txt.splitlines(keepends=True)

new_prompt = (
    '    prompt = f"""You are a JSON formatter. A web researcher already investigated this message and wrote their findings below. '
    'Your ONLY job is to convert those findings into JSON. '
    'DO NOT re-evaluate. DO NOT use your own knowledge. DO NOT contradict the researcher.\n'
    "\n"
    "ORIGINAL MESSAGE:\n"
    "{message[:1500]}\n"
    "{cta_note}\n"
    "WHAT THE RESEARCHER FOUND:\n"
    "{research[:3000]}\n"
    "\n"
    "Convert the researcher findings to JSON:\n"
    "- overall_verdict: what the RESEARCHER concluded. TRUE / FALSE / MANIPULATED / MIXTURE / MISLEADING / UNVERIFIABLE\n"
    "  * Researcher says info correct/verified -> TRUE\n"
    "  * Researcher says main claim wrong -> FALSE\n"
    "  * Researcher says URL/phone differs from official -> MANIPULATED\n"
    "  * Researcher says some parts true some false -> MIXTURE\n"
    "  * Researcher found insufficient info -> UNVERIFIABLE\n"
    "- overall_confidence: how confident does the researcher seem? 0-100\n"
    "- overall_evidence: researcher main conclusion, 1-2 sentences, in the SAME LANGUAGE as the original message\n"
    "- breakdown: 2-4 facts the researcher mentioned. Each verdict MUST MATCH what the researcher said for that fact. NEVER flip a TRUE finding to FALSE.\n"
    "- If overall_verdict is FALSE and overall_confidence < 65, set overall_verdict to UNVERIFIABLE\n"
    "\n"
    "Output ONLY valid JSON:\n"
    '{{"overall_verdict":"...","overall_confidence":0,"overall_evidence":"...","breakdown":[{{"point":"...","verdict":"...","explanation":"..."}}]}}\\"\\"\\"\\n'
)

# Replace lines 124-146 (1-indexed) = indices 123..145
lines[123:146] = [new_prompt]

p.write_text("".join(lines), encoding="utf-8")
print("done, total lines:", len(lines))
