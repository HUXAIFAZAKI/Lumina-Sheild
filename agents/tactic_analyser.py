import os, json

def _get_client():
    from google import genai
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY not set.")
    return genai.Client(api_key=api_key)


def analyse_tactics(message: str) -> list:
    client = _get_client()
    prompt = f"""
You are a manipulation tactic analyst. For the following viral message, detect which of these six tactics are present:
- URGENCY (e.g. "share before deleted")
- FAKE_AUTHORITY (e.g. "doctors say", "government confirmed")
- FEAR (e.g. threat of arrest, financial loss)
- SUPPRESSION (e.g. "they don't want you to know")
- RELIGIOUS_FRAMING (e.g. secular claim wrapped in religious language)
- SOCIAL_PROOF (e.g. "thousands already benefited")

Return a JSON object with a single key "tactics", containing a list of objects with:
- "tactic": one of the above
- "explanation": a 2-sentence explanation in the language of the original message (for ordinary citizens to understand how they are being manipulated)
If no tactics found, return {{"tactics": []}}.
Message: {message}
"""
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
    if isinstance(result, list):
        return result
    return result.get("tactics", []) if "tactics" in result else []