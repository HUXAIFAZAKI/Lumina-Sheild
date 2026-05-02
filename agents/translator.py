import os, json

def _get_client():
    from google import genai
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY not set.")
    return genai.Client(api_key=api_key)

def translate_and_extract(raw_text: str) -> dict:
    client = _get_client()
    prompt = f"""
You are Lumina Shield's multilingual text normalizer. Given the following text:

1. Detect the language(s) (e.g., "English", "Urdu", "Roman Urdu", "Spanish", "Mixed", etc.).
2. Normalize the text into a readable English representation if it's not English (transliterate mentally or translate, keep the meaning clear for downstream agents). If it is English, keep it as is.
3. Extract all:
   - URLs (http/https)
   - IP addresses (v4/v6)
   - Phone numbers
   - Email addresses
   - File names / hashes (if any)
Return ONLY a JSON object:
{{
  "detected_language": "...",
  "normalised_text": "...",
  "entities": {{
    "urls": [],
    "ips": [],
    "phones": [],
    "emails": [],
    "files": []
  }}
}}
Text: {raw_text}
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
    return json.loads(response.text)