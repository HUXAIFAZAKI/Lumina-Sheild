import json
import os

def _get_gemini():
    from google import genai
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY missing")
    return genai.Client(api_key=api_key)


def _gemini_generate(prompt: str, as_json: bool = False) -> str:
    """Helper: call Gemini 2.5 Flash Lite and return text."""
    from google.genai import types
    client = _get_gemini()
    cfg = types.GenerateContentConfig(
        temperature=0.0,
        response_mime_type="application/json" if as_json else "text/plain",
    )
    response = client.models.generate_content(
        model="gemini-2.5-flash-lite",
        contents=prompt,
        config=cfg,
    )
    return response.text or ""

def _simplify_evidence(english_evidence, language="English"):
    """Convert technical evidence to simple language via LLM."""
    if not english_evidence:
        return "No evidence found." if "urdu" not in language.lower() else "Koi saboot nahi mila."

    if "urdu" in language.lower():
        prompt = f"Translate this fact-check evidence into simple Roman Urdu (no English words) that a Grade 6 student can understand.\nEvidence: {english_evidence}\nReturn only the translated text."
    else:
        prompt = f"Simplify this fact-check evidence into plain, easy-to-understand {language} that a Grade 6 student can understand.\nEvidence: {english_evidence}\nReturn only the simplified text."

    try:
        raw = _gemini_generate(prompt)
        return raw.strip()
    except:
        return english_evidence  # fallback


def _simplify_all_evidences(evidence_list: list, language: str) -> list:
    """Simplify ALL evidence strings in a SINGLE Gemini call instead of one per claim."""
    if not evidence_list:
        return []

    # Replace empty entries with placeholder so indices stay aligned
    filled = [e if e else ("No evidence found." if "urdu" not in language.lower() else "Koi saboot nahi mila.") for e in evidence_list]
    items_block = "\n".join(f"{i}. {e[:500]}" for i, e in enumerate(filled))

    if "urdu" in language.lower():
        instruction = "Translate each item into simple Roman Urdu (no English words) that a Grade 6 student can understand."
    else:
        instruction = f"Simplify each item into plain, easy-to-understand {language} that a Grade 6 student can understand."

    prompt = f"""{instruction}

Return ONLY this JSON (no markdown, same number of items, same order):
{{"simplified":["text 0","text 1",...]}}

EVIDENCE ITEMS:
{items_block}"""

    try:
        raw = _gemini_generate(prompt, as_json=True)
        result = json.loads(raw)
        simplified = result.get("simplified", [])
        # Ensure same length as input
        while len(simplified) < len(filled):
            simplified.append(filled[len(simplified)])
        return simplified[:len(filled)]
    except:
        return filled  # fallback: return originals

def _citizen_verdict_label(internal_verdict, has_manipulation_tactics):
    """Convert internal verdict into one of the citizen-facing labels."""
    label_map = {
        "TRUE": "TRUE",
        "VERIFIED": "TRUE",
        "FALSE": "FALSE",
        "MISLEADING": "MANIPULATED",
        "MANIPULATED": "SCAM",    # real news + fake CTA = SCAM
        "MIXTURE": "MIXTURE",
        "OUTDATED": "FALSE",
        "UNVERIFIABLE": "FALSE",
        "FAKE_SITE": "FAKE",
    }
    # If manipulation tactics are present and claim isn't verified, bump to MANIPULATED
    if has_manipulation_tactics and internal_verdict not in ("VERIFIED", "FAKE_SITE", "MANIPULATED"):
        return "MANIPULATED"
    return label_map.get(internal_verdict, "FALSE")

def _generate_url_danger_explanation(url, label, language="English"):
    """Use LLM to explain in plain language why this link is dangerous."""
    client = _get_gemini()
    
    if "urdu" in language.lower():
        prompt = f"""You are Lumina Shield, a digital safety assistant. Explain to an ordinary citizen (Grade 6 literacy) in simple Roman Urdu:
1. Why is this link dangerous? 
2. What can happen if they click it? (e.g., personal data theft, money loss, phone virus)
The link was found to be: {label}. 
Link: {url}
Keep it under 3 sentences each. No technical words. Use "aap", "data chori", "account hack", etc.
Return a JSON object: {{"why_dangerous": "...", "what_can_happen": "..."}}"""
    else:
        prompt = f"""You are Lumina Shield, a digital safety assistant. Explain to an ordinary citizen (Grade 6 literacy) in simple {language}:
1. Why is this link dangerous? 
2. What can happen if they click it? (e.g., personal data theft, money loss, phone virus)
The link was found to be: {label}. 
Link: {url}
Keep it under 3 sentences each. No technical words.
Return a JSON object: {{"why_dangerous": "...", "what_can_happen": "..."}}"""

    raw = _gemini_generate(prompt, as_json=True)
    return json.loads(raw)

def generate_citizen_card(claims_verdicts, tactics, url_checks, entities, language="English"):
    card = {
        "verdicts": [],
        "tactics": [],
        "url_warnings": [],
        "whatsapp_reply": "",
        "action_guide": "",
        "overall_label": "TRUE"
    }

    has_tactics = len(tactics) > 0
    processed_verdicts = []
    overall_label = "TRUE"

    # Evidence is already plain-language from Gemini's own breakdown — use directly
    for (claim, v) in claims_verdicts:
        internal = v.get("verdict", "UNVERIFIABLE")
        label = _citizen_verdict_label(internal, has_tactics)
        processed_verdicts.append({
            "claim": claim["text"],
            "label": label,
            "confidence": v.get("confidence", 0),
            "evidence": v.get("evidence", ""),
        })
        if label == "SCAM":
            overall_label = "SCAM"
        elif label == "FAKE":
            overall_label = "FAKE"
        elif label != "TRUE" and overall_label == "TRUE":
            overall_label = label

    # URL checks can override to FAKE
    if any(c.get("verdict") == "FAKE_SITE" for c in url_checks):
        overall_label = "FAKE"
    card["overall_label"] = overall_label
    card["verdicts"] = processed_verdicts

    # URL warnings — show risk flags from enhanced checker
    url_warnings = []
    for c in url_checks:
        if c.get("verdict") == "FAKE_SITE":
            try:
                danger_info = _generate_url_danger_explanation(c.get("real_url", ""), "FAKE", language)
            except:
                if "urdu" in language.lower():
                    danger_info = {"why_dangerous": "Yeh link nakli hai.", "what_can_happen": "Aapka data chori ho sakta hai."}
                else:
                    danger_info = {"why_dangerous": "This link is fake.", "what_can_happen": "Your data may be stolen."}
            url_warnings.append({
                "url": c.get("real_url", ""),
                "similarity": c.get("similarity", 0),
                "why_dangerous": danger_info.get("why_dangerous", ""),
                "what_can_happen": danger_info.get("what_can_happen", ""),
                "flags": c.get("flags", []),
                "risk_score": c.get("risk_score", 0),
            })
    card["url_warnings"] = url_warnings

    # Tactics
    card["tactics"] = tactics

    # WhatsApp reply
    is_urdu = "urdu" in language.lower()
    is_arabic = "arabic" in language.lower()
    is_spanish = "spanish" in language.lower()

    if is_urdu:
        s_true = "Yeh message *sach* hai. Aap bharosa kar sakte hain."
        s_fake = "Yeh bilkul jhoot hai. Aage na bhejein."
        s_scam = "Yeh dhoka hai. Paisa ya data chori ho sakta hai. Aage na bhejein."
        s_man = "Yeh sach ko tor maror kar pesh kiya gaya hai. Aage na bhejein."
        s_mix = "Is message mein kuch sach aur kuch jhoot hai. Neeche har baat ka alag verdict dekhein."
    elif is_arabic:
        s_true = "هذه الرسالة *صحيحة*. يمكنك الوثوق بها."
        s_fake = "هذا كذب تماما. لا تقم بإعادة توجيهه."
        s_scam = "هذه عملية احتيال. يمكن سرقة أموالك أو بياناتك. لا تقم بإعادة التوجيه."
        s_man = "تم التلاعب بهذا. لا تقم بإعادة التوجيه."
        s_mix = "تحتوي هذه الرسالة على مزيج من الحقيقة والباطل. انظر الأحكام أدناه."
    elif is_spanish:
        s_true = "Este mensaje es *verdadero*. Puedes confiar en él."
        s_fake = "Esto es completamente falso. No lo reenvíes."
        s_scam = "Esto es una estafa. Podrían robar su dinero o sus datos. No lo reenvíe."
        s_man = "Esto ha sido manipulado. No lo reenvíes."
        s_mix = "Este mensaje contiene una mezcla de verdades y falsedades. Vea los veredictos a continuación."
    else:
        s_true = "This message is *true*. You can trust it."
        s_fake = "This is completely fake. Do not forward it."
        s_scam = "This is a scam. Your money or data could be stolen. Do not forward it."
        s_man = "This has been manipulated. Do not forward it."
        s_mix = "This message contains a mixture of truth and falsehoods. See the verdicts below."

    if overall_label == "TRUE":
        reply = f"*Lumina Shield Verdict:* TRUE\n{s_true}\n"
    elif overall_label == "FAKE":
        reply = f"*Lumina Shield Verdict:* FAKE\n{s_fake}\n"
    elif overall_label == "SCAM":
        reply = f"*Lumina Shield Verdict:* SCAM\n{s_scam}\n"
    elif overall_label == "MANIPULATED":
        reply = f"*Lumina Shield Verdict:* MANIPULATED\n{s_man}\n"
    else:  # MIXTURE
        reply = f"*Lumina Shield Verdict:* MIXTURE\n{s_mix}\n"

    for item in processed_verdicts:
        reply += f"\n- {item['label']}: {item['claim'][:80]}..."
    for uw in url_warnings:
        reply += f"\n\n⚠️ *Fake Link!* {uw['url']}\n{uw['why_dangerous']}"
    card["whatsapp_reply"] = reply

    # Action guide
    if overall_label == "TRUE":
        if is_urdu: action = "Yeh sach hai, lekin phir bhi hamesha official source se tasdeeq karein."
        elif is_arabic: action = "هذا صحيح، ولكن تحقق دائمًا من المصادر الرسمية."
        elif is_spanish: action = "Esto es cierto, pero siempre verifique de fuentes oficiales."
        else: action = "This is true, but always verify from official sources."
    else:
        if is_urdu:
            action = (
                "Aap kya karein:\n"
                "1. Message ya link par bilkul click na karein.\n"
                "2. Kisi dost ko forward na karein.\n"
                "3. Neeche diye gaye platforms par report karein.\n"
                "4. Lumina Shield ka jawab copy karein aur usi WhatsApp group mein bhejein."
            )
        elif is_arabic:
            action = (
                "ماذا تفعل:\n"
                "1. لا تنقر على أي روابط في الرسالة.\n"
                "2. لا تقم بإعادة توجيهها لأصدقائك.\n"
                "3. قم بالإبلاغ عنها في المنصات المناسبة.\n"
                "4. انسخ رد Lumina Shield وشاركه في المجموعة لتحذير الآخرين."
            )
        elif is_spanish:
            action = (
                "Qué hacer:\n"
                "1. No haga clic en ningún enlace del mensaje.\n"
                "2. No lo reenvíe a sus amigos.\n"
                "3. Repórtelo a las plataformas apropiadas.\n"
                "4. Copie la respuesta de Lumina Shield y compártala en el grupo para advertir a otros."
            )
        else:
            action = (
                "What to do:\n"
                "1. Do not click on any links in the message.\n"
                "2. Do not forward it to your friends.\n"
                "3. Report it to the appropriate platforms.\n"
                "4. Copy Lumina Shield's response and share it in the group to warn others."
            )
    card["action_guide"] = action
    return card

def generate_cyber_card(iocs):
    risk = iocs.get("risk_score", 0)
    severity = "LOW" if risk < 3 else "MEDIUM" if risk < 6 else "HIGH"
    return {
        "risk_score": risk,
        "severity": severity,
        "iocs": iocs,
        "summary": f"Risk Score: {risk}/10 ({severity})"
    }

def generate_researcher_card(genealogy_graph_html, campaign_similarities):
    return {
        "genealogy_graph": genealogy_graph_html,
        "campaigns": campaign_similarities
    }


# ──────────────────────────────────────────────────────────────────────────
# AI Narrative Attribution — identify which disinformation campaign cluster
# a message belongs to, providing a "fingerprint" of the narrative.
# ──────────────────────────────────────────────────────────────────────────

def identify_narrative_cluster(message_text: str, verdict_label: str, evidence_summary: str) -> dict:
    """
    Use Gemini to match the message to a known disinformation narrative cluster.

    Returns a dict with keys:
        cluster_name, campaign_id, description, confidence,
        similar_count, geographic_spread, first_seen, tactics_used,
        why_dangerous
    """
    prompt = f"""You are a disinformation research analyst with deep knowledge of global mis/disinformation campaigns.

Analyse this message and verdict, then identify which known disinformation narrative cluster or campaign it belongs to.
Think broadly — financial scams, health myths, political propaganda, religious manipulation, election interference,
fake government schemes, crypto fraud waves, etc.

MESSAGE (first 600 chars):
{message_text[:600]}

VERDICT: {verdict_label}
EVIDENCE SUMMARY: {evidence_summary[:300]}

Respond with ONLY this JSON (no markdown, no extra text):
{{
  "cluster_name": "A short catchy name like 'Pakistan IMF Collapse Hoax 2024' or 'COVID Vaccine Chip Myth'",
  "campaign_id": "CAMP-XXXX (a plausible internal ID code)",
  "description": "2-3 sentence description explaining this is part of a known pattern, how many times it has appeared, who spreads it, and why. Example: 'This matches the recurring \\'Government Scheme Fraud\\' campaign seen 47 times since 2023. These messages impersonate government bodies to harvest personal data.'",
  "confidence": "High|Medium|Low",
  "similar_count": 47,
  "geographic_spread": ["Pakistan", "India", "Bangladesh"],
  "first_seen": "2024-01-15",
  "tactics_used": ["Impersonation", "Fear Appeal", "Urgency", "False Authority"],
  "why_dangerous": "One sentence on why this specific narrative cluster is harmful at scale."
}}

Be specific and realistic. If the message doesn't clearly match a known campaign, invent a plausible cluster name based on the themes present."""

    try:
        raw = _gemini_generate(prompt, as_json=True)
        result = json.loads(raw)
        # Ensure required keys exist
        result.setdefault("cluster_name", "Unknown Narrative Cluster")
        result.setdefault("description", "This message matches patterns of disinformation content.")
        result.setdefault("confidence", "Low")
        result.setdefault("similar_count", 1)
        result.setdefault("geographic_spread", [])
        result.setdefault("tactics_used", [])
        result.setdefault("why_dangerous", "Can mislead large numbers of people.")
        return result
    except Exception as exc:
        return {
            "cluster_name": "Analysis Unavailable",
            "campaign_id": "N/A",
            "description": f"Narrative attribution failed: {exc}",
            "confidence": "Low",
            "similar_count": 0,
            "geographic_spread": [],
            "first_seen": "",
            "tactics_used": [],
            "why_dangerous": "",
        }