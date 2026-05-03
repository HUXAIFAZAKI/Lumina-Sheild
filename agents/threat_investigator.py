import asyncio
import concurrent.futures
from datetime import datetime
import ipaddress
import re
import socket
from typing import Any
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from utils.api_clients import (
    vt_url_scan, vt_url_report, vt_hash_lookup, urlscan_submit, abuseipdb_check,
    phishtank_check, whois_lookup, safe_browsing_check,
    shodan_host, dns_resolve_all, ip_geolocation, detect_tech_stack,
    threatfox_domain_check, crt_sh_subdomains, otx_domain_report
)
from urllib.parse import urlparse
import time

try:
    from src.extraction.artifact_extractor import extract_artifacts as _extract_src_artifacts
except Exception:
    _extract_src_artifacts = None


_SRC_RUNTIME: dict[str, Any] | None = None


def _build_ioc_result() -> dict[str, Any]:
    return {
        "ips": [],
        "domains": [],
        "hashes": [],
        "emails": [],
        "risk_score": 0.0,
        "details": {},
        "vt_vendors": {},
        "vt_categories": {},
        "vt_reputation": 0,
        "vt_stats": {},
        "vt_http_response": {},
        "geo": {},
        "tech_stack": {},
        "dns_records": {},
        "ssl_info": {},
        "threatfox": [],
        "subdomains": [],
    }


def _get_src_runtime() -> dict[str, Any]:
    global _SRC_RUNTIME
    if _SRC_RUNTIME is not None:
        return _SRC_RUNTIME

    try:
        from src.integrations.configurations import INTEGRATIONS
        from src.integrations.orchestrator import EnrichmentOrchestrator
        from src.integrations.models import ArtifactType

        _SRC_RUNTIME = {
            "ArtifactType": ArtifactType,
            "orchestrator": EnrichmentOrchestrator(INTEGRATIONS),
        }
    except Exception:
        _SRC_RUNTIME = {}

    return _SRC_RUNTIME


def _run_async(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(lambda: asyncio.run(coro)).result()


def _safe_append(items: list[str], value: str | None) -> None:
    if value and value not in items:
        items.append(value)


def _safe_append_lower(items: list[str], value: str | None) -> None:
    if not value:
        return

    lowered = value.lower()
    if all(existing.lower() != lowered for existing in items):
        items.append(value)


def _looks_like_hash(value: str) -> bool:
    candidate = value.strip().lower()
    return bool(re.fullmatch(r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}", candidate))


def _extract_hashes(value: str) -> list[str]:
    matches = re.findall(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b", value or "")
    hashes: list[str] = []
    for match in matches:
        normalized = match.lower()
        if normalized not in hashes:
            hashes.append(normalized)
    return hashes


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _extract_host(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}")
    return (parsed.hostname or parsed.netloc or value).split(":")[0].strip().lower()


def _extract_input_artifacts(value: str) -> dict[str, list[str]]:
    artifacts = {
        "ipv4": [],
        "domains": [],
        "urls": [],
    }
    candidate = value.strip()
    single_token = bool(candidate) and not re.search(r"\s", candidate)

    if _extract_src_artifacts is not None:
        try:
            extracted = _extract_src_artifacts(candidate)
            for ip in extracted.get("ipv4", []):
                _safe_append(artifacts["ipv4"], ip)
            for domain in extracted.get("domains", []):
                _safe_append_lower(artifacts["domains"], domain)
            for url in extracted.get("urls", []):
                _safe_append_lower(artifacts["urls"], url)
        except Exception:
            pass

    host = _extract_host(candidate) if single_token else ""
    if single_token and "://" in candidate:
        _safe_append_lower(artifacts["urls"], candidate)

    if _is_ip(host):
        _safe_append(artifacts["ipv4"], host)
    elif host and not _looks_like_hash(host):
        _safe_append_lower(artifacts["domains"], host)

    # Regex fallback for multi-word inputs (e.g. "explain youtube.com", "check 1.2.3.4 please")
    # Runs when _extract_src_artifacts is unavailable OR produced no results on free-text input.
    if not single_token and not (artifacts["urls"] or artifacts["domains"] or artifacts["ipv4"]):
        # Full URLs
        for u in re.findall(r'https?://\S+', candidate):
            _safe_append_lower(artifacts["urls"], u)
        # Bare domain-like tokens: word.tld or sub.word.tld (letters/digits/hyphens, dot, 2+ letter TLD)
        for token in re.findall(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            candidate,
        ):
            if not _is_ip(token) and not _looks_like_hash(token):
                _safe_append_lower(artifacts["domains"], token)
        # Bare IP addresses
        for token in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', candidate):
            try:
                ipaddress.ip_address(token)
                _safe_append(artifacts["ipv4"], token)
            except ValueError:
                pass

    return artifacts


def normalize_investigation_input(raw_input: str, allowed_kinds: set[str] | None = None) -> dict[str, Any]:
    candidate = (raw_input or "").strip()
    allowed = allowed_kinds or {"url", "domain", "ip", "hash"}
    result: dict[str, Any] = {
        "raw": candidate,
        "value": None,
        "kind": None,
        "extracted": False,
        "message": "",
    }

    if not candidate:
        result["message"] = "Please enter a URL, domain, IP, or file hash."
        return result

    extracted = _extract_input_artifacts(candidate)
    hashes = _extract_hashes(candidate)
    single_token = bool(candidate) and not re.search(r"\s", candidate)

    if _looks_like_hash(candidate):
        hashes = [candidate.lower(), *[item for item in hashes if item.lower() != candidate.lower()]]

    exact_domain = _extract_host(candidate) if single_token else None
    exact_url = candidate if single_token and "://" in candidate else None
    exact_ip = candidate if single_token and _is_ip(candidate) else None

    priorities: list[tuple[str, list[str]]] = []
    if exact_url and "url" in allowed:
        priorities.append(("url", [exact_url]))
    if exact_domain and not exact_url and not exact_ip and not _looks_like_hash(candidate) and "domain" in allowed:
        priorities.append(("domain", [exact_domain]))
    if exact_ip and "ip" in allowed:
        priorities.append(("ip", [exact_ip]))
    if single_token and _looks_like_hash(candidate) and "hash" in allowed:
        priorities.append(("hash", [candidate.lower()]))

    priorities.extend([
        ("url", extracted["urls"]),
        ("domain", extracted["domains"]),
        ("ip", extracted["ipv4"]),
        ("hash", hashes),
    ])

    for kind, values in priorities:
        if kind not in allowed:
            continue
        for value in values:
            normalized = value.strip()
            if not normalized:
                continue
            result["value"] = normalized
            result["kind"] = kind
            result["extracted"] = normalized.lower() != candidate.lower()
            if result["extracted"]:
                result["message"] = f"Extracted {kind} from the provided text: {normalized}"
            return result

    expected = "URL, domain, IP, or file hash"
    if allowed == {"url", "domain"}:
        expected = "URL or domain"
    elif allowed == {"url", "domain", "ip"}:
        expected = "URL, domain, or IP"
    elif allowed == {"url", "hash"}:
        expected = "URL or file hash"
    result["message"] = f"No valid {expected} found in that input."
    return result


def _parse_creation_date(value: Any) -> datetime | None:
    if isinstance(value, list):
        for item in value:
            parsed = _parse_creation_date(item)
            if parsed:
                return parsed
        return None

    if isinstance(value, datetime):
        return value

    if not value:
        return None

    text = str(value).strip()
    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S%z"):
        try:
            return datetime.strptime(text[: len(fmt)], fmt)
        except ValueError:
            continue

    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _apply_domain_age(iocs: dict[str, Any], whois_data: dict[str, Any]) -> None:
    creation = whois_data.get("creation_date") or whois_data.get("creationDate")
    created_at = _parse_creation_date(creation)
    if not created_at:
        return

    age_days = (datetime.now(created_at.tzinfo) - created_at).days
    iocs["details"]["domain_age_days"] = age_days
    if age_days < 30:
        iocs["risk_score"] += 2


def _apply_virustotal_data(iocs: dict[str, Any], payload: dict[str, Any], is_hash_lookup: bool) -> None:
    attrs = payload.get("data", {}).get("attributes", {})
    if not attrs:
        return

    stats = attrs.get("last_analysis_stats") or attrs.get("stats") or {}
    if stats:
        iocs["vt_stats"] = stats
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        iocs["risk_score"] += (malicious * 2 + suspicious * 0.5)
        if is_hash_lookup:
            iocs["details"]["vt_hash_stats"] = stats

    results = attrs.get("last_analysis_results") or attrs.get("results") or {}
    for vendor, info in results.items():
        iocs["vt_vendors"][vendor] = {
            "category": info.get("category", "undetected"),
            "result": info.get("result", info.get("category", "undetected")),
            "method": info.get("method", ""),
            "engine_name": info.get("engine_name", vendor),
        }

    iocs["vt_categories"] = attrs.get("categories", {}) or iocs["vt_categories"]
    iocs["vt_reputation"] = attrs.get("reputation", iocs["vt_reputation"])
    iocs["details"]["vt_votes"] = attrs.get("total_votes", iocs["details"].get("vt_votes", {}))

    http_headers = attrs.get("last_http_response_headers", {}) or {}
    if attrs.get("last_http_response_code"):
        iocs["vt_http_response"] = {
            "status_code": attrs.get("last_http_response_code"),
            "content_length": attrs.get("last_http_response_content_length"),
            "server": http_headers.get("server") or http_headers.get("Server", ""),
            "content_type": http_headers.get("content-type") or http_headers.get("Content-Type", ""),
        }

    iocs["details"]["vt_first_submission"] = attrs.get("first_submission_date")
    iocs["details"]["vt_last_analysis"] = attrs.get("last_analysis_date")
    iocs["details"]["vt_times_submitted"] = attrs.get("times_submitted")

    ssl_cert = attrs.get("last_https_certificate", {}) or {}
    san_entries = ssl_cert.get("extensions", {}).get("subject_alternative_name", [])
    if ssl_cert:
        iocs["ssl_info"] = {
            "issuer": ssl_cert.get("issuer", {}).get("O", "Unknown"),
            "subject": ssl_cert.get("subject", {}).get("CN", "Unknown"),
            "validity_not_before": ssl_cert.get("validity", {}).get("not_before", ""),
            "validity_not_after": ssl_cert.get("validity", {}).get("not_after", ""),
            "serial_number": ssl_cert.get("serial_number", ""),
            "thumbprint": ssl_cert.get("thumbprint", ""),
            "san_domains": [
                entry.get("value", "")
                for entry in san_entries
                if isinstance(entry, dict) and entry.get("value")
            ] if isinstance(san_entries, list) else [],
        }


def _apply_abuseipdb_data(iocs: dict[str, Any], payload: dict[str, Any]) -> None:
    check = payload.get("check", {}) if isinstance(payload, dict) else {}
    if not check:
        return

    score = check.get("abuseConfidenceScore", 0) or 0
    if score > 0:
        iocs["risk_score"] += score / 20.0
    iocs["details"]["abuseipdb"] = check


def _apply_whois_data(iocs: dict[str, Any], payload: dict[str, Any]) -> None:
    if not payload:
        return

    iocs["details"]["whois"] = payload
    _apply_domain_age(iocs, payload)


def _apply_otx_data(iocs: dict[str, Any], payload: dict[str, Any]) -> None:
    if not payload:
        return

    iocs["details"]["alienvault_otx"] = payload
    pulse_info = payload.get("general", {}).get("pulse_info", {}) if isinstance(payload, dict) else {}
    pulse_count = pulse_info.get("count", 0) or 0
    reputation = payload.get("reputation", {}).get("reputation", 0) if isinstance(payload, dict) else 0
    malware_count = payload.get("malware", {}).get("count", 0) if isinstance(payload, dict) else 0

    if pulse_count:
        iocs["risk_score"] += min(2.0, pulse_count * 0.25)
    if reputation and reputation < 0:
        iocs["risk_score"] += min(1.5, abs(reputation) / 10.0)
    if malware_count:
        iocs["risk_score"] += min(2.0, malware_count * 0.5)


def _apply_src_results(
    iocs: dict[str, Any],
    results: list[Any],
    artifact_kind: str,
) -> dict[str, bool]:
    coverage = {
        "virustotal": False,
        "whois": False,
        "abuseipdb": False,
        "alienvaultotx": False,
    }

    for result in results:
        if not getattr(result, "success", False) or not getattr(result, "data", None):
            continue

        integration = getattr(result, "integration", "")
        data = result.data
        if integration == "virustotal":
            _apply_virustotal_data(iocs, data, artifact_kind == "hash")
            coverage["virustotal"] = True
        elif integration == "whois":
            _apply_whois_data(iocs, data)
            coverage["whois"] = True
        elif integration == "abuseipdb":
            _apply_abuseipdb_data(iocs, data)
            coverage["abuseipdb"] = True
        elif integration == "alienvaultotx":
            _apply_otx_data(iocs, data)
            coverage["alienvaultotx"] = True

    return coverage


def _run_src_enrichment(artifact: str, artifact_kind: str) -> list[Any]:
    runtime = _get_src_runtime()
    orchestrator = runtime.get("orchestrator")
    artifact_type_enum = runtime.get("ArtifactType")
    if not orchestrator or artifact_type_enum is None:
        return []

    return _run_async(orchestrator.enrich(artifact, artifact_type_enum(artifact_kind)))

def investigate_threat(url: str = None, file_hash: str = None, progress_callback=None) -> dict:
    def _cb(n: int, total: int = 7, label: str = "") -> None:
        if progress_callback:
            try:
                progress_callback(n, total, label)
            except Exception:
                pass

    iocs = _build_ioc_result()

    if url and not file_hash and _looks_like_hash(url):
        file_hash = url.strip()
        url = None

    if url:
        url = url.strip()
        extracted = _extract_input_artifacts(url)
        domain = _extract_host(url)
        for ip in extracted["ipv4"]:
            _safe_append(iocs["ips"], ip)
        for found_domain in extracted["domains"]:
            _safe_append(iocs["domains"], found_domain)

        artifact_kind = "url" if extracted["urls"] else "ip" if _is_ip(domain) else "domain"
        enrichment_target = url if artifact_kind == "url" else domain
        coverage = {
            "virustotal": False,
            "whois": False,
            "abuseipdb": False,
            "alienvaultotx": False,
        }

        def task_src():
            return _run_src_enrichment(enrichment_target, artifact_kind)

        def task_resolve_ip():
            try:
                return domain if _is_ip(domain) else socket.gethostbyname(domain)
            except Exception:
                return None

        def task_sb(): return safe_browsing_check(url)
        def task_pt():
            try:
                return phishtank_check(url)
            except Exception:
                return False
        def task_us(): return urlscan_submit(url)
        def task_tech(): return detect_tech_stack(url)
        def task_tf(): return threatfox_domain_check(domain)
        def task_otx(): return otx_domain_report(domain)
        def task_subs(): return crt_sh_subdomains(domain)
        def task_dns(): return iocs["dns_records"] or dns_resolve_all(domain)

        def task_dom():
            try:
                import requests
                resp = requests.get(url, timeout=5, headers={"User-Agent": "LuminaShield/1.0 (Hackathon Project)"}, verify=False)
                html = resp.text[:3000]
                from agents.misinfo_investigator import _get_client
                client = _get_client()
                prompt = "Analyze this HTML snippet for zero-day phishing heuristics (hidden iframes, obfuscated JS, fake login forms, brand impersonation). Return a brief 1-2 sentence forensic summary. If nothing suspicious, say 'No obvious heuristic threats detected in DOM.'\n\nHTML:\n" + html
                ai_resp = client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.0
                )
                return ai_resp.choices[0].message.content.strip()
            except Exception as e:
                return f"DOM Analysis unavailable: {str(e)}"

        def task_redirects():
            try:
                import requests
                resp = requests.get(url, timeout=5, headers={"User-Agent": "LuminaShield/1.0 (Hackathon Project)"}, allow_redirects=True, verify=False)
                chain = [h.url for h in resp.history] + [resp.url]
                return chain
            except:
                return []


        _cb(0, 7)
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
            future_src = executor.submit(task_src)
            future_resolve = executor.submit(task_resolve_ip)
            future_sb = executor.submit(task_sb)
            future_pt = executor.submit(task_pt)
            future_us = executor.submit(task_us)
            future_dns = executor.submit(task_dns)
            future_tech = executor.submit(task_tech)
            future_tf = executor.submit(task_tf)
            future_otx = executor.submit(task_otx)
            future_subs = executor.submit(task_subs)
            future_dom = executor.submit(task_dom)
            future_redirs = executor.submit(task_redirects)

            src_results = future_src.result()
            coverage = _apply_src_results(iocs, src_results, artifact_kind)
            _cb(1, 7)

            if not coverage["virustotal"] and artifact_kind in {"url", "domain"}:
                vt_payload = vt_url_report(url) if artifact_kind == "url" else {}
                if vt_payload and "data" in vt_payload:
                    _apply_virustotal_data(iocs, vt_payload, is_hash_lookup=False)
            _cb(2, 7)

            resolved_ip = future_resolve.result()
            if resolved_ip:
                _safe_append(iocs["ips"], resolved_ip)

            future_whois = executor.submit(whois_lookup, domain) if not coverage["whois"] else None
            future_abuse = executor.submit(abuseipdb_check, resolved_ip) if not coverage["abuseipdb"] and resolved_ip else None
            future_shodan = executor.submit(shodan_host, resolved_ip) if resolved_ip else None
            future_geo = executor.submit(ip_geolocation, resolved_ip) if not iocs["geo"] and resolved_ip else None
            _cb(3, 7)

            # --- Safe Browsing ---
            sb = future_sb.result()
            if sb and "matches" in sb:
                iocs["risk_score"] += 5
                iocs["details"]["safe_browsing"] = "flagged"

            # --- PhishTank ---
            if future_pt.result():
                iocs["risk_score"] += 5
                iocs["details"]["phishtank"] = "known phishing"

            # --- URLScan ---
            us = future_us.result()
            if us and "data" in us:
                iocs["details"]["urlscan"] = "scanned"
                lists = us.get("lists", {})
                for ip in lists.get("ips", []):
                    if ip not in iocs["ips"]: iocs["ips"].append(ip)
                for d in lists.get("domains", []):
                    if d not in iocs["domains"]: iocs["domains"].append(d)
                cert = lists.get("certificates", [])
                if cert: iocs["details"]["certificates"] = cert[0]
            _cb(4, 7)

            # --- WHOIS ---
            w = future_whois.result() if future_whois else {}
            if w:
                _apply_whois_data(iocs, w)

            # --- AbuseIPDB ---
            abuse = future_abuse.result() if future_abuse else {}
            if abuse and "data" in abuse:
                _apply_abuseipdb_data(iocs, {"check": abuse["data"]})

            # --- Shodan ---
            shodan_res = future_shodan.result() if future_shodan else {}
            if shodan_res:
                iocs["details"]["shodan"] = shodan_res.get("ports", [])

            # --- IP Geo ---
            geo = future_geo.result() if future_geo else {}
            if geo: iocs["geo"] = geo
            _cb(5, 7)

            # --- DNS ---
            iocs["dns_records"] = future_dns.result()

            # --- Tech Stack ---
            iocs["tech_stack"] = future_tech.result()

            # --- ThreatFox ---
            tf_data = future_tf.result()
            if tf_data:
                iocs["threatfox"] = tf_data[:10]
                iocs["risk_score"] += 3

            # --- AlienVault OTX (direct fallback if src integration missed it) ---
            if not coverage.get("alienvaultotx"):
                try:
                    otx_data = future_otx.result()
                    if otx_data:
                        _apply_otx_data(iocs, otx_data)
                        pulse_count = otx_data.get("pulse_info", {}).get("count", 0) or 0
                        if pulse_count:
                            iocs["risk_score"] += min(2.0, pulse_count * 0.25)
                except Exception:
                    pass

            # --- Subdomains ---
            try:
                subs = future_subs.result()
                if subs: iocs["subdomains"] = subs[:20]
            except:
                pass
            _cb(6, 7)

            # --- Heuristics & Redirects ---
            iocs["dom_heuristics"] = future_dom.result()
            iocs["redirect_chain"] = future_redirs.result()
            _cb(7, 7)


    elif file_hash:
        file_hash = file_hash.strip()
        _safe_append(iocs["hashes"], file_hash)
        _cb(0, 7)

        coverage = _apply_src_results(iocs, _run_src_enrichment(file_hash, "hash"), "hash")
        _cb(3, 7)
        if not coverage["virustotal"]:
            vt = vt_hash_lookup(file_hash)
            if vt and "data" in vt:
                _apply_virustotal_data(iocs, vt, is_hash_lookup=True)
        _cb(6, 7)

        if iocs["vt_stats"]:
            iocs["risk_score"] = max(iocs["risk_score"], iocs["vt_stats"].get("malicious", 0) * 3)
        _cb(7, 7)

    # Clamp risk
    iocs["risk_score"] = round(min(10.0, iocs["risk_score"]), 1)
    return iocs


_THREAT_SYSTEM_PROMPT = """You are a senior cybersecurity analyst with expertise in phishing detection, malware analysis, and threat intelligence.

Your task is to analyze a given user input (URL or file hash) along with enriched threat intelligence data and determine whether it is:
- Benign (Safe)
- Suspicious
- Malicious

ANALYSIS INSTRUCTIONS:

1. Decision Making:
- Combine ALL signals (content + artifacts + threat intelligence + WHOIS + heuristics)
- Classify the input as: Benign, Suspicious, or Malicious

2. CRITICAL RULE (Avoid False Positives):
- If artifacts (domains, IPs, URLs) are from well-known, reputable, or whitelisted services AND no strong malicious signals exist → DO NOT mark them as malicious
- Do NOT flag content as malicious based only on: presence of a URL, generic wording
- Only mark malicious if there is STRONG evidence (multiple vendor hits, known campaign, confirmed phishing, etc.)

3. Content-Based Analysis:
- Detect phishing patterns: urgency language, fear tactics, rewards/prizes, impersonation
- Identify anomalies: mismatch between message and link, suspicious tone, social engineering

4. Artifact Analysis:
- Check domain age (new domains = higher risk), reputation scores, known malicious indicators
- Correlate with known campaigns from threat intelligence feeds

5. Balanced Reasoning:
- Do NOT overestimate weak signals
- Do NOT ignore strong indicators
- Be precise and evidence-based

STYLE GUIDELINES:
- Use simple, non-technical language understandable by a normal user
- Be concise but informative
- Explain "why" clearly
- Do NOT hallucinate data or exaggerate risk"""


def generate_threat_summary(url: str, iocs: dict) -> str:
    """Generate an AI-powered threat analysis using a structured system prompt."""
    try:
        import groq, os, json as _json
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            return "AI summary unavailable."
        client = groq.Groq(api_key=api_key)

        risk = iocs.get("risk_score", 0)
        vt_stats = iocs.get("vt_stats", {})
        geo = iocs.get("geo", {})
        tech = iocs.get("tech_stack", {})
        details = iocs.get("details", {})
        whois_data = details.get("whois", {})
        domain_age = details.get("domain_age_days")
        threatfox = iocs.get("threatfox", [])
        ssl = iocs.get("ssl_info", {})
        abuse = details.get("abuseipdb", {})
        redirect_chain = iocs.get("redirect_chain", [])
        dom_heuristics = iocs.get("dom_heuristics", "")

        enrichment_data = (
            f"VirusTotal: {vt_stats.get('malicious', 0)} malicious, "
            f"{vt_stats.get('suspicious', 0)} suspicious out of "
            f"{sum(vt_stats.values()) if vt_stats else 0} engines\n"
            f"PhishTank: {details.get('phishtank', 'clean')}\n"
            f"Safe Browsing: {details.get('safe_browsing', 'clean')}\n"
            f"AbuseIPDB confidence: {abuse.get('abuseConfidenceScore', 'N/A')}%\n"
            f"ThreatFox hits: {len(threatfox)}\n"
            f"Geo: {geo.get('country', 'Unknown')} / {geo.get('city', '')} — ISP: {geo.get('isp', 'Unknown')}"
        )

        whois_str = (
            f"Registrar: {whois_data.get('registrar', 'Unknown')}\n"
            f"Domain age: {f'{domain_age} days' if domain_age is not None else 'Unknown'}\n"
            f"SSL issuer: {ssl.get('issuer', 'Unknown')}\n"
            f"SSL subject: {ssl.get('subject', 'Unknown')}"
        )

        heuristics = (
            f"Risk score: {risk}/10\n"
            f"Server: {tech.get('server', 'Unknown')} | Powered by: {tech.get('powered_by', 'Unknown')}\n"
            f"Security headers present: {len(tech.get('security_headers', []))}\n"
            f"Redirect chain length: {len(redirect_chain)}\n"
            f"DOM heuristics: {dom_heuristics or 'Not analyzed'}"
        )

        user_content = (
            f"Input: {url}\n"
            f"Extracted IPs: {', '.join(iocs.get('ips', [])[:5]) or 'None'}\n"
            f"Extracted Domains: {', '.join(iocs.get('domains', [])[:5]) or 'None'}"
        )

        user_prompt = f"""INPUT DATA:

1. User Content / Target:
{user_content}

2. Threat Intelligence Data:
{enrichment_data}

3. WHOIS / Domain Intelligence:
{whois_str}

4. Heuristic Signals:
{heuristics}

---

Return a JSON object with exactly these keys:
{{
  "verdict": "Benign | Suspicious | Malicious",
  "confidence": "Low | Medium | High",
  "summary": "1-2 line simple explanation",
  "detailed_explanation": ["bullet 1", "bullet 2", "..."],
  "key_indicators": ["indicator 1", "indicator 2", "..."],
  "recommended_action": ["action 1", "action 2", "..."]
}}"""

        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": _THREAT_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.1,
            response_format={"type": "json_object"},
        )

        raw = resp.choices[0].message.content.strip()
        try:
            parsed = _json.loads(raw)
            # Format the structured response into readable text for the existing UI
            lines = [
                f"**Verdict:** {parsed.get('verdict', 'Unknown')} (Confidence: {parsed.get('confidence', 'Unknown')})",
                f"\n**Summary:** {parsed.get('summary', '')}",
                "\n**Detailed Explanation:**",
            ]
            for point in parsed.get("detailed_explanation", []):
                lines.append(f"- {point}")
            lines.append("\n**Key Indicators:**")
            for ind in parsed.get("key_indicators", []):
                lines.append(f"- {ind}")
            lines.append("\n**Recommended Action:**")
            for action in parsed.get("recommended_action", []):
                lines.append(f"- {action}")
            return "\n".join(lines)
        except Exception:
            return raw  # fallback: return raw text if JSON parsing fails

    except Exception as e:
        return f"AI summary generation failed: {str(e)}"


_NARRATIVE_SYSTEM_PROMPT = """You are an elite threat intelligence analyst specialising in cybercriminal campaign attribution, APT group profiling, and attack pattern recognition.

Your task: given enriched threat intelligence data, produce a Narrative Intelligence Score that goes far beyond a simple risk number.

You must:
1. Identify the TOP 3–5 attack scenarios this evidence supports, with calibrated probability percentages that sum to exactly 100.
2. Generate a single compelling headline narrative sentence that a CISO would read (include the top probability inline).
3. Profile the likely victim demographic precisely.
4. Derive a confidence interval (low–high) for the raw numeric risk score.
5. Name the campaign archetype.

Be precise, evidence-based, and never hallucinate. If evidence is weak or the target looks clean, assign the majority probability to a "Benign / Low Risk" scenario."""


def generate_narrative_intelligence(url: str, iocs: dict) -> dict:
    """Generate AI Narrative Intelligence Score — attack scenario probabilities, threat narrative, and confidence interval."""
    try:
        import groq, os, json as _json
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            return {}
        client = groq.Groq(api_key=api_key)

        risk = iocs.get("risk_score", 0)
        vt_stats = iocs.get("vt_stats", {})
        geo = iocs.get("geo", {})
        details = iocs.get("details", {})
        whois_data = details.get("whois", {})
        domain_age = details.get("domain_age_days")
        threatfox = iocs.get("threatfox", [])
        ssl = iocs.get("ssl_info", {})
        abuse = details.get("abuseipdb", {})
        dom_heuristics = iocs.get("dom_heuristics", "")
        redirect_chain = iocs.get("redirect_chain", [])
        subdomains = iocs.get("subdomains", [])
        tech = iocs.get("tech_stack", {})
        vt_categories = iocs.get("vt_categories", {})
        vt_vendors = iocs.get("vt_vendors", {})

        malicious_vendors = [v for v, d in vt_vendors.items() if d.get("category") == "malicious"][:5]

        evidence = (
            f"Target: {url}\n"
            f"Risk Score: {risk}/10\n"
            f"IPs: {', '.join(iocs.get('ips', [])[:3]) or 'None'}\n"
            f"Domains: {', '.join(iocs.get('domains', [])[:3]) or 'None'}\n\n"
            f"VirusTotal: {vt_stats.get('malicious', 0)} malicious / "
            f"{vt_stats.get('suspicious', 0)} suspicious / "
            f"{sum(vt_stats.values()) if vt_stats else 0} total engines\n"
            f"Malicious vendors: {', '.join(malicious_vendors) or 'None'}\n"
            f"VT Categories: {', '.join(f'{k}:{v}' for k, v in list(vt_categories.items())[:3]) or 'None'}\n\n"
            f"Geo: {geo.get('country','?')} / {geo.get('city','?')} — ISP: {geo.get('isp','?')}\n"
            f"Domain age: {f'{domain_age} days' if domain_age is not None else 'Unknown'}\n"
            f"Registrar: {whois_data.get('registrar','Unknown')}\n"
            f"SSL issuer: {ssl.get('issuer','Unknown')} | subject: {ssl.get('subject','Unknown')}\n\n"
            f"AbuseIPDB score: {abuse.get('abuseConfidenceScore','N/A')}%\n"
            f"ThreatFox hits: {len(threatfox)}\n"
            f"PhishTank: {details.get('phishtank','clean')}\n"
            f"Safe Browsing: {details.get('safe_browsing','clean')}\n"
            f"DOM heuristics: {(dom_heuristics or 'Not analyzed')[:200]}\n"
            f"Redirect chain length: {len(redirect_chain)}\n"
            f"Subdomains found: {len(subdomains)}\n"
            f"Tech stack: server={tech.get('server','?')}, CMS={tech.get('powered_by','?')}"
        )

        user_prompt = f"""Evidence:
{evidence}

Return a JSON object with EXACTLY these keys:
{{
  "narrative": "Single headline sentence with the top probability inline, e.g.: '82% probability: credential-harvesting campaign impersonating a government agency, targeting rural benefit recipients'",
  "scenarios": [
    {{"name": "Scenario Name", "probability": 82, "description": "Brief evidence-based explanation (max 15 words)", "icon": "🎣"}},
    {{"name": "...", "probability": 12, "description": "...", "icon": "🎭"}},
    {{"name": "...", "probability": 6, "description": "...", "icon": "💰"}}
  ],
  "target_profile": "Precise victim demographic (e.g., 'Government benefit recipients in rural Pakistan')",
  "risk_confidence_low": 7.0,
  "risk_confidence_high": 9.0,
  "campaign_archetype": "e.g., 'Credential Harvesting', 'Malware Distribution', 'C2 Infrastructure', 'Brand Impersonation', 'Benign / Low Risk'"
}}

Rules:
- scenario probabilities must sum to exactly 100
- Include 3–5 scenarios; top scenario reflects the strongest evidence
- If evidence is weak/clean, top scenario = "Benign / Low Risk" with ≥ 70% probability
- Icon guide: 🎣 phishing  🦠 malware  📡 C2/botnet  🎭 brand impersonation  💰 fraud  🕵️ espionage  ✅ benign  ❓ unknown
- risk_confidence_low / risk_confidence_high form a plausible range around the raw score of {risk}/10"""

        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": _NARRATIVE_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.15,
            response_format={"type": "json_object"},
        )

        raw = resp.choices[0].message.content.strip()
        return _json.loads(raw)

    except Exception as exc:
        return {"error": str(exc)}


def generate_typosquatting(domain: str) -> list:
    '''Generate and test basic domain typosquatting permutations.'''
    parts = domain.split(".")
    if len(parts) < 2: return []
    base = parts[0]
    tld = ".".join(parts[1:])
    
    permutations = set()
    # Omission
    for i in range(len(base)):
        permutations.add(base[:i] + base[i+1:] + "." + tld)
    # Repetition
    for i in range(len(base)):
        permutations.add(base[:i] + base[i]*2 + base[i+1:] + "." + tld)
    # Common tricks
    permutations.add(base + "-" + tld.replace(".", "-") + ".com")
    permutations.add(base + "s." + tld)
    
    import socket
    active = []
    # Test up to 15 permutations to avoid UI freeze
    for p in list(permutations)[:15]:
        if p == domain or len(p) < 4: continue
        try:
            ip = socket.gethostbyname(p)
            active.append({"domain": p, "ip": ip})
        except:
            pass
    return active

def generate_yara_rule(iocs: dict) -> str:
    '''Generate a YARA rule based on extracted IOCs via Groq LLM.'''
    try:
        from agents.misinfo_investigator import _get_client
        client = _get_client()
        ioc_summary = f"IPs: {iocs.get('ips', [])}, Domains: {iocs.get('domains', [])}, Hashes: {iocs.get('hashes', [])}"
        prompt = f"Write a professional YARA rule to detect the following Threat Intelligence IOCs:\n{ioc_summary}\nInclude meta tags for author 'Lumina Shield Analyst'. Return ONLY the raw YARA rule text."
        ai_resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0
        )
        rule = ai_resp.choices[0].message.content.strip()
        if rule.startswith("```"):
            rule = rule.split("\n", 1)[1].rsplit("```", 1)[0]
        return rule
    except Exception as e:
        return f"// Failed to generate YARA rule: {str(e)}"


def generate_snort_rule(iocs: dict) -> str:
    """Generate Snort/Suricata IDS rules from extracted IOCs via Groq LLM."""
    try:
        from agents.misinfo_investigator import _get_client
        client = _get_client()
        ioc_summary = (
            f"IPs: {iocs.get('ips', [])}, "
            f"Domains: {iocs.get('domains', [])}, "
            f"Hashes: {iocs.get('hashes', [])}, "
            f"Risk Score: {iocs.get('risk_score', 0)}/10"
        )
        prompt = (
            f"Write professional Snort 3 / Suricata IDS rules to detect network traffic "
            f"related to the following Threat Intelligence IOCs:\n{ioc_summary}\n"
            "Include SID numbers starting from 9000001, revision 1, classtype:trojan-activity "
            "where appropriate. Return ONLY the raw Snort rule text, one rule per line."
        )
        ai_resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0
        )
        rule = ai_resp.choices[0].message.content.strip()
        if rule.startswith("```"):
            rule = rule.split("\n", 1)[1].rsplit("```", 1)[0]
        return rule
    except Exception as e:
        return f"# Failed to generate Snort rule: {str(e)}"


_KNOWN_THREAT_ACTORS = {
    "APT28 (Fancy Bear)": ["Russia", "phishing", "credential harvesting", "spear phishing", "Sofacy"],
    "APT29 (Cozy Bear)": ["Russia", "steganography", "supply chain", "OAuth", "cloud"],
    "Lazarus Group": ["North Korea", "cryptocurrency", "financial", "watering hole", "WannaCry"],
    "APT41": ["China", "ransomware", "supply chain", "gaming", "espionage"],
    "FIN7": ["financial", "POS", "Carbanak", "hospitality", "retail"],
    "Conti": ["ransomware", "double extortion", "RDP", "Cobalt Strike"],
    "REvil / Sodinokibi": ["ransomware", "affiliate", "Kaseya", "MSP"],
    "TA505": ["phishing", "dridex", "clop", "financial", "malspam"],
    "Turla": ["Russia", "backdoor", "satellite", "espionage", "Snake"],
    "Sandworm": ["Russia", "ICS", "destructive", "NotPetya", "Ukraine", "energy"],
    "Scattered Spider": ["social engineering", "SIM swapping", "helpdesk", "cloud", "MGM"],
}

_MITRE_TACTICS = {
    "Initial Access": ["phishing", "spear phishing", "watering hole", "supply chain", "exploit public-facing"],
    "Execution": ["PowerShell", "cmd", "script", "macro", "WMI"],
    "Persistence": ["registry", "scheduled task", "startup", "backdoor", "rootkit"],
    "Defense Evasion": ["obfuscation", "steganography", "LOLBins", "packed", "encrypted"],
    "Credential Access": ["credential harvesting", "keylogger", "brute force", "OAuth", "cookie theft"],
    "Discovery": ["network scan", "port scan", "enumeration", "LDAP", "active directory"],
    "Lateral Movement": ["RDP", "WMI", "pass-the-hash", "lateral", "SMB"],
    "Command & Control": ["C2", "Cobalt Strike", "beacon", "DNS tunneling", "proxy"],
    "Exfiltration": ["data theft", "cloud", "FTP", "exfiltration", "S3"],
    "Impact": ["ransomware", "destructive", "wiper", "DDoS", "double extortion"],
}


def generate_threat_actor_profile(domain: str, iocs: dict) -> dict:
    """AI-powered threat actor profiling with disk caching and rate-limit guard."""
    from utils.disk_cache import cache_get, cache_set

    # ── 1. Disk cache hit (survives restarts, 6-hour TTL) ──────────────────
    cached = cache_get("actor_profile", domain)
    if cached is not None:
        cached["_from_cache"] = True
        return cached

    # ── 2. Build minimal context (keeps token count low) ───────────────────
    geo = iocs.get("geo", {})
    ioc_context = (
        f"domain={domain} "
        f"ips={iocs.get('ips', [])[:3]} "
        f"risk={iocs.get('risk_score', 0)}/10 "
        f"vt_malicious={iocs.get('vt_stats', {}).get('malicious', 0)} "
        f"threatfox={iocs.get('threatfox', [])[:2]} "
        f"country={geo.get('country', '?')} "
        f"heuristics={str(iocs.get('dom_heuristics', ''))[:100]} "
        f"redirects={len(iocs.get('redirect_chain', []))}"
    )

    prompt = (
        "You are a cybersecurity threat intelligence analyst. "
        "Analyse the following IOC data and respond with a single valid JSON object — no markdown, no extra text.\n\n"
        f"IOC DATA:\n{ioc_context}\n\n"
        "Return EXACTLY this JSON structure (fill every field with real analysis — never leave arrays empty or strings blank):\n"
        '{\n'
        '  "threat_actor_candidates": [\n'
        '    {"name": "APT28 / Fancy Bear", "confidence": "Medium", "reasoning": "Russian APT known for phishing infrastructure matching this domain pattern."},\n'
        '    {"name": "Unknown Cybercriminal", "confidence": "Low", "reasoning": "Generic financial phishing TTPs observed."}\n'
        '  ],\n'
        '  "campaign_narrative": "2-3 sentence description of what this threat actor is likely doing, why, and who the targets are.",\n'
        '  "threat_level": "Cybercriminal",\n'
        '  "motivation": "Financial",\n'
        '  "mitre_tactics": ["Initial Access", "Command & Control"],\n'
        '  "mitre_techniques": [\n'
        '    {"id": "T1566", "name": "Phishing", "relevance": "Domain used in spear-phishing lures."}\n'
        '  ],\n'
        '  "recommended_detections": ["Block domain at DNS layer", "Alert on outbound connections to this IP range"]\n'
        '}\n\n'
        "Base the analysis on the IOC data above. Choose the most plausible threat actor(s). "
        "The campaign_narrative MUST be a non-empty descriptive paragraph."
    )

    # ── 3. API call — no auto-retry, hard 20 s timeout ─────────────────────
    try:
        import groq as _groq
        import json as _json

        client = _groq.Groq(
            api_key=__import__("os").getenv("GROQ_API_KEY"),
            max_retries=0,          # never block on automatic retries
            timeout=20.0,           # hard wall-clock timeout
        )

        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=900,
            response_format={"type": "json_object"},
        )
        result = _json.loads(resp.choices[0].message.content)

        # ── Post-process: repair common model omissions ──────────────────
        if not result.get("threat_actor_candidates"):
            result["threat_actor_candidates"] = [
                {"name": "Unknown Actor", "confidence": "Low",
                 "reasoning": f"Insufficient distinctive signals for attribution on {domain}."}
            ]
        if not result.get("campaign_narrative"):
            risk = iocs.get("risk_score", 0)
            country = geo.get("country", "unknown origin")
            result["campaign_narrative"] = (
                f"This infrastructure ({domain}) exhibits a risk score of {risk}/10 "
                f"and appears to originate from {country}. "
                "The TTPs are consistent with opportunistic cybercriminal activity targeting end users."
            )
        if not result.get("mitre_tactics"):
            result["mitre_tactics"] = ["Initial Access"]
        if not result.get("recommended_detections"):
            result["recommended_detections"] = [f"Block {domain} at DNS/firewall layer"]

        result["_from_cache"] = False
        cache_set("actor_profile", result, 3600 * 6, domain)
        return result

    except _groq.RateLimitError:
        # Surface a clear rate-limit signal the UI can catch
        raise RuntimeError(
            "RATE_LIMIT: Groq free-tier TPM cap reached. "
            "Wait ~60 s before running another profile."
        )
    except Exception as e:
        return {
            "threat_actor_candidates": [{"name": "Unknown", "confidence": "Low", "reasoning": str(e)}],
            "mitre_tactics": [],
            "mitre_techniques": [],
            "campaign_narrative": f"Profiling failed: {e}",
            "threat_level": "Unknown",
            "motivation": "Unknown",
            "recommended_detections": [],
            "_from_cache": False,
        }


def investigate_threat_cached(url: str = None, file_hash: str = None, progress_callback=None) -> dict:
    """investigate_threat with persistent SQLite disk cache (survives restarts)."""
    from utils.disk_cache import cache_get, cache_set
    cache_key = url or file_hash or ""
    namespace = "investigate_threat"
    TTL = 3600 * 12  # 12 hours

    cached = cache_get(namespace, cache_key)
    if cached is not None:
        cached["_from_cache"] = True
        return cached

    result = investigate_threat(url=url, file_hash=file_hash, progress_callback=progress_callback)
    result["_from_cache"] = False
    cache_set(namespace, result, TTL, cache_key)
    return result


# ──────────────────────────────────────────────────────────────────────────
# Kill-Chain Timeline Reconstruction
# Maps IOC evidence to each Cyber Kill Chain phase via Groq LLM.
# ──────────────────────────────────────────────────────────────────────────

def generate_kill_chain_timeline(domain: str, iocs: dict, actor_profile: dict) -> dict:
    """
    Reconstruct the full Cyber Kill Chain timeline with IOC evidence mapped
    to each stage. Uses Groq llama-3.3-70b-versatile with 6-hour disk cache.

    Returns:
        {
          "phases": [
            {"phase": "Reconnaissance", "icon": "🔍",
             "evidence": "...", "ioc_refs": [...], "confidence": "Medium"},
            ...
          ],
          "narrative": "Overall paragraph reconstructing the attack story.",
          "attack_duration_estimate": "~2 weeks",
          "_from_cache": bool
        }
    """
    from utils.disk_cache import cache_get, cache_set

    cached = cache_get("kill_chain", domain)
    if cached is not None:
        cached["_from_cache"] = True
        return cached

    geo = iocs.get("geo", {})
    ioc_context = {
        "domain": domain,
        "ips": iocs.get("ips", [])[:4],
        "hashes": iocs.get("hashes", [])[:2],
        "emails": iocs.get("emails", [])[:2],
        "risk_score": iocs.get("risk_score", 0),
        "vt_malicious": iocs.get("vt_stats", {}).get("malicious", 0),
        "threatfox": [h.get("threat_type") for h in iocs.get("threatfox", [])[:3]],
        "redirect_chain_len": len(iocs.get("redirect_chain", [])),
        "dom_heuristics": str(iocs.get("dom_heuristics", ""))[:150],
        "whois_age_days": iocs.get("details", {}).get("domain_age_days"),
        "registrar": iocs.get("details", {}).get("whois", {}).get("registrar", "?") if isinstance(iocs.get("details", {}).get("whois"), dict) else "?",
        "country": geo.get("country", "?"),
        "open_ports": iocs.get("details", {}).get("open_ports", [])[:5],
        "mitre_tactics": actor_profile.get("mitre_tactics", [])[:5],
        "threat_level": actor_profile.get("threat_level", "Unknown"),
        "motivation": actor_profile.get("motivation", "Unknown"),
    }

    prompt = (
        "You are a senior threat intelligence analyst. "
        "Using the IOC data below, reconstruct the full Cyber Kill Chain timeline "
        "mapping specific evidence to each phase.\n\n"
        f"IOC DATA:\n{ioc_context}\n\n"
        "Return ONLY this JSON (no markdown). Fill EVERY field with real, specific analysis derived from the data:\n"
        '{\n'
        '  "phases": [\n'
        '    {\n'
        '      "phase": "Reconnaissance",\n'
        '      "icon": "🔍",\n'
        '      "evidence": "Specific evidence from IOC data mapped to this phase",\n'
        '      "ioc_refs": ["domain age: X days", "registrar: Y"],\n'
        '      "confidence": "High|Medium|Low"\n'
        '    },\n'
        '    {"phase": "Weaponization", "icon": "⚙️", ...},\n'
        '    {"phase": "Delivery", "icon": "📨", ...},\n'
        '    {"phase": "Exploitation", "icon": "💥", ...},\n'
        '    {"phase": "Installation", "icon": "🔧", ...},\n'
        '    {"phase": "Command & Control", "icon": "📡", ...},\n'
        '    {"phase": "Exfiltration / Impact", "icon": "🚨", ...}\n'
        '  ],\n'
        '  "narrative": "A 3-4 sentence paragraph reconstructing the full attack story, '
        'referencing specific IOCs and timeline.",\n'
        '  "attack_duration_estimate": "e.g. ~2 weeks of active operation"\n'
        '}\n\n'
        "Be specific. Reference actual domain names, IPs, port numbers, heuristics from the data. "
        "Never leave evidence or ioc_refs empty."
    )

    try:
        import groq as _groq, json as _json

        client = _groq.Groq(
            api_key=__import__("os").getenv("GROQ_API_KEY"),
            max_retries=0,
            timeout=25.0,
        )
        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.15,
            max_tokens=1200,
            response_format={"type": "json_object"},
        )
        result = _json.loads(resp.choices[0].message.content)

        # Ensure structure integrity
        phases = result.get("phases", [])
        expected = [
            ("Reconnaissance", "🔍"), ("Weaponization", "⚙️"), ("Delivery", "📨"),
            ("Exploitation", "💥"), ("Installation", "🔧"),
            ("Command & Control", "📡"), ("Exfiltration / Impact", "🚨"),
        ]
        if len(phases) < 7:
            existing_names = {p.get("phase", "") for p in phases}
            for pname, picon in expected:
                if pname not in existing_names:
                    phases.append({
                        "phase": pname, "icon": picon,
                        "evidence": f"Insufficient data to map evidence to {pname} phase.",
                        "ioc_refs": [], "confidence": "Low",
                    })
        result["phases"] = phases[:7]
        result.setdefault("narrative", f"Kill chain reconstruction for {domain} based on {iocs.get('risk_score', 0)}/10 risk score.")
        result.setdefault("attack_duration_estimate", "Unknown")
        result["_from_cache"] = False
        cache_set("kill_chain", result, 3600 * 6, domain)
        return result

    except _groq.RateLimitError:
        raise RuntimeError("RATE_LIMIT: Groq free-tier TPM cap reached. Wait ~60 s.")
    except Exception as exc:
        return {
            "phases": [],
            "narrative": f"Kill chain reconstruction failed: {exc}",
            "attack_duration_estimate": "Unknown",
            "_from_cache": False,
        }
