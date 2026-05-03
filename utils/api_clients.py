import requests
import os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import streamlit as st
from tenacity import retry, stop_after_attempt, wait_exponential

VT_API_KEY = os.getenv("VT_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
SAFE_BROWSING_KEY = os.getenv("SAFE_BROWSING_API_KEY")
SHODAN_KEY = os.getenv("SHODAN_API_KEY")

# ---- VirusTotal ----
import base64, time as _time

def _vt_url_id(url: str) -> str:
    """VT v3 URL identifier = base64(url) without trailing '='."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

@st.cache_data(ttl=3600*24, show_spinner=False)
def vt_url_scan(url: str) -> dict:
    """Submit URL for scanning, poll until done, return analysis result."""
    if not VT_API_KEY: return {"error": "API key missing"}
    headers={"x-apikey": VT_API_KEY, "User-Agent": "LuminaShield/1.0 (Hackathon Project)"}
    # Step 1: Submit the URL
    resp = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, headers=headers)
    if resp.status_code != 200:
        return {"error": f"Submit HTTP {resp.status_code}"}
    analysis_id = resp.json().get("data", {}).get("id")
    if not analysis_id:
        return {"error": "No analysis ID returned"}
    # Step 2: Poll analysis until completed (up to 60s)
    for _ in range(12):
        _time.sleep(5)
        analysis_resp = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )
        if analysis_resp.status_code == 200:
            data = analysis_resp.json()
            status = data.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                return data
    # Return whatever we got
    return analysis_resp.json() if analysis_resp.status_code == 200 else {"error": "Poll timeout"}

@st.cache_data(ttl=3600*24, show_spinner=False)
def vt_url_report(url: str) -> dict:
    """Fetch the FULL URL report â€” per-vendor verdicts, categories, reputation, HTTP info.
    This is equivalent to what you see on the VirusTotal website."""
    if not VT_API_KEY: return {"error": "API key missing"}
    headers={"x-apikey": VT_API_KEY, "User-Agent": "LuminaShield/1.0 (Hackathon Project)"}
    url_id = _vt_url_id(url)
    resp = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers=headers
    )
    if resp.status_code == 200:
        return resp.json()
    return {"error": f"Report HTTP {resp.status_code}"}

@st.cache_data(ttl=3600*24, show_spinner=False)
def vt_hash_lookup(file_hash: str) -> dict:
    if not VT_API_KEY: return {"error": "API key missing"}
    headers={"x-apikey": VT_API_KEY, "User-Agent": "LuminaShield/1.0 (Hackathon Project)"}
    resp = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers)
    return resp.json() if resp.status_code == 200 else {}

# ---- URLScan.io ----
@st.cache_data(ttl=3600*24, show_spinner=False)
def urlscan_submit(url: str) -> dict:
    if not URLSCAN_API_KEY:
        return {"error": "API key missing"}

    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json",
        "User-Agent": "LuminaShield/1.0 (Hackathon Project)",
    }

    try:
        resp = requests.post(
            "https://urlscan.io/api/v1/scan/",
            json={"url": url, "visibility": "public"},
            headers=headers,
            timeout=15,
        )
        if resp.status_code != 200:
            return {"error": f"Submit HTTP {resp.status_code}"}

        uuid = resp.json().get("uuid")
        if not uuid:
            return {"error": "No scan UUID returned"}

        import time

        for _ in range(10):
            time.sleep(3)
            try:
                result_resp = requests.get(
                    f"https://urlscan.io/api/v1/result/{uuid}/",
                    headers=headers,
                    timeout=15,
                )
            except requests.RequestException as exc:
                return {"error": f"URLScan result lookup failed: {exc}"}

            if result_resp.status_code == 200:
                return result_resp.json()

        return {"error": "URLScan poll timeout"}
    except requests.RequestException as exc:
        return {"error": f"URLScan submit failed: {exc}"}

# ---- AbuseIPDB ----
@st.cache_data(ttl=3600*2, show_spinner=False)
def abuseipdb_check(ip: str) -> dict:
    if not ABUSEIPDB_KEY: return {}
    headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json", "User-Agent": "LuminaShield/1.0 (Hackathon Project)"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    resp = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
    return resp.json() if resp.status_code == 200 else {}

# ---- PhishTank (no key needed) ----
@st.cache_data(ttl=3600*12, show_spinner=False)
def phishtank_check(url: str) -> bool:
    try:
        resp = requests.post("https://checkurl.phishtank.com/checkurl/", data={"url": url, "format": "json"}, headers={"User-Agent": "LuminaShield/1.0 (Hackathon Project)"})
        data = resp.json()
        return data.get("results", {}).get("in_database") == "true"
    except:
        return False

# ---- WHOIS ----
import whois
@st.cache_data(ttl=3600*24, show_spinner=False)
def whois_lookup(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "country": w.country
        }
    except:
        return {}

# ---- DNS Resolution via dnspython (FREE, no API key) ----
import dns.resolver

@st.cache_data(ttl=3600, show_spinner=False)
def dns_resolve_all(domain: str) -> dict:
    """Resolve A, AAAA, MX, NS, TXT, CNAME records using dnspython. Completely free."""
    records = {
        "A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": [],
    }
    for rtype in records.keys():
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for rdata in answers:
                val = str(rdata).strip('"')
                if rtype == "MX":
                    val = f"{rdata.preference} {rdata.exchange}"
                records[rtype].append(val)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, Exception):
            pass
    return records

@st.cache_data(ttl=3600, show_spinner=False)
def dns_reverse_lookup(ip: str) -> str:
    """Reverse DNS lookup for an IP."""
    try:
        from dns import reversename
        rev_name = reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR")
        return str(answers[0])
    except:
        return ""

# ---- Google Public DNS over HTTPS (FREE, no API key) ----
@st.cache_data(ttl=3600, show_spinner=False)
def google_dns_resolve(domain: str, rtype: str = "A") -> list:
    """Use Google Public DNS-over-HTTPS for DNS resolution. Completely free."""
    try:
        resp = requests.get(
            f"https://dns.google/resolve?name={domain}&type={rtype}",
            timeout=5
        )
        if resp.status_code == 200:
            data = resp.json()
            return [a.get("data", "") for a in data.get("Answer", [])]
    except:
        pass
    return []

# ---- crt.sh Subdomains (FREE, no API key) ----
@st.cache_data(ttl=3600, show_spinner=False)
def crt_sh_subdomains(domain: str) -> list:
    """Fetch subdomains using crt.sh (completely free, no API key)."""
    try:
        resp = requests.get(f"https://crt.sh/?q=%25{domain}&output=json", timeout=15, headers={"User-Agent": "LuminaShield/1.0 (Hackathon Project)"})
        if resp.status_code == 200:
            data = resp.json()
            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                if name and "*" not in name:
                    # FIX: use actual newline character, not escaped \\n
                    for sub in name.split("\n"):
                        sub = sub.strip()
                        if sub:
                            subdomains.add(sub)
            return sorted(list(subdomains))
    except:
        pass
    return []

# ---- URLHaus by abuse.ch (FREE, no API key) ----
@st.cache_data(ttl=3600, show_spinner=False)
def urlhaus_check(domain: str) -> dict:
    """Check domain against URLhaus (completely free, no API key)."""
    try:
        resp = requests.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": domain}, timeout=10, headers={"User-Agent": "LuminaShield/1.0 (Hackathon Project)"})
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

# ---- ThreatFox by abuse.ch (FREE, no API key) ----
@st.cache_data(ttl=3600, show_spinner=False)
def threatfox_search(search_term: str, search_type: str = "ioc") -> dict:
    """Search ThreatFox for IOCs. search_type: 'ioc', 'tag', 'malware', 'hash'."""
    try:
        payload = {"query": "search_ioc", "search_term": search_term}
        resp = requests.post("https://threatfox-api.abuse.ch/api/v1/", json=payload, timeout=10, headers={"User-Agent": "LuminaShield/1.0 (Hackathon Project)"})
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

@st.cache_data(ttl=3600, show_spinner=False)
def threatfox_domain_check(domain: str) -> list:
    """Check if a domain appears in ThreatFox IOC database."""
    result = threatfox_search(domain)
    if result and result.get("query_status") == "ok":
        return result.get("data", [])
    return []

# ---- IP Geolocation via ip-api.com (FREE, no API key, 45 req/min) ----
@st.cache_data(ttl=3600*6, show_spinner=False)
def ip_geolocation(ip: str) -> dict:
    """Get IP geolocation, ISP, ASN info. Free, no key needed."""
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query",
            timeout=5
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return data
    except:
        pass
    return {}

# ---- Google Safe Browsing ----
@st.cache_data(ttl=3600*2, show_spinner=False)
def safe_browsing_check(url: str) -> dict:
    if not SAFE_BROWSING_KEY: return {}
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_KEY}"
    body = {
        "client": {"clientId": "sachai", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    resp = requests.post(api_url, json=body, headers={"User-Agent": "LuminaShield/1.0 (Hackathon Project)"})
    return resp.json() if resp.status_code == 200 else {}

# ---- Shodan ----
@st.cache_data(ttl=3600*12, show_spinner=False)
def shodan_host(ip: str) -> dict:
    if not SHODAN_KEY: return {}
    try:
        resp = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}", headers={"User-Agent": "LuminaShield/1.0 (Hackathon Project)"})
        return resp.json() if resp.status_code == 200 else {}
    except:
        return {}

# ---- Technology Stack Detection (from HTTP headers) ----
@st.cache_data(ttl=3600*12, show_spinner=False)
def detect_tech_stack(url: str) -> dict:
    """Detect technologies from HTTP response headers. No API key needed."""
    tech = {
        "server": None,
        "powered_by": None,
        "framework": None,
        "cdn": None,
        "security_headers": [],
        "all_headers": {}
    }
    try:
        resp = requests.head(url if "://" in url else f"https://{url}",
                            timeout=8, allow_redirects=True,
                            headers={"User-Agent": "LuminaShield/1.0 (Hackathon Project)"},
                            verify=False)
        headers = dict(resp.headers)
        tech["all_headers"] = headers
        tech["server"] = headers.get("Server") or headers.get("server")
        tech["powered_by"] = headers.get("X-Powered-By") or headers.get("x-powered-by")

        # Framework detection from headers
        if headers.get("X-AspNet-Version") or headers.get("x-aspnet-version"):
            tech["framework"] = f"ASP.NET {headers.get('X-AspNet-Version', '')}"
        elif headers.get("X-Drupal-Cache") or headers.get("x-drupal-cache"):
            tech["framework"] = "Drupal"
        elif "wp-" in str(headers):
            tech["framework"] = "WordPress"

        # CDN detection
        cdn_headers={
            "cf-ray": "Cloudflare", "x-cdn": "CDN", "x-amz-cf-id": "AWS CloudFront",
            "x-cache": "CDN Cache", "x-fastly-request-id": "Fastly",
            "x-akamai-transformed": "Akamai",
        }
        for h, cdn_name in cdn_headers.items():
            if h in [k.lower() for k in headers.keys()]:
                tech["cdn"] = cdn_name
                break

        # Security headers check
        sec_headers = ["Strict-Transport-Security", "Content-Security-Policy",
                       "X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection",
                       "Referrer-Policy", "Permissions-Policy"]
        for sh in sec_headers:
            if sh.lower() in [k.lower() for k in headers.keys()]:
                tech["security_headers"].append(sh)
    except:
        pass
    return tech

# ---- Shodan InternetDB (FREE, no API key) ----
@st.cache_data(ttl=3600*12, show_spinner=False)
def shodan_internetdb(ip: str) -> dict:
    """Get open ports, CVEs, CPEs, hostnames from Shodan InternetDB. FREE, no key."""
    try:
        resp = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=8,
                            headers={"User-Agent": "LuminaShield/1.0 (Hackathon Project)"})
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

# ---- CIRCL Passive DNS (FREE, no API key) ----
@st.cache_data(ttl=3600*6, show_spinner=False)
def circl_pdns(query: str) -> list:
    """Get passive DNS history from CIRCL PDNS. FREE, no key. Returns list of {rrtype, rdata, time_first, time_last}."""
    try:
        resp = requests.get(
            f"https://www.circl.lu/pdns/query/{query}",
            timeout=15,
            headers={"User-Agent": "LuminaShield/1.0 (Hackathon Project)", "Accept": "application/json"}
        )
        if resp.status_code == 200:
            results = []
            for line in resp.text.strip().split('\n'):
                line = line.strip()
                if line:
                    try:
                        import json as _json
                        results.append(_json.loads(line))
                    except Exception:
                        pass
            return results
    except:
        pass
    return []

# ---- BGPView IP/ASN Intelligence (FREE, no API key) ----
@st.cache_data(ttl=3600*24, show_spinner=False)
def bgpview_ip_info(ip: str) -> dict:
    """Get ASN, prefix, country, RIR info for an IP. FREE, no key."""
    try:
        resp = requests.get(f"https://api.bgpview.io/ip/{ip}", timeout=10,
                            headers={"User-Agent": "LuminaShield/1.0 (Hackathon Project)"})
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

@st.cache_data(ttl=3600*24, show_spinner=False)
def bgpview_asn_info(asn: int) -> dict:
    """Get ASN details â€” name, description, peers, prefixes. FREE, no key."""
    try:
        resp = requests.get(f"https://api.bgpview.io/asn/{asn}", timeout=10,
                            headers={"User-Agent": "LuminaShield/1.0 (Hackathon Project)"})
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

# ---- HackerTarget Reverse IP Lookup (FREE, limited to 20 req/day) ----
@st.cache_data(ttl=3600*12, show_spinner=False)
def hackertarget_reverse_ip(ip: str) -> list:
    """Find all domains hosted on same IP. FREE, limited."""
    try:
        resp = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=12,
                            headers={"User-Agent": "LuminaShield/1.0 (Hackathon Project)"})
        if resp.status_code == 200 and "error" not in resp.text.lower():
            return [d.strip() for d in resp.text.strip().split('\n') if d.strip() and len(d.strip()) > 3]
    except:
        pass
    return []

# ---- MXToolbox-style Email Security Check (via DNS, FREE) ----
@st.cache_data(ttl=3600*6, show_spinner=False)
def email_security_check(domain: str) -> dict:
    """Check SPF, DKIM, DMARC presence via DNS TXT records. FREE."""
    result = {"spf": None, "dmarc": None, "dkim_hint": None}
    try:
        records = dns_resolve_all(domain)
        txt_recs = records.get("TXT", [])
        for r in txt_recs:
            if r.startswith("v=spf1"):
                result["spf"] = r
            if "v=dmarc1" in r.lower():
                result["dmarc"] = r
        # DMARC is typically at _dmarc.domain
        try:
            import dns.resolver as _res
            ans = _res.resolve(f"_dmarc.{domain}", "TXT")
            for rdata in ans:
                result["dmarc"] = str(rdata).strip('"')
        except Exception:
            pass
    except Exception:
        pass
    return result

# ---- AlienVault OTX Pulse search (FREE, no key for basic lookups) ----
@st.cache_data(ttl=3600*6, show_spinner=False)
def otx_domain_report(domain: str) -> dict:
    """Get OTX pulse/indicator report for a domain. FREE (no key for basic)."""
    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            timeout=10,
            headers={"User-Agent": "LuminaShield/1.0 (Hackathon Project)"}
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

@st.cache_data(ttl=3600*6, show_spinner=False)
def otx_ip_report(ip: str) -> dict:
    """Get OTX pulse/indicator report for an IP. FREE (no key for basic)."""
    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            timeout=10,
            headers={"User-Agent": "LuminaShield/1.0 (Hackathon Project)"}
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

# ---- URLScan.io Screenshot (uses existing API key if present) ----
@st.cache_data(ttl=3600*24, show_spinner=False)
def urlscan_latest_screenshot(domain: str) -> dict:
    """
    1. Search URLScan.io for an existing scan (no auth â€” search is public).
    2. Download the screenshot PNG bytes directly.
    3. If no URLScan history, fall back to thum.io (free, no API key, live render).
    """
    # Search without API key â€” adding an invalid key returns 403
    search_headers = {"User-Agent": "Mozilla/5.0 (compatible; LuminaShield/1.0)"}

    try:
        resp = requests.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=5&sort=date",
            headers=search_headers,
            timeout=10,
        )
        if resp.status_code == 200:
            for r in resp.json().get("results", []):
                uuid = r.get("_id", "")
                if not uuid:
                    continue
                screenshot_url = f"https://urlscan.io/screenshots/{uuid}.png"
                try:
                    img_resp = requests.get(screenshot_url, headers=search_headers, timeout=10)
                    if img_resp.status_code == 200 and len(img_resp.content) > 1000:
                        return {
                            "screenshot_bytes": img_resp.content,
                            "source": "urlscan",
                            "scan_url": f"https://urlscan.io/result/{uuid}/",
                            "scanned_at": r.get("task", {}).get("time", ""),
                            "score": r.get("verdicts", {}).get("overall", {}).get("score", 0),
                            "malicious": r.get("verdicts", {}).get("overall", {}).get("malicious", False),
                        }
                except Exception:
                    continue
    except Exception:
        pass

    # Fallback: thum.io live screenshot (free, no key required)
    try:
        thum_url = f"https://image.thum.io/get/width/900/https://{domain}"
        img_resp = requests.get(thum_url, timeout=15)
        if img_resp.status_code == 200 and img_resp.headers.get("content-type", "").startswith("image"):
            return {
                "screenshot_bytes": img_resp.content,
                "source": "thum.io",
                "scan_url": f"https://{domain}",
                "scanned_at": "",
                "score": 0,
                "malicious": False,
            }
    except Exception:
        pass

    return {}