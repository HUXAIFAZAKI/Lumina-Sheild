"""
artifact_extractor.py
---------------------
Production-ready utility to extract cybersecurity artifacts
(IPv4 addresses, domains, URLs) from free-form text.

Author  : Senior Python / Security Engineer
License : MIT
"""

import re
from typing import TypedDict


# ---------------------------------------------------------------------------
# Type hint for the return value
# ---------------------------------------------------------------------------

class Artifacts(TypedDict):
    ipv4: list[str]
    domains: list[str]
    urls: list[str]


# ---------------------------------------------------------------------------
# Compiled regex patterns  (compiled once at import time for performance)
# ---------------------------------------------------------------------------

# IPv4: four octets 0-255.
# Guard: must be preceded by a non-alphanumeric char (or start-of-string)
# AND followed by a non-alphanumeric char (or end-of-string).
# This rejects both "1.2.3.4.5" (extra trailing octet) AND
# "version 3.1.4.1" where the token before the IP is a word char like 'n'.
_RE_IPV4 = re.compile(
    r"(?<![.\w])"                                                   # no word-char or dot before
    r"(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)"
    r"(?![.\w])"                                                    # no word-char or dot after
)

# URL: http / https scheme followed by a valid host + optional path/query/fragment.
# Stops at common trailing punctuation that is unlikely part of the URL.
_RE_URL = re.compile(
    r"https?://"                          # scheme
    r"(?:[A-Za-z0-9\-._~%]+@)?"          # optional userinfo
    r"(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}" # host (labels + TLD)
    r"(?::\d{1,5})?"                      # optional port
    r"(?:/[^\s<>\"'(){}|\\^\[\]`]*)?"    # optional path/query/fragment
    r"(?<![.,;:!?'\")])"                  # strip common trailing punctuation
)

# Domain: a standalone hostname that is NOT part of a URL already captured.
# Requires at least one dot, a valid TLD of 2+ chars, and word boundaries.
_RE_DOMAIN = re.compile(
    r"(?<!\w)"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)"  # one or more labels
    r"+[A-Za-z]{2,}"                                            # TLD
    r"(?!\w)"
)

# TLDs that are suspiciously short or common English words to reject as false positives
_FALSE_POSITIVE_TLDS = {
    "e", "g", "s", "t", "d", "n", "m", "x",   # single chars from abbreviations
}

# Common file extensions mistaken for domains (e.g. "setup.exe", "report.pdf").
# Includes binary/script extensions that often appear in malware URLs (.bin, .sh, .ps1 …)
_EXTENSION_BLOCKLIST = re.compile(
    r"\.(exe|dll|pdf|docx?|xlsx?|pptx?|zip|tar|gz|rar|7z"
    r"|png|jpe?g|gif|svg|mp[34]|avi|mov"
    r"|bin|sh|bash|ps1|bat|cmd|iso|img|dmg|msi|apk|deb|rpm)$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_urls(text: str) -> list[str]:
    """Return deduplicated, lowercased URLs found in *text*."""
    matches = _RE_URL.findall(text)
    seen: set[str] = set()
    result: list[str] = []
    for url in matches:
        normalised = url.lower()
        if normalised not in seen:
            seen.add(normalised)
            result.append(normalised)
    return result


def _extract_ipv4(text: str) -> list[str]:
    """Return deduplicated IPv4 addresses found in *text*."""
    matches = _RE_IPV4.findall(text)
    seen: set[str] = set()
    result: list[str] = []
    for ip in matches:
        if ip not in seen:
            seen.add(ip)
            result.append(ip)
    return result


def _host_from_url(url: str) -> str:
    """Extract the bare hostname (no scheme, port, or path) from a URL."""
    # Strip scheme
    host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    # Strip userinfo
    host = re.sub(r"^[^@]+@", "", host)
    # Strip path / query / fragment
    host = host.split("/")[0].split("?")[0].split("#")[0]
    # Strip port
    host = host.rsplit(":", 1)[0] if ":" in host else host
    return host.lower()


def _is_valid_domain(candidate: str) -> bool:
    """
    Basic sanity checks to filter out false positives.

    Rejects:
    - Pure IPv4 addresses (handled separately)
    - Known file extensions (e.g. report.pdf)
    - Single-character TLDs that are almost always abbreviations
    """
    if _RE_IPV4.fullmatch(candidate):
        return False
    if _EXTENSION_BLOCKLIST.search(candidate):
        return False
    tld = candidate.rsplit(".", 1)[-1].lower()
    if tld in _FALSE_POSITIVE_TLDS:
        return False
    return True


def _extract_domains(text: str, url_hosts: set[str]) -> list[str]:
    """
    Return standalone domains found in *text*, excluding any host that
    already appears in a URL (to prevent double-reporting).
    """
    matches = _RE_DOMAIN.findall(text)
    seen: set[str] = set()
    result: list[str] = []
    for domain in matches:
        normalised = domain.lower().rstrip(".")
        if normalised in seen:
            continue
        if normalised in url_hosts:          # already captured via URL
            continue
        if not _is_valid_domain(normalised):
            continue
        seen.add(normalised)
        result.append(normalised)
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_artifacts(text: str) -> Artifacts:
    """
    Extract cybersecurity artifacts from *text*.

    Parameters
    ----------
    text : str
        Raw text to analyse (log lines, emails, threat reports, etc.)

    Returns
    -------
    Artifacts
        A dictionary with three keys:
        - ``"ipv4"``    – list of unique IPv4 address strings
        - ``"domains"`` – list of unique standalone domain strings
        - ``"urls"``    – list of unique URL strings
        All string values are lowercased and deduplicated.

    Notes
    -----
    * A domain that is part of a captured URL is **not** added to
      ``"domains"`` to avoid duplication.
    * IPv4 addresses embedded inside URLs are captured as part of the URL
      and are also returned in ``"ipv4"``.
    """
    if not isinstance(text, str):
        raise TypeError(f"Expected str, got {type(text).__name__!r}")

    urls = _extract_urls(text)

    # Build the set of hostnames already covered by the extracted URLs
    url_hosts: set[str] = {_host_from_url(u) for u in urls}

    ipv4 = _extract_ipv4(text)
    domains = _extract_domains(text, url_hosts)

    return Artifacts(ipv4=ipv4, domains=domains, urls=urls)


# ---------------------------------------------------------------------------
# Example usage
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    SAMPLE_TEXT = """
    Threat Intel Report – 2024-06-01

    The C2 server was observed at 192.168.1.105 and also at 10.0.0.23.
    Phishing emails linked to http://malicious-site.com/payload?id=42 and
    https://update.evil-corp.ru/download/malware.bin were detected.

    The domain api.legit-service.io was queried independently.
    Contact admin@internal.corp or visit https://internal.corp/dashboard.

    Localhost (127.0.0.1) and broadcast (255.255.255.255) should be ignored
    in most threat feeds. The string "version 3.1.4.1" is NOT an IP.
    """

    results = extract_artifacts(SAMPLE_TEXT)

    print("=" * 55)
    print("  Artifact Extraction Results")
    print("=" * 55)
    for key, values in results.items():
        print(f"\n[{key.upper()}]")
        if values:
            for v in values:
                print(f"  • {v}")
        else:
            print("  (none)")
    print()