"""URL Threat and Brand-Jacking Heuristic Analyzer."""

import re
import ipaddress
import tldextract
import validators
from scamshield.patterns import IMPERSONATION_TARGETS, URL_SHORTENERS, HIGH_RISK_TLDS

def extract_urls(text: str) -> list[str]:
    """Finds all URLs inside raw text or SMS."""
    url_pattern = r"(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9.-]+\.(?:com|in|org|net|xyz|top|site|co|online|live|info)[^\s]*)"
    candidates = re.findall(url_pattern, text)
    cleaned = []
    for cand in candidates:
        if isinstance(cand, tuple):
            cand = cand[0]
        cand = cand.rstrip(".,;!?)")
        if not cand.startswith(("http://", "https://")):
            cand = "http://" + cand
        if validators.url(cand):
            cleaned.append(cand)
    return list(set(cleaned))

def analyze_single_url(url: str) -> dict:
    """Analyzes a URL for deceptive lookalikes and suspicious artifacts."""
    extracted = tldextract.extract(url)
    domain = extracted.domain.lower()
    suffix = extracted.suffix.lower()
    subdomain = extracted.subdomain.lower()
    full_registered_domain = f"{domain}.{suffix}"

    risk_points = 0
    warning_signs = []

    # 1. Unencrypted HTTP for software/login
    if url.lower().startswith("http://"):
        risk_points += 15
        warning_signs.append(f"Insecure Link (HTTP): '{url}' does not use SSL/HTTPS encryption, typical of rogue download sites.")

    # 2. Raw IP address usage
    try:
        ipaddress.ip_address(domain)
        risk_points += 35
        warning_signs.append(f"Uses a raw IP address ({domain}) instead of a verified registered domain.")
    except ValueError:
        pass

    # 3. URL Shortener Detection
    if full_registered_domain in URL_SHORTENERS:
        risk_points += 20
        warning_signs.append(f"Uses a URL shortener ({full_registered_domain}) to hide its true destination.")

    # 4. Brand Impersonation & Typosquatting (e.g. goldwhatsapp.co)
    all_brands = [b.replace(" ", "") for sublist in IMPERSONATION_TARGETS.values() for b in sublist]
    for brand in all_brands:
        # Brand hijacked inside the domain name (e.g., 'goldwhatsapp' contains 'whatsapp')
        if brand in domain and domain != brand:
            risk_points += 40
            warning_signs.append(
                f"Brand Typosquatting / Spoofing: '{full_registered_domain}' incorporates the brand name '{brand.upper()}' without authorization."
            )
        # Brand in subdomain
        elif brand in subdomain and brand != domain:
            risk_points += 40
            warning_signs.append(
                f"Subdomain Deception: Brand '{brand.upper()}' placed in subdomain, but actual domain is '{full_registered_domain}'."
            )

    # 5. Suspicious executable / download paths
    if re.search(r"/(get|download|file|app|setup|\w+\.apk|\w+\.exe)$", url.lower()):
        risk_points += 20
        warning_signs.append(f"Direct executable/app download trigger detected in URL path ({url}).")

    # 6. High-Risk TLDs
    if suffix in HIGH_RISK_TLDS:
        risk_points += 25
        warning_signs.append(f"High-risk top-level domain (.{suffix}) commonly used in phishing campaigns.")

    return {
        "url": url,
        "domain": full_registered_domain,
        "risk_points": min(risk_points, 100),
        "warning_signs": warning_signs
    }