"""Email Phishing & Domain Spoofing Analyzer."""

import re
import tldextract
from scamshield.patterns import IMPERSONATION_TARGETS, HIGH_RISK_TLDS

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com", 
    "rediffmail.com", "proton.me", "protonmail.com", "icloud.com"
}

# Genuine root domains for Indian institutions
OFFICIAL_DOMAINS = {
    "income tax": "incometax.gov.in",
    "rbi": "rbi.org.in",
    "sbi": "sbi.co.in",
    "hdfc": "hdfcbank.com",
    "icici": "icicibank.com",
    "epfo": "epfindia.gov.in",
    "india post": "indiapost.gov.in"
}

def analyze_email_metadata(sender_email: str, subject: str, body: str) -> dict:
    """
    Analyzes email sender addresses, display spoofing, and subject lines for fraud.
    """
    risk_points = 0
    warnings = []
    sender_email = sender_email.strip().lower()

    # Extract domain from email (e.g., support@sbi-update.xyz -> sbi-update.xyz)
    match = re.search(r"@([\w.-]+)", sender_email)
    domain_part = match.group(1) if match else ""

    ext = tldextract.extract(domain_part)
    registered_domain = f"{ext.domain}.{ext.suffix}"

    # 1. Check if claiming to be an official institution
    claimed_brand = None
    combined_text = f"{sender_email} {subject} {body}".lower()

    for brand, official_domain in OFFICIAL_DOMAINS.items():
        if brand in combined_text:
            claimed_brand = brand
            
            # Critical Alert: Claiming to be Bank/Govt from a FREE email provider
            if registered_domain in FREE_EMAIL_PROVIDERS:
                risk_points += 50
                warnings.append(
                    f"Free Webmail Impersonation: Claims to be from '{brand.upper()}', "
                    f"but is sent from a public free email account (@{registered_domain}). Official agencies NEVER use free email."
                )
            
            # Domain Spoofing / Typosquatting
            elif registered_domain and registered_domain != official_domain:
                risk_points += 45
                warnings.append(
                    f"Domain Spoofing: Claims to represent '{brand.upper()}', "
                    f"but email is sent from '@{registered_domain}' instead of the verified domain '@{official_domain}'."
                )
            break

    # 2. Check for High-Risk TLDs in sender domain (.xyz, .top, .buzz)
    if ext.suffix in HIGH_RISK_TLDS:
        risk_points += 30
        warnings.append(f"Suspicious Sender Extension: Domain '@{registered_domain}' uses a high-risk TLD (.{ext.suffix}) favored by spam networks.")

    # 3. Subject Line Urgency / Bait
    subject_lower = subject.lower()
    if re.search(r"(refund approved|tax refund|salary on hold|immediate verification|account suspended|de-activated)", subject_lower):
        risk_points += 25
        warnings.append(f"Subject Urgency Bait: Subject line ('{subject}') uses psychological coercion to force quick action.")

    return {
        "email_risk_points": min(risk_points, 100),
        "email_warnings": warnings,
        "claimed_brand": claimed_brand,
        "sender_domain": registered_domain
    }