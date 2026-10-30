"""Explainable Fraud & Phishing Detection Engine."""

import re
from scamshield.patterns import FRAUD_SIGNATURES, IMPERSONATION_TARGETS
from scamshield.url_analyzer import extract_urls, analyze_single_url

class ScamShieldEngine:
    def __init__(self):
        self.signatures = FRAUD_SIGNATURES

    def analyze(self, text: str) -> dict:
        total_score = 0
        detected_triggers = []
        impersonation_found = []

        lower_text = text.lower()

        # 1. Detect Brand Impersonation
        for category, entities in IMPERSONATION_TARGETS.items():
            for entity in entities:
                pattern = rf"\b{re.escape(entity)}\b"
                if re.search(pattern, lower_text):
                    impersonation_found.append({
                        "entity": entity.upper(),
                        "category": category
                    })

        # 2. Check for Fraud Signatures
        for sig in self.signatures:
            if re.search(sig["pattern"], lower_text):
                total_score += sig["weight"]
                detected_triggers.append({
                    "id": sig["id"],
                    "category": sig["category"],
                    "weight": sig["weight"],
                    "explanation": sig["explanation"]
                })

        # 3. Extract and Analyze URLs
        urls = extract_urls(text)
        url_analyses = [analyze_single_url(u) for u in urls]
        for url_res in url_analyses:
            total_score += url_res["risk_points"]

        # 4. Multiplier: Impersonation combined with scam triggers
        if impersonation_found and len(detected_triggers) > 0:
            total_score += 15

        risk_score = min(total_score, 100)

        if risk_score >= 70:
            level = "CRITICAL / HIGH RISK"
        elif risk_score >= 40:
            level = "MEDIUM / SUSPICIOUS"
        else:
            level = "LOW / SAFE"

        recommendations = self._generate_recommendations(detected_triggers, url_analyses)

        return {
            "risk_score": risk_score,
            "risk_level": level,
            "impersonation_detected": impersonation_found,
            "triggers": detected_triggers,
            "url_analysis": url_analyses,
            "recommendations": recommendations,
        }

    def _generate_recommendations(self, triggers, urls) -> list[str]:
        recs = []
        trigger_ids = {t["id"] for t in triggers}

        if "FAKE_APP_MALWARE" in trigger_ids:
            recs.append("NEVER download apps from web browser links or WhatsApp messages. Install apps ONLY from the Google Play Store or Apple App Store.")
        if "UPI_RECEIVE_COLLECT" in trigger_ids:
            recs.append("NEVER enter your UPI PIN to receive money. UPI PIN is only needed to transfer money out.")
        if "ELECTRICITY_POWER_CUT" in trigger_ids:
            recs.append("Verify electricity bill status directly through your state DISCOM's official app. Never call numbers provided in SMS.")
        if "KYC_ACCOUNT_BLOCKED" in trigger_ids:
            recs.append("Do not click links or call numbers provided in SMS. Visit your nearest official bank branch or use the official mobile banking app.")
        if "DIGITAL_ARREST_LEGAL" in trigger_ids:
            recs.append("Disconnect the call immediately. Indian police and courts NEVER conduct trials over WhatsApp or Skype video calls.")
        if "UNSOLICITED_COLD_SPAM" in trigger_ids:
            recs.append("Unsolicited message from an unverified business. Tap Block and Report on WhatsApp.")
        if urls:
            recs.append("Do not open links with unfamiliar domain names or unencrypted HTTP connections.")

        recs.append("In case of cyber fraud in India, dial the National Cyber Crime Helpline at 1930 immediately.")
        return recs