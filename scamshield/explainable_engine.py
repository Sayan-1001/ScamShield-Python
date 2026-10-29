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

        # 1. Detect Brand / Organization Impersonation
        for category, entities in IMPERSONATION_TARGETS.items():
            for entity in entities:
                pattern = rf"\b{re.escape(entity)}\b"
                if re.search(pattern, lower_text):
                    impersonation_found.append({
                        "entity": entity.upper(),
                        "category": category
                    })

        # 2. Check for Fraud Signatures (Scam Vectors)
        for sig in self.signatures:
            matches = re.findall(sig["pattern"], lower_text)
            if matches:
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

        # 4. Bonus weight: If an impersonation is detected alongside urgency or payment requests
        if impersonation_found and len(detected_triggers) > 0:
            total_score += 15

        # Normalize score between 0 and 100
        risk_score = min(total_score, 100)

        # Classify Severity Level
        if risk_score >= 70:
            level = "CRITICAL / HIGH RISK"
            color = "red"
        elif risk_score >= 40:
            level = "MEDIUM / SUSPICIOUS"
            color = "orange"
        else:
            level = "LOW / SAFE"
            color = "green"

        # Generate Actionable Safety Recommendations
        recommendations = self._generate_recommendations(detected_triggers, url_analyses, impersonation_found)

        return {
            "risk_score": risk_score,
            "risk_level": level,
            "badge_color": color,
            "impersonation_detected": impersonation_found,
            "triggers": detected_triggers,
            "url_analysis": url_analyses,
            "recommendations": recommendations,
            "cleaned_input": text
        }

    def _generate_recommendations(self, triggers, urls, impersonations) -> list[str]:
        recs = []
        trigger_ids = {t["id"] for t in triggers}

        if "UPI_RECEIVE_COLLECT" in trigger_ids:
            recs.append("NEVER enter your UPI PIN to receive money. UPI PIN is only needed to send money.")
        if "ELECTRICITY_POWER_CUT" in trigger_ids:
            recs.append("Verify electricity bill status directly through your state DISCOM's official app or consumer portal.")
        if "KYC_ACCOUNT_BLOCKED" in trigger_ids:
            recs.append("Do not click links or call numbers provided in SMS. Visit your nearest official bank branch or use the official mobile banking app.")
        if "DIGITAL_ARREST_LEGAL" in trigger_ids:
            recs.append("Disconnect the call immediately. Indian law enforcement does not issue warrants or conduct trials over WhatsApp/Skype video calls. Report to cybercrime.gov.in (1930).")
        if "PART_TIME_JOB_TELEGRAM" in trigger_ids:
            recs.append("Ignore job offers on WhatsApp/Telegram that promise fast money for liking videos or rating hotels.")
        if urls:
            recs.append("Do not open links with unfamiliar domain names or shortened URLs.")

        # Default fallback recommendation
        if not recs:
            recs.append("Always verify sender authenticity directly through verified channels.")
            
        recs.append("In case of financial fraud, dial the National Cyber Crime Helpline at 1930 immediately.")
        return recs