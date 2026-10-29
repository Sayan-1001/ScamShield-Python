"""Indian Scam Taxonomy & Pattern Definitions (Updated with Malware & Tech Brands)."""

import re

# Brand/Entity impersonation patterns
IMPERSONATION_TARGETS = {
    "Messaging & Social Apps": [
        "whatsapp", "telegram", "instagram", "facebook", "meta", "youtube", "snapchat"
    ],
    "Telecom & OTT": [
        "jio", "airtel", "vi", "vodafone", "bsnl", "netflix", "prime video"
    ],
    "Banking / Wallets": [
        "sbi", "state bank", "hdfc", "icici", "axis bank", "pnb", "bob", 
        "paytm", "phonepe", "gpay", "google pay", "bhim", "cred"
    ],
    "Government / Public Services": [
        "india post", "epfo", "income tax", "rbi", "aadhaar", "uidai", 
        "mseb", "bses", "tneb", "discom", "electricity board", "mumbai police", "cbi", "cyber cell"
    ],
    "E-Commerce / Logistics": [
        "amazon", "flipkart", "bluedart", "delhivery", "dtdc"
    ]
}

# Targeted Fraud & Malware Signatures
FRAUD_SIGNATURES = [
    {
        "id": "FAKE_APP_MALWARE",
        "category": "Fake App / Trojan Malware",
        "pattern": r"(whatsapp gold|whatsapp pink|whatsapp plus|upgrade to .* gold|free upgrade to|click (the )?link to download|download (the )?apk|install this update)",
        "weight": 40,
        "explanation": "Severe Threat (Malware / Trojan): Official apps (like WhatsApp) NEVER distribute updates or 'Gold' editions via random web links. This is a known Trojan dropper designed to steal OTPs and access contacts."
    },
    {
        "id": "LOTTERY_PRIZE_BAIT",
        "category": "Lottery / Reward Bait",
        "pattern": r"(congratulations!?|you('ve| have) been selected|lucky winner|won a (free|cash|gift|reward)|claim (your )?(prize|reward|cashback))",
        "weight": 25,
        "explanation": "Social Engineering Bait: Scammers use unsolicited 'Congratulations' and fake rewards to lower your defenses and get you to click unknown links."
    },
    {
        "id": "UPI_RECEIVE_COLLECT",
        "category": "UPI / Payment Scam",
        "pattern": r"(scan (this )?qr|enter (your )?upi pin to (receive|credit|get)|send (rs\.?|inr|re\.?) 1 to (verify|activate)|money request)",
        "weight": 35,
        "explanation": "Critical Red Flag: In UPI, you NEVER need to enter your UPI PIN or scan a QR code to RECEIVE money."
    },
    {
        "id": "ELECTRICITY_POWER_CUT",
        "category": "Utility / Disconnection Scam",
        "pattern": r"(power will be disconnected|electricity (line|supply) (will be|to be) (disconnected|cut)|bill was not updated|contact (officer|our officer|call at) \+?[0-9]{10})",
        "weight": 30,
        "explanation": "High Risk: Electricity DISCOMs never send messages from personal 10-digit mobile numbers asking you to call an officer."
    },
    {
        "id": "KYC_ACCOUNT_BLOCKED",
        "category": "Banking / KYC Scam",
        "pattern": r"(kyc (has )?expired|account (will be|has been) (blocked|suspended|deactivated|frozen)|update pan card|sim will be deactivated)",
        "weight": 30,
        "explanation": "High Risk: Banks and telecom operators never threaten immediate account suspension via SMS/WhatsApp links."
    },
    {
        "id": "DIGITAL_ARREST_LEGAL",
        "category": "Digital Arrest / Police Extortion",
        "pattern": r"(digital arrest|mumbai police|customs clearance|cbi officer|narcotics department|arrest warrant issued|parcel contains illegal)",
        "weight": 40,
        "explanation": "Severe Threat: 'Digital Arrest' is completely fictitious. Indian police never hold legal trials over video calls."
    },
    {
        "id": "PART_TIME_JOB_TELEGRAM",
        "category": "Task / Job Scam",
        "pattern": r"(work from home|like youtube videos|earn rs\.?\s?[0-9]{3,5}\s?(per day|daily)|telegram group|task completion|daily payout)",
        "weight": 25,
        "explanation": "High Risk: 'YouTube like / task completion' scams lure victims with small initial payouts via Telegram, then trap them into paying deposits."
    },
    {
        "id": "REMOTE_ACCESS_APPS",
        "category": "Malicious App / Device Takeover",
        "pattern": r"(anydesk|teamviewer|rustdesk|quicksupport)",
        "weight": 35,
        "explanation": "Severe Risk: Never install remote-screen sharing apps for unverified callers."
    }
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy", "cutt.ly", "shorturl.at"
}

HIGH_RISK_TLDS = {
    "xyz", "top", "work", "cfd", "click", "rest", "cam", "fit", "buzz", "gq", "ml", "cc"
}