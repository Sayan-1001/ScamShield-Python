"""Indian Scam Taxonomy & Pattern Definitions."""

import re

# Brand/Entity impersonation patterns
IMPERSONATION_TARGETS = {
    "Messaging & Social Apps": [
        "whatsapp", "telegram", "instagram", "facebook", "meta", "youtube", "snapchat",
        "व्हाट्सएप", "टेलीग्राम", "इंस्टाग्राम", "फेसबुक", "यूट्यूब"
    ],
    "Telecom & OTT": [
        "jio", "airtel", "vi", "vodafone", "bsnl", "netflix", "prime video",
        "जियो", "एयरटेल", "वोडाफोन", "बीएसएनएल"
    ],
    "Banking / Wallets": [
        "sbi", "state bank", "hdfc", "icici", "axis bank", "pnb", "bob",
        "paytm", "phonepe", "gpay", "google pay", "bhim", "cred",
        "एसबीआई", "स्टेट बैंक", "भारतीय स्टेट बैंक", "एचडीएफसी", "आईसीआईसीआई", "एक्सिस बैंक",
        "पीएनबी", "पेटीएम", "फोनपे", "गूगल पे", "भीम"
    ],
    "Government / Public Services": [
        "india post", "epfo", "income tax", "rbi", "aadhaar", "uidai",
        "mseb", "bses", "tneb", "discom", "electricity board", "mumbai police", "cbi", "cyber cell",
        "भारतीय डाक", "इंडिया पोस्ट", "ईपीएफओ", "इनकम टैक्स", "आयकर", "आयकर विभाग",
        "आरबीआई", "भारतीय रिजर्व बैंक", "आधार", "यूआईडीएआई",
        "बिजली विभाग", "बिजली बोर्ड", "मुंबई पुलिस", "सीबीआई", "साइबर सेल"
    ],
    "E-Commerce / Logistics": [
        "amazon", "flipkart", "bluedart", "delhivery", "dtdc",
        "अमेज़न", "फ्लिपकार्ट", "ब्लूडार्ट", "डिलीवरी"
    ],
    "Global Authority & Enterprise": [
        "tesla", "byd", "apple", "microsoft", "crypto",
        "टेस्ला", "एप्पल", "माइक्रोसॉफ्ट", "क्रिप्टो"
    ]
}

# Targeted Fraud, Malware, and Spam Signatures
FRAUD_SIGNATURES = [
    {
        "id": "FAKE_APP_MALWARE",
        "category": "Fake App / Trojan Malware",
        "pattern": r"(whatsapp gold|whatsapp pink|whatsapp plus|upgrade to .* gold|free upgrade to|click (the )?link to download|download (the )?apk|install this update|व्हाट्सएप गोल्ड|व्हाट्सएप पिंक|मुफ्त अपग्रेड|डाउनलोड करने के लिए लिंक पर क्लिक करें|एपीके डाउनलोड करें|यह अपडेट इंस्टॉल करें|ऐप डाउनलोड करें)",
        "weight": 40,
        "explanation": "Severe Threat (Malware / Trojan): Official platforms never distribute software upgrades or 'Gold/Pink' editions via third-party web links. This is a known Trojan dropper designed to steal OTPs and personal data."
    },
    {
        "id": "LOTTERY_PRIZE_BAIT",
        "category": "Lottery / Reward Bait",
        "pattern": r"(congratulations!?|you('ve| have) been selected|lucky winner|won a (free|cash|gift|reward)|claim (your )?(prize|reward|cashback)|बधाई हो|आपका चयन हुआ है|लकी विजेता|लॉटरी जीती है|कैशबैक जीता|इनाम (जीतें|पाएं|क्लेम करें)|पुरस्कार प्राप्त करें|इनाम की राशि)",
        "weight": 25,
        "explanation": "Social Engineering Bait: Attackers use fake congratulations and rewards to lower your defenses and get you to click unverified links."
    },
    {
        "id": "UNSOLICITED_COLD_SPAM",
        "category": "Unsolicited Cold Spam / Outreach",
        "pattern": r"(we are a (professional|leading) (factory|manufacturer|supplier|company)|mainly produces|our main customers include|contact me at any of your convenient|our official website|हम एक (अग्रणी|पेशेवर) (कंपनी|निर्माता|आपूर्तिकर्ता) हैं|हमारी आधिकारिक वेबसाइट|अपनी सुविधा के अनुसार संपर्क करें)",
        "weight": 30,
        "explanation": "Suspicious Cold Outreach: Unsolicited sales pitch from an unverified overseas business. Automated messaging bots frequently target personal WhatsApp numbers."
    },
    {
        "id": "CREDIBILITY_ANCHORING",
        "category": "Brand Name-Dropping (Prestige Trap)",
        "pattern": r"(tesla china|white knight|customers include tesla|suppliers for tesla|byd, and etc|टेस्ला चाइना|हमारे ग्राहक टेस्ला)",
        "weight": 20,
        "explanation": "Name-Dropping Tactic: Cites high-profile global brand names (like Tesla or BYD) to manufacture unverified credibility."
    },
    {
        "id": "UPI_RECEIVE_COLLECT",
        "category": "UPI / Payment Scam",
        "pattern": r"(scan (this )?qr|enter (your )?upi pin to (receive|credit|get)|send (rs\.?|inr|re\.?) 1 to (verify|activate)|money request|क्यूआर कोड स्कैन करें|क्यूआर स्कैन करें|पैसे (प्राप्त करने|पाने|क्रेडिट करने) के लिए (अपना )?यूपीआई पिन (डालें|दर्ज करें)|यूपीआई पिन दर्ज करें|सत्यापित करने के लिए 1 रुपये भेजें|पिन डालें और पैसे पाएं|upi pin daale|paise pane ke liye pin)",
        "weight": 35,
        "explanation": "Critical Red Flag: In UPI, you NEVER need to enter your UPI PIN or scan a QR code to RECEIVE money. Entering a PIN will deduct funds from your account."
    },
    {
        "id": "ELECTRICITY_POWER_CUT",
        "category": "Utility / Disconnection Scam",
        "pattern": r"(power will be disconnected|electricity (line|supply) (will be|to be) (disconnected|cut)|bill was not updated|contact (officer|our officer|call at) \+?[0-9]{10}|बिजली (कनेक्शन|सप्लाई|लाइन)?\s?(आज रात )?(काट दी जाएगी|बंद कर दी जाएगी|काट दिया जाएगा|डिस्कनेक्ट)|बिजली बिल अपडेट नहीं|अधिकारी से संपर्क करें|bijli (kat|band) (di jayegi|ho jayegi))",
        "weight": 30,
        "explanation": "High Risk: Electricity DISCOMs never send messages from personal 10-digit mobile numbers asking you to call an officer to prevent disconnection."
    },
    {
        "id": "KYC_ACCOUNT_BLOCKED",
        "category": "Banking / KYC Scam",
        "pattern": r"(kyc (has )?expired|account (will be|has been) (blocked|suspended|deactivated|frozen)|update pan card|sim will be deactivated|केवाईसी (समाप्त|अपडेट|एक्सपायर)|पैन कार्ड अपडेट करें|आधार अपडेट करें|खाता (बंद|ब्लॉक|निलंबित|फ्रीज) (हो जाएगा|कर दिया गया है|हो गया है)|सिम (बंद|डीएक्टिवेट) (हो जाएगा|कर दिया जाएगा)|khata (band|block) ho jayega|kyc update kare)",
        "weight": 30,
        "explanation": "High Risk: Banks and telecom operators never threaten immediate account suspension via SMS/WhatsApp with third-party links."
    },
    {
        "id": "DIGITAL_ARREST_LEGAL",
        "category": "Digital Arrest / Police Extortion",
        "pattern": r"(digital arrest|mumbai police|customs clearance|cbi officer|narcotics department|arrest warrant issued|parcel contains illegal|डिजिटल अरेस्ट|मुंबई पुलिस|सीबीआई अधिकारी|नारकोटिक्स विभाग|कस्टम विभाग|गिरफ्तारी वारंट|अरेस्ट वारंट|पार्सल में अवैध|मनी लॉन्ड्रिंग|कानूनी कार्रवाई|साइबर सेल नोटिस)",
        "weight": 40,
        "explanation": "Severe Threat: 'Digital Arrest' is completely fictitious. Indian police, CBI, or courts will NEVER conduct trials or place you under arrest over video calls."
    },
    {
        "id": "PART_TIME_JOB_TELEGRAM",
        "category": "Task / Job Scam",
        "pattern": r"(work from home|like youtube videos|earn rs\.?\s?[0-9]{3,5}\s?(per day|daily)|telegram group|task completion|daily payout|घर बैठे (काम|पैसे कमाएं|कमाई)|पार्ट टाइम जॉब|यूट्यूब वीडियो लाइक|टेलीग्राम (ग्रुप|चैनल)|प्रतिदिन [0-9]{3,5} (रुपये|रु) कमाएं|रोज़ाना कमाई|टास्क पूरा करें|ghar baithe paise)",
        "weight": 25,
        "explanation": "High Risk: 'YouTube like / task completion' scams lure victims with initial payouts on Telegram, then demand deposits in fake investment schemes."
    },
    {
        "id": "REMOTE_ACCESS_APPS",
        "category": "Malicious App / Device Takeover",
        "pattern": r"(anydesk|teamviewer|rustdesk|quicksupport|एनीडेस्क|टीमव्यूअर|क्विकसपोर्ट|रस्टडेस्क)",
        "weight": 35,
        "explanation": "Severe Risk: Never install remote-screen sharing apps for unverified callers. They are used to steal OTPs and access banking applications."
    }
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy", "cutt.ly", "shorturl.at"
}

HIGH_RISK_TLDS = {
    "xyz", "top", "work", "cfd", "click", "rest", "cam", "fit", "buzz", "gq", "ml", "cc"
}