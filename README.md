# 🛡️ ScamShield India — Threat Defense OS

An AI-assisted, explainable cybersecurity and fraud-detection platform built for the Indian threat landscape. **ScamShield India** helps citizens analyze suspicious SMS, WhatsApp messages, emails, URLs, and screenshots in **English and Hindi (Devanagari & Hinglish)**, explains *why* a message is risky, and guides victims through immediate emergency containment protocols.

---

## ✨ Key Features

### 1. 🏠 ScamShield India Landing Hub
- **Instant Verify Bar:** Paste any suspicious SMS, WhatsApp forward, UPI message, APK link, or URL and jump straight into threat analysis.
- **Quick-Test Indian Fraud Presets:** One-click test vectors for OTP Phishing, Electricity Bill Fake APKs, and Part-Time Job Lures.
- **National Escalation Access:** Direct pointers to the **1930 Cyber Crime Helpline**, **NCRP (`cybercrime.gov.in`)**, and the **15-Minute Emergency Freeze Protocol**.

### 2. 📡 Multi-Vector Scam Analysis Engine (`Threat Scanner`)
- **4 Input Channels:**
  - **SMS & Text** (supports English, Hindi Devanagari, and Hinglish)
  - **Email Headers & Body** (checks sender domain spoofing & free-webmail impersonation)
  - **Suspicious URL / QR Links** (detects brand typosquatting, subdomain deception, HTTP downloads, raw IPs, shorteners, and high-risk TLDs)
  - **File / Screenshot OCR** (powered by **Gemini 3.5 Flash-Lite** to extract English & Hindi text verbatim from screenshots)
- **Explainable Risk Scoring (`0–100`):** Categorizes threats as `LOW / SAFE`, `MEDIUM / SUSPICIOUS`, or `CRITICAL / HIGH RISK` with a visual threat gauge and anomaly breakdown.
- **Interactive Semantic Breakdown:** Highlights flagged phrases and malicious links inline with hover tooltips explaining the psychological trigger or fraud tactic.
- **Actionable Mitigation & Dossier Export:** Generates tailored safety steps, direct reporting links (`cybercrime.gov.in`), SHA-256 payload hashes, and downloadable `.txt` incident reports.

### 3. 🗂️ Scam Catalog & Anatomy Inspector
- Browse real-world Indian fraud vectors (**Banking/KYC Phishing**, **UPI Collect/QR Cashback Traps**, **Telegram Task/Job Scams**, **Digital Arrest Extortion**, **Electricity Disconnection SMS**, and **Spyware/Trojan APKs**) and test any sample directly in the scanner.
- **Interactive Scam Anatomy Inspector:** Toggle between **Victim Lens** and **Attacker Lens** and inspect psychological exploit drivers (*Urgency, Authority, Scarcity, Greed*).

### 4. 🚨 Emergency Response (Golden Hour Protocol)
- **4-Tier Containment Checklist:**
  1. **Account Freeze & Kill-Switch:** Filterable directory of 24/7 Indian bank fraud hotlines (SBI, HDFC, ICICI, Axis, Kotak, NPCI/1930).
  2. **Session Revocation:** Steps to sign out of compromised Google/Android and Apple iOS sessions and remove remote-access apps.
  3. **Official Cybercrime Dossier Generator:** Pre-fill incident details (UTR, suspect ID, amount, narration) and download a standardized complaint statement for `cybercrime.gov.in` and `sancharsaathi.gov.in` (Chakshu).
  4. **Credit Bureau Monitoring:** Quick references for TransUnion CIBIL, Experian India, Equifax India, and CRIF High Mark.
- Includes confidential mental health support helplines (**Tele-MANAS `14416`**, **KIRAN `1800-599-0019`**).

### 5. 📊 Threat Feed & Personal Forensics Audit Vault
- Regional threat trend cards, demographic channel heatmap, and high-risk phishing pattern watchlist.
- **Supabase Auth + SQLite Audit Vault:** Sign in via Supabase Authentication to save and manage personal scan logs and screenshot evidence locally in SQLite (with Guest session support).

---

## 🧠 Detection Architecture

- **`scamshield/explainable_engine.py`** — Rule-based explainable scoring engine (`ScamShieldEngine`) combining brand impersonation detection (ASCII + Devanagari-safe boundaries), weighted fraud signatures, URL heuristics, and contextual recommendations.
- **`scamshield/patterns.py`** — Bilingual (English + Hindi/Hinglish) taxonomy of Indian impersonation targets (banks, UPI wallets, telecoms, government agencies, e-commerce) and 10 fraud signature categories.
- **`scamshield/url_analyzer.py`** — Extracts URLs via regex/`validators` and flags brand-jacking, subdomain spoofing (`tldextract`), unencrypted HTTP, raw IPs, URL shorteners, `.apk`/`.exe` links, and high-risk TLDs.
- **`scamshield/email_analyzer.py`** — Detects free-provider impersonation (`@gmail.com`, etc.) and domain spoofing against official Indian domains (`sbi.co.in`, `rbi.org.in`, `incometax.gov.in`, `epfindia.gov.in`, `indiapost.gov.in`, etc.) plus English/Hindi subject urgency bait.
- **`scamshield/ocr_engine.py`** — Image optimization (Pillow downscaling) + **Gemini 3.5 Flash-Lite** (`google-genai`) OCR extracting English and Hindi text verbatim.
- **`scamshield/db.py` & `scamshield/auth.py`** — SQLite incident storage (`UPLOAD_DIR` for screenshots) and Supabase user authentication.

---

## 🛠️ Tech Stack

- **Frontend / UI:** Streamlit (custom Cyber Threat Defense dark-mode CSS)
- **Language:** Python 3.10+
- **OCR / Vision AI:** Google Gemini 3.5 Flash-Lite (`google-genai`, `Pillow`)
- **URL & Domain Analysis:** `tldextract`, `validators`
- **Auth & Storage:** Supabase Auth + SQLite

---

## ⚙️ Setup & Local Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/<your-username>/<your-repo-name>.git
   cd <your-repo-name>
