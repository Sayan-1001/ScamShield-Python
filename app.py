"""
ScamShield India — AI-Powered Fraud & Phishing Defense Platform
Theme: Cyber-Mesh Electric Blue HUD
"""

import os
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

from scamshield.explainable_engine import ScamShieldEngine
from scamshield.ocr_engine import extract_text_from_image
from scamshield.email_analyzer import analyze_email_metadata
from scamshield.db import init_db, save_scan_result, get_all_scans, clear_all_scans, UPLOAD_DIR

# Initialize Database & Engine
init_db()
engine = ScamShieldEngine()

# Page Setup
st.set_page_config(
    page_title="SCAMSHIELD INDIA | Cyber Defense HUD",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ==============================================================================
# CYBER-HUD ELECTRIC BLUE STYLING
# ==============================================================================
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@600;700;900&family=Rajdhani:wght@600;700&family=Inter:wght@400;500;600;700&display=swap');

    /* 1. Remove Streamlit Header, Deploy Button & 3-Dots */
    header[data-testid="stHeader"] {
        display: none !important;
    }
    footer {
        display: none !important;
    }
    .block-container {
        padding-top: 1.5rem !important;
        padding-bottom: 2rem !important;
        max-width: 94% !important;
    }

    /* 2. Cyber-Blue Canvas Background */
    .stApp {
        background-color: #020b18 !important;
        background-image: 
            radial-gradient(circle at 50% 8%, rgba(0, 212, 255, 0.22) 0%, transparent 60%),
            radial-gradient(circle at 10% 80%, rgba(0, 102, 255, 0.16) 0%, transparent 50%),
            radial-gradient(circle at 90% 90%, rgba(3, 105, 161, 0.16) 0%, transparent 50%),
            linear-gradient(180deg, #020b18 0%, #03152d 100%) !important;
        color: #e0f2fe !important;
        font-family: 'Inter', sans-serif;
    }

    /* 3. Cyber HUD Banner */
    .hud-banner {
        border: 1px solid rgba(0, 229, 255, 0.35);
        background: rgba(3, 22, 49, 0.7);
        box-shadow: 0 0 35px rgba(0, 212, 255, 0.15), inset 0 0 25px rgba(0, 212, 255, 0.05);
        border-radius: 12px;
        padding: 30px 20px;
        text-align: center;
        margin-bottom: 25px;
    }
    .hud-title-wrap {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 18px;
    }
    .hud-title {
        font-family: 'Orbitron', sans-serif;
        font-size: 3.2rem;
        font-weight: 900;
        letter-spacing: 5px;
        color: #ffffff;
        text-shadow: 0 0 18px rgba(0, 240, 255, 0.8), 0 0 35px rgba(0, 160, 255, 0.5);
        margin: 0;
        text-transform: uppercase;
    }
    .hud-title-india {
        color: #00f0ff;
        font-family: 'Orbitron', sans-serif;
        font-weight: 900;
        text-shadow: 0 0 20px #00f0ff;
        margin-left: 10px;
    }

    /* Tagline with Updated Rajdhani Font */
    .hud-tagline-box {
        display: inline-block;
        border: 1px solid rgba(0, 229, 255, 0.6);
        padding: 7px 26px;
        margin-top: 15px;
        background: rgba(0, 229, 255, 0.08);
        border-radius: 4px;
        box-shadow: 0 0 15px rgba(0, 229, 255, 0.25);
    }
    .hud-tagline {
        font-family: 'Rajdhani', sans-serif;
        font-size: 1.18rem;
        font-weight: 700;
        color: #ffffff;
        letter-spacing: 4px;
        text-transform: uppercase;
        margin: 0;
        text-shadow: 0 0 10px rgba(0, 229, 255, 0.7);
    }

    /* 4. Streamlit Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 12px;
        background-color: transparent;
        border-bottom: 1px solid #0c2a52;
        padding-bottom: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        font-family: 'Orbitron', sans-serif;
        font-size: 0.95rem;
        font-weight: 700;
        letter-spacing: 1px;
        color: #7dd3fc !important;
        background: rgba(6, 30, 65, 0.55) !important;
        border: 1px solid #0e3b73 !important;
        border-radius: 6px;
        padding: 10px 22px;
        transition: all 0.2s ease;
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, rgba(0, 229, 255, 0.25), rgba(0, 102, 255, 0.35)) !important;
        border-color: #00f0ff !important;
        color: #ffffff !important;
        box-shadow: 0 0 16px rgba(0, 240, 255, 0.4) !important;
    }

    /* 5. Custom Segmented Bar Style (NO MCQ Radio Circles) */
    div[data-testid="stSegmentedControl"] {
        background: #04142b !important;
        border: 1px solid #0e3b73 !important;
        border-radius: 8px !important;
        padding: 5px !important;
    }
    div[data-testid="stSegmentedControl"] button {
        flex: 1 !important;
        font-family: 'Rajdhani', sans-serif !important;
        font-size: 1.05rem !important;
        font-weight: 700 !important;
        letter-spacing: 0.8px !important;
        padding: 12px 18px !important;
        border-radius: 6px !important;
        color: #94a3b8 !important;
        border: 1px solid transparent !important;
        transition: all 0.2s ease !important;
    }
    div[data-testid="stSegmentedControl"] button[aria-selected="true"] {
        background: linear-gradient(135deg, rgba(0, 210, 255, 0.28), rgba(0, 102, 255, 0.38)) !important;
        color: #00f0ff !important;
        border: 1px solid #00e5ff !important;
        font-weight: 800 !important;
        box-shadow: 0 0 14px rgba(0, 229, 255, 0.35) !important;
    }

    /* 6. Inputs & Text Areas */
    .stTextArea textarea, .stTextInput input {
        background-color: #04142b !important;
        color: #f0f9ff !important;
        border: 1px solid #0e3b73 !important;
        border-radius: 6px !important;
    }
    .stTextArea textarea:focus, .stTextInput input:focus {
        border-color: #00e5ff !important;
        box-shadow: 0 0 10px rgba(0, 229, 255, 0.3) !important;
    }

    /* 7. Action Buttons */
    div.stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #00d2ff 0%, #0066ff 100%) !important;
        color: #020b18 !important;
        font-family: 'Orbitron', sans-serif !important;
        font-weight: 900 !important;
        font-size: 1.05rem !important;
        letter-spacing: 1.5px !important;
        border: none !important;
        border-radius: 6px !important;
        padding: 14px 28px !important;
        box-shadow: 0 0 20px rgba(0, 210, 255, 0.5) !important;
    }

    /* 8. Cards */
    .cyber-card {
        background: #04142b;
        border: 1px solid #0e386e;
        border-radius: 10px;
        padding: 22px;
        margin-bottom: 15px;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
    }
    .card-danger { border-left: 5px solid #ff3366 !important; }
    .card-warning { border-left: 5px solid #ffbb00 !important; }
    .card-info { border-left: 5px solid #00e5ff !important; }

    /* 9. Stat Pill */
    .stat-pill {
        background: #04142b;
        border: 1px solid #0e386e;
        border-radius: 8px;
        padding: 18px 20px;
        text-align: center;
    }
    .stat-val {
        font-family: 'Orbitron', sans-serif;
        font-size: 1.7rem;
        font-weight: 800;
        color: #00f0ff;
    }
    .stat-lbl {
        font-family: 'Rajdhani', sans-serif;
        font-size: 0.95rem;
        font-weight: 600;
        color: #94a3b8;
        letter-spacing: 1px;
    }
</style>
""", unsafe_allow_html=True)


# ==============================================================================
# HEADER: 3D SHIELD LOGO + SCAMSHIELD INDIA TITLE + NEW TAGLINE FONT
# ==============================================================================
# 3D Vector Shield SVG with metallic gradients and cyan depth glow
SHIELD_3D_SVG = """
<svg width="68" height="74" viewBox="0 0 68 74" fill="none" xmlns="http://www.w3.org/2000/svg" style="filter: drop-shadow(0 0 16px rgba(0, 240, 255, 0.6));">
    <defs>
        <linearGradient id="shieldRim" x1="0" y1="0" x2="68" y2="74" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stop-color="#00f0ff"/>
            <stop offset="50%" stop-color="#0066ff"/>
            <stop offset="100%" stop-color="#001a4d"/>
        </linearGradient>
        <linearGradient id="shieldCore" x1="34" y1="6" x2="34" y2="66" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stop-color="#08214d"/>
            <stop offset="100%" stop-color="#020d20"/>
        </linearGradient>
        <linearGradient id="shieldEmblem" x1="20" y1="20" x2="48" y2="52" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stop-color="#00f0ff"/>
            <stop offset="100%" stop-color="#0088ff"/>
        </linearGradient>
    </defs>
    <!-- Outer 3D Rim -->
    <path d="M34 2L64 13V35C64 53.5 51.2 70.2 34 74C16.8 70.2 4 53.5 4 35V13L34 2Z" fill="url(#shieldRim)"/>
    <!-- Inner Metallic Core -->
    <path d="M34 6L59 15.5V34C59 49.5 48.4 64 34 67.5C19.6 64 9 49.5 9 34V15.5L34 6Z" fill="url(#shieldCore)"/>
    <!-- 3D Bevel Highlight -->
    <path d="M34 6L59 15.5V34C59 49.5 48.4 64 34 67.5V6Z" fill="white" fill-opacity="0.08"/>
    <!-- Center Cyber Emblem -->
    <path d="M34 20L47 25V35C47 43 41.5 50.5 34 53C26.5 50.5 21 43 21 35V25L34 20Z" fill="url(#shieldEmblem)"/>
    <path d="M34 26L41 29V35C41 39.5 38 44 34 45.5V26Z" fill="white" fill-opacity="0.25"/>
</svg>
"""

# ==============================================================================
# HEADER: 3D SHIELD LOGO + SCAMSHIELD INDIA TITLE (No-Indent Fix)
# ==============================================================================
banner_html = f"""<div class="hud-banner">
<div class="hud-title-wrap">
{SHIELD_3D_SVG}
<h1 class="hud-title">SCAMSHIELD<span class="hud-title-india">INDIA</span></h1>
</div>
<div class="hud-tagline-box">
<p class="hud-tagline">THINK BEFORE YOU CLICK. VERIFY BEFORE YOU TRUST</p>
</div>
</div>"""

st.markdown(banner_html, unsafe_allow_html=True)

# ==============================================================================
# MAIN TABS (LANDING PAGE FIRST)
# ==============================================================================
tab_home, tab_scanner, tab_history, tab_emergency = st.tabs([
    "🏠 HOME & THREAT HUB",
    "⚡ THREAT SCANNER",
    "🗂️ AUDIT LOGS (DB)",
    "🚨 1930 HELPLINE"
])


# ==============================================================================
# TAB 1: LANDING PAGE & THREAT HUB (SCAM TYPES + VISUALS + SCAN/REPORT BUTTONS)
# ==============================================================================
with tab_home:
    st.write("")

    # Visual Metric Ribbon
    s1, s2, s3, s4 = st.columns(4)
    with s1:
        st.markdown('<div class="stat-pill"><div class="stat-val">&lt; 0.8s</div><div class="stat-lbl">DETECTION LATENCY</div></div>', unsafe_allow_html=True)
    with s2:
        st.markdown('<div class="stat-pill"><div class="stat-val">100%</div><div class="stat-lbl">EXPLAINABLE LOGIC</div></div>', unsafe_allow_html=True)
    with s3:
        st.markdown('<div class="stat-pill"><div class="stat-val">6+ VECTORS</div><div class="stat-lbl">INDIAN MODUS OPERANDI</div></div>', unsafe_allow_html=True)
    with s4:
        st.markdown('<div class="stat-pill"><div class="stat-val">ZERO-LEAK</div><div class="stat-lbl">CREDENTIAL ISOLATION</div></div>', unsafe_allow_html=True)

    st.write("")
    st.markdown("### 📚 Prevalent Indian Cyber Scams & Warning Signs")
    st.caption("Review how modern digital payment scams, panic tactics, and malware impersonations operate.")

    # Visual Scam Vectors Grid
    r1_c1, r1_c2, r1_c3 = st.columns(3)

    with r1_c1:
        st.markdown("""
        <div class="cyber-card card-warning">
            <span style="font-family:'Rajdhani'; font-weight:700; color:#ffbb00; letter-spacing:1px; font-size:0.85rem;">[ UPI / PAYMENT FRAUD ]</span>
            <h4 style="color:#ffffff; margin:6px 0 8px 0; font-family:'Orbitron'; font-size:1.1rem;">Cashback & QR Collect</h4>
            <p style="color:#94a3b8; font-size:0.9rem; line-height:1.5;">
                Fraudsters send QR codes or collect requests via PhonePe, GPay, or Paytm, falsely claiming you won a cashback reward.
            </p>
            <div style="background:#020b18; padding:10px; border-radius:6px; font-size:0.82rem; color:#ffbb00; margin-top:8px;">
                ⚠️ <strong>The Golden Rule:</strong> You NEVER need to enter your UPI PIN to RECEIVE money.
            </div>
        </div>
        """, unsafe_allow_html=True)

    with r1_c2:
        st.markdown("""
        <div class="cyber-card card-danger">
            <span style="font-family:'Rajdhani'; font-weight:700; color:#ff3366; letter-spacing:1px; font-size:0.85rem;">[ EXTORTION / POLICE COERCION ]</span>
            <h4 style="color:#ffffff; margin:6px 0 8px 0; font-family:'Orbitron'; font-size:1.1rem;">"Digital Arrest" Extortion</h4>
            <p style="color:#94a3b8; font-size:0.9rem; line-height:1.5;">
                Callers impersonating CBI or Mumbai Police claim your Aadhaar is tied to illegal drug parcels or money laundering.
            </p>
            <div style="background:#020b18; padding:10px; border-radius:6px; font-size:0.82rem; color:#ff3366; margin-top:8px;">
                ⚠️ <strong>Legal Reality:</strong> Indian law has NO 'Digital Arrest'. Police never conduct trials over Skype or video calls.
            </div>
        </div>
        """, unsafe_allow_html=True)

    with r1_c3:
        st.markdown("""
        <div class="cyber-card card-info">
            <span style="font-family:'Rajdhani'; font-weight:700; color:#00e5ff; letter-spacing:1px; font-size:0.85rem;">[ UTILITY / PANIC TRAP ]</span>
            <h4 style="color:#ffffff; margin:6px 0 8px 0; font-family:'Orbitron'; font-size:1.1rem;">Power-Cut Bill SMS</h4>
            <p style="color:#94a3b8; font-size:0.9rem; line-height:1.5;">
                SMS threats claiming electricity will be disconnected tonight unless you call an unauthorized 10-digit mobile number.
            </p>
            <div style="background:#020b18; padding:10px; border-radius:6px; font-size:0.82rem; color:#00e5ff; margin-top:8px;">
                ⚠️ <strong>Defense:</strong> State DISCOMs never send disconnection threats from personal WhatsApp numbers.
            </div>
        </div>
        """, unsafe_allow_html=True)

    r2_c1, r2_c2, r2_c3 = st.columns(3)

    with r2_c1:
        st.markdown("""
        <div class="cyber-card card-warning">
            <span style="font-family:'Rajdhani'; font-weight:700; color:#ffbb00; letter-spacing:1px; font-size:0.85rem;">[ MALWARE / SPYWARE ]</span>
            <h4 style="color:#ffffff; margin:6px 0 8px 0; font-family:'Orbitron'; font-size:1.1rem;">WhatsApp Gold APKs</h4>
            <p style="color:#94a3b8; font-size:0.9rem; line-height:1.5;">
                Fake update links promising exclusive themes or features that drop spyware APKs to siphon banking OTPs and passwords.
            </p>
            <div style="background:#020b18; padding:10px; border-radius:6px; font-size:0.82rem; color:#ffbb00; margin-top:8px;">
                ⚠️ <strong>Defense:</strong> Official apps are NEVER distributed through `.apk` links or third-party web domains.
            </div>
        </div>
        """, unsafe_allow_html=True)

    with r2_c2:
        st.markdown("""
        <div class="cyber-card card-danger">
            <span style="font-family:'Rajdhani'; font-weight:700; color:#ff3366; letter-spacing:1px; font-size:0.85rem;">[ TASK SCAM ]</span>
            <h4 style="color:#ffffff; margin:6px 0 8px 0; font-family:'Orbitron'; font-size:1.1rem;">Part-Time Job Telegram</h4>
            <p style="color:#94a3b8; font-size:0.9rem; line-height:1.5;">
                Promises ₹3,500 daily for liking YouTube videos. Scammers give small initial payouts before demanding deposits.
            </p>
            <div style="background:#020b18; padding:10px; border-radius:6px; font-size:0.82rem; color:#ff3366; margin-top:8px;">
                ⚠️ <strong>Defense:</strong> Legitimate companies never recruit or conduct investments through Telegram groups.
            </div>
        </div>
        """, unsafe_allow_html=True)

    with r2_c3:
        st.markdown("""
        <div class="cyber-card card-info">
            <span style="font-family:'Rajdhani'; font-weight:700; color:#00e5ff; letter-spacing:1px; font-size:0.85rem;">[ BANKING PHISHING ]</span>
            <h4 style="color:#ffffff; margin:6px 0 8px 0; font-family:'Orbitron'; font-size:1.1rem;">KYC / PAN Suspension</h4>
            <p style="color:#94a3b8; font-size:0.9rem; line-height:1.5;">
                SMS threats that your SBI, HDFC, or ICICI account is blocked today unless you update PAN details on an unauthorized link.
            </p>
            <div style="background:#020b18; padding:10px; border-radius:6px; font-size:0.82rem; color:#00e5ff; margin-top:8px;">
                ⚠️ <strong>Defense:</strong> Banks never ask you to update KYC via SMS links. Always use the verified mobile app.
            </div>
        </div>
        """, unsafe_allow_html=True)


# ==============================================================================
# TAB 2: THREAT SCANNER (WITH BARS INSTEAD OF MCQ RADIO CIRCLES)
# ==============================================================================
with tab_scanner:
    st.write("")
    st.markdown("### ⚡ Live Fraud & Phishing Detection")
    st.caption("Analyze suspicious messages, phishing emails, links, or uploaded screenshots.")

    # Input format rendered as BARS (Segmented Control - NO MCQ CIRCLES)
    selected_bar = st.segmented_control(
        "Choose Input Format:",
        ["💬 Text / SMS / Link", "📧 Email Phishing", "📷 Upload Screenshot (OCR)"],
        default="💬 Text / SMS / Link"
    )

    active_text = ""
    scan_type = "Text / SMS"
    image_to_save = None
    extra_email_score = 0
    email_warnings = []

    st.write("")

    if selected_bar == "💬 Text / SMS / Link":
        text_val = st.text_area("Paste the message, SMS, or URL to inspect:", height=130, placeholder="e.g. Electricity power will be disconnected at 9:30 PM. Call officer at 9876543210.")
        active_text = text_val.strip()
        scan_type = "SMS / URL"

    elif selected_bar == "📧 Email Phishing":
        col_m1, col_m2 = st.columns(2)
        with col_m1:
            e_sender = st.text_input("Sender Address:", placeholder="e.g. refunds@incometax-gov-update.xyz")
        with col_m2:
            e_subject = st.text_input("Subject Line:", placeholder="e.g. URGENT: Income Tax Refund Approved")
        e_body = st.text_area("Email Body Content:", height=120)

        if e_sender or e_body:
            active_text = f"From: {e_sender}\nSubject: {e_subject}\n\n{e_body}"
            scan_type = "Email"
            meta = analyze_email_metadata(e_sender, e_subject, e_body)
            extra_email_score = meta["email_risk_points"]
            email_warnings = meta["email_warnings"]

    elif selected_bar == "📷 Upload Screenshot (OCR)":
        screenshot = st.file_uploader("Upload message screenshot (PNG, JPG, JPEG):", type=["png", "jpg", "jpeg"])
        if screenshot is not None:
            image_to_save = screenshot
            if st.button("🔍 Extract Text via Gemini 3.5 Lite"):
                with st.spinner("Decoding screenshot with sub-second vision..."):
                    extracted_text, err = extract_text_from_image(screenshot)
                    if err:
                        st.error(err)
                    else:
                        st.success("Text extracted successfully!")
                        st.session_state["hud_ocr_text"] = extracted_text

            if "hud_ocr_text" in st.session_state:
                ocr_edit = st.text_area("Extracted Content:", value=st.session_state["hud_ocr_text"], height=100)
                active_text = ocr_edit.strip()
                scan_type = "Screenshot"

    st.write("")
    if st.button("🛡️ ANALYZE THREAT NOW", type="primary", use_container_width=True):
        if not active_text:
            st.warning("Please enter text or upload an image first.")
        else:
            with st.spinner("Running heuristic & threat intelligence engine..."):
                result = engine.analyze(active_text)

            final_score = min(result["risk_score"] + extra_email_score, 100)
            final_level = "CRITICAL THREAT" if final_score >= 70 else ("SUSPICIOUS" if final_score >= 40 else "SAFE")
            result["risk_score"] = final_score
            result["risk_level"] = final_level

            # Save to SQLite Database automatically
            db_id = save_scan_result(
                scan_type=scan_type,
                content=active_text,
                result=result,
                image_file=image_to_save
            )

            # Results Display HUD
            st.divider()
            c1, c2, c3 = st.columns([1.2, 1.2, 2.6])
            
            score_color = "#ff3366" if final_score >= 70 else ("#ffbb00" if final_score >= 40 else "#00e5ff")
            
            with c1:
                st.markdown(f"""
                <div class="cyber-card" style="text-align:center;">
                    <span style="font-size:0.85rem; color:#94a3b8; font-family:'Rajdhani'; font-weight:700;">RISK SCORE</span>
                    <h2 style="font-family:'Orbitron'; color:{score_color}; font-size:2.4rem; margin:5px 0;">{final_score} / 100</h2>
                </div>
                """, unsafe_allow_html=True)

            with c2:
                st.markdown(f"""
                <div class="cyber-card" style="text-align:center;">
                    <span style="font-size:0.85rem; color:#94a3b8; font-family:'Rajdhani'; font-weight:700;">STATUS LEVEL</span>
                    <h2 style="font-family:'Orbitron'; color:{score_color}; font-size:1.6rem; margin:12px 0;">{final_level}</h2>
                </div>
                """, unsafe_allow_html=True)

            with c3:
                if result["impersonation_detected"]:
                    imps = ", ".join([f"{item['entity']} ({item['category']})" for item in result["impersonation_detected"]])
                    st.markdown(f"""
                    <div class="cyber-card card-danger">
                        <span style="font-size:0.85rem; color:#ff3366; font-family:'Rajdhani'; font-weight:700;">🎭 IMPERSONATION DETECTED</span>
                        <p style="margin:6px 0 0 0; color:#ffffff; font-weight:600;">{imps}</p>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown("""
                    <div class="cyber-card card-info">
                        <span style="font-size:0.85rem; color:#00e5ff; font-family:'Rajdhani'; font-weight:700;">SOURCE BRAND</span>
                        <p style="margin:6px 0 0 0; color:#94a3b8;">No official brand claimed.</p>
                    </div>
                    """, unsafe_allow_html=True)

            st.caption(f"💾 Incident saved to local forensics audit log (Record ID #{db_id})")

            # Explainable Indicators
            st.markdown("### 🔍 Explainable Red Flags Detected")

            for ew in email_warnings:
                st.markdown(f"""
                <div class="cyber-card card-danger">
                    <strong style="color:#ff3366;">📧 Email Header & Domain Spoofing</strong><br>
                    <span style="color:#e0f2fe;">{ew}</span>
                </div>
                """, unsafe_allow_html=True)

            for trig in result["triggers"]:
                st.markdown(f"""
                <div class="cyber-card card-danger">
                    <strong style="color:#ff3366;">🚩 Flag: {trig['category']} (+{trig['weight']} Points)</strong><br>
                    <span style="color:#e0f2fe;">{trig['explanation']}</span>
                </div>
                """, unsafe_allow_html=True)

            for u in result["url_analysis"]:
                for ws in u["warning_signs"]:
                    st.markdown(f"""
                    <div class="cyber-card card-warning">
                        <strong style="color:#ffbb00;">🔗 URL Threat Indicator ({u['url']})</strong><br>
                        <span style="color:#e0f2fe;">{ws}</span>
                    </div>
                    """, unsafe_allow_html=True)

            st.markdown("### 🛡️ Recommended Security Actions")
            for rec in result["recommendations"]:
                st.markdown(f"- **{rec}**")


# ==============================================================================
# TAB 3: AUDIT LOGS (PERSISTENT SQLITE DATABASE)
# ==============================================================================
with tab_history:
    st.write("")
    st.markdown("### 🗂️ Forensics Audit Log & Saved Evidence")
    st.caption("All analyzed incidents, risk scores, and screenshots are securely stored in a local SQLite database.")

    scans = get_all_scans()

    col_h1, col_h2 = st.columns([4, 1])
    with col_h1:
        st.write(f"Total Logged Incidents: **{len(scans)}**")
    with col_h2:
        if st.button("🗑️ Clear All Logs"):
            clear_all_scans()
            st.rerun()

    if not scans:
        st.info("No recorded scans yet. Analyze any text or screenshot in the Threat Scanner tab.")
    else:
        for item in scans:
            risk_color = "#ff3366" if item["risk_score"] >= 70 else ("#ffbb00" if item["risk_score"] >= 40 else "#00e5ff")
            
            with st.expander(f"Incident #{item['id']} — {item['scan_type']} | Score: {item['risk_score']}/100 ({item['threat_level']}) — {item['timestamp']}"):
                col_i1, col_i2 = st.columns([2, 1])
                with col_i1:
                    st.markdown("**Evidence Content:**")
                    st.code(item["content"], language="text")
                    if item["impersonation"]:
                        st.markdown(f"**Impersonated Target:** `{item['impersonation']}`")
                
                with col_i2:
                    st.markdown(f"**Risk Level:** <span style='color:{risk_color}; font-weight:bold;'>{item['threat_level']}</span>", unsafe_allow_html=True)
                    st.markdown(f"**Date:** `{item['timestamp']}`")
                    
                    if item["image_filename"]:
                        img_path = os.path.join(UPLOAD_DIR, item["image_filename"])
                        if os.path.exists(img_path):
                            st.image(img_path, caption="Saved Screenshot Evidence", use_container_width=True)


# ==============================================================================
# TAB 4: 1930 EMERGENCY HELPLINE
# ==============================================================================
with tab_emergency:
    st.write("")
    st.markdown("""
    <div style="border: 1px solid #ff3366; background: rgba(255, 51, 102, 0.1); box-shadow: 0 0 25px rgba(255, 51, 102, 0.2); border-radius: 8px; padding: 24px; margin-bottom: 25px;">
        <h2 style="font-family:'Orbitron'; color:#ff3366; margin:0 0 8px 0;">NATIONAL CYBERCRIME HELPLINE: 1930</h2>
        <p style="font-size:1.05rem; color:#f0f9ff; margin:0; line-height:1.6;">
            If you have suffered an unauthorized financial deduction, dial <strong>1930</strong> immediately. 
            The <strong>Golden Hour (first 2 hours)</strong> is critical for the Indian Cyber Crime Coordination Centre (I4C) 
            to freeze money transfers before they are cashed out.
        </p>
    </div>
    """, unsafe_allow_html=True)

    col_e1, col_e2, col_e3 = st.columns(3)

    with col_e1:
        st.subheader("1. National Portal")
        st.markdown("File complaints for financial fraud, identity theft, or social media harassment.")
        st.link_button("🌐 cybercrime.gov.in", "https://cybercrime.gov.in", use_container_width=True)

    with col_e2:
        st.subheader("2. Sanchar Saathi (Chakshu)")
        st.markdown("Report fraudulent calls, spam SMS headers, and rogue WhatsApp numbers.")
        st.link_button("📱 Chakshu Portal", "https://sancharsaathi.gov.in", use_container_width=True)

    with col_e3:
        st.subheader("3. Bank Card Freeze")
        st.markdown("Immediately call your bank's 24x7 fraud desk to block cards and netbanking.")
        st.info("Have your UTR reference number, account number, and transaction time ready.")

    st.divider()
    st.markdown("""
    #### 📋 Emergency Incident Checklist
    1. **Preserve All Evidence:** Do not delete SMS messages, WhatsApp chats, call recordings, or bank receipts.
    2. **Call 1930 Immediately:** State the debit account number, transaction timestamp, and recipient UPI/account info.
    3. **File Complaint on cybercrime.gov.in:** Download the acknowledgement PDF for bank chargeback claims and FIR filing.
    4. **Change Passwords:** Immediately update your UPI PIN and NetBanking passwords from a secure device.
    """)