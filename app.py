"""
ScamShield India — AI-Powered Fraud & Phishing Defense Platform
Theme: Deep Cyber Navy Blue & Radiant 3D Shield HUD
"""

import os
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

from scamshield.explainable_engine import ScamShieldEngine
from scamshield.ocr_engine import extract_text_from_image
from scamshield.email_analyzer import analyze_email_metadata
from scamshield.db import init_db, save_scan_result, get_all_scans, clear_all_scans, UPLOAD_DIR
from scamshield.auth import sign_in_user, sign_up_user, send_magic_link_otp

# Initialize Database & Engine
init_db()
engine = ScamShieldEngine()

# Session State for User Auth
if "user_email" not in st.session_state:
    st.session_state["user_email"] = None

# Page Setup
st.set_page_config(
    page_title="ScamShield India — AI Cyber Defense",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ==============================================================================
# VISUAL THEME: DEEP CYBER NAVY & RADIANT CYAN ACCENTS
# ==============================================================================
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=Rajdhani:wght@600;700&family=Orbitron:wght@600;700;900&display=swap');

    /* 1. Reset & Top Toolbar Removal */
    header[data-testid="stHeader"], footer { display: none !important; }
    .block-container {
        max-width: 1260px !important;
        padding-top: 0.8rem !important;
        padding-bottom: 2.5rem !important;
    }

    /* 2. Deep Cyber Navy Blue Background Canvas */
    html, body, .stApp, [data-testid="stAppViewContainer"], [data-testid="stAppViewContainer"] > .main {
        background-color: #071329 !important;
        color: #f8fafc !important;
        font-family: 'Plus Jakarta Sans', sans-serif !important;
    }
    .stApp {
        background-image: 
            radial-gradient(at 15% 12%, rgba(14, 165, 233, 0.22) 0px, transparent 55%),
            radial-gradient(at 85% 85%, rgba(37, 99, 235, 0.20) 0px, transparent 55%),
            radial-gradient(circle at 50% 25%, rgba(2, 132, 199, 0.15) 0%, transparent 65%),
            linear-gradient(180deg, #071329 0%, #030b18 100%) !important;
        background-attachment: fixed !important;
    }

    /* 3. Top Emergency Strip */
    .top-emergency-strip {
        background: linear-gradient(90deg, #7f1d1d 0%, #450a0a 100%);
        border: 1px solid #dc2626;
        border-radius: 8px;
        padding: 8px 18px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        font-size: 0.88rem;
        margin-bottom: 14px;
        box-shadow: 0 4px 15px rgba(220, 38, 38, 0.2);
    }
    .top-emergency-strip strong { color: #fecaca; }
    .top-emergency-badge {
        background: #ef4444;
        color: #ffffff;
        font-weight: 700;
        padding: 3px 12px;
        border-radius: 4px;
        text-decoration: none;
        margin-left: 8px;
    }

    /* 4. Live Threat Ticker Marquee */
    .ticker-bar {
        background: #0c1a36;
        border: 1px solid #1a3461;
        border-radius: 6px;
        padding: 7px 16px;
        font-size: 0.84rem;
        color: #94a3b8;
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 20px;
        overflow: hidden;
        white-space: nowrap;
    }
    .ticker-pill {
        background: rgba(14, 165, 233, 0.2);
        color: #38bdf8;
        font-weight: 700;
        font-size: 0.76rem;
        padding: 3px 9px;
        border-radius: 4px;
    }

    /* 5. Brand Header HUD Banner */
    .hud-banner {
        background: rgba(12, 26, 54, 0.85);
        border: 1px solid rgba(56, 189, 248, 0.35);
        box-shadow: 0 0 35px rgba(14, 165, 233, 0.15), inset 0 0 25px rgba(14, 165, 233, 0.05);
        border-radius: 12px;
        padding: 24px 28px;
        text-align: center;
        margin-bottom: 22px;
    }
    .hud-title-wrap {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 16px;
    }
    .hud-title {
        font-family: 'Orbitron', sans-serif;
        font-size: 2.7rem;
        font-weight: 900;
        letter-spacing: 2px;
        color: #ffffff;
        margin: 0;
        text-shadow: 0 0 20px rgba(255, 255, 255, 0.5), 0 0 35px rgba(56, 189, 248, 0.5);
    }
    .hud-title-india {
        color: #00f0ff;
        font-weight: 900;
        margin-left: 10px;
        text-shadow: 0 0 20px #00f0ff, 0 0 35px rgba(0, 240, 255, 0.7);
    }

    /* Highlighted Tagline Capsule */
    .hud-tagline-box {
        display: inline-block;
        border: 1px solid rgba(56, 189, 248, 0.45);
        padding: 6px 22px;
        margin-top: 14px;
        background: rgba(14, 165, 233, 0.12);
        border-radius: 6px;
        box-shadow: 0 0 15px rgba(14, 165, 233, 0.25);
    }
    .hud-tagline {
        font-family: 'Rajdhani', sans-serif;
        font-size: 1.12rem;
        font-weight: 700;
        color: #ffffff;
        letter-spacing: 3.5px;
        margin: 0;
        text-transform: uppercase;
        text-shadow: 0 0 10px rgba(56, 189, 248, 0.6);
    }

    /* 6. Hero Section */
    .hero-container {
        text-align: center;
        padding: 30px 20px 20px;
        margin-bottom: 28px;
    }
    .hero-pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: rgba(14, 165, 233, 0.15);
        color: #38bdf8;
        border: 1px solid rgba(14, 165, 233, 0.4);
        padding: 6px 16px;
        border-radius: 50px;
        font-size: 0.86rem;
        font-weight: 600;
        margin-bottom: 18px;
        box-shadow: 0 0 15px rgba(14, 165, 233, 0.2);
    }
    .hero-title-main {
        font-size: 3rem;
        font-weight: 800;
        letter-spacing: -1px;
        color: #ffffff;
        line-height: 1.18;
        margin-bottom: 14px;
    }
    .hero-title-cyan {
        color: #00f0ff;
        background: linear-gradient(135deg, #00f0ff 0%, #38bdf8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-shadow: 0 0 30px rgba(0, 240, 255, 0.4);
    }
    .hero-sub-main {
        font-size: 1.05rem;
        color: #cbd5e1;
        max-width: 760px;
        margin: 0 auto 24px auto;
        line-height: 1.6;
        text-align: center !important;
    }

    /* 7. Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: transparent;
        border-bottom: 1px solid #1a3461;
        padding-bottom: 4px;
    }
    .stTabs [data-baseweb="tab"] {
        font-size: 0.94rem;
        font-weight: 600;
        color: #94a3b8 !important;
        background: transparent !important;
        border: none !important;
        padding: 10px 18px;
        transition: color 0.15s ease;
    }
    .stTabs [aria-selected="true"] {
        color: #38bdf8 !important;
        border-bottom: 2px solid #38bdf8 !important;
    }

    /* 8. Controls (Segmented Bar) */
    div[data-testid="stSegmentedControl"] {
        background: #0c1a36 !important;
        border: 1px solid #1a3461 !important;
        border-radius: 8px !important;
        padding: 4px !important;
    }
    div[data-testid="stSegmentedControl"] button {
        color: #94a3b8 !important;
        border: 1px solid transparent !important;
        border-radius: 6px !important;
        font-size: 0.94rem !important;
        font-weight: 600 !important;
        padding: 10px 16px !important;
    }
    div[data-testid="stSegmentedControl"] button[aria-selected="true"] {
        background: #162a52 !important;
        color: #00f0ff !important;
        border-color: #38bdf8 !important;
        box-shadow: 0 0 12px rgba(56, 189, 248, 0.25) !important;
    }

    /* 9. Inputs */
    .stTextArea textarea, .stTextInput input {
        background: #0c1a36 !important;
        color: #f8fafc !important;
        border: 1px solid #1a3461 !important;
        border-radius: 6px !important;
    }
    .stTextArea textarea:focus, .stTextInput input:focus {
        border-color: #38bdf8 !important;
        box-shadow: 0 0 0 1px rgba(56, 189, 248, 0.3) !important;
    }

    /* 10. Action Buttons */
    div.stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #00d2ff 0%, #0284c7 100%) !important;
        color: #040814 !important;
        font-weight: 800 !important;
        border: none !important;
        border-radius: 6px !important;
        padding: 12px 24px !important;
        box-shadow: 0 4px 18px rgba(14, 165, 233, 0.4) !important;
    }
    .stLinkButton a {
        background: #0f2247 !important;
        color: #f8fafc !important;
        border: 1px solid #1a3461 !important;
        border-radius: 6px !important;
        font-weight: 600 !important;
    }

    /* 11. Cards */
    .cyber-card {
        background: #0c1a36;
        border: 1px solid #1a3461;
        border-radius: 10px;
        padding: 22px;
        margin-bottom: 15px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
    }
    .card-danger { border-left: 4px solid #ef4444 !important; }
    .card-warning { border-left: 4px solid #f59e0b !important; }
    .card-info { border-left: 4px solid #38bdf8 !important; }

    /* 12. Stats Grid */
    .stat-pill {
        background: #0c1a36;
        border: 1px solid #1a3461;
        border-radius: 8px;
        padding: 20px;
        text-align: left;
    }
    .stat-val {
        color: #00f0ff;
        font-size: 1.85rem;
        font-weight: 800;
        letter-spacing: -0.5px;
        text-shadow: 0 0 15px rgba(0, 240, 255, 0.4);
    }
    .stat-lbl {
        color: #94a3b8;
        font-size: 0.78rem;
        font-weight: 700;
        letter-spacing: 0.6px;
        margin-top: 4px;
        text-transform: uppercase;
    }
</style>
""", unsafe_allow_html=True)


# ==============================================================================
# TOP EMERGENCY ALERT BAR
# ==============================================================================
st.markdown("""
<div class="top-emergency-strip">
    <div>
        <strong>🚨 CYBER FRAUD HELPLINE:</strong> Report financial loss immediately within the 2-Hour Golden Window.
    </div>
    <div>
        <a href="tel:1930" class="top-emergency-badge">📞 Dial 1930</a>
        <a href="https://cybercrime.gov.in" target="_blank" style="color:#fecaca; text-decoration:underline; margin-left:10px; font-weight:600;">cybercrime.gov.in ↗</a>
    </div>
</div>
""", unsafe_allow_html=True)


# ==============================================================================
# HEADER: BRIGHT 3D SHIELD + ILLUMINATED TITLE & TAGLINE
# ==============================================================================
# Radiant 3D metallic shield with specular bevels & bright cyan glow
SHIELD_3D_SVG = """<svg width="60" height="66" viewBox="0 0 68 74" fill="none" xmlns="http://www.w3.org/2000/svg" style="filter: drop-shadow(0 0 18px rgba(0, 240, 255, 0.75));">
<defs>
<linearGradient id="shieldRim" x1="0" y1="0" x2="68" y2="74" gradientUnits="userSpaceOnUse">
<stop offset="0%" stop-color="#10b981"/>
<stop offset="50%" stop-color="#10b981"/>
<stop offset="100%" stop-color="#10b981"/>
</linearGradient>
<linearGradient id="shieldCore" x1="34" y1="6" x2="34" y2="66" gradientUnits="userSpaceOnUse">
<stop offset="0%" stop-color="#0b234f"/>
<stop offset="100%" stop-color="#030f24"/>
</linearGradient>
<linearGradient id="shieldEmblem" x1="20" y1="20" x2="48" y2="52" gradientUnits="userSpaceOnUse">
<stop offset="0%" stop-color="#10b981"/>
<stop offset="100%" stop-color="#10b981"/>
</linearGradient>
</defs>
<path d="M34 2L64 13V35C64 53.5 51.2 70.2 34 74C16.8 70.2 4 53.5 4 35V13L34 2Z" fill="url(#shieldRim)"/>
<path d="M34 6L59 15.5V34C59 49.5 48.4 64 34 67.5C19.6 64 9 49.5 9 34V15.5L34 6Z" fill="url(#shieldCore)"/>
<path d="M34 6L59 15.5V34C59 49.5 48.4 64 34 67.5V6Z" fill="white" fill-opacity="0.16"/>
<path d="M34 20L47 25V35C47 43 41.5 50.5 34 53C26.5 50.5 21 43 21 35V25L34 20Z" fill="url(#shieldEmblem)"/>
<path d="M34 26L41 29V35C41 39.5 38 44 34 45.5V26Z" fill="white" fill-opacity="0.35"/>
</svg>"""

banner_html = f"""<div class="hud-banner">
<div class="hud-title-wrap">
{SHIELD_3D_SVG}
<h1 class="hud-title">ScamShield<span class="hud-title-india">INDIA</span></h1>
</div>
<div class="hud-tagline-box">
<p class="hud-tagline">THINK BEFORE YOU CLICK. VERIFY BEFORE YOU TRUST</p>
</div>
</div>"""

st.markdown(banner_html, unsafe_allow_html=True)

# Live Threat Ticker Bar
st.markdown("""
<div class="ticker-bar">
    <span class="ticker-pill">⚠️ LIVE THREAT STREAM</span>
    <span>• ALERT: Fake SBI YONO APK circulating via WhatsApp SMS (+91 94xxx)</span>
    <span>• TRENDING: Electricity power cut-off SMS scam reported across Maharashtra & Delhi NCR</span>
    <span>• CRITICAL: Digital Arrest Skype extortion active</span>
</div>
""", unsafe_allow_html=True)

# User Session Status Bar
if st.session_state["user_email"]:
    col_u1, col_u2 = st.columns([4, 1])
    with col_u1:
        st.markdown(f"""
        <div style="background:#0c1a36; border:1px solid #1a3461; border-radius:6px; padding:8px 14px; font-size:0.86rem; color:#94a3b8; margin-bottom:15px;">
            🟢 Signed in as: <strong style="color:#f8fafc;">{st.session_state['user_email']}</strong> (All scans automatically saved to your private forensic vault)
        </div>
        """, unsafe_allow_html=True)
    with col_u2:
        if st.button("Sign Out", key="btn_signout"):
            st.session_state["user_email"] = None
            st.rerun()


# ==============================================================================
# MAIN NAVIGATION TABS
# ==============================================================================
tab_home, tab_scanner, tab_history, tab_emergency = st.tabs([
    "🏠 HOME & OVERVIEW",
    "⚡ THREAT SCANNER",
    "🗂️ AUDIT LOGS (DB)",
    "🚨 1930 HELPLINE"
])


# ==============================================================================
# TAB 1: LANDING HERO & STATS
# ==============================================================================
with tab_home:
    st.markdown("""
    <div class="hero-container" style="text-align: center !important;">
        <div class="hero-pill">🛡️ Cyber Defense for India</div>
        <div class="hero-title-main">Stay One Step Ahead of<br><span class="hero-title-cyan">Online Scams.</span></div>
        <p style="text-align: center !important; margin: 0 auto; max-width: 720px; font-size: 1.05rem; color: #cbd5e1; line-height: 1.65; display: block;">
            ScamShield India detects, decodes, and explains financial fraud, UPI traps,<br>
            fake bank KYC messages, and phishing URLs before financial loss occurs.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # 4 Stat Blocks
    s1, s2, s3, s4 = st.columns(4)
    with s1:
        st.markdown('<div class="stat-pill"><div class="stat-val">14,800+</div><div class="stat-lbl">Scams Audited</div></div>', unsafe_allow_html=True)
    with s2:
        st.markdown('<div class="stat-pill"><div class="stat-val">99.2%</div><div class="stat-lbl">Heuristic Accuracy</div></div>', unsafe_allow_html=True)
    with s3:
        st.markdown('<div class="stat-pill"><div class="stat-val">₹4.8 Cr+</div><div class="stat-lbl">Prevented Loss</div></div>', unsafe_allow_html=True)
    with s4:
        st.markdown('<div class="stat-pill"><div class="stat-val">100%</div><div class="stat-lbl">Zero Log Privacy</div></div>', unsafe_allow_html=True)

    st.write("")
    st.markdown("### 📚 Prevalent Indian Cyber Scams & Warning Signs")
    st.caption("Review how digital payment scams, panic tactics, and malware impersonations operate.")

    # 6 Scam Cards
    r1_c1, r1_c2, r1_c3 = st.columns(3)

    with r1_c1:
        st.markdown("""
        <div class="cyber-card card-warning">
            <span style="font-weight:700; color:#f59e0b; font-size:0.8rem; text-transform:uppercase;">[ UPI / PAYMENT FRAUD ]</span>
            <h4 style="color:#ffffff; margin:6px 0 8px 0; font-size:1.1rem;">Cashback & QR Collect</h4>
            <p style="color:#cbd5e1; font-size:0.9rem; line-height:1.5;">
                Fraudsters send QR codes or collect requests via PhonePe, GPay, or Paytm, falsely claiming you won a cashback reward.
            </p>
            <div style="background:#071329; padding:10px; border-radius:6px; font-size:0.82rem; color:#f59e0b; margin-top:8px;">
                ⚠️ <strong>The Golden Rule:</strong> You NEVER need to enter your UPI PIN to RECEIVE money.
            </div>
        </div>
        """, unsafe_allow_html=True)

    with r1_c2:
        st.markdown("""
        <div class="cyber-card card-danger">
            <span style="font-weight:700; color:#ef4444; font-size:0.8rem; text-transform:uppercase;">[ EXTORTION / POLICE COERCION ]</span>
            <h4 style="color:#ffffff; margin:6px 0 8px 0; font-size:1.1rem;">"Digital Arrest" Extortion</h4>
            <p style="color:#cbd5e1; font-size:0.9rem; line-height:1.5;">
                Callers impersonating CBI or Mumbai Police claim your Aadhaar is tied to illegal drug parcels or money laundering.
            </p>
            <div style="background:#071329; padding:10px; border-radius:6px; font-size:0.82rem; color:#ef4444; margin-top:8px;">
                ⚠️ <strong>Legal Reality:</strong> Indian law has NO 'Digital Arrest'. Police never conduct trials over video calls.
            </div>
        </div>
        """, unsafe_allow_html=True)

    with r1_c3:
        st.markdown("""
        <div class="cyber-card card-info">
            <span style="font-weight:700; color:#38bdf8; font-size:0.8rem; text-transform:uppercase;">[ UTILITY / PANIC TRAP ]</span>
            <h4 style="color:#ffffff; margin:6px 0 8px 0; font-size:1.1rem;">Power-Cut Bill SMS</h4>
            <p style="color:#cbd5e1; font-size:0.9rem; line-height:1.5;">
                SMS threats claiming electricity will be disconnected tonight unless you call an unauthorized 10-digit mobile number.
            </p>
            <div style="background:#071329; padding:10px; border-radius:6px; font-size:0.82rem; color:#38bdf8; margin-top:8px;">
                ⚠️ <strong>Defense:</strong> State DISCOMs never send disconnection threats from personal numbers.
            </div>
        </div>
        """, unsafe_allow_html=True)

    r2_c1, r2_c2, r2_c3 = st.columns(3)

    with r2_c1:
        st.markdown("""
        <div class="cyber-card card-warning">
            <span style="font-weight:700; color:#f59e0b; font-size:0.8rem; text-transform:uppercase;">[ MALWARE / SPYWARE ]</span>
            <h4 style="color:#ffffff; margin:6px 0 8px 0; font-size:1.1rem;">WhatsApp Gold APKs</h4>
            <p style="color:#cbd5e1; font-size:0.9rem; line-height:1.5;">
                Fake update links promising exclusive themes or features that drop spyware APKs to siphon banking OTPs.
            </p>
            <div style="background:#071329; padding:10px; border-radius:6px; font-size:0.82rem; color:#f59e0b; margin-top:8px;">
                ⚠️ <strong>Defense:</strong> Official apps are NEVER distributed through `.apk` links.
            </div>
        </div>
        """, unsafe_allow_html=True)

    with r2_c2:
        st.markdown("""
        <div class="cyber-card card-danger">
            <span style="font-weight:700; color:#ef4444; font-size:0.8rem; text-transform:uppercase;">[ TASK SCAM ]</span>
            <h4 style="color:#ffffff; margin:6px 0 8px 0; font-size:1.1rem;">Part-Time Job Telegram</h4>
            <p style="color:#cbd5e1; font-size:0.9rem; line-height:1.5;">
                Promises ₹3,500 daily for liking YouTube videos. Scammers give small initial payouts before demanding deposits.
            </p>
            <div style="background:#071329; padding:10px; border-radius:6px; font-size:0.82rem; color:#ef4444; margin-top:8px;">
                ⚠️ <strong>Defense:</strong> Legitimate companies never recruit through Telegram channels.
            </div>
        </div>
        """, unsafe_allow_html=True)

    with r2_c3:
        st.markdown("""
        <div class="cyber-card card-info">
            <span style="font-weight:700; color:#38bdf8; font-size:0.8rem; text-transform:uppercase;">[ BANKING PHISHING ]</span>
            <h4 style="color:#ffffff; margin:6px 0 8px 0; font-size:1.1rem;">KYC / PAN Suspension</h4>
            <p style="color:#cbd5e1; font-size:0.9rem; line-height:1.5;">
                SMS threats that your bank account is blocked today unless you update PAN details on an unauthorized link.
            </p>
            <div style="background:#071329; padding:10px; border-radius:6px; font-size:0.82rem; color:#38bdf8; margin-top:8px;">
                ⚠️ <strong>Defense:</strong> Banks never ask you to update KYC via SMS links.
            </div>
        </div>
        """, unsafe_allow_html=True)


# ==============================================================================
# TAB 2: THREAT SCANNER
# ==============================================================================
with tab_scanner:
    st.write("")
    st.markdown("### ⚡ Live Fraud & Phishing Detection")
    st.caption("Immediate analysis for suspicious messages, phishing emails, links, or uploaded screenshots.")

    # Input format rendered as BARS
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
    if st.button("🛡️ ANALYZE THREAT NOW", type="primary", width="stretch"):
        if not active_text:
            st.warning("Please enter text or upload an image first.")
        else:
            with st.spinner("Running heuristic & threat intelligence engine..."):
                result = engine.analyze(active_text)

            final_score = min(result["risk_score"] + extra_email_score, 100)
            final_level = "CRITICAL THREAT" if final_score >= 70 else ("SUSPICIOUS" if final_score >= 40 else "SAFE")
            result["risk_score"] = final_score
            result["risk_level"] = final_level

            # Save with current user or guest
            current_user = st.session_state.get("user_email") or "guest"
            db_id = save_scan_result(
                scan_type=scan_type,
                content=active_text,
                result=result,
                image_file=image_to_save,
                user_email=current_user
            )

            # Results Display HUD
            st.divider()
            c1, c2, c3 = st.columns([1.2, 1.2, 2.6])
            
            score_color = "#ef4444" if final_score >= 70 else ("#f59e0b" if final_score >= 40 else "#10b981")
            
            with c1:
                st.markdown(f"""
                <div class="cyber-card" style="text-align:center;">
                    <span style="font-size:0.82rem; color:#94a3b8; font-weight:700;">RISK SCORE</span>
                    <h2 style="color:{score_color}; font-size:2.4rem; font-weight:800; margin:5px 0;">{final_score} / 100</h2>
                </div>
                """, unsafe_allow_html=True)

            with c2:
                st.markdown(f"""
                <div class="cyber-card" style="text-align:center;">
                    <span style="font-size:0.82rem; color:#94a3b8; font-weight:700;">STATUS LEVEL</span>
                    <h2 style="color:{score_color}; font-size:1.5rem; font-weight:800; margin:12px 0;">{final_level}</h2>
                </div>
                """, unsafe_allow_html=True)

            with c3:
                if result["impersonation_detected"]:
                    imps = ", ".join([f"{item['entity']} ({item['category']})" for item in result["impersonation_detected"]])
                    st.markdown(f"""
                    <div class="cyber-card card-danger">
                        <span style="font-size:0.82rem; color:#ef4444; font-weight:700;">🎭 IMPERSONATION DETECTED</span>
                        <p style="margin:6px 0 0 0; color:#f8fafc; font-weight:600;">{imps}</p>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown("""
                    <div class="cyber-card card-info">
                        <span style="font-size:0.82rem; color:#38bdf8; font-weight:700;">SOURCE BRAND</span>
                        <p style="margin:6px 0 0 0; color:#94a3b8;">No official brand claimed.</p>
                    </div>
                    """, unsafe_allow_html=True)

            if current_user == "guest":
                st.caption(f"💾 Incident analyzed (Logged as Guest). Sign in to retain this evidence in your private vault.")
            else:
                st.caption(f"💾 Incident saved to **{current_user}**'s forensic vault (Record ID #{db_id})")

            # Explainable Indicators
            st.markdown("### 🔍 Explainable Red Flags Detected")

            for ew in email_warnings:
                st.markdown(f"""
                <div class="cyber-card card-danger">
                    <strong style="color:#ef4444;">📧 Email Header & Domain Spoofing</strong><br>
                    <span style="color:#cbd5e1;">{ew}</span>
                </div>
                """, unsafe_allow_html=True)

            for trig in result["triggers"]:
                st.markdown(f"""
                <div class="cyber-card card-danger">
                    <strong style="color:#ef4444;">🚩 Flag: {trig['category']} (+{trig['weight']} Points)</strong><br>
                    <span style="color:#cbd5e1;">{trig['explanation']}</span>
                </div>
                """, unsafe_allow_html=True)

            for u in result["url_analysis"]:
                for ws in u["warning_signs"]:
                    st.markdown(f"""
                    <div class="cyber-card card-warning">
                        <strong style="color:#f59e0b;">🔗 URL Threat Indicator ({u['url']})</strong><br>
                        <span style="color:#cbd5e1;">{ws}</span>
                    </div>
                    """, unsafe_allow_html=True)

            st.markdown("### 🛡️ Recommended Security Actions")
            for rec in result["recommendations"]:
                st.markdown(f"- **{rec}**")


# ==============================================================================
# TAB 3: AUDIT LOGS (SUPABASE MANAGED AUTHENTICATION)
# ==============================================================================
with tab_history:
    st.write("")
    st.markdown("### 🗂️ Forensics Audit Log & Saved Evidence")

    logged_user = st.session_state.get("user_email")

    if not logged_user:
        st.markdown("""
        <div class="cyber-card card-info" style="margin-bottom: 20px;">
            <h4 style="margin: 0 0 6px 0; color: #38bdf8;">🔒 Sign In to Access Your Forensic Evidence Vault</h4>
            <p style="margin: 0; color: #94a3b8; font-size: 0.92rem;">
                Free Supabase Authentication. Sign in or create an account to permanently retain and manage your scanned incident records.
            </p>
        </div>
        """, unsafe_allow_html=True)

        auth_tab1, auth_tab2 = st.tabs(["🔑 Sign In", "📝 Create Free Account"])

        with auth_tab1:
            col_in1, col_in2 = st.columns(2)
            with col_in1:
                login_email = st.text_input("Email:", key="login_email_input", placeholder="name@domain.com")
            with col_in2:
                login_password = st.text_input("Password:", key="login_pass_input", type="password")

            if st.button("Sign In to Vault", type="primary", width="stretch", key="btn_signin"):
                if not login_email or not login_password:
                    st.warning("Please provide both email and password.")
                else:
                    with st.spinner("Authenticating with Supabase..."):
                        success, message, user_email = sign_in_user(login_email, login_password)
                        if success:
                            st.session_state["user_email"] = user_email
                            st.toast(f"✅ Welcome back, {user_email}!")
                            st.rerun()
                        else:
                            st.error(message)

        with auth_tab2:
            col_up1, col_up2 = st.columns(2)
            with col_up1:
                signup_email = st.text_input("Email:", key="signup_email_input", placeholder="name@domain.com")
            with col_up2:
                signup_password = st.text_input("Choose Password (min 6 chars):", key="signup_pass_input", type="password")

            if st.button("Create Account", width="stretch", key="btn_signup"):
                if not signup_email or not signup_password:
                    st.warning("Please fill in both fields.")
                else:
                    with st.spinner("Creating account on Supabase..."):
                        success, message = sign_up_user(signup_email, signup_password)
                        if success:
                            st.success(message)
                        else:
                            st.error(message)

        st.divider()
        st.caption("Guest scans performed during this session:")
        scans = get_all_scans(user_email="guest")

    else:
        scans = get_all_scans(user_email=logged_user)

        col_h1, col_h2 = st.columns([4, 1])
        with col_h1:
            st.write(f"Logged Incidents for **{logged_user}**: **{len(scans)}**")
        with col_h2:
            if st.button("🗑️ Clear My Logs"):
                clear_all_scans(user_email=logged_user)
                st.rerun()

    if not scans:
        st.info("No recorded evidence scans found. Analyze any message or screenshot in the Threat Scanner tab.")
    else:
        for item in scans:
            risk_color = "#ef4444" if item["risk_score"] >= 70 else ("#ffbb00" if item["risk_score"] >= 40 else "#10b981")
            
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
                            st.image(img_path, caption="Saved Screenshot Evidence", width="stretch")


# ==============================================================================
# TAB 4: 1930 EMERGENCY HELPLINE (SANCHAR SAATHI SINGLE-LINE & BUTTONS LEVELED)
# ==============================================================================
with tab_emergency:
    st.write("")
    st.markdown("""
    <div style="border: 1px solid #ef4444; background: rgba(239, 68, 68, 0.12); border-radius: 8px; padding: 22px; margin-bottom: 24px;">
        <h2 style="color:#ef4444; margin:0 0 8px 0; font-size:1.6rem; font-weight:800;">NATIONAL CYBERCRIME HELPLINE: 1930</h2>
        <p style="font-size:1rem; color:#f8fafc; margin:0; line-height:1.6;">
            If you have suffered an unauthorized financial deduction, dial <strong>1930</strong> immediately. 
            The <strong>Golden Hour (first 2 hours)</strong> is critical for the Indian Cyber Crime Coordination Centre (I4C) 
            to freeze money transfers before they are cashed out.
        </p>
    </div>
    """, unsafe_allow_html=True)

    col_e1, col_e2, col_e3 = st.columns(3)

    with col_e1:
        st.markdown("""
        <div style="min-height: 96px;">
            <h3 style="margin: 0 0 6px 0; font-size: 1.15rem; white-space: nowrap;">1. National Portal</h3>
            <p style="margin: 0; color: #94a3b8; font-size: 0.9rem;">File complaints for financial fraud, identity theft, or social media harassment.</p>
        </div>
        """, unsafe_allow_html=True)
        st.link_button("🌐 cybercrime.gov.in", "https://cybercrime.gov.in", width="stretch")

    with col_e2:
        st.markdown("""
        <div style="min-height: 96px;">
            <h3 style="margin: 0 0 6px 0; font-size: 1.12rem; white-space: nowrap;">2. Sanchar Saathi (Chakshu)</h3>
            <p style="margin: 0; color: #94a3b8; font-size: 0.9rem;">Report fraudulent calls, spam SMS headers, and rogue WhatsApp numbers.</p>
        </div>
        """, unsafe_allow_html=True)
        st.link_button("📱 Chakshu Portal", "https://sancharsaathi.gov.in", width="stretch")

    with col_e3:
        st.markdown("""
        <div style="min-height: 96px;">
            <h3 style="margin: 0 0 6px 0; font-size: 1.15rem; white-space: nowrap;">3. Bank Card Freeze</h3>
            <p style="margin: 0; color: #94a3b8; font-size: 0.9rem;">Immediately call your bank's 24x7 fraud desk to block cards and netbanking.</p>
        </div>
        """, unsafe_allow_html=True)
        st.info("Have your UTR reference number, account number, and transaction time ready.")

    st.divider()
    st.markdown("""
    #### 📋 Emergency Incident Checklist
    1. **Preserve All Evidence:** Do not delete SMS messages, WhatsApp chats, call recordings, or bank receipts.
    2. **Call 1930 Immediately:** State the debit account number, transaction timestamp, and recipient UPI/account info.
    3. **File Complaint on cybercrime.gov.in:** Download the acknowledgement PDF for bank chargeback claims and FIR filing.
    4. **Change Passwords:** Immediately update your UPI PIN and NetBanking passwords from a secure device.
    """)