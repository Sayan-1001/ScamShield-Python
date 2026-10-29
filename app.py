"""ScamShield India — Interactive Web Application (Local OCR)."""

import streamlit as st
from scamshield.explainable_engine import ScamShieldEngine
from scamshield.ocr_engine import extract_text_from_image

st.set_page_config(
    page_title="ScamShield India",
    page_icon="🛡️",
    layout="wide"
)

# Custom Styling
st.markdown("""
<style>
    .metric-card {
        padding: 1.2rem;
        border-radius: 0.6rem;
        background-color: #f8f9fa;
        border-left: 6px solid #ff4b4b;
        margin-bottom: 1rem;
    }
</style>
""", unsafe_allow_html=True)

engine = ScamShieldEngine()

if "analyzed_text" not in st.session_state:
    st.session_state["analyzed_text"] = ""

st.title("🛡️ ScamShield India")
st.caption("Explainable Fraud & Phishing Detection for Common Indian Cyber Threats")

# Sidebar - Preset Common Indian Scams
st.sidebar.header("Try Common Indian Scams")
preset = st.sidebar.selectbox(
    "Choose a sample message to test:",
    [
        "Custom Input",
        "Electricity Bill Disconnection Scam",
        "UPI Money Request Scam",
        "Fake Part-Time Job on Telegram",
        "Digital Arrest / Mumbai Police Call",
        "SBI / HDFC KYC Expiry Link"
    ]
)

preset_texts = {
    "Electricity Bill Disconnection Scam": (
        "Dear Consumer, your electricity power will be disconnected today midnight at 9:30 PM "
        "because your previous month bill was not updated. Immediately contact our electricity officer "
        "at 9876543210. Discom Office."
    ),
    "UPI Money Request Scam": (
        "Congratulations! You won cashback reward of Rs 2,500 from Google Pay. "
        "Scan this QR code and enter your UPI PIN to claim money instantly."
    ),
    "Fake Part-Time Job on Telegram": (
        "Work from home opportunity! Like YouTube videos and earn Rs 3500 daily. "
        "Instant payout every evening. Join our Telegram group to start your first task: http://bit.ly/work-part-time-in"
    ),
    "Digital Arrest / Mumbai Police Call": (
        "This is an urgent notice from Mumbai Police and CBI Cyber Cell. An arrest warrant has been issued "
        "in your name as your Aadhaar card is tied to money laundering. You are placed under digital arrest. "
        "Call us immediately."
    ),
    "SBI / HDFC KYC Expiry Link": (
        "Dear Customer, your SBI YONO account will be blocked today. Please update PAN Card immediately "
        "to avoid deactivation. Click here: http://sbi.bank-kyc-verification.xyz/login"
    )
}

# Input Tabs
tab1, tab2 = st.tabs(["💬 Inspect Message / URL", "📷 Upload Screenshot (Local OCR)"])

with tab1:
    default_text = preset_texts.get(preset, "") if preset != "Custom Input" else ""
    text_input = st.text_area(
        "Paste the SMS, WhatsApp message, or URL below:",
        value=default_text,
        height=140,
        placeholder="e.g. Dear customer, your bank account is suspended. Click http://... to verify."
    )
    if text_input:
        st.session_state["analyzed_text"] = text_input

with tab2:
    uploaded_file = st.file_uploader(
        "Upload a screenshot of the message (PNG, JPG, JPEG):", 
        type=["png", "jpg", "jpeg"]
    )
    if uploaded_file is not None:
        if st.button("🔍 Extract Text with OCR"):
            with st.spinner("Extracting text locally..."):
                extracted_text, error = extract_text_from_image(uploaded_file)
                if error:
                    st.error(error)
                else:
                    st.success("Text extracted instantly!")
                    st.session_state["analyzed_text"] = extracted_text

    if st.session_state.get("analyzed_text") and uploaded_file is not None:
        st.session_state["analyzed_text"] = st.text_area(
            "Extracted Message for Analysis:",
            value=st.session_state["analyzed_text"],
            height=120
        )

# Analyze Button
analyze_button = st.button("🛡️ Analyze Threat & Explain", type="primary")

active_text = st.session_state.get("analyzed_text", "").strip()

if analyze_button and active_text:
    with st.spinner("Analyzing message signatures and web artifacts..."):
        result = engine.analyze(active_text)

    # 1. Summary Header
    st.divider()
    col1, col2, col3 = st.columns([1, 1, 2])
    
    with col1:
        st.metric(label="Risk Score", value=f"{result['risk_score']} / 100")
        
    with col2:
        st.metric(label="Threat Status", value=result["risk_level"])

    with col3:
        if result["impersonation_detected"]:
            entities = ", ".join([f"{item['entity']} ({item['category']})" for item in result["impersonation_detected"]])
            st.warning(f"🎭 **Impersonation Detected:** {entities}")
        else:
            st.info("No specific institutional brand claimed.")

    # 2. Explainable Warning Signs
    st.subheader("🔍 Why is this message suspicious? (Explainable Signs)")
    
    has_triggers = bool(result["triggers"])
    has_url_warnings = any(bool(u["warning_signs"]) for u in result["url_analysis"])

    if not has_triggers and not has_url_warnings:
        st.success("No recognized scam markers, urgency tactics, or malicious URL patterns were discovered.")
    else:
        for trig in result["triggers"]:
            st.markdown(f"""
            <div class="metric-card">
                <strong>🚩 Category: {trig['category']}</strong> (Weight: +{trig['weight']})<br>
                <span>{trig['explanation']}</span>
            </div>
            """, unsafe_allow_html=True)

        for url_res in result["url_analysis"]:
            if url_res["warning_signs"]:
                for warn in url_res["warning_signs"]:
                    st.markdown(f"""
                    <div class="metric-card">
                        <strong>🔗 Suspicious Link Indicator</strong> ({url_res['url']})<br>
                        <span>{warn}</span>
                    </div>
                    """, unsafe_allow_html=True)

    # 3. Actionable Safety Recommendations
    st.subheader("🛡️ Actionable Next Steps")
    for rec in result["recommendations"]:
        st.markdown(f"- {rec}")

elif analyze_button and not active_text:
    st.warning("Please enter some text or upload and extract a screenshot first.")