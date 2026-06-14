"""
Deraa (درع) — AI-Driven Egyptian Dialect SMS Phishing Detection
Streamlit Frontend: High-fidelity, RTL Arabic-supported interface
"""

import requests
import streamlit as st
from PIL import Image
import io

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
API_BASE_URL = "http://localhost:8000"

RISK_CONFIG = {
    "SAFE":     {"color": "#00C897", "bg": "#0a2e20", "border": "#00C897", "label": "آمن",     "emoji": "✅", "bar_color": "#00C897"},
    "LOW":      {"color": "#FFD166", "bg": "#2a2000", "border": "#FFD166", "label": "منخفض",   "emoji": "🟡", "bar_color": "#FFD166"},
    "MEDIUM":   {"color": "#FF8C42", "bg": "#2a1500", "border": "#FF8C42", "label": "متوسط",   "emoji": "🟠", "bar_color": "#FF8C42"},
    "HIGH":     {"color": "#EF4444", "bg": "#2a0a0a", "border": "#EF4444", "label": "عالٍ",    "emoji": "🔴", "bar_color": "#EF4444"},
    "CRITICAL": {"color": "#FF0044", "bg": "#1a0000", "border": "#FF0044", "label": "حرج",     "emoji": "🚨", "bar_color": "#FF0044"},
}

LAYER_LABELS = {
    "intent_analysis":       ("🧠", "تحليل النية والسياق"),
    "sender_verification":   ("👤", "التحقق من هوية المرسل"),
    "url_analysis":          ("🔗", "تحليل الروابط"),
}

# ─────────────────────────────────────────────
# Page Config
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="درع | كشف الاحتيال بالذكاء الاصطناعي",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─────────────────────────────────────────────
# Global CSS: RTL, Arabic font, dark cyber theme
# ─────────────────────────────────────────────
st.markdown("""
<style>
  /* ── Arabic Font ── */
  @import url('https://fonts.googleapis.com/css2?family=Cairo:wght@300;400;600;700;900&family=JetBrains+Mono:wght@400;600&display=swap');

  /* ── Reset & Base ── */
  html, body, [class*="css"] {
    direction: rtl;
    font-family: 'Cairo', 'Segoe UI', sans-serif;
    background-color: #060b14;
    color: #e2e8f0;
  }

  /* ── Hide Streamlit Chrome ── */
  #MainMenu, footer, header { visibility: hidden; }
  .block-container { padding: 0 !important; max-width: 100% !important; }

  /* ── Scrollbar ── */
  ::-webkit-scrollbar { width: 6px; }
  ::-webkit-scrollbar-track { background: #0d1117; }
  ::-webkit-scrollbar-thumb { background: #1e3a5f; border-radius: 3px; }

  /* ── Main layout wrapper ── */
  .deraa-root {
    min-height: 100vh;
    background: linear-gradient(135deg, #060b14 0%, #0a1628 50%, #060b14 100%);
    padding: 0;
  }

  /* ── Header / Hero ── */
  .hero-section {
    background: linear-gradient(135deg, #0a1628 0%, #0d2040 40%, #091520 100%);
    border-bottom: 1px solid rgba(0, 200, 151, 0.2);
    padding: 2.5rem 3rem 2rem;
    position: relative;
    overflow: hidden;
  }
  .hero-section::before {
    content: '';
    position: absolute;
    top: -50%;
    left: -20%;
    width: 400px;
    height: 400px;
    background: radial-gradient(circle, rgba(0,200,151,0.06) 0%, transparent 70%);
    pointer-events: none;
  }
  .hero-logo {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-bottom: 0.5rem;
  }
  .hero-shield {
    font-size: 3.5rem;
    filter: drop-shadow(0 0 16px rgba(0,200,151,0.5));
    animation: pulse-glow 3s ease-in-out infinite;
  }
  @keyframes pulse-glow {
    0%, 100% { filter: drop-shadow(0 0 12px rgba(0,200,151,0.4)); }
    50%       { filter: drop-shadow(0 0 28px rgba(0,200,151,0.8)); }
  }
  .hero-title {
    font-size: 3rem;
    font-weight: 900;
    background: linear-gradient(135deg, #00C897 0%, #00a8ff 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin: 0;
    line-height: 1;
    letter-spacing: -1px;
  }
  .hero-subtitle {
    font-size: 1rem;
    color: #7fb3d3;
    margin: 0.25rem 0 0;
    font-weight: 300;
  }
  .hero-tagline {
    font-size: 1.1rem;
    color: #94a3b8;
    font-weight: 400;
    margin-top: 0.5rem;
  }
  .hero-tagline span {
    color: #00C897;
    font-weight: 600;
  }
  .status-pill {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    background: rgba(0,200,151,0.12);
    border: 1px solid rgba(0,200,151,0.3);
    border-radius: 100px;
    padding: 0.25rem 0.9rem;
    font-size: 0.8rem;
    color: #00C897;
    margin-top: 0.75rem;
  }
  .status-dot {
    width: 7px;
    height: 7px;
    background: #00C897;
    border-radius: 50%;
    animation: blink 2s infinite;
  }
  @keyframes blink {
    0%, 100% { opacity: 1; }
    50%       { opacity: 0.3; }
  }

  /* ── Input Section ── */
  .input-section {
    padding: 2rem 3rem;
    max-width: 1400px;
    margin: 0 auto;
  }

  /* ── Tab Selector ── */
  .stTabs [data-baseweb="tab-list"] {
    gap: 0.5rem;
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 12px;
    padding: 0.35rem;
  }
  .stTabs [data-baseweb="tab"] {
    background: transparent !important;
    color: #7fb3d3 !important;
    border-radius: 9px !important;
    font-family: 'Cairo', sans-serif !important;
    font-weight: 600 !important;
    font-size: 1rem !important;
    padding: 0.6rem 1.5rem !important;
    border: none !important;
    transition: all 0.2s ease !important;
  }
  .stTabs [aria-selected="true"] {
    background: linear-gradient(135deg, rgba(0,200,151,0.2), rgba(0,168,255,0.15)) !important;
    color: #00C897 !important;
    border: 1px solid rgba(0,200,151,0.3) !important;
  }
  .stTabs [data-baseweb="tab-panel"] {
    padding-top: 1.5rem;
  }

  /* ── Input Cards ── */
  .input-card {
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 16px;
    padding: 1.5rem;
    margin-bottom: 1rem;
  }
  .input-label {
    font-size: 0.85rem;
    font-weight: 600;
    color: #7fb3d3;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 0.6rem;
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }

  /* ── Form Elements ── */
  .stTextArea textarea {
    background: rgba(0,0,0,0.3) !important;
    border: 1px solid rgba(255,255,255,0.1) !important;
    border-radius: 12px !important;
    color: #e2e8f0 !important;
    font-family: 'Cairo', sans-serif !important;
    font-size: 1.05rem !important;
    direction: rtl !important;
    resize: vertical !important;
    min-height: 140px !important;
    transition: border-color 0.2s !important;
  }
  .stTextArea textarea:focus {
    border-color: rgba(0,200,151,0.5) !important;
    box-shadow: 0 0 0 2px rgba(0,200,151,0.1) !important;
  }
  .stTextInput input {
    background: rgba(0,0,0,0.3) !important;
    border: 1px solid rgba(255,255,255,0.1) !important;
    border-radius: 10px !important;
    color: #e2e8f0 !important;
    font-family: 'Cairo', sans-serif !important;
    font-size: 0.95rem !important;
    direction: ltr !important;
  }
  .stTextInput input:focus {
    border-color: rgba(0,200,151,0.5) !important;
  }

  /* ── Analyze Button ── */
  .stButton > button {
    width: 100% !important;
    background: linear-gradient(135deg, #00C897 0%, #00a070 100%) !important;
    color: #060b14 !important;
    border: none !important;
    border-radius: 12px !important;
    font-family: 'Cairo', sans-serif !important;
    font-size: 1.1rem !important;
    font-weight: 700 !important;
    padding: 0.75rem 2rem !important;
    letter-spacing: 0.05em !important;
    transition: all 0.25s ease !important;
    box-shadow: 0 4px 20px rgba(0,200,151,0.3) !important;
  }
  .stButton > button:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 8px 32px rgba(0,200,151,0.5) !important;
    background: linear-gradient(135deg, #00dfa8 0%, #00b880 100%) !important;
  }
  .stButton > button:active {
    transform: translateY(0) !important;
  }

  /* ── Results Section ── */
  .results-section {
    padding: 0 3rem 3rem;
    max-width: 1400px;
    margin: 0 auto;
  }

  /* ── Risk Score Card ── */
  .risk-score-card {
    border-radius: 20px;
    padding: 2.5rem;
    margin-bottom: 1.5rem;
    position: relative;
    overflow: hidden;
  }
  .risk-score-card::after {
    content: '';
    position: absolute;
    top: 0; right: 0;
    width: 200px; height: 200px;
    border-radius: 50%;
    background: radial-gradient(circle, rgba(255,255,255,0.04) 0%, transparent 70%);
    pointer-events: none;
  }
  .risk-number {
    font-size: 5.5rem;
    font-weight: 900;
    line-height: 1;
    font-family: 'JetBrains Mono', monospace;
    margin-bottom: 0.25rem;
  }
  .risk-label-badge {
    display: inline-block;
    border-radius: 100px;
    padding: 0.35rem 1.2rem;
    font-size: 1rem;
    font-weight: 700;
    margin-bottom: 1rem;
  }
  .verdict-text {
    font-size: 1.2rem;
    font-weight: 600;
    margin-top: 0.5rem;
    line-height: 1.4;
  }

  /* ── Progress Bar ── */
  .risk-bar-track {
    height: 10px;
    background: rgba(255,255,255,0.08);
    border-radius: 100px;
    overflow: hidden;
    margin: 1rem 0;
  }
  .risk-bar-fill {
    height: 100%;
    border-radius: 100px;
    transition: width 1s ease;
  }

  /* ── Layer Analysis Cards ── */
  .layer-card {
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 14px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 0.75rem;
  }
  .layer-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.5rem;
  }
  .layer-title {
    font-size: 1rem;
    font-weight: 700;
    color: #e2e8f0;
  }
  .layer-score-badge {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.9rem;
    font-weight: 600;
    padding: 0.2rem 0.7rem;
    border-radius: 100px;
  }
  .layer-mini-bar {
    height: 5px;
    background: rgba(255,255,255,0.08);
    border-radius: 100px;
    overflow: hidden;
    margin: 0.5rem 0;
  }
  .flag-item {
    background: rgba(255,255,255,0.04);
    border-right: 3px solid #FF8C42;
    border-radius: 0 8px 8px 0;
    padding: 0.4rem 0.75rem;
    margin-top: 0.35rem;
    font-size: 0.9rem;
    color: #c9d4e0;
    direction: rtl;
  }
  .flag-safe {
    border-right-color: #00C897;
  }
  .no-flags {
    color: #4a6080;
    font-size: 0.88rem;
    font-style: italic;
    margin-top: 0.4rem;
  }

  /* ── Recommendations ── */
  .rec-card {
    background: rgba(0,200,151,0.05);
    border: 1px solid rgba(0,200,151,0.15);
    border-radius: 14px;
    padding: 1.25rem 1.5rem;
  }
  .rec-title {
    font-size: 1rem;
    font-weight: 700;
    color: #00C897;
    margin-bottom: 0.75rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .rec-item {
    padding: 0.45rem 0;
    border-bottom: 1px solid rgba(255,255,255,0.05);
    font-size: 0.95rem;
    color: #b8cfe0;
    direction: rtl;
  }
  .rec-item:last-child { border-bottom: none; }

  /* ── Extracted Text Box ── */
  .ocr-box {
    background: rgba(0,0,0,0.4);
    border: 1px solid rgba(0,168,255,0.2);
    border-radius: 12px;
    padding: 1rem 1.25rem;
    font-family: 'Cairo', sans-serif;
    font-size: 0.95rem;
    color: #94a3b8;
    direction: rtl;
    margin-bottom: 1.5rem;
    white-space: pre-wrap;
    max-height: 160px;
    overflow-y: auto;
  }
  .ocr-label {
    font-size: 0.78rem;
    font-weight: 600;
    color: #00a8ff;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 0.4rem;
  }

  /* ── Divider ── */
  .cyber-divider {
    height: 1px;
    background: linear-gradient(90deg, transparent, rgba(0,200,151,0.2), transparent);
    margin: 2rem 0;
  }

  /* ── Section Title ── */
  .section-title {
    font-size: 1.1rem;
    font-weight: 700;
    color: #7fb3d3;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-size: 0.85rem;
  }

  /* ── File Uploader ── */
  .stFileUploader > div {
    background: rgba(0,0,0,0.2) !important;
    border: 2px dashed rgba(0,200,151,0.25) !important;
    border-radius: 14px !important;
    transition: border-color 0.2s !important;
  }
  .stFileUploader > div:hover {
    border-color: rgba(0,200,151,0.5) !important;
  }

  /* ── Spinner ── */
  .stSpinner > div {
    border-color: #00C897 !important;
    border-right-color: transparent !important;
  }

  /* ── Footer ── */
  .deraa-footer {
    text-align: center;
    padding: 2rem;
    color: #334155;
    font-size: 0.8rem;
    border-top: 1px solid rgba(255,255,255,0.05);
    margin-top: 2rem;
  }
  .deraa-footer a { color: #00C897; text-decoration: none; }

  /* ── RTL fix for columns ── */
  .stColumns { flex-direction: row-reverse; }

  /* ── Alert boxes ── */
  .stAlert { border-radius: 12px !important; font-family: 'Cairo', sans-serif !important; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# Helper: Score → Color
# ─────────────────────────────────────────────
def score_to_color(score: float) -> str:
    if score < 20:   return "#00C897"
    if score < 40:   return "#FFD166"
    if score < 60:   return "#FF8C42"
    if score < 80:   return "#EF4444"
    return "#FF0044"


def layer_score_color(score: float) -> str:
    if score < 0.25:  return "#00C897"
    if score < 0.50:  return "#FFD166"
    if score < 0.75:  return "#FF8C42"
    return "#EF4444"


# ─────────────────────────────────────────────
# Render: Risk Score Card
# ─────────────────────────────────────────────
def render_risk_card(result: dict):
    score     = result["risk_score"]
    level     = result["risk_level"]
    verdict   = result["verdict"]
    cfg       = RISK_CONFIG.get(level, RISK_CONFIG["MEDIUM"])
    bar_color = cfg["bar_color"]
    main_color = cfg["color"]

    st.markdown(f"""
    <div class="risk-score-card" style="
        background: linear-gradient(135deg, {cfg['bg']} 0%, rgba(0,0,0,0.5) 100%);
        border: 1.5px solid {cfg['border']}40;
    ">
      <div style="display:flex; align-items:flex-start; justify-content:space-between; gap:1rem;">
        <div>
          <div class="risk-number" style="color:{main_color};">{score:.0f}<span style="font-size:2rem; opacity:0.6;">%</span></div>
          <div class="risk-bar-track" style="width:280px;">
            <div class="risk-bar-fill" style="width:{score}%; background:linear-gradient(90deg, {bar_color}88, {bar_color});"></div>
          </div>
          <div class="verdict-text" style="color:{main_color};">{verdict}</div>
        </div>
        <div style="text-align:center; min-width:80px;">
          <div style="font-size:3.5rem; line-height:1; margin-bottom:0.25rem;">{cfg['emoji']}</div>
          <div class="risk-label-badge" style="background:{main_color}22; color:{main_color}; border:1px solid {main_color}44;">
            مستوى {cfg['label']}
          </div>
        </div>
      </div>
      <div style="margin-top:1rem; font-size:0.8rem; color:#334155;">
        📅 {result.get('analysis_timestamp','')[:19].replace('T',' ')} UTC
      </div>
    </div>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────────
# Render: Layer Breakdown
# ─────────────────────────────────────────────
def render_layer_breakdown(layer_results: dict):
    st.markdown('<div class="section-title">🔍 تفاصيل التحليل متعدد الطبقات</div>', unsafe_allow_html=True)

    for key, (icon, title) in LAYER_LABELS.items():
        layer = layer_results.get(key, {})
        score = layer.get("score", 0.0)
        flags = layer.get("flags", [])
        color = layer_score_color(score)
        pct   = round(score * 100)

        flags_html = ""
        if flags:
            for f in flags:
                is_safe = "✅" in f
                cls = "flag-item flag-safe" if is_safe else "flag-item"
                flags_html += f'<div class="{cls}">{f}</div>'
        else:
            flags_html = '<div class="no-flags">لم يتم رصد مؤشرات في هذه الطبقة</div>'

        st.markdown(f"""
        <div class="layer-card">
          <div class="layer-header">
            <div class="layer-title">{icon} {title}</div>
            <div class="layer-score-badge" style="background:{color}20; color:{color}; border:1px solid {color}44;">
              {pct}%
            </div>
          </div>
          <div class="layer-mini-bar">
            <div style="height:100%; width:{pct}%; background:linear-gradient(90deg,{color}66,{color}); border-radius:100px; transition:width 1s;"></div>
          </div>
          {flags_html}
        </div>
        """, unsafe_allow_html=True)


# ─────────────────────────────────────────────
# Render: Recommendations
# ─────────────────────────────────────────────
def render_recommendations(recs: list):
    if not recs:
        return
    items_html = "".join(f'<div class="rec-item">{r}</div>' for r in recs)
    st.markdown(f"""
    <div class="rec-card">
      <div class="rec-title">🛡️ التوصيات الأمنية</div>
      {items_html}
    </div>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────────
# Render: Extracted Text (OCR)
# ─────────────────────────────────────────────
def render_extracted_text(text: str):
    if not text:
        return
    st.markdown(f"""
    <div class="ocr-label">📝 النص المستخرج من الصورة (OCR)</div>
    <div class="ocr-box">{text}</div>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────────
# API Calls
# ─────────────────────────────────────────────
def call_analyze_text(text: str, sender: str) -> dict | None:
    try:
        payload = {"text": text, "sender": sender or None}
        r = requests.post(f"{API_BASE_URL}/analyze-text", json=payload, timeout=30)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        st.error("❌ لا يمكن الاتصال بالخادم. تأكد من تشغيل `main.py` على المنفذ 8000.")
    except requests.exceptions.Timeout:
        st.error("⏱️ انتهت مهلة الاتصال بالخادم.")
    except Exception as e:
        st.error(f"❌ خطأ: {str(e)}")
    return None


def call_analyze_image(file_bytes: bytes, filename: str, sender: str) -> dict | None:
    try:
        files  = {"file": (filename, file_bytes, "image/jpeg")}
        params = {"sender": sender} if sender else {}
        r = requests.post(f"{API_BASE_URL}/analyze-image", files=files, params=params, timeout=60)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        st.error("❌ لا يمكن الاتصال بالخادم. تأكد من تشغيل `main.py` على المنفذ 8000.")
    except requests.exceptions.Timeout:
        st.error("⏱️ انتهت مهلة الاتصال بالخادم. استخراج النص من الصور يستغرق وقتاً أطول.")
    except Exception as e:
        st.error(f"❌ خطأ: {str(e)}")
    return None


# ─────────────────────────────────────────────
# MAIN APP
# ─────────────────────────────────────────────
def main():
    # ── Hero Header ──────────────────────────────────────────────────────
    st.markdown("""
    <div class="hero-section">
      <div class="hero-logo">
        <span class="hero-shield">🛡️</span>
        <div>
          <div class="hero-title">درع</div>
          <div class="hero-subtitle">DERAA · Cybersecurity Intelligence</div>
        </div>
      </div>
      <div class="hero-tagline">
        محرك <span>ذكاء اصطناعي</span> متخصص في كشف رسائل التصيد الاحتيالي باللهجة المصرية
      </div>
      <div class="status-pill">
        <div class="status-dot"></div>
        النظام يعمل · AI Engine Online
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Main Content ─────────────────────────────────────────────────────
    st.markdown('<div class="input-section">', unsafe_allow_html=True)

    tab_text, tab_image = st.tabs(["📝 تحليل رسالة نصية", "🖼️ تحليل صورة (Screenshot)"])

    # ── TAB 1: Text Analysis ──────────────────────────────────────────────
    with tab_text:
        col_input, col_info = st.columns([3, 1], gap="large")

        with col_input:
            st.markdown('<div class="input-label">✉️ نص الرسالة</div>', unsafe_allow_html=True)
            sms_text = st.text_area(
                label="sms_text",
                label_visibility="collapsed",
                placeholder="الصق هنا نص الرسالة المشبوهة باللهجة المصرية أو العربية...\n\nمثال: تم تجميد حسابك فورا اضغط الرابط لاعادة التفعيل",
                height=160,
                key="sms_text_input",
            )

            sender_text = st.text_input(
                label="sender_text",
                label_visibility="collapsed",
                placeholder="🆔 هوية المرسل (اختياري) — مثال: +201012345678 أو BankMisr",
                key="sender_text_input",
            )

            text_btn = st.button("🔍 تحليل الرسالة", key="analyze_text_btn", use_container_width=True)

        with col_info:
            st.markdown("""
            <div style="background:rgba(0,200,151,0.06); border:1px solid rgba(0,200,151,0.15); border-radius:14px; padding:1.25rem; font-size:0.88rem; color:#7fb3d3;">
              <div style="color:#00C897; font-weight:700; margin-bottom:0.75rem;">⚙️ طبقات التحليل</div>
              <div style="margin-bottom:0.5rem;">🧠 <strong>الطبقة 1</strong><br>نموذج NLP لتحليل النية والسياق</div>
              <div style="margin-bottom:0.5rem;">👤 <strong>الطبقة 2</strong><br>التحقق من هوية المرسل</div>
              <div>🔗 <strong>الطبقة 3</strong><br>تحليل الروابط الاحتيالية</div>
            </div>
            """, unsafe_allow_html=True)

        if text_btn:
            if not sms_text.strip():
                st.warning("⚠️ من فضلك أدخل نص الرسالة أولاً.")
            else:
                with st.spinner("🤖 جاري التحليل بالذكاء الاصطناعي..."):
                    result = call_analyze_text(sms_text.strip(), sender_text.strip())

                if result:
                    st.markdown('<div class="cyber-divider"></div>', unsafe_allow_html=True)
                    st.markdown("### 📊 نتيجة التحليل")
                    render_risk_card(result)
                    col_l, col_r = st.columns(2, gap="large")
                    with col_l:
                        render_layer_breakdown(result.get("layer_results", {}))
                    with col_r:
                        render_recommendations(result.get("recommendations", []))

    # ── TAB 2: Image Analysis ─────────────────────────────────────────────
    with tab_image:
        col_upload, col_guide = st.columns([3, 1], gap="large")

        with col_upload:
            st.markdown('<div class="input-label">📸 ارفع صورة الرسالة</div>', unsafe_allow_html=True)
            uploaded_file = st.file_uploader(
                label="image_uploader",
                label_visibility="collapsed",
                type=["png", "jpg", "jpeg", "webp"],
                help="ارفع لقطة شاشة (screenshot) للرسالة المشبوهة",
                key="image_uploader",
            )

            sender_img = st.text_input(
                label="sender_img",
                label_visibility="collapsed",
                placeholder="🆔 هوية المرسل (اختياري) — كما يظهر في الصورة",
                key="sender_img_input",
            )

            if uploaded_file:
                img = Image.open(uploaded_file)
                st.image(img, caption="الصورة المرفوعة", use_column_width=True)

            img_btn = st.button("🔍 استخراج وتحليل النص", key="analyze_img_btn", use_container_width=True)

        with col_guide:
            st.markdown("""
            <div style="background:rgba(0,168,255,0.06); border:1px solid rgba(0,168,255,0.15); border-radius:14px; padding:1.25rem; font-size:0.88rem; color:#7fb3d3;">
              <div style="color:#00a8ff; font-weight:700; margin-bottom:0.75rem;">🖼️ تعليمات الصورة</div>
              <div style="margin-bottom:0.4rem;">✅ استخدم صور عالية الوضوح</div>
              <div style="margin-bottom:0.4rem;">✅ تأكد أن النص واضح ومقروء</div>
              <div style="margin-bottom:0.4rem;">✅ PNG أو JPG مدعومان</div>
              <div style="margin-bottom:0.4rem;">⏱️ قد يستغرق الاستخراج 10–30 ثانية</div>
              <div style="margin-top:0.75rem; padding-top:0.75rem; border-top:1px solid rgba(255,255,255,0.08);">
                📡 يستخدم محرك <strong>EasyOCR</strong> المدعوم للغة العربية
              </div>
            </div>
            """, unsafe_allow_html=True)

        if img_btn:
            if not uploaded_file:
                st.warning("⚠️ من فضلك ارفع صورة أولاً.")
            else:
                with st.spinner("🔡 جاري استخراج النص بـ OCR ثم التحليل..."):
                    file_bytes = uploaded_file.getvalue()
                    result = call_analyze_image(file_bytes, uploaded_file.name, sender_img.strip())

                if result:
                    st.markdown('<div class="cyber-divider"></div>', unsafe_allow_html=True)
                    if result.get("extracted_text"):
                        render_extracted_text(result["extracted_text"])
                    st.markdown("### 📊 نتيجة التحليل")
                    render_risk_card(result)
                    col_l, col_r = st.columns(2, gap="large")
                    with col_l:
                        render_layer_breakdown(result.get("layer_results", {}))
                    with col_r:
                        render_recommendations(result.get("recommendations", []))

    st.markdown('</div>', unsafe_allow_html=True)

    # ── Sample Messages (Sidebar) ─────────────────────────────────────────
    with st.sidebar:
        st.markdown("### 🧪 أمثلة للاختبار")
        st.markdown("انسخ هذه الرسائل في حقل التحليل:")

        st.markdown("**🔴 رسالة احتيالية:**")
        st.code("تم تجميد حسابك البنكي فورا اضغط هنا لاعادة التفعيل http://bit.ly/bankmisr-update", language=None)

        st.markdown("**🟠 مشبوهة - انتحال هوية:**")
        st.code("مبروك! تكسب كاش 5000 جنيه من بنك مصر اضغط الرابط الان", language=None)

        st.markdown("**✅ رسالة آمنة:**")
        st.code("رصيدك الحالي 1500 جنيه شكرا لاستخدامك خدمات بنك مصر", language=None)

        st.markdown("---")
        st.markdown("**👤 مرسلين للاختبار:**")
        st.markdown("- `+201012345678` → رقم موبايل عادي (مشبوه)")
        st.markdown("- `BankMisr` → مرسل موثق")
        st.markdown("- `WIN123` → كود مشبوه")

        st.markdown("---")
        st.caption("درع v1.0.0 · Powered by FastAPI + Streamlit")

    # ── Footer ────────────────────────────────────────────────────────────
    st.markdown("""
    <div class="deraa-footer">
      🛡️ <strong>درع (Deraa)</strong> — منصة مكافحة التصيد الاحتيالي بالذكاء الاصطناعي
      <br>مخصصة للسوق المصري · للاستخدام التعليمي والبحثي
      <br><br>
      <span style="color:#1e3a5f;">© 2025 Deraa Cybersecurity · Powered by NLP + Machine Learning</span>
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
