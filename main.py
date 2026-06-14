"""
Deraa (درع) - AI-Driven Egyptian Dialect SMS Phishing Detection System
FastAPI Backend: Multi-layered AI analysis pipeline

Architecture:
  Layer 1: NLP Intent & Context Classifier (TF-IDF + Logistic Regression)
  Layer 2: Entity & Sender Verification Engine
  Layer 3: Heuristic & Live URL Risk Analyzer
  OCR Pipeline: EasyOCR for Arabic text extraction from images
"""
import builtins
builtins.corrupt_msg = "Warning: Corrupt model file detected or download interrupted."

import ssl
ssl._create_default_https_context = ssl._create_unverified_context
import re
import io
import math
import base64
import logging
from typing import Optional
from datetime import datetime

import numpy as np
import easyocr
import requests  # تم التأكد من استيراد مكتبة الفحص الحي هنا
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from PIL import Image

# Scikit-learn NLP components
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder

# ─────────────────────────────────────────────
# Logging Configuration
# ─────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("deraa")

# ─────────────────────────────────────────────
# App Initialization
# ─────────────────────────────────────────────
app = FastAPI(
    title="Deraa (درع) - Phishing Detection API",
    description="AI-powered Egyptian dialect SMS phishing detection engine",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
# LAYER 1: NLP TRAINING DATA
# Egyptian dialect phishing vs. legitimate SMS examples
# ─────────────────────────────────────────────
TRAINING_CORPUS = [
    # ── PHISHING SAMPLES (label=1) ──────────────────────────────────────────
    ("تم تجميد حسابك البنكي فورا اضغط هنا لاعادة التفعيل", 1),
    ("مبروك! تكسب كاش 5000 جنيه اضغط الرابط دلوقتي", 1),
    ("حسابك في خطر قم بتحديث بياناتك الان او سيتم الغاء الخدمة", 1),
    ("بنك مصر يطلب منك تاكيد هويتك بسبب نشاط مريب على حسابك", 1),
    ("انت الفائز بجائزة فودافون المليون اتصل بنا فورا", 1),
    ("تم اختيارك للحصول على قرض شخصي بدون فوائد اضغط هنا", 1),
    ("تنبيه امني من البنك الاهلي بياناتك مسربة غير بياناتك الان", 1),
    ("مبروك ربحت شنطة سفر مجانية لشرم الشيخ سجل الان", 1),
    ("حسابك فيه مشكله لازم تتحقق منها دلوقتي عشان متتعاقبش", 1),
    ("عرض خاص لعملاء فودافون احصل على 10 جيجا مجانا اضغط الرابط", 1),
    ("تحذير هام تم رصد محاولات دخول على حسابك غير بياناتك الان", 1),
    ("انتهى صلاحية بطاقتك الائتمانية جدد الان لتجنب الايقاف", 1),
    ("اثبت هويتك لتجنب تعليق الحساب ارسل صورة بطاقتك", 1),
    ("انت محظوظ اتضمنت في سحب كاش بنك QNB سجل هنا", 1),
    ("مطلوب منك الدخول لتاكيد بياناتك البنكية خلال 24 ساعه", 1),
    ("خدمة الانترنت هتتقطع لو معملتش التحديث المطلوب دلوقتي", 1),
    ("النظام رصد معاملة مشبوهة من حسابك برجاء الدخول فورا", 1),
    ("اكاديمية فودافون بتكسب 2000 كل اسبوع سجل بياناتك دلوقتي", 1),

    # ── LEGITIMATE SAMPLES (label=0) ────────────────────────────────────────
    ("رصيدك الحالي 1500 جنيه شكرا لاستخدامك خدمات بنك مصر", 0),
    ("تم تحويل مبلغ 200 جنيه من حسابك بنجاح", 0),
    ("موعدك مع الدكتور غدا الساعة 3 عصرا في عيادة النيل", 0),
    ("كودك للدخول هو 4829 لا تشاركه مع احد", 0),
    ("تم تفعيل باقة الانترنت بنجاح باقيها 30 يوم", 0),
    ("شكرا لدفع فاتورة الكهرباء المبلغ 350 جنيه تم الدفع بنجاح", 0),
    ("تم استلام طلبك رقم 78432 وسيتم التوصيل خلال يومين", 0),
    ("رصيدك الحالي في الخط 15 جنيه لتجديد الباقة اتصل 888", 0),
    ("تذكير موعد صيانة العداد غدا من 9 صباحا لـ 12 ظهرا", 0),
    ("باقتك انتهت يمكنك التجديد عن طريق تطبيق المصرف او الفروع", 0),
    ("تم تسجيل شكواك برقم 445521 سيتم الرد خلال 48 ساعة", 0),
    ("رسالة من جهاز الكمبيوتر تم اتمام عملية النسخ الاحتياطي", 0),
    ("تم الرد على استفسارك يرجى مراجعة البريد الالكتروني", 0),
    ("يسعدنا خدمتك في بنك القاهرة للاستفسار اتصل 19666", 0),
    ("تم تحديث بياناتك بنجاح شكرا لاستخدامك خدماتنا", 0),
    ("تم استلام دفعتك بقيمة 500 جنيه الرقم المرجعي 998812", 0),
]

# ─────────────────────────────────────────────
# LAYER 1: ML MODEL TRAINING
# ─────────────────────────────────────────────
def build_nlp_model() -> Pipeline:
    texts, labels = zip(*TRAINING_CORPUS)

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(2, 5),
            max_features=8000,
            sublinear_tf=True,
            strip_accents=None,
            min_df=1,
        )),
        ("clf", LogisticRegression(
            C=2.0,
            max_iter=1000,
            class_weight="balanced",
            solver="lbfgs",
        )),
    ])

    pipeline.fit(list(texts), list(labels))
    logger.info("NLP intent model trained on %d samples.", len(texts))
    return pipeline

NLP_MODEL = build_nlp_model()

# ─────────────────────────────────────────────
# LAYER 2: ENTITY & SENDER VERIFICATION DATA
# ─────────────────────────────────────────────
TRUSTED_ENTITY_SENDERS = {
    "بنك مصر": ["BankMisr", "Bank-Misr", "BANQUE-MISR"],
    "البنك الاهلي": ["NBE", "Ahly-Bank", "NBEGYPT"],
    "البنك الاهلي المصري": ["NBE", "Ahly-Bank", "NBEGYPT"],
    "بنك القاهرة": ["BankCairo", "BANQUE-CAIRO"],
    "بنك cib": ["CIB", "CIB-Egypt"],
    "cib": ["CIB", "CIB-Egypt"],
    "فودافون": ["Vodafone", "VF-Egypt", "VODAFONE"],
    "اتصالات": ["Etisalat", "Etisalat-EG"],
    "we": ["TEDATA", "WE-Telecom"],
    "اورنج": ["Orange", "ORANGE-EG"],
    "بنك قطر الوطني": ["QNB", "QNBALAHLI"],
    "qnb": ["QNB", "QNBALAHLI"],
    "فوري": ["Fawry", "FAWRY"],
    "الضرائب": ["TAX-EG", "ETA-EGYPT"],
    "المرور": ["MOROUR", "POLICE-EG"],
    "الشهر العقاري": ["NSER-EG"],
}

MOBILE_NUMBER_PATTERNS = [
    r"^01[0125]\d{8}$",
    r"^\+2001[0125]\d{8}$",
    r"^002001[0125]\d{8}$",
    r"^\d{10,15}$",
]

SUSPICIOUS_SENDER_PATTERNS = [
    r"^[A-Z]{2,6}\d{3,}$",
    r"^\d{5,6}$",
]

# ─────────────────────────────────────────────
# LAYER 3: URL HEURISTIC ANALYZER DATA
# ─────────────────────────────────────────────
SAFE_EGYPTIAN_DOMAINS = {
    "banquemisr.com", "nbe.com.eg", "cibeg.com", "qnbalahli.com",
    "bankcairo.com.eg", "fawry.com", "vodafone.com.eg", "orange.eg",
    "etisalat.eg", "we.eg", "amazon.eg", "jumia.com.eg", "talabat.com",
    "gov.eg", "mof.gov.eg", "finance.gov.eg", "police.gov.eg",
}

TYPOSQUAT_PATTERNS = [
    r"bankm[il1]sr", r"nbe-eg", r"c[il1]b-eg", r"vodaf[0o]ne",
    r"fawryy", r"bank-[a-z]+-eg", r"secure.*login", r"update.*account",
    r"verify.*bank", r"account.*suspend", r"confirm.*identity",
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "rb.gy", "cutt.ly", "is.gd", "buff.ly", "short.io",
}

# ─────────────────────────────────────────────
# OCR ENGINE INITIALIZATION
# ─────────────────────────────────────────────
logger.info("Initializing EasyOCR reader for Arabic + English...")
OCR_READER = easyocr.Reader(["ar", "en"], gpu=False, verbose=False)
logger.info("EasyOCR ready.")

# ─────────────────────────────────────────────
# PYDANTIC MODELS
# ─────────────────────────────────────────────
class TextAnalysisRequest(BaseModel):
    text: str
    sender: Optional[str] = None

class LayerResult(BaseModel):
    score: float
    flags: list[str]
    details: dict

class AnalysisResponse(BaseModel):
    risk_score: float
    risk_level: str
    verdict: str
    extracted_text: Optional[str]
    layer_results: dict[str, LayerResult]
    recommendations: list[str]
    analysis_timestamp: str

# ─────────────────────────────────────────────
# UTILITY FUNCTIONS
# ─────────────────────────────────────────────
def extract_urls(text: str) -> list[str]:
    url_pattern = re.compile(
        r"(?:https?://|www\.)[^\s\u0600-\u06FF،؟!،\.\s]{3,}|"
        r"[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,6}(?:/[^\s]*)?",
        re.IGNORECASE,
    )
    return url_pattern.findall(text)

def normalize_arabic(text: str) -> str:
    text = re.sub(r"[\u064B-\u065F\u0670]", "", text)
    text = re.sub(r"[إأآا]", "ا", text)
    text = re.sub(r"\u0640", "", text)
    text = re.sub(r"ة", "ه", text)
    return text.strip()

def get_domain_from_url(url: str) -> str:
    url = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    url = re.sub(r"^www\.", "", url, flags=re.IGNORECASE)
    return url.split("/")[0].lower()

# ─────────────────────────────────────────────
# LAYER 1: NLP INTENT ANALYSIS
# ─────────────────────────────────────────────
def analyze_intent_layer(text: str) -> LayerResult:
    normalized = normalize_arabic(text)
    flags = []
    details = {}

    ml_proba = NLP_MODEL.predict_proba([normalized])[0]
    phishing_proba = float(ml_proba[1])
    details["ml_phishing_probability"] = round(phishing_proba, 4)

    URGENCY_TRIGGERS = ["فورا", "دلوقتي", "الان", "عاجل", "خلال 24", "خلال ساعة", "قبل", "لازم", "هتتعطل", "هتتقطع", "سيتم الغاء"]
    FEAR_TRIGGERS = ["تم تجميد", "في خطر", "مشبوه", "مريب", "تعليق", "ايقاف", "تحذير", "تنبيه", "مسرب", "سيتم الحذف", "تم اختراق"]
    REWARD_TRIGGERS = ["مبروك", "فزت", "فائز", "جائزة", "كاش", "هدية", "مجانا", "ربحت", "اتضمنت", "تكسب", "بدون فوائد", "قرض فوري"]
    CREDENTIAL_TRIGGERS = ["ارسل بطاقتك", "صورة الهوية", "رقم الحساب", "cvv", "الرقم السري", "pin", "كلمة السر", "باسورد", "بياناتك"]

    urgency_hits = [w for w in URGENCY_TRIGGERS if w in normalized]
    fear_hits = [w for w in FEAR_TRIGGERS if w in normalized]
    reward_hits = [w for w in REWARD_TRIGGERS if w in normalized]
    credential_hits = [w for w in CREDENTIAL_TRIGGERS if w in normalized]

    details["urgency_keywords"] = urgency_hits
    details["fear_keywords"] = fear_hits
    details["reward_keywords"] = reward_hits
    details["credential_keywords"] = credential_hits

    if urgency_hits:
        flags.append(f"🚨 أسلوب الاستعجال والضغط: {', '.join(urgency_hits)}")
    if fear_hits:
        flags.append(f"😨 أسلوب الترهيب والتخويف: {', '.join(fear_hits)}")
    if reward_hits:
        flags.append(f"🎁 وعود وهمية بمكافآت أو جوائز: {', '.join(reward_hits)}")
    if credential_hits:
        flags.append(f"🔐 طلب بيانات حساسة أو شخصية: {', '.join(credential_hits)}")

    rule_score = min((len(urgency_hits) * 0.15) + (len(fear_hits) * 0.2) + (len(reward_hits) * 0.15) + (len(credential_hits) * 0.25), 1.0)
    blended_score = (phishing_proba * 0.6) + (rule_score * 0.4)
    details["rule_based_score"] = round(rule_score, 4)
    details["blended_score"] = round(blended_score, 4)

    return LayerResult(score=blended_score, flags=flags, details=details)

# ─────────────────────────────────────────────
# LAYER 2: ENTITY & SENDER VERIFICATION
# ─────────────────────────────────────────────
def analyze_sender_layer(text: str, sender: Optional[str]) -> LayerResult:
    normalized = normalize_arabic(text.lower())
    flags = []
    details = {"sender": sender or "لم يُحدد", "claimed_entities": []}
    score = 0.0

    claimed_entities = []
    for entity_name, verified_senders in TRUSTED_ENTITY_SENDERS.items():
        if entity_name in normalized:
            claimed_entities.append({"entity": entity_name, "verified_senders": verified_senders})

    details["claimed_entities"] = [e["entity"] for e in claimed_entities]

    if claimed_entities and sender:
        sender_clean = sender.strip()
        for entity_info in claimed_entities:
            entity_name = entity_info["entity"]
            verified = entity_info["verified_senders"]

            sender_is_verified = any(v.lower() == sender_clean.lower() for v in verified)

            if sender_is_verified:
                flags.append(f"✅ المرسل '{sender_clean}' موثق لـ {entity_name}")
                score = max(score - 0.1, 0.0)
            else:
                is_mobile = any(re.match(p, sender_clean) for p in MOBILE_NUMBER_PATTERNS)
                is_suspicious_code = any(re.match(p, sender_clean) for p in SUSPICIOUS_SENDER_PATTERNS)

                if is_mobile:
                    flags.append(f"🚩 '{entity_name}' ادعاء من رقم موبايل عادي '{sender_clean}' — مشبوه جداً")
                    score += 0.75
                elif is_suspicious_code:
                    flags.append(f"⚠️ '{entity_name}' ادعاء من كود مرسل مجهول '{sender_clean}'")
                    score += 0.45
                else:
                    flags.append(f"⚠️ المرسل '{sender_clean}' غير مدرج في قائمة المرسلين المعتمدين لـ {entity_name}")
                    score += 0.35

    elif claimed_entities and not sender:
        entity_names = [e["entity"] for e in claimed_entities]
        flags.append(f"❓ الرسالة تدّعي أنها من {', '.join(entity_names)} لكن لم يُحدد المرسل")
        score += 0.2

    elif sender:
        is_mobile = any(re.match(p, sender.strip()) for p in MOBILE_NUMBER_PATTERNS)
        if is_mobile:
            flags.append(f"📱 الرسالة مرسلة من رقم موبايل مباشر '{sender}' (غير معهود للرسائل الرسمية)")
            score += 0.2

    details["sender_risk_score"] = round(min(score, 1.0), 4)
    return LayerResult(score=min(score, 1.0), flags=flags, details=details)


# ─────────────────────────────────────────────
# LAYER 3: URL HEURISTIC & LIVE ANALYZER (تمت إضافة الفحص الحي هنا)
# ─────────────────────────────────────────────
def verify_url_live(url: str) -> tuple[bool, str]:
    """
    يقوم بعمل فحص حي للرابط في الخلفية للتأكد من وجوده ونشاطه وسيرفره.
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
        
    try:
        # كود فحص سريع للـ Headers فقط لتوفير الوقت والباقة
        response = requests.head(url, timeout=3, allow_redirects=True)
        if 200 <= response.status_code < 400:
            return True, f"Status Code: {response.status_code}"
        else:
            return False, f"كود استجابة مشبوه أو خطأ ({response.status_code})"
    except requests.exceptions.ConnectionError:
        return False, "الدومين وهمي أو السيرفر غير موجود تماماً (Connection Error)"
    except requests.exceptions.Timeout:
        return False, "انتهت مهلة الاتصال - السيرفر لا يستجيب (Timeout)"
    except requests.exceptions.RequestException as e:
        return False, f"فشل الاتصال: {str(e)}"


def analyze_url_layer(text: str) -> LayerResult:
    urls = extract_urls(text)
    flags = []
    details = {"urls_found": urls, "url_scores": {}}
    total_url_score = 0.0

    if not urls:
        details["note"] = "لا توجد روابط في الرسالة"
        return LayerResult(score=0.0, flags=flags, details=details)

    for url in urls:
        domain = get_domain_from_url(url)
        url_score = 0.0
        url_flags = []

        # 1️⃣ الفحص الحي للرابط أولاً للتصدي للروابط الوهمية والميتة
        is_live, live_reason = verify_url_live(url)
        
        if not is_live:
            url_flags.append(f"🚨 رابط وهمي أو ميت وغير موجود فعلياً: {live_reason}")
            url_score += 1.0  # إعطاء أعلى درجة خطورة فوراً
        else:
            # 2️⃣ لو الرابط شغال، يكمل الفحص التحليلي للهيكل والدومين كالمعتاد
            if any(safe in domain for safe in SAFE_EGYPTIAN_DOMAINS):
                url_flags.append("✅ نطاق موثوق")
                url_score -= 0.2
            else:
                url_score += 0.3
                url_flags.append("❓ نطاق غير معروف")

            if any(shortener in domain for shortener in SHORTENER_DOMAINS):
                url_flags.append("🔗 رابط مختصر — يخفي الوجهة الحقيقية")
                url_score += 0.5

            for pattern in TYPOSQUAT_PATTERNS:
                if re.search(pattern, domain, re.IGNORECASE):
                    url_flags.append("🎭 نمط انتحال هوية: يشبه نطاقات البنوك/الاتصالات")
                    url_score += 0.6
                    break

            if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
                url_flags.append("🖥️ رابط يستخدم عنوان IP مباشر — مشبوه جداً")
                url_score += 0.7

            subdomain_count = domain.count(".")
            if subdomain_count >= 3:
                url_flags.append(f"🌐 نطاق فرعي مشبوه ({subdomain_count} مستويات)")
                url_score += 0.3

            if url.startswith("http://"):
                url_flags.append("🔓 رابط غير مشفر (HTTP وليس HTTPS)")
                url_score += 0.25

        url_score = max(0.0, min(url_score, 1.0))
        details["url_scores"][url[:50]] = {
            "domain": domain,
            "score": round(url_score, 3),
            "flags": url_flags,
            "is_live": is_live,
            "live_reason": live_reason
        }

        if url_score > 0.3:
            flags.append(f"🔴 رابط مشبوه [{domain}]: {'; '.join(url_flags)}")
        elif url_flags:
            flags.append(f"🟡 رابط يستدعي المراجعة [{domain}]: {'; '.join(url_flags)}")

        total_url_score = max(total_url_score, url_score)

    return LayerResult(score=total_url_score, flags=flags, details=details)

# ─────────────────────────────────────────────
# SCORE AGGREGATION & RISK LABELING
# ─────────────────────────────────────────────
def compute_final_risk(layer1: LayerResult, layer2: LayerResult, layer3: LayerResult) -> tuple[float, str, str]:
    WEIGHT_INTENT = 0.50
    WEIGHT_SENDER = 0.30
    WEIGHT_URL    = 0.20

    raw = (layer1.score * WEIGHT_INTENT + layer2.score * WEIGHT_SENDER + layer3.score * WEIGHT_URL)
    amplified = 1 / (1 + math.exp(-10 * (raw - 0.4)))
    final_score = round(amplified * 100, 1)

    if final_score < 20:
        level, verdict = "SAFE", "✅ الرسالة آمنة — لم يتم رصد أي مؤشرات احتيال"
    elif final_score < 40:
        level, verdict = "LOW", "🟡 خطر منخفض — يُنصح بالتحقق من المرسل قبل الرد"
    elif final_score < 60:
        level, verdict = "MEDIUM", "🟠 خطر متوسط — توجد مؤشرات مثيرة للقلق تستدعي الحذر"
    elif final_score < 80:
        level, verdict = "HIGH", "🔴 خطر عالٍ — الرسالة تحتوي على أنماط احتيالية واضحة"
    else:
        level, verdict = "CRITICAL", "🚨 خطر حرج — رسالة تصيد احتيالي بدرجة عالية من اليقين"

    return final_score, level, verdict


def generate_recommendations(risk_level: str, layer1: LayerResult, layer2: LayerResult, layer3: LayerResult) -> list[str]:
    recs = []
    if risk_level in ("HIGH", "CRITICAL"):
        recs.append("🚫 لا تضغط على أي روابط في هذه الرسالة تحت أي ظرف")
        recs.append("🗑️ احذف الرسالة فوراً ولا ترد عليها")
        recs.append("📞 إذا كانت تدّعي أنها من بنكك، اتصل بالبنك مباشرة على الرقم الرسمي المطبوع على البطاقة")
        recs.append("🚔 أبلغ عن الرسالة لمركز شرطة الإنترنت المصري (CERT-EG)")

    if risk_level == "MEDIUM":
        recs.append("⚠️ لا ترسل أي بيانات شخصية أو مصرفية استجابةً لهذه الرسالة")
        recs.append("🔍 تحقق من هوية المرسل عبر القناة الرسمية قبل اتخاذ أي إجراء")

    if layer3.score > 0.3 and layer3.details.get("urls_found"):
        recs.append("🔗 لا تفتح الروابط المرفقة — يمكن التحقق منها عبر VirusTotal.com")

    if layer2.score > 0.5:
        recs.append("🏦 البنوك الحقيقية لا ترسل رسائل SMS تطلب فيها بيانات الحساب أو الرقم السري")

    if layer1.details.get("credential_keywords"):
        recs.append("🔐 لا تشارك أرقام البطاقات أو رمز CVV أو الرقم السري مع أي جهة عبر الرسائل")

    if risk_level in ("SAFE", "LOW"):
        recs.append("✅ الرسالة تبدو آمنة، لكن تحلَّ دائمًا بالحذر مع أي رسائل تطلب بيانات شخصية")

    return recs

# ─────────────────────────────────────────────
# CORE ANALYSIS ORCHESTRATOR
# ─────────────────────────────────────────────
def run_full_analysis(text: str, sender: Optional[str], extracted_text: Optional[str] = None) -> AnalysisResponse:
    logger.info("Running analysis | sender=%s | text_length=%d", sender, len(text))

    layer1 = analyze_intent_layer(text)
    layer2 = analyze_sender_layer(text, sender)
    layer3 = analyze_url_layer(text)

    final_score, risk_level, verdict = compute_final_risk(layer1, layer2, layer3)
    recommendations = generate_recommendations(risk_level, layer1, layer2, layer3)

    return AnalysisResponse(
        risk_score=final_score,
        risk_level=risk_level,
        verdict=verdict,
        extracted_text=extracted_text,
        layer_results={
            "intent_analysis": layer1,
            "sender_verification": layer2,
            "url_analysis": layer3,
        },
        recommendations=recommendations,
        analysis_timestamp=datetime.utcnow().isoformat() + "Z",
    )

# ─────────────────────────────────────────────
# API ENDPOINTS
# ─────────────────────────────────────────────
@app.get("/", tags=["Health"])
async def root():
    return {
        "service": "Deraa (درع) Phishing Detection API",
        "version": "1.0.0",
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

@app.post("/analyze-text", response_model=AnalysisResponse, tags=["Analysis"])
async def analyze_text(request: TextAnalysisRequest):
    if not request.text or len(request.text.strip()) < 5:
        raise HTTPException(status_code=400, detail="النص قصير جداً أو فارغ")
    return run_full_analysis(text=request.text.strip(), sender=request.sender)

@app.post("/analyze-image", response_model=AnalysisResponse, tags=["Analysis"])
async def analyze_image(file: UploadFile = File(...), sender: Optional[str] = None):
    allowed_types = {"image/png", "image/jpeg", "image/jpg", "image/webp"}
    if file.content_type not in allowed_types:
        raise HTTPException(status_code=415, detail=f"نوع الملف غير مدعوم. المدعوم: {', '.join(allowed_types)}")

    try:
        contents = await file.read()
        image = Image.open(io.BytesIO(contents)).convert("RGB")
        img_array = np.array(image)
    except Exception as e:
        logger.error("Image loading failed: %s", e)
        raise HTTPException(status_code=422, detail="فشل في قراءة الصورة. تأكد من صحة الملف.")

    try:
        logger.info("Running OCR on uploaded image (%dx%d)", image.width, image.height)
        ocr_results = OCR_READER.readtext(img_array, detail=0, paragraph=True, text_threshold=0.6)
        extracted_text = " ".join(ocr_results).strip()
        logger.info("OCR extracted %d characters", len(extracted_text))
    except Exception as e:
        logger.error("OCR failed: %s", e)
        raise HTTPException(status_code=500, detail="فشل استخراج النص من الصورة.")

    if not extracted_text:
        raise HTTPException(status_code=422, detail="لم يتمكن النظام من استخراج أي نص من الصورة. تأكد من وضوح الصورة.")

    return run_full_analysis(text=extracted_text, sender=sender, extracted_text=extracted_text)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)