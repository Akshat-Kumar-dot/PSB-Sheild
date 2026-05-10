"""
ml_predictor.py
Drop this in the same folder as main.py.
It loads the trained models and exposes two functions:
    ml_predict_url(url)  → {"verdict", "riskScore", "confidence"}
    ml_predict_apk(...)  → {"verdict", "riskScore", "confidence"}
"""

import re, os
import numpy as np

# ── Load models once at startup ───────────────────────────────────────────────
_url_model = None
_url_le    = None
_apk_model = None
_apk_le    = None

def _load():
    global _url_model, _url_le, _apk_model, _apk_le
    try:
        import joblib
        _url_model = joblib.load("models/url_model.pkl")
        _url_le    = joblib.load("models/label_encoder_url.pkl")
        _apk_model = joblib.load("models/apk_model.pkl")
        _apk_le    = joblib.load("models/label_encoder_apk.pkl")
        print("✓ ML models loaded successfully")
        return True
    except Exception as e:
        print(f"WARNING: ML models not found ({e}). Run train_model.py first.")
        return False

ML_READY = _load()

OFFICIAL_DOMAINS = ["sbi.co.in", "onlinesbi.sbi", "yonobusiness.sbi", "retail.onlinesbi.sbi"]
REAL_PACKAGE     = "com.sbi.lotusintouch"
DANGEROUS_PERMS  = [
    "READ_SMS","RECEIVE_SMS","SEND_SMS","READ_CONTACTS","READ_CALL_LOG",
    "SYSTEM_ALERT_WINDOW","BIND_ACCESSIBILITY_SERVICE",
    "RECORD_AUDIO","READ_PHONE_STATE","PROCESS_OUTGOING_CALLS",
]
SUSPICIOUS_TLDS = [
    ".xyz",".tk",".top",".gq",".ml",".cf",".pw",".club",".inn",
    ".info",".biz",".work",".live",".online",".site",".website",
    ".tech",".store",".fun",".loan",".click",".download",".link",
    ".win",".party",".racing",".trade",".webcam",".science",
]


# ── Feature extractors (must match train_model.py exactly) ────────────────────

def _url_features(url: str) -> list:
    lower = url.lower()
    f1  = int(any(d in lower for d in OFFICIAL_DOMAINS))
    has_brand = any(k in lower for k in ["sbi","yono","sbionline","onlinesbi"])
    f2  = int(has_brand and not f1)
    f3  = int(any(t in lower for t in SUSPICIOUS_TLDS))
    f4  = int(any(s in lower for s in ["bit.ly","tinyurl","t.co","goo.gl","ow.ly","rb.gy","cutt.ly"]))
    f5  = int(bool(re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', lower)))
    f6  = int(".apk" in lower)
    urgency = ["urgent","expire","kyc","block","suspend","verify","immediate","otp","reward","freeze"]
    f7  = sum(1 for w in urgency if w in lower)
    try:
        dp = re.findall(r'https?://([^/]+)', lower)
        f8 = dp[0].count('.') if dp else 0
    except: f8 = 0
    f9  = int(lower.startswith("https://"))
    try:
        dp  = re.findall(r'https?://([^/]+)', lower)
        f10 = len(dp[0]) if dp else 0
    except: f10 = 0
    try:
        dp  = re.findall(r'https?://([^/]+)', lower)
        f11 = sum(c.isdigit() for c in (dp[0] if dp else ""))
    except: f11 = 0
    try:
        dp  = re.findall(r'https?://([^/]+)', lower)
        f12 = (dp[0] if dp else "").count('-')
    except: f12 = 0
    f13 = len(url)
    f14 = int("yono" in lower)
    f15 = int(f2 and "sbi" in lower)
    return [f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11,f12,f13,f14,f15]


def _apk_features(package: str, permissions: list, cert: str, embedded_urls: list) -> list:
    perms_upper = [p.upper() for p in permissions]
    f1  = int(package == REAL_PACKAGE)
    f2  = int(("sbi" in package.lower() or "yono" in package.lower()) and package != REAL_PACKAGE)
    f3  = int(any(p in perms_upper for p in ["READ_SMS","RECEIVE_SMS","SEND_SMS"]))
    f4  = int("SYSTEM_ALERT_WINDOW" in perms_upper)
    f5  = int("BIND_ACCESSIBILITY_SERVICE" in perms_upper)
    f6  = int("READ_CALL_LOG" in perms_upper or "PROCESS_OUTGOING_CALLS" in perms_upper)
    f7  = int("RECORD_AUDIO" in perms_upper)
    f8  = int("self" in cert.lower() or "missing" in cert.lower() or "unverified" in cert.lower())
    bad = [u for u in embedded_urls if not any(d in u for d in OFFICIAL_DOMAINS)]
    f9  = min(len(bad), 5)
    f10 = sum(1 for p in perms_upper if p in [d.upper() for d in DANGEROUS_PERMS])
    f11 = int("READ_CONTACTS" in perms_upper)
    f12 = int("READ_PHONE_STATE" in perms_upper)
    return [f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11,f12]


# ── Risk score from probability ───────────────────────────────────────────────
def _to_risk(verdict: str, proba: np.ndarray, classes: list) -> int:
    """Convert ML probability to 0-100 risk score."""
    class_list = list(classes)
    if verdict in ["PHISHING","FAKE_MALICIOUS"]:
        base = 70
        idx  = class_list.index(verdict) if verdict in class_list else 0
        conf = proba[idx]
        return min(100, int(base + conf * 30))
    elif verdict == "SUSPICIOUS":
        return int(35 + proba[class_list.index(verdict)] * 30) if verdict in class_list else 50
    else:
        idx = class_list.index(verdict) if verdict in class_list else 0
        return max(0, int((1 - proba[idx]) * 30))


# ── Public API ────────────────────────────────────────────────────────────────

def ml_predict_url(url: str) -> dict:
    if not ML_READY:
        return None
    feats = np.array([_url_features(url)])
    pred  = _url_le.inverse_transform(_url_model.predict(feats))[0]
    proba = _url_model.predict_proba(feats)[0]
    conf  = int(max(proba) * 100)
    risk  = _to_risk(pred, proba, _url_le.classes_)
    return {"verdict": pred, "riskScore": risk, "confidence": conf}


def ml_predict_apk(package: str, permissions: list, cert: str, embedded_urls: list) -> dict:
    if not ML_READY:
        return None
    feats = np.array([_apk_features(package, permissions, cert, embedded_urls)])
    pred  = _apk_le.inverse_transform(_apk_model.predict(feats))[0]
    proba = _apk_model.predict_proba(feats)[0]
    conf  = int(max(proba) * 100)
    risk  = _to_risk(pred, proba, _apk_le.classes_)
    return {"verdict": pred, "riskScore": risk, "confidence": conf}