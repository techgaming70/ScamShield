from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from pathlib import Path
from urllib.parse import urlparse
import re
import html

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND = BASE_DIR / "frontend"

app = FastAPI(
    title="ScamShield API",
    description="Safety-oriented scam analysis prototype",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

URL_RE = re.compile(r"""(?i)\b(?:(?:https?://)|(?:www\.))[^\s<>"']+""")

# These are intentionally explainable demo rules rather than claims of perfect detection.
RULES = [
    ("urgency", re.compile(
        r"\b(urgent|immediately|act now|last chance|within \d+ (?:minutes?|hours?)|today only|expire(?:s|d)? now)\b",
        re.I
    ), "Creates urgency or pressure to act quickly."),
    ("credential_request", re.compile(
        r"\b(otp|one[- ]time password|password|pin|cvv|card number|upi pin|verification code)\b",
        re.I
    ), "Requests credentials or authentication information."),
    ("payment_request", re.compile(
        r"(?:pay|send|transfer|deposit|fee|processing charge|registration fee).{0,60}(?:₹|\brs\.?|\binr\b|\bmoney\b|\bpayment\b)",
        re.I
    ), "Pushes for a payment or transfer."),
    ("guaranteed_return", re.compile(
        r"\b(guaranteed|sure profit|fixed return|risk[- ]free|double your money|100% return)\b",
        re.I
    ), "Uses unusually certain or guaranteed financial-return language."),
    ("impersonation", re.compile(
        r"\b(bank|rbi|sebi|police|income tax|government|official|support team|customer care)\b.{0,50}\b(verify|click|pay|share|send)\b",
        re.I
    ), "Combines an official-looking identity with a request for action."),
    ("remote_access", re.compile(
        r"\b(anydesk|teamviewer|remote access|screen share|remote desktop)\b",
        re.I
    ), "Requests remote access or screen sharing."),
    ("suspicious_link", re.compile(
        r"\b(?:https?://|www\.)[^\s]+",
        re.I
    ), "Contains a link that should be independently verified before opening."),
]

TRANSLATIONS = {
    "en": {
        "high": "High risk",
        "medium": "Needs caution",
        "low": "Lower apparent risk",
        "unknown": "Unable to determine",
    },
    "hi": {
        "high": "उच्च जोखिम",
        "medium": "सावधानी आवश्यक",
        "low": "कम स्पष्ट जोखिम",
        "unknown": "निर्धारित नहीं किया जा सका",
    },
    "bn": {
        "high": "উচ্চ ঝুঁকি",
        "medium": "সতর্কতা প্রয়োজন",
        "low": "কম দৃশ্যমান ঝুঁকি",
        "unknown": "নির্ধারণ করা যায়নি",
    },
    "ta": {
        "high": "அதிக ஆபத்து",
        "medium": "எச்சரிக்கை தேவை",
        "low": "குறைந்த வெளிப்படையான ஆபத்து",
        "unknown": "தீர்மானிக்க முடியவில்லை",
    },
    "te": {
        "high": "அதிக ஆபத்து",
        "medium": "எச்சரிக்கை தேவை",
        "low": "குறைந்த வெளிப்படையான ஆபத்து",
        "unknown": "தீர்மானிக்க முடியவில்லை",
    },
    "mr": {
        "high": "उच्च धोका",
        "medium": "सावधगिरी आवश्यक",
        "low": "कमी स्पष्ट धोका",
        "unknown": "ठरवता आले नाही",
    },
}

class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000)
    language: str = "en"

class URLRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)
    language: str = "en"

def redact_sensitive(text: str) -> str:
    patterns = [
        (r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", "[REDACTED CARD NUMBER]"),
        (r"\b\d{6}\b", "[REDACTED OTP/PIN]"),
        (r"(?i)\b(?:otp|one[- ]time password|verification code)\s*[:\-]?\s*\d{4,8}\b",
         "[REDACTED OTP]"),
        (r"(?i)\b(?:cvv|cvc)\s*[:\-]?\s*\d{3,4}\b", "[REDACTED CVV]"),
        (r"(?i)\b(?:upi pin|pin)\s*[:\-]?\s*\d{4,6}\b", "[REDACTED PIN]"),
    ]
    result = text
    for pattern, replacement in patterns:
        result = re.sub(pattern, replacement, result)
    return result

def extract_urls(text: str):
    return [u.rstrip(".,);]}>") for u in URL_RE.findall(text)]

def safe_url_check(raw_url: str):
    candidate = raw_url.strip()
    if not re.match(r"^[a-z]+://", candidate, re.I):
        candidate = "http://" + candidate

    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
    except Exception:
        return {
            "url": raw_url,
            "valid": False,
            "flags": ["The URL could not be parsed safely."],
            "domain": "",
        }

    flags = []
    if parsed.scheme != "https":
        flags.append("The link does not use HTTPS.")

    if "@" in parsed.netloc:
        flags.append("The URL contains an @ symbol, which can hide the actual destination.")

    if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        flags.append("The hostname is an IP address rather than a normal domain.")

    suspicious_words = [
        "verify", "secure-login", "account-check", "kyc", "wallet",
        "refund", "bonus", "claim", "support", "update-password"
    ]
    hits = [w for w in suspicious_words if w in host or w in parsed.path.lower()]
    if hits:
        flags.append("The URL contains pressure/account-themed words: " + ", ".join(hits) + ".")

    # Punycode is not automatically malicious, but deserves caution.
    if host.startswith("xn--") or ".xn--" in host:
        flags.append("The domain uses internationalized/punycode notation; verify it carefully.")

    if len(host) > 45:
        flags.append("The hostname is unusually long.")

    return {
        "url": raw_url,
        "valid": bool(host),
        "domain": host,
        "flags": flags,
    }

def analyze_text(text: str, language: str = "en"):
    safe_text = redact_sensitive(text)
    flags = []
    evidence = []

    for name, pattern, explanation in RULES:
        matches = list(pattern.finditer(text))
        if matches:
            flags.append(name)
            snippets = []
            for m in matches[:2]:
                start = max(0, m.start() - 35)
                end = min(len(text), m.end() + 35)
                snippets.append(text[start:end].strip())
            evidence.append({
                "rule": name,
                "explanation": explanation,
                "snippets": snippets
            })

    urls = extract_urls(text)
    url_results = [safe_url_check(u) for u in urls]
    for result in url_results:
        if result["flags"]:
            if "suspicious_link" not in flags:
                flags.append("suspicious_link")
            for flag in result["flags"]:
                evidence.append({
                    "rule": "url_check",
                    "explanation": flag,
                    "snippets": [result["url"]]
                })

    # Explainable score, not a probability.
    weights = {
        "urgency": 18,
        "credential_request": 28,
        "payment_request": 22,
        "guaranteed_return": 25,
        "impersonation": 18,
        "remote_access": 24,
        "suspicious_link": 12,
    }
    raw_score = min(100, sum(weights.get(f, 8) for f in set(flags)))

    if raw_score >= 60:
        level = "high"
    elif raw_score >= 30:
        level = "medium"
    elif raw_score > 0:
        level = "low"
    else:
        level = "unknown"

    # Confidence reflects rule coverage, not truth probability.
    if not flags:
        confidence = 35
    else:
        confidence = min(92, 45 + len(set(flags)) * 8)

    safe_steps = [
        "Pause before clicking, paying, or sharing information.",
        "Verify the claim through the organisation's official app, website, or phone number.",
        "Do not share OTPs, PINs, passwords, CVV, or remote access.",
        "If money has already been sent, contact the relevant bank/payment provider through its official channel.",
        "Report the incident through an appropriate official fraud-reporting channel.",
    ]

    labels = TRANSLATIONS.get(language, TRANSLATIONS["en"])

    return {
        "risk_level": level,
        "risk_label": labels[level],
        "score": raw_score,
        "confidence": confidence,
        "flags": list(dict.fromkeys(flags)),
        "evidence": evidence,
        "redacted_text": safe_text,
        "urls": url_results,
        "safe_steps": safe_steps,
        "disclaimer": "Prototype safety analysis only. This is not investment advice and does not guarantee that a message is safe or fraudulent.",
    }

@app.get("/")
async def home():
    return FileResponse(FRONTEND / "index.html")

@app.get("/app.js")
async def app_js():
    return FileResponse(FRONTEND / "app.js", media_type="application/javascript")

@app.get("/style.css")
async def style_css():
    return FileResponse(FRONTEND / "style.css", media_type="text/css")

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "ScamShield"}

@app.post("/api/analyze")
async def analyze(request: AnalyzeRequest):
    return analyze_text(request.text, request.language)

@app.post("/api/check-url")
async def check_url(request: URLRequest):
    result = safe_url_check(request.url)
    return {
        "result": result,
        "risk_level": "medium" if result["flags"] else "low",
        "disclaimer": "This checker does not open the URL. It only inspects the URL string.",
    }

@app.post("/api/ocr")
async def ocr_info(file: UploadFile = File(...)):
    # OCR is performed client-side with Tesseract.js in this MVP.
    # This endpoint exists so a future server-side OCR engine can be plugged in.
    data = await file.read()
    return {
        "filename": file.filename,
        "received_bytes": len(data),
        "message": "For this MVP, run OCR in the browser and send extracted text to /api/analyze.",
    }
