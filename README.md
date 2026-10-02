# ScamShield — Pause Before the Damage

A hackathon-ready MVP based on the submitted ScamShield concept.

## Features

- Analyze suspicious text/messages
- Extract and inspect URLs without opening them
- Screenshot OCR using Tesseract.js in the browser
- Browser voice input using Web Speech API
- Hindi/English + several regional-language UI/output options
- Rule-based scam red-flag engine
- Risk level + confidence
- Evidence-based explanation
- OTP/account/card/UPI masking
- Safe verification checklist
- Incident report export
- No investment recommendations or price predictions
- Lightweight FastAPI backend

## Project structure

```text
ScamShield/
├── backend/
│   └── main.py
├── frontend/
│   ├── index.html
│   ├── app.js
│   └── style.css
├── requirements.txt
├── .gitignore
└── README.md
```

## Run locally

### 1. Install Python 3.10+

```bash
python -m venv .venv
```

Windows:

```bash
.venv\Scripts\activate
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

### 2. Start the server

From the ScamShield folder:

```bash
uvicorn backend.main:app --reload
```

Open:

http://127.0.0.1:8000

## Important demo note

This is a prototype safety classifier, not a financial-advice system and not a replacement for official fraud authorities or banks.

The URL checker intentionally does not visit suspicious URLs. It performs safe string/domain checks only.

For screenshot OCR, the browser loads Tesseract.js from its CDN. For an offline deployment, download/vendor Tesseract.js locally.

## Suggested demo

Paste:

> URGENT! Your KYC will expire today. Click http://example-login-verify.com immediately and pay ₹10 to avoid account suspension. Share OTP after payment.

The system should identify urgency, suspicious URL characteristics, payment pressure and OTP requests, mask sensitive information, and recommend independent verification.

## Production upgrades

- Replace demo heuristics with validated classifiers
- Integrate an approved URL reputation provider
- Add server-side OCR/speech processing where legally appropriate
- Add authentication and rate limiting
- Encrypt sensitive data
- Add human-review workflow
- Add multilingual evaluation datasets
- Add audit logging with data minimization
