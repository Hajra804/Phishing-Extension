"""
app.py — PhishGuard Flask API
==============================
REST API that receives email text and returns ML-based phishing predictions.

Endpoints:
    POST /predict   — Classify an email
    GET  /health    — Health check
    GET  /stats     — Prediction statistics

Usage:
    python train_model.py   # train & save model first
    python app.py           # start the API on port 5000
"""

import pickle
import re
import os
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=["*"])  # allow browser extension calls

# ─── Load model ───────────────────────────────────────────────
MODEL_PATH = "phishguard_model.pkl"

def load_model():
    if not os.path.exists(MODEL_PATH):
        print(f"[ERROR] Model not found at {MODEL_PATH}")
        print("[INFO]  Run: python train_model.py")
        return None
    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)

model = load_model()

# ─── Stats tracker ────────────────────────────────────────────
stats = {"total": 0, "phishing": 0, "safe": 0}

# ─── Suspicious indicators ────────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "suspend", "login", "click here", "confirm",
    "account", "password", "limited", "expire", "winner",
    "congratulations", "prize", "free", "action required",
    "immediately", "warning", "alert", "update your", "wire transfer",
    "lottery", "claim", "selected", "approved", "irs",
]

SUSPICIOUS_TLDS = ['.tk', '.ml', '.xyz', '.info', '.click', '.work', '.top', '.gq', '.cf']

def extract_risk_factors(subject: str, body: str) -> list:
    """Extract human-readable risk factors from email content."""
    text = f"{subject} {body}".lower()
    factors = []

    # URLs
    urls = re.findall(r'https?://\S+', text, re.IGNORECASE)
    if urls:
        factors.append({
            "icon": "🔗",
            "label": f"Contains {len(urls)} URL(s)",
            "value": "HIGH" if len(urls) > 2 else "MED",
            "severity": "high" if len(urls) > 2 else "medium",
        })

    # Suspicious TLD
    if any(tld in text for tld in SUSPICIOUS_TLDS):
        factors.append({
            "icon": "⚠️",
            "label": "Suspicious domain extension (.tk, .xyz…)",
            "value": "HIGH",
            "severity": "high",
        })

    # Keyword count
    kw_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in text)
    if kw_count > 0:
        severity = "high" if kw_count >= 4 else "medium" if kw_count >= 2 else "low"
        factors.append({
            "icon": "🔍",
            "label": f"{kw_count} suspicious keyword(s) detected",
            "value": "HIGH" if severity == "high" else "MED" if severity == "medium" else "LOW",
            "severity": severity,
        })

    # Urgency language
    urgency_words = ["urgent", "immediately", "action required", "24 hours", "expire today"]
    if any(w in text for w in urgency_words):
        factors.append({
            "icon": "⏰",
            "label": "Creates urgency or time pressure",
            "value": "MED",
            "severity": "medium",
        })

    # All caps subject
    if subject and subject == subject.upper() and len(subject) > 5:
        factors.append({
            "icon": "📢",
            "label": "Subject line in ALL CAPS",
            "value": "LOW",
            "severity": "low",
        })

    # IP address in URL
    if re.search(r'https?://\d+\.\d+\.\d+\.\d+', text):
        factors.append({
            "icon": "🖥️",
            "label": "URL contains raw IP address",
            "value": "HIGH",
            "severity": "high",
        })

    # Excessive special characters
    special_count = len(re.findall(r'[!$%@#*]', subject + body))
    if special_count > 5:
        factors.append({
            "icon": "❗",
            "label": f"{special_count} special characters in message",
            "value": "LOW",
            "severity": "low",
        })

    return factors

# ─── Routes ───────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "model_loaded": model is not None,
        "timestamp": datetime.utcnow().isoformat(),
    })

@app.route("/stats", methods=["GET"])
def get_stats():
    return jsonify(stats)

@app.route("/predict", methods=["POST"])
def predict():
    if model is None:
        return jsonify({"error": "Model not loaded. Run train_model.py first."}), 503

    data = request.get_json(force=True)
    if not data:
        return jsonify({"error": "Invalid JSON body"}), 400

    subject = str(data.get("subject", "")).strip()
    body    = str(data.get("body",    "")).strip()

    if not body and not subject:
        return jsonify({"error": "Both subject and body are empty"}), 400

    # Combine subject + body for classification
    email_text = f"{subject}\n{body}"

    try:
        prediction   = model.predict([email_text])[0]            # "phishing" | "safe"
        probabilities = model.predict_proba([email_text])[0]     # [p_safe, p_phishing]
        classes       = model.classes_                            # ['phishing', 'safe']

        phishing_idx = list(classes).index("phishing")
        confidence   = float(probabilities[phishing_idx]) if prediction == "phishing" \
                       else float(probabilities[1 - phishing_idx])

        # Adjust: if safe, confidence = P(safe)
        if prediction == "safe":
            safe_idx   = list(classes).index("safe")
            confidence = float(probabilities[safe_idx])

        factors = extract_risk_factors(subject, body)

        # Update stats
        stats["total"] += 1
        stats[prediction] += 1

        return jsonify({
            "prediction":  prediction,
            "confidence":  round(confidence, 4),
            "factors":     factors,
            "email_length": len(email_text),
            "scanned_at":  datetime.utcnow().isoformat(),
        })

    except Exception as e:
        app.logger.error(f"Prediction error: {e}")
        return jsonify({"error": "Prediction failed", "detail": str(e)}), 500

# ─── Run ──────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "="*45)
    print("   🛡️  PhishGuard API — Starting up")
    print("="*45)
    print(f"   Model loaded : {'✅' if model else '❌ Run train_model.py'}")
    print("   Endpoint     : http://localhost:5000/predict")
    print("   Health check : http://localhost:5000/health")
    print("="*45 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
