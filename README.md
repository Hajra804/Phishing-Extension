# 🛡️ PhishGuard — AI-Based Phishing Email Detection

A browser extension + ML backend that detects phishing emails in **Gmail** and **Outlook** in real time.



### 1. Backend Setup

```bash
cd backend
pip install -r requirements.txt

# Train the ML model (creates phishguard_model.pkl)
python train_model.py

# Start the API server
python app.py
# → Running at http://localhost:5000
```

**Test the API:**
```bash
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"subject": "URGENT: Verify your account!", "body": "Click here to avoid suspension http://secure-verify.tk"}'
```

Expected response:
```json
{
  "prediction": "phishing",
  "confidence": 0.9341,
  "factors": [
    { "icon": "🔗", "label": "Contains 1 URL(s)", "value": "MED", "severity": "medium" },
    { "icon": "⚠️", "label": "Suspicious domain extension (.tk...)", "value": "HIGH", "severity": "high" },
    { "icon": "⏰", "label": "Creates urgency or time pressure", "value": "MED", "severity": "medium" }
  ]
}
```

---

### 2. Load the Browser Extension

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the `extension/` folder
5. The PhishGuard icon appears in your toolbar ✅

> **Icons:** Add `icon16.png`, `icon48.png`, `icon128.png` to `extension/icons/`. You can use any shield/security icon.

---

## 🔌 API Reference

### `POST /predict`

**Body:**
```json
{
  "subject": "Email subject line",
  "body": "Full email body text"
}
```

**Response:**
```json
{
  "prediction": "phishing",
  "confidence": 0.9341,
  "factors": [ ... ],
  "email_length": 342,
  "scanned_at": "2024-11-15T14:32:10"
}
```

### `GET /health`
Returns API status and model load state.

### `GET /stats`
Returns total scans, phishing count, safe count for this session.

---

## 🔧 Extension Architecture

```
Gmail/Outlook Page
       ↓
content.js (MutationObserver watches for email opens)
       ↓ extracts subject + body
background.js (service worker / message relay)
       ↓
Flask API @ localhost:5000/predict
       ↓
ML Prediction + Risk Factors
       ↓
popup.js (renders result card)
       +
content.js (injects red warning banner on page if phishing)
```

