# 🛡️ PhishGuard — AI-Powered Phishing Email Detection

PhishGuard is a browser extension integrated with a machine learning backend that identifies phishing emails in real time on Gmail and Outlook.

---

# 🚀 Backend Installation & Setup

Navigate to the backend directory:

```bash
cd backend
```

Install all required dependencies:

```bash
pip install -r requirements.txt
```

Train the machine learning model:

```bash
python train_model.py
```

This command generates the trained model file:

```bash
phishguard_model.pkl
```

Start the Flask API server:

```bash
python app.py
```

The backend will run locally at:

```bash
http://localhost:5000
```

---

# 🧪 API Testing

You can test the prediction endpoint using the following cURL command:

```bash
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"subject": "URGENT: Verify your account!", "body": "Click here to avoid suspension http://secure-verify.tk"}'
```

### Example Response

```json
{
  "prediction": "phishing",
  "confidence": 0.9341,
  "factors": [
    {
      "icon": "🔗",
      "label": "Contains 1 URL(s)",
      "value": "MED",
      "severity": "medium"
    },
    {
      "icon": "⚠️",
      "label": "Suspicious domain extension (.tk...)",
      "value": "HIGH",
      "severity": "high"
    },
    {
      "icon": "⏰",
      "label": "Creates urgency or time pressure",
      "value": "MED",
      "severity": "medium"
    }
  ]
}
```

---

# 🌐 Loading the Browser Extension

1. Open Chrome and go to:

```text
chrome://extensions/
```

2. Turn on **Developer Mode** using the toggle in the top-right corner.

3. Click **Load unpacked**.

4. Select the `extension/` directory.

5. Once loaded successfully, the PhishGuard extension icon will appear in the Chrome toolbar ✅

### Extension Icons

Place the following icon files inside:

```text
extension/icons/
```

Required files:

* `icon16.png`
* `icon48.png`
* `icon128.png`

You may use any shield or cybersecurity-themed icon.

---

# 🔌 API Endpoints

## POST `/predict`

Analyzes an email and determines whether it is safe or phishing.

### Request Body

```json
{
  "subject": "Email subject line",
  "body": "Full email body text"
}
```

### Response

```json
{
  "prediction": "phishing",
  "confidence": 0.9341,
  "factors": [ ... ],
  "email_length": 342,
  "scanned_at": "2024-11-15T14:32:10"
}
```

---

## GET `/health`

Returns the API health status along with model availability information.

---

## GET `/stats`

Provides session statistics including:

* Total emails scanned
* Number of phishing emails detected
* Number of safe emails detected

---

# ⚙️ Extension Workflow & Architecture

```text
Gmail / Outlook Interface
            ↓
content.js → Detects opened emails using MutationObserver
            ↓ Extracts email subject & body
background.js → Handles message passing/service worker
            ↓
Flask API → localhost:5000/predict
            ↓
ML Model → Generates prediction & risk analysis
            ↓
popup.js → Displays phishing result card
            +
content.js → Injects warning banner for phishing emails
```

---

# ✨ Features

* Real-time phishing email detection
* Gmail and Outlook integration
* Machine learning powered analysis
* Risk factor explanation system
* Dynamic phishing warning banners
* Lightweight browser extension architecture
* Session-based scan statistics

---

# 🛠️ Tech Stack

### Frontend / Extension

* JavaScript
* Chrome Extension APIs
* MutationObserver

### Backend

* Python
* Flask
* Scikit-learn

### Machine Learning

* NLP-based phishing detection model
* Feature extraction and risk scoring

