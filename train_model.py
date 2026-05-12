"""
train_model.py — PhishGuard ML Model Trainer
============================================
Trains a Naive Bayes classifier on phishing email features.
Run this ONCE to generate phishguard_model.pkl

Usage:
    python train_model.py
"""

import pickle
import re
import numpy as np
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder

# ─── Synthetic Training Data ─────────────────────────────────────────────────
# In production: replace with the Enron Spam Dataset or CEAS-08 dataset.
# Download from: https://www.kaggle.com/datasets/rtatman/fraudulent-email-corpus

PHISHING_EMAILS = [
    "Urgent: Your account has been suspended. Verify your identity immediately at http://secure-verify.tk",
    "CONGRATULATIONS! You've won $1,000,000. Click here to claim your prize now: http://prize-claim.xyz",
    "Your PayPal account is limited. Please verify your information: http://paypal-secure.ml/login",
    "Security Alert: Unusual login detected. Update your password immediately: http://accounts-verify.com",
    "Dear valued customer, your bank account will be closed. Login now: http://bankofamerica-secure.tk",
    "ACTION REQUIRED: Verify your Amazon account to avoid suspension http://amazon-verify.info",
    "Your Apple ID has been locked. Click here to unlock it: http://appleid-unlock.xyz",
    "IRS NOTICE: You owe back taxes. Pay immediately to avoid legal action http://irs-payment.ml",
    "Your Netflix subscription will expire. Update your payment: http://netflix-billing.tk",
    "URGENT: Your email storage is full. Click here to upgrade for free: http://free-upgrade.xyz",
    "Please update your account information immediately to avoid termination",
    "Verify your identity or your account will be permanently deleted within 24 hours",
    "You have a pending wire transfer of $5000. Click to authorize: http://wire-auth.tk",
    "Your password expires today! Reset now to keep access: http://password-reset.ml",
    "DHL DELIVERY FAILED. Pay customs fee to release your package: http://dhl-customs.xyz",
    "WINNER NOTIFICATION: You have been selected for our lottery. Claim now!",
    "Immediate action required: suspicious activity on your account",
    "Your account credentials must be verified within 2 hours or be deactivated",
    "Free gift card! Enter your details to claim $500 Amazon gift card now",
    "Important: Your Microsoft 365 license will expire. Click to renew: http://ms365-renew.tk",
    "ALERT: Someone is trying to access your account from Russia. Verify now",
    "Your crypto wallet requires verification. Login at http://crypto-verify.xyz",
    "Congratulations! You've been pre-approved for a $10,000 loan. No credit check!",
    "Your SSN has been compromised. Contact us immediately to protect your identity",
    "Nigerian Prince needs your help to transfer $45 million. You keep 30%",
]

SAFE_EMAILS = [
    "Hi John, please find attached the Q3 financial report for your review. Let me know if you have questions.",
    "Meeting reminder: Team standup tomorrow at 10 AM in Conference Room B.",
    "Your order #12345 has been shipped and will arrive by Friday. Track it here.",
    "Thank you for subscribing to our newsletter. Here are this week's top stories.",
    "Project update: The development team has completed phase 2. See details below.",
    "Invitation: Sarah's birthday party this Saturday at 7 PM. RSVP by Thursday.",
    "Your monthly statement is ready. You spent $342.50 this month.",
    "Lunch today? There's a great new sushi place on 5th Ave. Want to try it?",
    "Hi, I wanted to follow up on our conversation from last week about the proposal.",
    "Reminder: Your dentist appointment is scheduled for next Monday at 3 PM.",
    "The pull request you submitted has been approved and merged into main.",
    "Weekly digest: Here are the top articles our team found interesting this week.",
    "Your flight confirmation for New York on Dec 15th. Booking reference: AB1234.",
    "Can we reschedule our 2 PM call? I have a conflict that came up this afternoon.",
    "Great job on the presentation yesterday! The client was very impressed.",
    "Attached are the meeting notes from our discussion on Thursday.",
    "Your library book is due in 3 days. Renew it online to avoid late fees.",
    "The annual company picnic is July 4th at Riverside Park. Bring your family!",
    "Code review completed. Minor suggestions on lines 45-50, otherwise looks great.",
    "Your tax documents are ready for download in your secure portal.",
    "Hope you're feeling better! Take all the time you need to recover.",
    "Here is the invoice for services rendered in November. Payment due Dec 1.",
    "The new product launch is confirmed for Q1 next year. Exciting times ahead!",
    "Good morning team, here is the agenda for today's sprint planning session.",
    "Thanks for your feedback on the beta. We've addressed your suggestions in v1.2.",
]

# ─── Build Dataset ────────────────────────────────────────────────────────────

def build_dataset():
    texts  = PHISHING_EMAILS + SAFE_EMAILS
    labels = ["phishing"] * len(PHISHING_EMAILS) + ["safe"] * len(SAFE_EMAILS)
    return texts, labels

# ─── Feature Engineering ──────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "suspend", "login", "click here", "confirm",
    "account", "password", "limited", "unusual", "locked", "expire",
    "winner", "congratulations", "prize", "free", "action required",
    "immediately", "warning", "alert", "security", "update your",
    "credit card", "ssn", "social security", "wire transfer", "bitcoin",
    "crypto", "lottery", "claim", "selected", "approved", "irs",
]

def count_urls(text):
    return len(re.findall(r'https?://\S+', text, re.IGNORECASE))

def count_suspicious_keywords(text):
    text_lower = text.lower()
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in text_lower)

def count_special_chars(text):
    return len(re.findall(r'[!$%@#*]', text))

def has_ip_url(text):
    return int(bool(re.search(r'https?://\d+\.\d+\.\d+\.\d+', text)))

def has_suspicious_tld(text):
    suspicious_tlds = ['.tk', '.ml', '.xyz', '.info', '.click', '.work', '.top', '.gq']
    text_lower = text.lower()
    return int(any(tld in text_lower for tld in suspicious_tlds))

def extract_features(texts):
    """Extract hand-crafted numeric features for each email."""
    features = []
    for text in texts:
        features.append([
            count_urls(text),
            count_suspicious_keywords(text),
            count_special_chars(text),
            has_ip_url(text),
            has_suspicious_tld(text),
            len(text),            # email length
            text.upper() == text, # all caps flag
            text.count("!"),      # exclamation marks
        ])
    return np.array(features)

# ─── Train ────────────────────────────────────────────────────────────────────

def train():
    texts, labels = build_dataset()

    # TF-IDF pipeline with Naive Bayes (best for text classification)
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),       # unigrams + bigrams
            max_features=5000,
            stop_words="english",
            sublinear_tf=True,        # log TF scaling
        )),
        ("clf", MultinomialNB(alpha=0.1)),
    ])

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )

    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)

    print("\n" + "="*50)
    print("  PhishGuard Model Training Report")
    print("="*50)
    print(f"\n  Accuracy : {accuracy_score(y_test, y_pred)*100:.1f}%")
    print(f"\n  Classification Report:")
    print(classification_report(y_test, y_pred))

    # Cross-validation
    cv_scores = cross_val_score(pipeline, texts, labels, cv=5, scoring="accuracy")
    print(f"  5-Fold CV Accuracy: {cv_scores.mean()*100:.1f}% ± {cv_scores.std()*100:.1f}%")
    print("="*50 + "\n")

    # Save model
    with open("phishguard_model.pkl", "wb") as f:
        pickle.dump(pipeline, f)
    print("  ✅ Model saved to phishguard_model.pkl")
    print("  ▶  Start the API with: python app.py\n")

if __name__ == "__main__":
    train()
