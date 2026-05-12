// content.js — PhishGuard Content Script
// Injected into Gmail & Outlook pages to extract email data and trigger scans.

const API_BASE = "http://localhost:5000";
let autoScan = true;
let lastEmailHash = null;
let observer = null;

// ─── Init ────────────────────────────────────────────────────
init();

async function init() {
  const stored = await chrome.storage.local.get(["autoScan"]);
  autoScan = stored.autoScan !== false;
  startObserver();
}

// ─── Message listener (from popup / background) ───────────────
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.action === "extractEmail") {
    const data = extractEmail();
    sendResponse(data || { error: "No email content found. Please open an email first." });
  }
  if (msg.action === "setAutoScan") {
    autoScan = msg.value;
  }
  return true; // keep async channel open
});

// ─── Email extraction (Gmail + Outlook) ─────────────────────
function extractEmail() {
  // --- Gmail ---
  if (location.hostname === "mail.google.com") return extractGmail();
  // --- Outlook Live / Office ---
  if (location.hostname.includes("outlook")) return extractOutlook();
  return null;
}

function extractGmail() {
  // Subject
  const subjectEl = document.querySelector("h2.hP");
  const subject   = subjectEl?.innerText?.trim() || "";

  // Body — Gmail renders inside a div.a3s
  const bodyEl = document.querySelector("div.a3s.aiL, div.a3s");
  const body   = bodyEl?.innerText?.trim() || "";

  if (!body) return null;
  return { subject, body };
}

function extractOutlook() {
  const subjectEl = document.querySelector(
    "[data-testid='subject'], .Subject, [aria-label*='Subject']"
  );
  const subject = subjectEl?.innerText?.trim() || "";

  const bodyEl = document.querySelector(
    "[data-testid='message-body'], .ReadingPaneContent, [role='document']"
  );
  const body = bodyEl?.innerText?.trim() || "";

  if (!body) return null;
  return { subject, body };
}

// ─── Auto-scan via DOM observer ───────────────────────────────
function startObserver() {
  if (observer) observer.disconnect();

  observer = new MutationObserver(debounce(() => {
    if (!autoScan) return;
    const data = extractEmail();
    if (!data) return;

    const hash = simpleHash(data.subject + data.body.slice(0, 200));
    if (hash === lastEmailHash) return; // same email, skip
    lastEmailHash = hash;

    chrome.runtime.sendMessage({ action: "scanStarted" });
    sendToBackend(data);
  }, 1200));

  observer.observe(document.body, { childList: true, subtree: true });
}

// ─── Send to backend ──────────────────────────────────────────
async function sendToBackend({ subject, body }) {
  try {
    const res = await fetch(`${API_BASE}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ subject, body }),
    });
    if (!res.ok) return;
    const result = await res.json();

    // Update stats & push result to popup
    chrome.storage.local.get(["scanCount", "threatCount"], (data) => {
      const sc = (data.scanCount  || 0) + 1;
      const tc = (data.threatCount || 0) + (result.prediction === "phishing" ? 1 : 0);
      chrome.storage.local.set({ scanCount: sc, threatCount: tc, lastResult: result });
    });

    chrome.runtime.sendMessage({ action: "analysisResult", result });

    // Inject banner directly on the page for phishing emails
    if (result.prediction === "phishing") injectWarningBanner(result);
    else removeWarningBanner();

  } catch (_) {
    // backend not running — silently fail
  }
}

// ─── In-page warning banner ───────────────────────────────────
function injectWarningBanner(result) {
  removeWarningBanner();
  const pct = Math.round((result.confidence || 0) * 100);
  const banner = document.createElement("div");
  banner.id = "phishguard-banner";
  banner.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; z-index: 999999;
    background: linear-gradient(90deg, #1a0008, #2d0010);
    border-bottom: 2px solid #ff3b5c;
    padding: 10px 20px;
    display: flex; align-items: center; gap: 14px;
    font-family: 'Rajdhani', 'Segoe UI', sans-serif;
    font-size: 15px; font-weight: 600;
    color: #f0f6fc;
    box-shadow: 0 4px 30px rgba(255,59,92,.4);
    animation: slideDown .3s ease;
  `;
  banner.innerHTML = `
    <style>
      @keyframes slideDown { from { transform:translateY(-100%); } to { transform:translateY(0); } }
    </style>
    <span style="font-size:20px;">⚠️</span>
    <span>
      <strong style="color:#ff3b5c; letter-spacing:.05em;">PHISHING DETECTED</strong>
      &nbsp;·&nbsp; Confidence: <strong style="color:#ffb800;">${pct}%</strong>
      &nbsp;·&nbsp; <span style="color:#888; font-weight:400;">Do not click links or provide credentials.</span>
    </span>
    <button onclick="document.getElementById('phishguard-banner').remove()" style="
      margin-left:auto; background:transparent; border:1px solid #ff3b5c;
      color:#ff3b5c; border-radius:4px; padding:4px 10px; cursor:pointer;
      font-family:inherit; font-size:13px;">✕ Dismiss</button>
  `;
  document.body.prepend(banner);
}

function removeWarningBanner() {
  document.getElementById("phishguard-banner")?.remove();
}

// ─── Helpers ──────────────────────────────────────────────────
function debounce(fn, delay) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), delay); };
}

function simpleHash(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
  }
  return h;
}
