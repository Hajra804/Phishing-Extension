// popup.js — PhishGuard Extension Popup Controller

const API_BASE = "http://localhost:5000";

// ─── DOM refs ────────────────────────────────────────────────
const resultCard      = document.getElementById("resultCard");
const resultIcon      = document.getElementById("resultIcon");
const resultLabel     = document.getElementById("resultLabel");
const resultSub       = document.getElementById("resultSub");
const confidenceBadge = document.getElementById("confidenceBadge");
const scanBar         = document.getElementById("scanBar");
const factorsSection  = document.getElementById("factorsSection");
const factorsList     = document.getElementById("factorsList");
const scanBtn         = document.getElementById("scanBtn");
const reportBtn       = document.getElementById("reportBtn");
const scanCount       = document.getElementById("scanCount");
const threatCount     = document.getElementById("threatCount");
const autoScanToggle  = document.getElementById("autoScanToggle");
const statusDot       = document.getElementById("statusDot");

// ─── Load saved stats ────────────────────────────────────────
chrome.storage.local.get(["scanCount", "threatCount", "autoScan", "lastResult"], (data) => {
  scanCount.textContent   = data.scanCount   || 0;
  threatCount.textContent = data.threatCount || 0;
  autoScanToggle.checked  = data.autoScan !== false;

  if (data.lastResult) renderResult(data.lastResult);
});

// ─── Auto-scan toggle ────────────────────────────────────────
autoScanToggle.addEventListener("change", () => {
  chrome.storage.local.set({ autoScan: autoScanToggle.checked });
  chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
    if (tab) chrome.tabs.sendMessage(tab.id, { action: "setAutoScan", value: autoScanToggle.checked });
  });
});

// ─── Manual scan ─────────────────────────────────────────────
scanBtn.addEventListener("click", () => {
  setScanningState();
  chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
    if (!tab) return showError("No active tab found.");
    chrome.tabs.sendMessage(tab.id, { action: "extractEmail" }, (response) => {
      if (chrome.runtime.lastError || !response) {
        return showError("Could not extract email. Make sure an email is open.");
      }
      if (response.error) return showError(response.error);
      analyzeEmail(response.subject, response.body);
    });
  });
});

// ─── Report button ───────────────────────────────────────────
reportBtn.addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
    chrome.storage.local.get(["lastResult"], (data) => {
      const result = data.lastResult || {};
      const msg = encodeURIComponent(
        `PhishGuard Report\nURL: ${tab?.url}\nResult: ${result.prediction || "unknown"}\nConfidence: ${result.confidence || "?"}`
      );
      chrome.tabs.create({ url: `mailto:report@phishguard.local?subject=Phishing+Report&body=${msg}` });
    });
  });
});

// ─── Listen for results pushed from content script ───────────
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.action === "analysisResult") renderResult(msg.result);
  if (msg.action === "scanStarted")    setScanningState();
});

// ─── Core analysis function ───────────────────────────────────
async function analyzeEmail(subject, body) {
  try {
    const res = await fetch(`${API_BASE}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ subject, body }),
    });
    if (!res.ok) throw new Error(`Server error ${res.status}`);
    const result = await res.json();
    renderResult(result);

    // persist stats
    chrome.storage.local.get(["scanCount", "threatCount"], (data) => {
      const sc = (data.scanCount || 0) + 1;
      const tc = (data.threatCount || 0) + (result.prediction === "phishing" ? 1 : 0);
      chrome.storage.local.set({ scanCount: sc, threatCount: tc, lastResult: result });
      scanCount.textContent   = sc;
      threatCount.textContent = tc;
    });
  } catch (err) {
    showError("Backend unreachable. Is Flask running on port 5000?");
  }
}

// ─── UI renderers ─────────────────────────────────────────────
function setScanningState() {
  resultCard.className = "result-card scanning";
  resultIcon.textContent  = "📡";
  resultLabel.textContent = "SCANNING...";
  resultSub.textContent   = "Analysing email content";
  confidenceBadge.textContent = "--";
  scanBar.style.display = "block";
  factorsSection.classList.add("hidden");
  statusDot.style.background    = "var(--accent)";
  statusDot.style.boxShadow     = "0 0 8px var(--accent)";
}

function renderResult(result) {
  const isPhishing = result.prediction === "phishing";
  const pct = Math.round((result.confidence || 0) * 100);

  resultCard.className = `result-card ${isPhishing ? "phishing" : "safe"}`;
  scanBar.style.display = "none";

  resultIcon.textContent  = isPhishing ? "⚠️" : "✅";
  resultLabel.textContent = isPhishing ? "PHISHING DETECTED" : "EMAIL IS SAFE";
  resultSub.textContent   = isPhishing
    ? "This email shows signs of phishing."
    : "No phishing indicators found.";
  confidenceBadge.textContent = `${pct}%`;

  statusDot.style.background = isPhishing ? "var(--danger)" : "var(--safe)";
  statusDot.style.boxShadow  = isPhishing ? "0 0 8px var(--danger)" : "0 0 8px var(--safe)";

  // render risk factors
  if (result.factors && result.factors.length > 0) {
    factorsSection.classList.remove("hidden");
    factorsList.innerHTML = result.factors.map(f => `
      <div class="factor">
        <div class="factor-icon">${f.icon}</div>
        <div class="factor-text">${f.label}</div>
        <div class="factor-score ${f.severity}">${f.value}</div>
      </div>
    `).join("");
  } else {
    factorsSection.classList.add("hidden");
  }

  // Desktop notification for phishing
  if (isPhishing) {
    chrome.notifications?.create({
      type: "basic",
      iconUrl: "icons/icon48.png",
      title: "⚠️ PhishGuard Alert",
      message: `Phishing detected with ${pct}% confidence. Stay safe!`,
    });
  }
}

function showError(msg) {
  resultCard.className = "result-card scanning";
  scanBar.style.display = "none";
  resultIcon.textContent  = "❌";
  resultLabel.textContent = "ERROR";
  resultSub.textContent   = msg;
  confidenceBadge.textContent = "!";
  factorsSection.classList.add("hidden");
}
