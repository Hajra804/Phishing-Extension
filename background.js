// background.js — PhishGuard Service Worker

// ─── Extension install / update ───────────────────────────────
chrome.runtime.onInstalled.addListener(({ reason }) => {
  if (reason === "install") {
    chrome.storage.local.set({ scanCount: 0, threatCount: 0, autoScan: true });
    console.log("[PhishGuard] Installed. Watching Gmail and Outlook.");
  }
});

// ─── Message relay between content ↔ popup ────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Relay analysis results to any open popup
  if (msg.action === "analysisResult" || msg.action === "scanStarted") {
    chrome.runtime.sendMessage(msg).catch(() => {
      // popup may be closed — ignore
    });
  }

  // Handle report action
  if (msg.action === "reportPhishing") {
    logThreat(msg.url, msg.result);
  }

  return false;
});

// ─── Threat log ───────────────────────────────────────────────
function logThreat(url, result) {
  chrome.storage.local.get(["threatLog"], (data) => {
    const log = data.threatLog || [];
    log.unshift({
      url,
      prediction: result.prediction,
      confidence: result.confidence,
      timestamp: new Date().toISOString(),
    });
    // keep last 50 entries
    chrome.storage.local.set({ threatLog: log.slice(0, 50) });
  });
}

// ─── Context menu (right-click → "Scan with PhishGuard") ─────
chrome.contextMenus?.create({
  id: "phishguard-scan",
  title: "🛡️ Scan with PhishGuard",
  contexts: ["selection"],
});

chrome.contextMenus?.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "phishguard-scan" && info.selectionText) {
    chrome.tabs.sendMessage(tab.id, {
      action: "scanSelection",
      text: info.selectionText,
    });
  }
});
