// background.js — PhishGuard Service Worker
// Responsibilities:
//   • Receive DOM signals from content.js
//   • Run heuristic scoring (via utils.js)
//   • Manage blacklist & whitelist in chrome.storage.local
//   • Block phishing pages by redirecting to warning.html

importScripts("utils.js"); // brings in analyzeSignals()

// ─── Storage helpers
async function getList(key) {
  return new Promise(resolve => {
    chrome.storage.local.get([key], result => {
      resolve(result[key] || []);
    });
  });
}

async function setList(key, arr) {
  return new Promise(resolve => {
    chrome.storage.local.set({ [key]: arr }, resolve);
  });
}

// Returns hostname from a URL string
function getHost(rawURL) {
  try { return new URL(rawURL).hostname.toLowerCase(); }
  catch { return rawURL.toLowerCase(); }
}

// ─── Blacklist / Whitelist operations ─────────────────────
async function isBlacklisted(host) {
  const list = await getList("blacklist");
  return list.includes(host);
}

async function isWhitelisted(host) {
  const list = await getList("whitelist");
  return list.includes(host);
}

async function addToBlacklist(host) {
  const list = await getList("blacklist");
  if (!list.includes(host)) {
    list.push(host);
    await setList("blacklist", list);
  }
  // Remove from whitelist if present
  const wl = await getList("whitelist");
  await setList("whitelist", wl.filter(h => h !== host));
}

async function addToWhitelist(host) {
  const list = await getList("whitelist");
  if (!list.includes(host)) {
    list.push(host);
    await setList("whitelist", list);
  }
  // Remove from blacklist if present
  const bl = await getList("blacklist");
  await setList("blacklist", bl.filter(h => h !== host));
}

async function removeFromBlacklist(host) {
  const list = await getList("blacklist");
  await setList("blacklist", list.filter(h => h !== host));
}

// ─── Cache: recent scores per tab (avoid re-running on popup open) ──
const tabScoreCache = {}; // tabId → { score, verdict, reasons, url }

// ─── Message handler ─────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {//Whenever any part of extension sends a message → handle it here

  // --- Content script sends DOM signals ---
  if (msg.type === "ANALYZE_PAGE") {//run when website is open 
    (async () => {
      const url = msg.url;
      const host = getHost(url);

      // Skip internal/extension pages
      if (url.startsWith("chrome://") || url.startsWith("chrome-extension://")) {
        sendResponse({ score: 0, verdict: "safe", reasons: [] });
        return;
      }

      // Whitelisted → always safe
      if (await isWhitelisted(host)) {
        const result = { score: 0, verdict: "safe", reasons: ["Whitelisted by user"] };
        tabScoreCache[sender.tab?.id] = { ...result, url };
        sendResponse(result);
        return;
      }

      // Blacklisted → immediate block
      if (await isBlacklisted(host)) {
        const result = { score: 100, verdict: "phishing", reasons: ["In user blacklist"] };
        tabScoreCache[sender.tab?.id] = { ...result, url };
        sendResponse(result);
        blockTab(sender.tab?.id, url, result.score, ["In user blacklist"]);
        return;
      }

      // Run heuristic analysis
      const result = analyzeSignals({ url, dom: msg.dom });

      // Cache result for this tab
      if (sender.tab?.id) {
        tabScoreCache[sender.tab.id] = { ...result, url };
      }

      // Auto-add confirmed phishing sites to blacklist
      if (result.verdict === "phishing") {
        await addToBlacklist(host);
        blockTab(sender.tab?.id, url, result.score, result.reasons);
      }

      sendResponse(result); //sand response back to content.js which will show the popup 
    })();

    return true; // keep channel open for async response
  }

  // --- Popup requests cached score for current tab ---
  if (msg.type === "GET_TAB_SCORE") {
    (async () => {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const tab = tabs[0];
      if (!tab) { sendResponse(null); return; }

      const cached = tabScoreCache[tab.id];
      const host = getHost(tab.url || "");

      const blacklisted = await isBlacklisted(host);
      const whitelisted = await isWhitelisted(host);

      sendResponse({
        cached: cached || null,
        host,
        url: tab.url,
        blacklisted,
        whitelisted
      });
    })();
    return true;
  }

  // --- Popup marks site as phishing ---
  if (msg.type === "MARK_PHISHING") {
    (async () => {
      await addToBlacklist(msg.host);
      sendResponse({ ok: true });
    })();
    return true;
  }

  // --- Popup whitelists site ---
  if (msg.type === "MARK_SAFE") {
    (async () => {
      await addToWhitelist(msg.host);
      sendResponse({ ok: true });
    })();
    return true;
  }

  // --- Popup removes from blacklist ---
  if (msg.type === "REMOVE_BLACKLIST") {
    (async () => {
      await removeFromBlacklist(msg.host);
      sendResponse({ ok: true });
    })();
    return true;
  }

  // --- Popup requests full lists ---
  if (msg.type === "GET_LISTS") {
    (async () => {
      const blacklist = await getList("blacklist");
      const whitelist = await getList("whitelist");
      sendResponse({ blacklist, whitelist });
    })();
    return true;
  }
});






//  Block a tab by redirecting to warning page 
function blockTab(tabId, originalURL, score, reasons) {
  if (!tabId) return;

  const warningURL = chrome.runtime.getURL("warning.html") +
    "?url=" + encodeURIComponent(originalURL) +
    "&score=" + score +
    "&reasons=" + encodeURIComponent(JSON.stringify(reasons));

  chrome.tabs.update(tabId, { url: warningURL });
}

//Auto Block on Navigation
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return; // main frame only
  const url = details.url;
  if (!url.startsWith("http")) return;

  const host = getHost(url);
  if (await isBlacklisted(host)) {
    blockTab(details.tabId, url, 100, ["Previously blacklisted"]);
  }
});
