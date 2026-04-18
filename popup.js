// ============================================================
// popup.js — PhishGuard Popup Controller
// Talks to background.js via chrome.runtime.sendMessage
// ============================================================

"use strict";
 

//things of html element we need to change when we get score and reason from background.js
const ringProgress  = document.getElementById("ringProgress");
const scoreNum      = document.getElementById("scoreNum");
const verdictBadge  = document.getElementById("verdictBadge");
const verdictText   = document.getElementById("verdictText");
const verdictIcon   = document.getElementById("verdictIcon");
const siteURL       = document.getElementById("siteURL");
const reasonsList   = document.getElementById("reasonsList");
const btnPhishing   = document.getElementById("btnPhishing");
const btnSafe       = document.getElementById("btnSafe");
const btnRemove     = document.getElementById("btnRemove");
const tabBlacklist  = document.getElementById("tabBlacklist");
const tabWhitelist  = document.getElementById("tabWhitelist");
const listItems     = document.getElementById("listItems");
const toast         = document.getElementById("toast");
const CIRCUMFERENCE = 2 * Math.PI * 30;
// Ring circumference (r=30 → C = 2πr ≈ 188.5)


let currentHost = "";
let activeListTab = "blacklist";

// ── Utility: toast notification ─────────────────────────────
function showToast(msg, duration = 1600) {
  toast.textContent = msg;
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), duration);
}

//ui ring score 
function setRing(score, verdict) {
  const offset = CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE;
  ringProgress.style.strokeDashoffset = offset;

  const colorMap = {
    safe: "#22c55e",
    suspicious: "#f59e0b",
    phishing: "#ef4444"
  };
  ringProgress.style.stroke = colorMap[verdict] || "#22c55e";
}

// ── Render score + verdict 
function renderScore(score, verdict, reasons, url, blacklisted, whitelisted) {
  // Ring
  setRing(score, verdict);
  scoreNum.textContent = score;

  // Badge
  verdictBadge.className = "verdict-badge " + verdict;
  const icons = { safe: "✔", suspicious: "⚠", phishing: "✖" };
  const labels = { safe: "Safe", suspicious: "Suspicious", phishing: "Phishing" };
  verdictIcon.textContent = icons[verdict] || "●";
  verdictText.textContent = labels[verdict] || verdict;

  // URL
  siteURL.textContent = url || currentHost;

  // Reasons
  if (reasons && reasons.length > 0) {
    const dotColors = { safe: "#22c55e", suspicious: "#f59e0b", phishing: "#ef4444" };
    reasonsList.innerHTML = reasons.map(r => `
      <div class="reason-item">
        <span class="reason-dot" style="background:${dotColors[verdict] || '#888'}"></span>
        <span>${escapeHTML(r)}</span>
      </div>
    `).join("");
  } else {
    reasonsList.innerHTML = '<div class="empty-list">No suspicious signals detected.</div>';
  }

  // Buttons
  if (blacklisted) {
    btnPhishing.style.display = "none";
    btnSafe.style.display = "none";
    btnRemove.style.display = "flex";
  } else {
    btnPhishing.style.display = "flex";
    btnSafe.style.display = "flex";
    btnRemove.style.display = "none";
  }

  if (whitelisted) {
    btnSafe.disabled = true;
    btnSafe.textContent = "✔ Trusted";
  } else {
    btnSafe.disabled = false;
    btnSafe.textContent = "✔ Mark Safe";
  }
}

function escapeHTML(str) {
  return str.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}//somthing about secuirty dont know about it 

// ── Render list of blacklisted or whitelisted sites
function renderList(data) {
  const items = data[activeListTab] || [];
  if (items.length === 0) {
    listItems.innerHTML = `<div class="empty-list">No sites ${activeListTab === "blacklist" ? "blocked" : "trusted"} yet.</div>`;
    return;
  }

  listItems.innerHTML = items.map(host => `
    <div class="list-item">
      <span class="list-item-host" title="${escapeHTML(host)}">${escapeHTML(host)}</span>
      <button class="list-item-remove" data-host="${escapeHTML(host)}" data-list="${activeListTab}" title="Remove">✕</button>
    </div>
  `).join("");

  // Attach remove buttons
  listItems.querySelectorAll(".list-item-remove").forEach(btn => {
    btn.addEventListener("click", async () => {
      const host = btn.dataset.host;
      const listType = btn.dataset.list;
      if (listType === "blacklist") {
        await sendMsg("REMOVE_BLACKLIST", { host });
        showToast(`${host} removed from blocklist`);
      } else {
        // Re-use remove pattern (whitelist remove = mark as phishing or just remove)
        const wl = await chrome.storage.local.get(["whitelist"]);
        const filtered = (wl.whitelist || []).filter(h => h !== host);
        await chrome.storage.local.set({ whitelist: filtered });
        showToast(`${host} removed from trusted list`);
      }
      refreshLists();
    });
  });
}

// ── Send a message to background 
function sendMsg(type, extra = {}) {
  return new Promise(resolve => {
    chrome.runtime.sendMessage({ type, ...extra }, resolve);
  });
}

// ── Refresh lists panel ──────────────────────────────────────
async function refreshLists() {
  const data = await sendMsg("GET_LISTS");
  renderList(data);
}

// ── Bootstrap this function Initialization whenpopup open 
async function init() {
  const info = await sendMsg("GET_TAB_SCORE");

  if (!info) {
    renderScore(0, "safe", [], "", false, false);
    return;
  }

  currentHost = info.host;

  if (info.cached) {
    renderScore(
      info.cached.score,
      info.cached.verdict,
      info.cached.reasons,
      info.url,
      info.blacklisted,
      info.whitelisted
    );
  } else {
    // No cached score yet (very fast nav) — show neutral
    renderScore(0, "safe", ["Page not yet analyzed — reload to scan"], info.url, info.blacklisted, info.whitelisted);
  }

  refreshLists();
}

// ── Button handlers ──────────────────────────────────────────
btnPhishing.addEventListener("click", async () => {
  if (!currentHost) return;
  await sendMsg("MARK_PHISHING", { host: currentHost });
  showToast(`🚫 ${currentHost} added to blocklist`);
  // Re-fetch to update UI
  const info = await sendMsg("GET_TAB_SCORE");
  if (info) {
    renderScore(
      info.cached?.score || 100,
      "phishing",
      info.cached?.reasons || ["Manually marked as phishing"],
      info.url,
      true,
      false
    );
  }
  refreshLists();
});

btnSafe.addEventListener("click", async () => {
  if (!currentHost) return;
  await sendMsg("MARK_SAFE", { host: currentHost });
  showToast(`✔ ${currentHost} added to trusted list`);
  const info = await sendMsg("GET_TAB_SCORE");
  if (info) {
    renderScore(0, "safe", ["Whitelisted by user"], info.url, false, true);
  }
  refreshLists();
});

btnRemove.addEventListener("click", async () => {
  if (!currentHost) return;
  await sendMsg("REMOVE_BLACKLIST", { host: currentHost });
  showToast(`${currentHost} unblocked`);
  const info = await sendMsg("GET_TAB_SCORE");
  if (info) {
    renderScore(
      info.cached?.score || 0,
      info.cached?.verdict || "safe",
      info.cached?.reasons || [],
      info.url,
      false,
      false
    );
  }
  refreshLists();
});

// ── List tab toggle ──────────────────────────────────────────
tabBlacklist.addEventListener("click", () => {
  activeListTab = "blacklist";
  tabBlacklist.classList.add("active");
  tabWhitelist.classList.remove("active");
  refreshLists();
});

tabWhitelist.addEventListener("click", () => {
  activeListTab = "whitelist";
  tabWhitelist.classList.add("active");
  tabBlacklist.classList.remove("active");
  refreshLists();
});

// ── Run ──────────────────────────────────────────────────────
init();



// User opens popup
//        ↓
// popup.js → asks background.js
//        ↓
// Gets score + data
//        ↓
// Displays:
//    ✔ Score
//    ✔ Verdict
//    ✔ Reasons
//        ↓
// User clicks buttons
//        ↓
// Message sent to background.js
//        ↓
// Storage updated
//        ↓
// UI refreshed