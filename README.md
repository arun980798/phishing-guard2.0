# 🛡 PhishGuard — Heuristic Phishing Detection Extension

A lightweight, fully offline Chrome extension (Manifest V3) that detects phishing websites using heuristic + DOM analysis. No external APIs, no ML, no preloaded blacklists.

---

## 📁 Folder Structure

```
phishing-guard/
├── manifest.json       # Extension manifest (MV3)
├── background.js       # Service worker: scoring, blacklist, blocking
├── content.js          # DOM collector + popup toast injector
├── utils.js            # All heuristic scoring functions
├── popup.html          # Extension popup UI
├── popup.js            # Popup controller
├── warning.html        # Full-screen block page
├── styles.css          # Content-script popup styles
├── icons/
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
└── README.md
```

---

## 🚀 How to Load in Chrome (Windows)

1. **Download / unzip** this folder to any location (e.g., `C:\PhishGuard\`)
2. Open Chrome and navigate to: `chrome://extensions`
3. Enable **Developer Mode** (toggle in top-right corner)
4. Click **"Load unpacked"**
5. Select the `phishing-guard/` folder
6. The PhishGuard icon will appear in your toolbar 🎉

---

## 🔧 How It Works

### Detection Flow
```
User visits site
     ↓
content.js collects URL + DOM signals
     ↓
Sends to background.js
     ↓
utils.js runs heuristic scoring
     ↓
Risk score (0–100) generated
     ↓
0–30  → Safe    (green popup)
31–70 → Suspicious (yellow popup)
71–100 → Phishing (red popup + block page)
```

### URL Heuristics (utils.js)
| Check | Points |
|---|---|
| IP address as hostname | +30 |
| URL length > 100 chars | +10 |
| `@` symbol in URL | +20 |
| 3+ hyphens in domain | +15 |
| 4+ subdomains | +15 |
| Suspicious keywords (login, verify, etc.) | +5 per keyword |
| Brand name in path but not in domain | +25 |
| Double slash redirect trick | +10 |
| Non-standard port | +10 |
| Heavy percent-encoding | +12 |
| Plain HTTP | +5 |

### DOM Heuristics (content.js → utils.js)
| Check | Points |
|---|---|
| Password input present | +15 |
| >5 hidden inputs | +12 |
| Form submits to external domain | +25 |
| 3+ sensitive data inputs | +18 |
| Credential-harvesting text patterns | +10 |
| No favicon | +5 |
| Right-click disabled | +8 |
| iFrames present | +5 each |

---

## 🖱 Using the Popup

Click the PhishGuard icon in the toolbar to see:

- **Risk score ring** (0–100)
- **Verdict badge** (Safe / Suspicious / Phishing)
- **Detection signals** list
- **Mark as Phishing** → adds to local blacklist, future visits blocked
- **Mark as Safe** → whitelists site, disables detection
- **Blocked / Trusted** list viewer with remove buttons

---

## 🚫 Blacklist Behavior

- Starts **empty** — no preloaded list
- A site is added when:
  - Heuristic score ≥ 71 (automatic)
  - User clicks "Mark as Phishing"
- Blocked sites redirect to `warning.html` with score + reasons
- User can unblock from the popup list

---

## 🔒 Privacy

- **No data leaves your browser**
- **No telemetry** of any kind
- **No external APIs** called
- All data stored in `chrome.storage.local` (your device only)

---

## 📚 Academic Notes

This extension implements:





🔥 Phishing Detection Bases
🧠 1. URL-Based Checks
IP address used instead of domain
Long URL length
Presence of “@” symbol
Excessive hyphens in domain
Too many subdomains (dots)
Suspicious keywords in URL
Brand name mismatch (spoofing)
Double slashes in URL
Non-standard port usage
Encoded/obfuscated characters
Use of HTTP instead of HTTPS
🌐 2. DOM-Based Checks
Presence of password field
High number of hidden inputs
Form submitting to external domain
Multiple sensitive input fields
Suspicious or urgent text content
Missing favicon
Disabled right-click
Use of iFrames

- **Heuristic analysis**: Rule-based scoring without ML
- **DOM analysis**: Structural page analysis at runtime
- **Dynamic blacklisting**: Storage-backed, grows from detections
- **Chrome Extension MV3**: Service workers, content scripts, declarative rules
- **Privacy-by-design**: Zero egress, offline-only

Inspired by academic research on URL-based and DOM-based phishing detection without reliance on real-time threat intelligence feeds.
