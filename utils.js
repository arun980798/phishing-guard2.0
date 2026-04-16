// ============================================================
// utils.js — PhishGuard Heuristic Engine
// All scoring functions live here, shared between content.js
// and background.js.  No external deps, fully offline.
// ============================================================

/**
 * Master scoring entry point.
 * Accepts a plain object of URL + DOM signals and returns
 *   { score: 0-100, reasons: string[], verdict: 'safe'|'suspicious'|'phishing' }
 */
function analyzeSignals(signals) {
  let score = 0;
  const reasons = [];

  // ---------- URL-based checks ----------
  const urlResult = scoreURL(signals.url || "");
  score += urlResult.score;
  reasons.push(...urlResult.reasons);

  // ---------- DOM-based checks ----------
  if (signals.dom) {
    const domResult = scoreDOM(signals.dom);
    score += domResult.score;
    reasons.push(...domResult.reasons);
  }

  // Clamp to 0-100
  score = Math.min(100, Math.max(0, score));

  let verdict = "safe";
  if (score >= 71) verdict = "phishing";
  else if (score >= 31) verdict = "suspicious";

  return { score, reasons, verdict };
}

// ─────────────────────────────────────────────
//  URL Heuristics
// ─────────────────────────────────────────────
function scoreURL(rawURL) {
  let score = 0;
  const reasons = [];

  let url;
  try {
    url = new URL(rawURL);
  } catch {
    // Unparseable URL is suspicious
    return { score: 20, reasons: ["Malformed / unparseable URL"] };
  }

  const full = rawURL;
  const hostname = url.hostname.toLowerCase();
  const path = url.pathname + url.search;

  // 1. IP address used as host (big red flag)
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    score += 30;
    reasons.push("IP address used instead of domain name");
  }

  // 2. URL total length
  if (full.length > 100) {
    score += 10;
    reasons.push(`Unusually long URL (${full.length} chars)`);
  } else if (full.length > 75) {
    score += 5;
    reasons.push(`Moderately long URL (${full.length} chars)`);
  }

  // 3. @ symbol in URL (redirects to different host)
  if (full.includes("@")) {
    score += 20;
    reasons.push('URL contains "@" (potential redirect trick)');
  }

  // 4. Excessive hyphens in domain
  const hyphens = (hostname.match(/-/g) || []).length;
  if (hyphens >= 3) {
    score += 15;
    reasons.push(`Domain has ${hyphens} hyphens (typosquatting indicator)`);
  } else if (hyphens === 2) {
    score += 8;
    reasons.push("Domain has multiple hyphens");
  }

  // 5. Excessive dots / subdomains
  const dots = (hostname.match(/\./g) || []).length;
  if (dots >= 4) {
    score += 15;
    reasons.push(`Excessive subdomains (${dots} dots in host)`);
  } else if (dots === 3) {
    score += 8;
    reasons.push("Multiple subdomains detected");
  }

  // 6. Suspicious keywords in URL
  const suspiciousKeywords = [
    "login", "signin", "sign-in", "log-in",
    "verify", "verification", "validate",
    "secure", "security", "update", "confirm",
    "account", "banking", "paypal", "apple",
    "google", "microsoft", "amazon", "facebook",
    "instagram", "netflix", "password", "credential",
    "webscr", "ebayisapi", "cmd=_login"
  ];

  const urlLower = full.toLowerCase();
  const matchedKw = suspiciousKeywords.filter(kw => urlLower.includes(kw));
  if (matchedKw.length >= 3) {
    score += 20;
    reasons.push(`Many phishing keywords in URL: ${matchedKw.slice(0,4).join(", ")}`);
  } else if (matchedKw.length > 0) {
    score += matchedKw.length * 5;
    reasons.push(`Suspicious keyword(s) in URL: ${matchedKw.join(", ")}`);
  }

  // 7. Brand mismatch – brand name in path/subdomain but NOT in registrable domain
  const brands = [
    "paypal", "apple", "google", "microsoft", "amazon",
    "facebook", "instagram", "netflix", "chase", "wells",
    "bankofamerica", "citibank", "ebay", "dropbox"
  ];

  // Extract registrable domain (last two labels, e.g. "evil.com")
  const parts = hostname.split(".");
  const registrableDomain = parts.slice(-2).join(".").toLowerCase();

  brands.forEach(brand => {
    const inFull = urlLower.includes(brand);
    const inRegistrable = registrableDomain.includes(brand);
    if (inFull && !inRegistrable) {
      score += 25;
      reasons.push(`Brand "${brand}" appears in URL but not in registrable domain (spoofing)`);
    }
  });

  // 8. Double slash (redirect trick)
  if (/https?:\/\/.+\/\/.+/.test(full)) {
    score += 10;
    reasons.push("Double slashes detected in URL path (redirect trick)");
  }

  // 9. Non-standard port
  if (url.port && !["80", "443", ""].includes(url.port)) {
    score += 10;
    reasons.push(`Non-standard port in URL: ${url.port}`);
  }

  // 10. Hex / percent-encoded characters (obfuscation)
  const encodedChars = (full.match(/%[0-9a-fA-F]{2}/g) || []).length;
  if (encodedChars > 5) {
    score += 12;
    reasons.push(`Heavy URL encoding detected (${encodedChars} encoded chars)`);
  }

  // 11. HTTP (not HTTPS) — small flag only (HTTPS can still be phishing)
  if (url.protocol === "http:") {
    score += 5;
    reasons.push("Page served over plain HTTP (not HTTPS)");
  }

  return { score, reasons };
}

// ─────────────────────────────────────────────
//  DOM Heuristics
// ─────────────────────────────────────────────
function scoreDOM(dom) {
  let score = 0;
  const reasons = [];

  // 1. Password input field
  if (dom.hasPasswordField) {
    score += 15;
    reasons.push("Page contains a password input field");
  }

  // 2. Hidden inputs
  if (dom.hiddenInputCount > 5) {
    score += 12;
    reasons.push(`Many hidden inputs (${dom.hiddenInputCount}) – common in phishing forms`);
  } else if (dom.hiddenInputCount > 2) {
    score += 6;
    reasons.push(`${dom.hiddenInputCount} hidden inputs detected`);
  }

  // 3. Form submitting to a different domain
  if (dom.externalFormAction) {
    score += 25;
    reasons.push(`Form submits to external domain: ${dom.externalFormAction}`);
  }

  // 4. Multiple sensitive input fields
  if (dom.sensitiveInputCount >= 3) {
    score += 18;
    reasons.push(`${dom.sensitiveInputCount} sensitive inputs (email/user/phone/card) on page`);
  } else if (dom.sensitiveInputCount === 2) {
    score += 8;
    reasons.push("Multiple sensitive data inputs detected");
  }

  // 5. Fake login UI keywords in visible text
  if (dom.hasSensitiveText) {
    score += 10;
    reasons.push("Page text contains credential/verification prompts");
  }

  // 6. No favicon (common in hastily-made phishing pages)
  if (dom.noFavicon) {
    score += 5;
    reasons.push("No favicon detected");
  }

  // 7. Disabled right-click / context menu
  if (dom.disabledContextMenu) {
    score += 8;
    reasons.push("Right-click / context menu is disabled");
  }

  // 8. iFrame usage (embedding another site)
  if (dom.iframeCount > 0) {
    score += dom.iframeCount * 5;
    reasons.push(`${dom.iframeCount} iFrame(s) detected on page`);
  }

  return { score, reasons };
}

// Export for use as a module (background.js) or global (content.js)
if (typeof module !== "undefined") {
  module.exports = { analyzeSignals, scoreURL, scoreDOM };
}
