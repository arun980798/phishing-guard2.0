(function () {
  "use strict"; //Self-running function (IIFE)

  // Prevent running multiple time at a time
  if (window.__phishGuardRan) return;
  window.__phishGuardRan = true;


  //collect dom things
  function collectDOMSignals() {
    const currentHost = location.hostname.toLowerCase();

    // check Password inputs
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    //check Hidden inputs
    const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
    //check Sensitive-data inputs (email, tel, text fields with sensitive names)
    const sensitiveNames =
      /user|email|mail|phone|mobile|card|credit|debit|cvv|pin|ssn|dob|birth/i;
    const sensitiveInputs = document.querySelectorAll(
      'input[type="text"], input[type="email"], input[type="tel"], input[type="number"]',
    );
    const matchedSensitive = Array.from(sensitiveInputs).filter((el) =>
      sensitiveNames.test(el.name + " " + el.id + " " + el.placeholder),
    );

    // Forms submitting to external domain
    let externalFormAction = null;
    const forms = document.querySelectorAll("form[action]"); //External Form Submission (VERY IMPORTANT)
    for (const form of forms) {
      try {
        //check hostnamae or from are same or not
        const actionURL = new URL(form.action, location.href);
        if (actionURL.hostname && actionURL.hostname !== currentHost) {
          //Converts form action into full URL
          externalFormAction = actionURL.hostname;
          break;
        }
      } catch {}
    }

    // Sensitive body text
    const bodyText = (document.body && document.body.innerText) || "";
    const sensitiveTextPattern = //check Suspicious Text
      /verify your (account|identity|email|password|card)|enter your (password|credentials|social security|credit card|otp)|your account (has been|will be) (suspended|locked|limited)/i;
    const hasSensitiveText = sensitiveTextPattern.test(bodyText);

    // check favicon presence
    const favLinks = document.querySelectorAll('link[rel*="icon"]');
    const noFavicon = favLinks.length === 0;

    // Context menu disabled
    let disabledContextMenu = false;
    // We can't directly check listeners, but inline attribute is detectable
    if (
      document.body &&
      document.body.getAttribute("oncontextmenu") &&
      document.body.getAttribute("oncontextmenu").includes("return false") //Disabled Right Click
    ) {
      disabledContextMenu = true;
    } //this code make problem   thats why we add this

    // iFrames
    const iframes = document.querySelectorAll("iframe");

    return {
      hasPasswordField: passwordInputs.length > 0,
      hiddenInputCount: hiddenInputs.length,
      sensitiveInputCount: matchedSensitive.length,
      externalFormAction,

      hasSensitiveText,
      noFavicon,
      disabledContextMenu,
      iframeCount: iframes.length,
    }; //return this data
  }

  // ── 2. Send signals to background for scoring ─────────────
  const domSignals = collectDOMSignals();

  chrome.runtime.sendMessage(
    {
      type: "ANALYZE_PAGE",
      url: location.href,
      dom: domSignals,
    },
    (response) => {
      // in response we get score and verdict from background
      if (chrome.runtime.lastError) return; // Extension context may be gone
      if (!response) return;
      showPopup(response.score, response.verdict, response.reasons);
    },
  );

  // ── 3. Popup notification
  function showPopup(score, verdict, reasons) {
    // Remove any existing popup
    const existing = document.getElementById("__phishguard_popup__");
    if (existing) existing.remove();

    const popup = document.createElement("div");
    popup.id = "__phishguard_popup__";

    const colorMap = {
      safe: { bg: "#16a34a", border: "#15803d", icon: "✔", label: "Safe" },
      suspicious: {
        bg: "#d97706",
        border: "#b45309",
        icon: "⚠",
        label: "Suspicious",
      },
      phishing: {
        bg: "#dc2626",
        border: "#b91c1c",
        icon: "✖",
        label: "Phishing Risk",
      },
    };

    const c = colorMap[verdict] || colorMap.safe;

    popup.innerHTML = `
      <div class="pg-icon">${c.icon}</div>
      <div class="pg-body">
        <div class="pg-label">${c.label}</div>
        <div class="pg-score">Risk Score: ${score}/100</div>
      </div>
    `;

    // Inline critical styles so they survive any page reset
    Object.assign(popup.style, {
      position: "fixed",
      bottom: "20px",
      right: "20px",

      zIndex: "2147483647",
      display: "flex",
      alignItems: "center",
      gap: "10px",
      padding: "12px 18px",
      background: c.bg,
      border: `2px solid ${c.border}`,
      borderRadius: "10px",
      color: "#fff",
      fontFamily: "'Segoe UI', sans-serif",
      fontSize: "14px",
      boxShadow: "0 4px 20px rgba(0,0,0,0.35)",
      transition: "opacity 0.4s ease",
      opacity: "0",
      pointerEvents: "none",
    });

    document.body.appendChild(popup);

    // Fade in
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        popup.style.opacity = "1";
      });
    });

    // Duration: safe=600ms, suspicious=1000ms, phishing=1200ms
    const durations = { safe: 600, suspicious: 1000, phishing: 1200 };
    const duration = durations[verdict] || 800;

    setTimeout(() => {
      popup.style.opacity = "0";
      setTimeout(() => popup.remove(), 450);
    }, duration);
  }
})();
