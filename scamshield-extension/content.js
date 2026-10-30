// Intercept all link clicks across the page
document.addEventListener("click", async function (event) {
  const anchor = event.target.closest("a");
  if (!anchor || !anchor.href) return;

  const targetUrl = anchor.href;

  // Skip intra-page anchors, void links, mailto, and tel
  if (
    targetUrl.startsWith("#") ||
    targetUrl.startsWith("javascript:") ||
    targetUrl.startsWith("mailto:") ||
    targetUrl.startsWith("tel:")
  ) {
    return;
  }

  // 1. CRITICAL: Prevent navigation IMMEDIATELY (synchronously)
  event.preventDefault();
  event.stopImmediatePropagation();

  try {
    // 2. Query ScamShield Python API
    const response = await fetch("http://localhost:8000/check-url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: targetUrl }),
    });

    const data = await response.json();

    if (data.is_scam) {
      // 3. If it's a SCAM: Keep navigation blocked and show the persistent modal
      showWarningPopup(targetUrl, data.risk_score, data.warning_signs, anchor.target);
    } else {
      // 4. If it's SAFE: Resume navigation normally
      navigateSafely(targetUrl, anchor.target);
    }
  } catch (err) {
    console.warn("ScamShield backend offline or unreachable. Allowing navigation.");
    navigateSafely(targetUrl, anchor.target);
  }
}, true);

function navigateSafely(url, target) {
  if (target === "_blank") {
    window.open(url, "_blank");
  } else {
    window.location.href = url;
  }
}

function showWarningPopup(url, score, reasons, target) {
  const existing = document.getElementById("scamshield-modal");
  if (existing) existing.remove();

  const modal = document.createElement("div");
  modal.id = "scamshield-modal";
  modal.innerHTML = `
    <div class="scamshield-card">
      <div class="scamshield-header">
        <span style="font-size: 1.8rem;">🚨</span>
        <h3 style="margin: 0; color: #ff6b6b; font-size: 1.25rem;">ScamShield Warning: Suspicious Link</h3>
      </div>
      <p style="word-break: break-all; font-size: 0.9rem; color: #94a3b8; margin: 10px 0;">
        <strong>Target:</strong> ${url}
      </p>
      <p style="font-size: 1rem; margin: 10px 0;">
        <strong>Risk Score:</strong> <span style="color:#ff4b4b; font-weight:bold;">${score} / 100</span>
      </p>
      <div style="margin: 14px 0; font-size: 0.9rem; line-height: 1.5; color: #cbd5e1;">
        <strong>Detected Red Flags:</strong>
        <ul style="padding-left: 20px; margin-top: 6px;">
          ${reasons.map(r => `<li>${r}</li>`).join("")}
        </ul>
      </div>
      <div style="display: flex; gap: 12px; margin-top: 20px;">
        <button id="scamshield-cancel-btn" style="background:#22c55e; color:white; border:none; padding:10px 16px; border-radius:6px; cursor:pointer; font-weight:bold;">
          Stay on this page (Recommended)
        </button>
        <button id="scamshield-proceed-btn" style="background:transparent; color:#94a3b8; border:1px solid #475569; padding:10px 16px; border-radius:6px; cursor:pointer;">
          Proceed anyway (Unsafe)
        </button>
      </div>
    </div>
  `;

  document.body.appendChild(modal);

  // Close popup and stay safely on the current page
  document.getElementById("scamshield-cancel-btn").onclick = function () {
    modal.remove();
  };

  // Only proceed if user explicitly overrides the warning
  document.getElementById("scamshield-proceed-btn").onclick = function () {
    modal.remove();
    navigateSafely(url, target);
  };
}
// ==========================================
// REAL-TIME WHATSAPP WEB MESSAGE SCANNER
// ==========================================
if (window.location.hostname === "web.whatsapp.com") {
  console.log("🛡️ ScamShield WhatsApp Web Scanner Active");

  // Watch for incoming chat bubbles
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType === 1) {
          // Look for text spans inside WhatsApp chat bubbles
          const textElements = node.querySelectorAll(".selectable-text span");
          textElements.forEach(async (el) => {
            const messageText = el.innerText?.trim();

            // Ignore short greetings or empty text
            if (!messageText || messageText.length < 15) return;
            if (el.dataset.scamshieldChecked) return;
            el.dataset.scamshieldChecked = "true";

            try {
              // Send message to local Python API
              const res = await fetch("http://localhost:8000/check-text", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ text: messageText }),
              });
              const data = await res.json();

              if (data.is_scam) {
                // Highlight the message bubble in red
                const bubble = el.closest(".message-in") || el.parentElement;
                bubble.style.border = "2px solid #ef4444";
                bubble.style.backgroundColor = "rgba(239, 68, 68, 0.15)";
                bubble.style.borderRadius = "8px";

                // Attach alert badge
                const badge = document.createElement("div");
                badge.style.color = "#ef4444";
                badge.style.fontWeight = "bold";
                badge.style.fontSize = "0.85rem";
                badge.style.marginTop = "4px";
                badge.innerText = `🚨 ScamShield Alert (${data.risk_score}/100): ${data.reasons[0] || "Potential Fraud"}`;
                bubble.appendChild(badge);
              }
            } catch (e) {
              // API offline
            }
          });
        }
      }
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });
}