// reveal.js — inline secret-value reveal for the admin portal.
//
// Hooks any <form data-reveal action="...reveal" method="POST"> in the page.
// On submit, intercepts and POSTs with X-Reveal-Fragment: 1, then injects the
// returned HTML fragment into the matching [data-reveal-target-row][data-reveal-id]
// element. Without JS the form falls through to the dedicated value page —
// graceful degradation.
//
// Mitigations vs. a naive inline-reveal:
//   1. Single-reveal-at-a-time — revealing X auto-hides any other revealed row.
//   2. Auto-hide timer — 30s after a reveal the DOM is scrubbed.
//   3. Visibility-loss hide — switching tab / minimising window scrubs immediately.
//   4. Copy-then-hide — clicking Copy writes to clipboard, flashes "Copied",
//      then hides the row.
(function () {
  "use strict";

  var HIDE_AFTER_MS = 30000;
  var activeRow = null;
  var activeTimer = null;

  function clearTimer() {
    if (activeTimer) {
      clearTimeout(activeTimer);
      activeTimer = null;
    }
  }

  function hideActive() {
    clearTimer();
    if (!activeRow) return;
    var target = activeRow.querySelector("[data-reveal-target]");
    if (target) target.innerHTML = "";
    activeRow.hidden = true;
    activeRow = null;
  }

  function findTargetRow(form) {
    var id = form.getAttribute("data-reveal-id");
    if (!id) return null;
    return document.querySelector(
      '[data-reveal-target-row][data-reveal-id="' + cssEscape(id) + '"]'
    );
  }

  function cssEscape(s) {
    if (window.CSS && CSS.escape) return CSS.escape(s);
    return s.replace(/[^a-zA-Z0-9_-]/g, "\\$&");
  }

  document.addEventListener("submit", async function (e) {
    var form = e.target.closest("form[data-reveal]");
    if (!form) return;
    e.preventDefault();

    var row = findTargetRow(form);
    if (!row) return; // no target → fall back is impossible from here; bail

    // Toggle off if this row is the active one.
    if (activeRow === row) {
      hideActive();
      return;
    }

    // Mitigation 1: single-reveal — drop whatever was previously visible.
    hideActive();

    var btn = form.querySelector("button[type=submit]");
    var origLabel = btn ? btn.textContent : null;
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Loading…";
    }

    try {
      var resp = await fetch(form.action, {
        method: "POST",
        headers: { "X-Reveal-Fragment": "1" },
        credentials: "same-origin",
      });
      if (!resp.ok) {
        alert("Reveal failed (" + resp.status + ")");
        return;
      }
      var html = await resp.text();
      var target = row.querySelector("[data-reveal-target]");
      if (!target) return;
      target.innerHTML = html;
      row.hidden = false;
      activeRow = row;
      // Mitigation 2: auto-hide timer.
      clearTimer();
      activeTimer = setTimeout(hideActive, HIDE_AFTER_MS);
    } catch (err) {
      alert("Reveal failed: " + (err && err.message ? err.message : err));
    } finally {
      if (btn) {
        btn.disabled = false;
        if (origLabel != null) btn.textContent = origLabel;
      }
    }
  });

  // Mitigation 3: hide on tab/window visibility loss.
  document.addEventListener("visibilitychange", function () {
    if (document.hidden) hideActive();
  });

  // Hide button + Copy button (delegated, scoped to the active reveal row).
  document.addEventListener("click", async function (e) {
    var hideBtn = e.target.closest("[data-reveal-hide]");
    if (hideBtn) {
      hideActive();
      return;
    }
    var copyBtn = e.target.closest("[data-reveal-copy]");
    if (!copyBtn) return;

    var card = copyBtn.closest(".reveal-card") || activeRow;
    if (!card) return;
    var textEl = card.querySelector("[data-reveal-text]");
    if (!textEl) return;

    try {
      await navigator.clipboard.writeText(textEl.textContent);
      var orig = copyBtn.textContent;
      copyBtn.textContent = "Copied";
      // Mitigation 4: copy-then-hide. Brief flash, then scrub.
      setTimeout(function () {
        copyBtn.textContent = orig;
        hideActive();
      }, 800);
    } catch (err) {
      alert("Copy failed: " + (err && err.message ? err.message : err));
    }
  });
})();
