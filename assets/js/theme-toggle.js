/* Hunt-Sage: theme toggle (dark default), applied before first paint. */
(function () {
  var KEY = "hunt-sage-theme";
  var root = document.documentElement;

  function apply(theme) {
    root.classList.remove("hs-theme-dark", "hs-theme-light");
    root.classList.add(theme === "light" ? "hs-theme-light" : "hs-theme-dark");
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", theme === "light" ? "#F5F7FB" : "#0A0F1F");
    var btn = document.querySelector("[data-hs-theme-toggle]");
    if (btn) {
      btn.setAttribute("aria-pressed", theme === "light" ? "true" : "false");
      btn.setAttribute("title", theme === "light" ? "Switch to dark theme" : "Switch to light theme");
    }
  }

  function current() {
    try {
      var stored = localStorage.getItem(KEY);
      if (stored === "light" || stored === "dark") return stored;
    } catch (e) { /* storage unavailable */ }
    return "dark"; // the site is designed dark-first
  }

  // Apply immediately (this script is in <head>) to avoid a flash of the wrong theme.
  apply(current());

  document.addEventListener("DOMContentLoaded", function () {
    apply(current());
    var btn = document.querySelector("[data-hs-theme-toggle]");
    if (!btn) return;
    btn.addEventListener("click", function () {
      var next = root.classList.contains("hs-theme-light") ? "dark" : "light";
      try { localStorage.setItem(KEY, next); } catch (e) { /* ignore */ }
      // brief, deliberate cross-fade on the big surfaces only while switching
      root.classList.add("hs-switching");
      apply(next);
      window.setTimeout(function () { root.classList.remove("hs-switching"); }, 360);
    });
  });
})();
