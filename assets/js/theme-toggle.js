(function() {
  const storageKey = "hunt-sage-theme";
  const classDark = "hs-theme-dark";
  const classLight = "hs-theme-light";

  function applyTheme(theme) {
    document.documentElement.classList.remove(classDark, classLight);
    document.documentElement.classList.add(theme === "light" ? classLight : classDark);
  }

  function initTheme() {
    const stored = localStorage.getItem(storageKey);
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    const theme = stored || (prefersDark ? "dark" : "light");
    applyTheme(theme);
  }

  function toggleTheme() {
    const current = document.documentElement.classList.contains(classLight) ? "light" : "dark";
    const next = current === "light" ? "dark" : "light";
    localStorage.setItem(storageKey, next);
    applyTheme(next);
  }

  document.addEventListener("DOMContentLoaded", function() {
    initTheme();
    const btn = document.querySelector("[data-hs-theme-toggle]");
    if (btn) {
      btn.addEventListener("click", toggleTheme);
    }
  });
})();
