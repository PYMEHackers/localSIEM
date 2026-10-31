"use strict";

// Applied before the first paint so the page never flashes the other theme.
// Loaded as a file because the Content-Security-Policy forbids inline
// scripts. Without an explicit choice the page follows the system theme, also
// when it changes while the page is open.
(function fBootTheme() {
  let vTheme = null;
  try {
    vTheme = window.localStorage.getItem("localsiem.theme");
  } catch (vError) {
    vTheme = null;
  }
  if (vTheme !== "light" && vTheme !== "dark") {
    vTheme = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  document.documentElement.setAttribute("data-theme", vTheme);
})();
