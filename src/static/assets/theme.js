/* theme.js - the light/dark switch, and the only script on this site.
   It keeps one value ("theme") in this browser's localStorage and sets
   data-theme on the page. Nothing is sent anywhere. Without it, the page
   follows the device setting and the switch stays hidden. */
(function () {
  var root = document.documentElement;

  try {
    var saved = localStorage.getItem("theme");
    if (saved === "light" || saved === "dark") root.setAttribute("data-theme", saved);
  } catch (e) {}

  function current() {
    var t = root.getAttribute("data-theme");
    if (t === "light" || t === "dark") return t;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function label(button) {
    var dark = current() === "light";
    button.textContent = dark ? "Dark" : "Light";
    button.setAttribute("aria-label", dark ? "Switch to dark theme" : "Switch to light theme");
  }

  document.addEventListener("DOMContentLoaded", function () {
    var buttons = document.querySelectorAll("[data-theme-toggle]");
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].removeAttribute("hidden");
      label(buttons[i]);
      buttons[i].addEventListener("click", function () {
        var next = current() === "dark" ? "light" : "dark";
        root.setAttribute("data-theme", next);
        try { localStorage.setItem("theme", next); } catch (e) {}
        for (var j = 0; j < buttons.length; j++) label(buttons[j]);
      });
    }
  });
})();
