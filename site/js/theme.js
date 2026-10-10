// Runs before the page paints: the stored theme, and the `js` class the
// stylesheet uses to lay out script-driven pages. A classic script, so it
// blocks rendering for the few lines it takes.
(function () {
  var d = document.documentElement;
  d.classList.add("js");
  try {
    var t = localStorage.getItem("swarmchase.theme");
    if (t === "light" || t === "dark") d.setAttribute("data-theme", t);
  } catch (e) {}
})();
