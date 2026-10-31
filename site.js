/* Shared behaviour for every page: the theme switch, the contents list,
   back to top, and reveal-on-scroll. Pages declare their contents in a
   <script type="application/json" id="contents"> list of {id, label}. */
(function () {
  "use strict";
  const root = document.documentElement;
  const media = window.matchMedia("(prefers-color-scheme: dark)");

  /* ---------- Theme ---------- */
  function stored() { try { return localStorage.getItem("theme"); } catch (e) { return null; } }
  function apply(theme) {
    root.dataset.theme = theme;
    const b = document.querySelector(".theme-switch");
    if (b) { b.setAttribute("aria-pressed", String(theme === "dark")); b.querySelector(".sr").textContent = theme === "dark" ? "Switch to light mode" : "Switch to dark mode"; }
  }
  const sw = document.createElement("button");
  sw.type = "button"; sw.className = "theme-switch"; sw.setAttribute("aria-label", "Theme"); sw.innerHTML = '<span class="sr"></span>';
  sw.addEventListener("click", () => {
    const next = root.dataset.theme === "dark" ? "light" : "dark";
    try { localStorage.setItem("theme", next); } catch (e) { /* private mode */ }
    apply(next);
  });
  document.body.appendChild(sw);
  apply(root.dataset.theme || stored() || (media.matches ? "dark" : "light"));
  media.addEventListener("change", e => { if (!stored()) apply(e.matches ? "dark" : "light"); });

  /* ---------- Contents ---------- */
  const spec = document.getElementById("contents");
  let items = [];
  try { items = spec ? JSON.parse(spec.textContent) : []; } catch (e) { items = []; }
  // An item with an href is a plain link (to another page); one with an id is a section here.
  items = items.filter(i => i.href || document.getElementById(i.id));
  if (items.length) {
    const list = () => "<ol>" + items.map(i => i.href ? '<li class="away"><a href="' + i.href + '">' + i.label + "</a></li>"
      : '<li><a href="#' + i.id + '" data-target="' + i.id + '">' + i.label + "</a></li>").join("") + "</ol>";
    const aside = document.createElement("nav");
    aside.className = "contents"; aside.setAttribute("aria-label", "Contents");
    aside.innerHTML = '<p class="ttl">Contents</p>' + list() + '<a class="top" href="#top">Back to top</a>';
    document.body.appendChild(aside);
    const btn = document.createElement("button");
    btn.type = "button"; btn.className = "contents-btn"; btn.textContent = "Contents"; btn.setAttribute("aria-expanded", "false");
    const sheet = document.createElement("nav");
    sheet.className = "contents-sheet"; sheet.setAttribute("aria-label", "Contents");
    sheet.innerHTML = '<p class="ttl">On this page</p>' + list();
    document.body.appendChild(sheet); document.body.appendChild(btn);
    const close = () => { sheet.classList.remove("open"); btn.setAttribute("aria-expanded", "false"); };
    btn.addEventListener("click", () => { const open = !sheet.classList.contains("open"); sheet.classList.toggle("open", open); btn.setAttribute("aria-expanded", String(open)); });
    sheet.addEventListener("click", e => { if (e.target.closest("a")) close(); });
    document.addEventListener("click", e => { if (!e.target.closest(".contents-sheet, .contents-btn")) close(); });
    document.addEventListener("keydown", e => { if (e.key === "Escape") close(); });
    requestAnimationFrame(() => { aside.classList.add("ready"); btn.classList.add("ready"); });

    // Mark the section in view. The target nearest the top of the screen wins.
    const targets = items.filter(i => i.id).map(i => document.getElementById(i.id));
    function current() {
      let best = null, bestTop = -Infinity;
      targets.forEach(t => { const top = t.getBoundingClientRect().top; if (top <= 120 && top > bestTop) { best = t; bestTop = top; } });
      if (!best && window.scrollY < 10) best = null;
      document.querySelectorAll(".contents a, .contents-sheet a").forEach(a => {
        const on = best && a.dataset.target === best.id;
        if (on) a.setAttribute("aria-current", "true"); else a.removeAttribute("aria-current");
      });
    }
    let ticking = false;
    window.addEventListener("scroll", () => { if (!ticking) { ticking = true; requestAnimationFrame(() => { current(); ticking = false; }); } }, { passive: true });
    current();
  }

  /* ---------- Back to top ---------- */
  if (!document.getElementById("top")) { const a = document.createElement("span"); a.id = "top"; document.body.insertBefore(a, document.body.firstChild); }
  const top = document.createElement("button");
  top.type = "button"; top.className = "to-top"; top.textContent = "Top"; top.setAttribute("aria-label", "Back to top");
  top.addEventListener("click", () => window.scrollTo({ top: 0, behavior: "smooth" }));
  document.body.appendChild(top);
  const showTop = () => top.classList.toggle("show", window.scrollY > window.innerHeight * 0.9);
  window.addEventListener("scroll", showTop, { passive: true }); showTop();

  /* ---------- Reveal once when scrolled into view ---------- */
  if ("IntersectionObserver" in window) {
    const io = new IntersectionObserver(entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } }), { threshold: 0.2 });
    const watch = () => document.querySelectorAll("[data-reveal]:not(.in)").forEach(el => io.observe(el));
    watch();
    new MutationObserver(watch).observe(document.body, { childList: true, subtree: true });
  } else {
    document.querySelectorAll("[data-reveal]").forEach(el => el.classList.add("in"));
  }
})();
