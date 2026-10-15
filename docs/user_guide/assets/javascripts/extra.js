(function () {
  var KEY = "pf-focus";
  var ICON_HIDE = '<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 3h6v6"/><path d="M9 21H3v-6"/><path d="M21 3l-7 7"/><path d="M3 21l7-7"/></svg>';
  var ICON_SHOW = '<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 14h6v6"/><path d="M20 10h-6V4"/><path d="M14 10l7-7"/><path d="M3 21l7-7"/></svg>';

  function stored() {
    try {
      return localStorage.getItem(KEY) === "1";
    } catch (e) {
      return false;
    }
  }

  function store(on) {
    try {
      localStorage.setItem(KEY, on ? "1" : "0");
    } catch (e) {}
  }

  function label(btn, on) {
    var text = on ? "Show side panels" : "Hide side panels";
    btn.title = text;
    btn.setAttribute("aria-label", text);
    btn.setAttribute("aria-pressed", on ? "true" : "false");
    btn.innerHTML = on ? ICON_SHOW : ICON_HIDE;
  }

  function apply(on) {
    document.documentElement.classList.toggle("pf-focus", on);
    var btn = document.querySelector(".pf-focus-toggle");
    if (btn) label(btn, on);
  }

  function mount() {
    var on = stored();
    apply(on);
    if (document.querySelector(".pf-focus-toggle")) return;
    var header = document.querySelector(".md-header__inner");
    if (!header) return;
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "md-header__button md-icon pf-focus-toggle";
    label(btn, on);
    btn.addEventListener("click", function () {
      var next = !document.documentElement.classList.contains("pf-focus");
      store(next);
      apply(next);
    });
    var search = header.querySelector(".md-search");
    header.insertBefore(btn, search || null);
  }

  apply(stored());
  if (typeof window.document$ !== "undefined" && window.document$.subscribe) {
    window.document$.subscribe(mount);
  } else if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mount);
  } else {
    mount();
  }

  document.addEventListener("keydown", function (ev) {
    if (ev.key !== "\\" || ev.ctrlKey || ev.metaKey || ev.altKey) return;
    var t = ev.target;
    if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
    var next = !document.documentElement.classList.contains("pf-focus");
    store(next);
    apply(next);
  });
})();

(function () {
  var NS = "http://www.w3.org/2000/svg";
  var W = 480, H = 290, TOP = 62, BOTTOM = 30, SIDE = 12;

  function el(name, attrs, text) {
    var n = document.createElementNS(NS, name);
    for (var k in attrs) n.setAttribute(k, attrs[k]);
    if (text != null) n.textContent = text;
    return n;
  }

  function fmt(v) {
    return v >= 10 ? v.toFixed(1).replace(/\.0$/, "") : v.toFixed(1);
  }

  function render(box) {
    var labels = (box.dataset.labels || "").split(",");
    var values = (box.dataset.values || "").split(",").map(Number);
    if (!labels.length || labels.length !== values.length || values.some(isNaN)) return;
    var max = Math.max.apply(null, values) * 1.12;
    var slot = (W - 2 * SIDE) / values.length;
    var bw = slot * 0.62;
    var plot = H - TOP - BOTTOM;
    var unit = box.dataset.unit || "";
    var svg = el("svg", {
      viewBox: "0 0 " + W + " " + H,
      role: "img",
      "aria-label": box.dataset.title + ", in " + unit + "s: " +
        labels.map(function (l, i) { return l + " " + values[i]; }).join(", ")
    });
    svg.appendChild(el("text", { x: W / 2, y: 20, "class": "pf-chart-title" }, box.dataset.title));
    svg.appendChild(el("text", { x: W / 2, y: 42, "class": "pf-chart-unit" }, "(" + unit + "s)"));
    svg.appendChild(el("line", { x1: SIDE, x2: W - SIDE, y1: H - BOTTOM, y2: H - BOTTOM, "class": "pf-chart-axis" }));
    var bars = [];
    values.forEach(function (v, i) {
      var h = plot * v / max;
      var x = SIDE + slot * i + (slot - bw) / 2;
      var y = H - BOTTOM - h;
      var last = i === values.length - 1;
      var rect = el("rect", { x: x, y: y, width: bw, height: h, rx: 3, "class": "pf-chart-bar" + (last ? " pf-chart-bar--last" : "") });
      var val = el("text", { x: x + bw / 2, y: y - 6, "class": "pf-chart-value" }, fmt(v));
      svg.appendChild(rect);
      svg.appendChild(val);
      svg.appendChild(el("text", { x: x + bw / 2, y: H - BOTTOM + 18, "class": "pf-chart-label" }, labels[i]));
      bars.push({ rect: rect, val: val, v: v });
    });
    box.textContent = "";
    box.appendChild(svg);
    return bars;
  }

  function play(bars) {
    var step = 220;
    bars.forEach(function (b, i) {
      b.rect.classList.remove("pf-grow");
      b.val.classList.remove("pf-show");
      void b.rect.getBoundingClientRect();
      setTimeout(function () {
        b.rect.classList.add("pf-grow");
        var t0 = null;
        b.val.classList.add("pf-show");
        function tick(t) {
          if (t0 === null) t0 = t;
          var k = Math.min(1, (t - t0) / 600);
          b.val.textContent = fmt(b.v * k);
          if (k < 1) requestAnimationFrame(tick);
        }
        requestAnimationFrame(tick);
      }, i * step);
    });
  }

  function mountCharts() {
    var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    document.querySelectorAll(".pf-chart:not([data-ready])").forEach(function (box) {
      var bars = render(box);
      if (!bars) return;
      box.setAttribute("data-ready", "1");
      if (reduce) box.classList.add("pf-chart--fade");
      if (!("IntersectionObserver" in window)) {
        bars.forEach(function (b) { b.rect.classList.add("pf-grow", "pf-static"); b.val.classList.add("pf-show"); });
        return;
      }
      box.classList.add("pf-chart--animated");
      box.title = "Click to replay";
      box.addEventListener("click", function () { play(bars); });
      var io = new IntersectionObserver(function (entries) {
        if (entries[0].isIntersecting) {
          io.disconnect();
          play(bars);
        }
      }, { threshold: 0.4 });
      io.observe(box);
    });
  }

  if (typeof window.document$ !== "undefined" && window.document$.subscribe) {
    window.document$.subscribe(mountCharts);
  } else if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mountCharts);
  } else {
    mountCharts();
  }
})();

(function () {
  var NS = "http://www.w3.org/2000/svg";

  function el(name, attrs, text) {
    var n = document.createElementNS(NS, name);
    for (var k in attrs) n.setAttribute(k, attrs[k]);
    if (text != null) n.textContent = text;
    return n;
  }

  function box(svg, x, y, w, h, cls, name, sub, textCls) {
    svg.appendChild(el("rect", { x: x, y: y, width: w, height: h, rx: 10, "class": "pf-flow-box " + cls }));
    svg.appendChild(el("text", { x: x + w / 2, y: y + h / 2 - 4, "class": "pf-flow-name " + (textCls || "") }, name));
    svg.appendChild(el("text", { x: x + w / 2, y: y + h / 2 + 16, "class": "pf-flow-sub " + (textCls || "") }, sub));
  }

  function chip(svg, kind, anim, label) {
    var g = el("g", { "class": "pf-flow-chip pf-flow-chip--" + kind + " pf-flow-anim " + anim });
    g.appendChild(el("rect", { x: -54, y: -13, width: 108, height: 26, rx: 13 }));
    g.appendChild(el("text", { x: 0, y: 1 }, label));
    svg.appendChild(g);
  }

  var WIDE = {
    view: "0 0 900 280",
    agent: [20, 105, 170, 90], pf: [370, 100, 160, 100], ok: [720, 30, 160, 72], bad: [720, 194, 160, 72],
    lines: [[190, 150, 370, 150], [530, 135, 720, 70], [530, 165, 720, 228]],
    a: [110, 150], p: [450, 150], k: [790, 66], m: [612, 190],
    check: [872, 30], x: [612, 156], refused: [612, 228], alert: [450, 83]
  };
  var TALL = {
    view: "0 0 400 560",
    agent: [115, 20, 170, 70], pf: [120, 220, 160, 90], ok: [10, 466, 170, 72], bad: [220, 466, 170, 72],
    lines: [[200, 90, 200, 220], [170, 310, 95, 466], [230, 310, 305, 466]],
    a: [200, 55], p: [200, 265], k: [95, 502], m: [266, 392],
    check: [172, 466], x: [266, 358], refused: [266, 428], alert: [200, 196]
  };

  function draw(root) {
    var L = root.clientWidth < 560 ? TALL : WIDE;
    var svg = el("svg", {
      viewBox: L.view,
      role: "img",
      "aria-label": "Animation: the agent sends a placeholder; Pi Fortress swaps in the real key for its own service, and refuses the placeholder sent to any other server."
    });
    if (L === TALL) svg.setAttribute("class", "pf-flow--tall");
    var vars = {
      ax: L.a[0], ay: L.a[1], px: L.p[0], py: L.p[1], kx: L.k[0], ky: L.k[1], mx: L.m[0], my: L.m[1],
      apx: (L.a[0] + L.p[0]) / 2, apy: (L.a[1] + L.p[1]) / 2, pkx: (L.p[0] + L.k[0]) / 2, pky: (L.p[1] + L.k[1]) / 2
    };
    var style = "";
    for (var v in vars) style += "--" + v + ":" + vars[v] + "px;";
    svg.setAttribute("style", style);
    var defs = el("defs", {});
    var grad = el("linearGradient", { id: "pf-shield", x1: 0, y1: 0, x2: 0, y2: 1 });
    grad.appendChild(el("stop", { offset: 0, "stop-color": "#93c5fd" }));
    grad.appendChild(el("stop", { offset: 1, "stop-color": "#60a5fa" }));
    defs.appendChild(grad);
    svg.appendChild(defs);
    L.lines.forEach(function (l) {
      svg.appendChild(el("line", { x1: l[0], y1: l[1], x2: l[2], y2: l[3], "class": "pf-flow-line" }));
    });
    chip(svg, "ph", "pf-a1", "placeholder");
    chip(svg, "key", "pf-a2", "real key");
    chip(svg, "ph", "pf-a3", "placeholder");
    chip(svg, "bad", "pf-a4", "placeholder");
    box(svg, L.agent[0], L.agent[1], L.agent[2], L.agent[3], "pf-flow-box--agent", "AI agent", "holds only placeholders");
    box(svg, L.pf[0], L.pf[1], L.pf[2], L.pf[3], "pf-flow-box--pf", "Pi Fortress", "swaps or refuses", "pf-flow-pf-text");
    box(svg, L.ok[0], L.ok[1], L.ok[2], L.ok[3], "pf-flow-box--ok", "Claude API", "the key's own service");
    box(svg, L.bad[0], L.bad[1], L.bad[2], L.bad[3], "pf-flow-box--bad", "evil.example", "the attacker's server");
    var ok = el("g", { "class": "pf-flow-anim pf-ok" });
    ok.appendChild(el("circle", { cx: L.check[0], cy: L.check[1], r: 14, "class": "pf-flow-ok" }));
    ok.appendChild(el("text", { x: L.check[0], y: L.check[1] + 5, "class": "pf-flow-mark", fill: "#fff" }, "\u2713"));
    svg.appendChild(ok);
    var x = el("g", { "class": "pf-flow-anim pf-x" });
    x.appendChild(el("circle", { cx: L.x[0], cy: L.x[1], r: 14, "class": "pf-flow-x" }));
    x.appendChild(el("text", { x: L.x[0], y: L.x[1] + 5, "class": "pf-flow-mark", fill: "#fff" }, "\u2715"));
    x.appendChild(el("text", { x: L.refused[0], y: L.refused[1], "class": "pf-flow-mark pf-flow-x" }, "refused"));
    x.appendChild(el("rect", { x: L.alert[0] - 45, y: L.alert[1] - 11, width: 90, height: 22, rx: 11, "class": "pf-flow-alert" }));
    x.appendChild(el("text", { x: L.alert[0], y: L.alert[1] + 4, "class": "pf-flow-mark", fill: "#fff" }, "alert sent"));
    svg.appendChild(x);
    root.insertBefore(svg, root.firstChild);
    return L;
  }

  function mountFlows() {
    document.querySelectorAll(".pf-flow:not([data-ready])").forEach(function (root) {
      root.setAttribute("data-ready", "1");
      var layout = draw(root);
      root.classList.add("pf-play");
      var toggle = function () { root.classList.toggle("pf-paused"); };
      var wire = function () {
        var svg = root.querySelector("svg");
        svg.setAttribute("tabindex", "0");
        svg.appendChild(el("title", {}, "Click to pause or play"));
        svg.addEventListener("click", toggle);
        svg.addEventListener("keydown", function (ev) {
          if (ev.key === " " || ev.key === "Enter") {
            ev.preventDefault();
            toggle();
          }
        });
      };
      wire();
      var timer = null;
      window.addEventListener("resize", function () {
        clearTimeout(timer);
        timer = setTimeout(function () {
          if (!root.isConnected) return;
          var want = root.clientWidth < 560 ? TALL : WIDE;
          if (want === layout) return;
          root.removeChild(root.querySelector("svg"));
          layout = draw(root);
          wire();
        }, 200);
      });
    });
  }

  if (typeof window.document$ !== "undefined" && window.document$.subscribe) {
    window.document$.subscribe(mountFlows);
  } else if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mountFlows);
  } else {
    mountFlows();
  }
})();
