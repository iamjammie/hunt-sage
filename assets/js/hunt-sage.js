/* Hunt-Sage page enhancements:
 *  - copy button + language tag on fenced code blocks
 *  - ATT&CK technique ids in tables/lists become links to attack.mitre.org
 *  - ★ difficulty ratings get a consistent style
 *  - live row filter for large tables (.hs-filter)
 *  - learning-path progress (localStorage, per browser)
 *  - playbook finder ("what can I hunt with my data?") and the maturity self-assessment
 * No tracking, no network calls, no dependencies. Everything degrades to plain HTML without JS.
 */
(function () {
  "use strict";

  /* ---------------------------------------------------------------- helpers */
  function $(sel, root) { return (root || document).querySelector(sel); }
  function $all(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function el(tag, attrs, children) {
    var e = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      if (k === "text") e.textContent = attrs[k];
      else if (k === "html") e.innerHTML = attrs[k];
      else if (k === "class") e.className = attrs[k];
      else e.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) { if (c) e.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return e;
  }
  var store = {
    get: function (k, fallback) { try { var v = localStorage.getItem(k); return v === null ? fallback : JSON.parse(v); } catch (e) { return fallback; } },
    set: function (k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) { /* private mode etc. */ } }
  };
  function escapeHtml(s) { return String(s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }

  /* ------------------------------------------------------------ code blocks */
  var LANG_LABELS = {
    kql: "KQL", spl: "SPL", powershell: "PowerShell", bash: "bash", sh: "sh", yaml: "YAML", yml: "YAML",
    text: "text", json: "JSON", python: "Python", sql: "SQL", xml: "XML", ini: "ini", console: "console",
    plaintext: "text", shell: "shell", cmd: "cmd", batch: "batch", regex: "regex", markdown: "Markdown", md: "Markdown"
  };

  function enhanceCodeBlocks(scope) {
    $all("div.highlighter-rouge", scope).forEach(function (div) {
      var m = /language-([a-z0-9_+-]+)/i.exec(div.className);
      if (m) div.setAttribute("data-lang", LANG_LABELS[m[1].toLowerCase()] || m[1]);
      if (div.querySelector(".hs-copy")) return;
      var pre = div.querySelector("pre");
      if (!pre) return;
      var btn = el("button", { type: "button", "class": "hs-copy", text: "Copy", "aria-label": "Copy code to clipboard" });
      btn.addEventListener("click", function () {
        var text = pre.innerText.replace(/\n$/, "");
        var done = function () {
          btn.textContent = "Copied";
          btn.classList.add("is-done");
          setTimeout(function () { btn.textContent = "Copy"; btn.classList.remove("is-done"); }, 1600);
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
        } else {
          fallbackCopy(text); done();
        }
      });
      div.appendChild(btn);
    });
  }

  function fallbackCopy(text) {
    var ta = el("textarea", { readonly: "" });
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.top = "-1000px";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); } catch (e) { /* ignore */ }
    document.body.removeChild(ta);
  }

  /* ------------------------------------------------------------ ATT&CK ids */
  var ATTACK_RE = /\b(TA\d{4}|T\d{4}(?:\.\d{3})?)\b/g;
  var SKIP = { A: 1, CODE: 1, PRE: 1, SCRIPT: 1, STYLE: 1, BUTTON: 1, H1: 1, H2: 1, H3: 1, H4: 1, H5: 1, H6: 1, INPUT: 1, TEXTAREA: 1 };

  function attackUrl(id) {
    if (id.charAt(1) === "A") return "https://attack.mitre.org/tactics/" + id + "/";
    return "https://attack.mitre.org/techniques/" + id.replace(".", "/") + "/";
  }

  function linkAttackIds(root) {
    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode: function (node) {
        if (!ATTACK_RE.test(node.nodeValue)) return NodeFilter.FILTER_REJECT;
        ATTACK_RE.lastIndex = 0;
        for (var e = node.parentNode; e && e !== root; e = e.parentNode) {
          if (SKIP[e.nodeName] || (e.classList && e.classList.contains("hs-no-attack-links"))) return NodeFilter.FILTER_REJECT;
        }
        return NodeFilter.FILTER_ACCEPT;
      }
    });
    var nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    nodes.forEach(function (node) {
      var text = node.nodeValue, frag = document.createDocumentFragment(), last = 0, m;
      ATTACK_RE.lastIndex = 0;
      while ((m = ATTACK_RE.exec(text)) !== null) {
        frag.appendChild(document.createTextNode(text.slice(last, m.index)));
        frag.appendChild(el("a", { "class": "hs-attack", href: attackUrl(m[1]), target: "_blank", rel: "noopener", title: "Open " + m[1] + " on attack.mitre.org", text: m[1] }));
        last = m.index + m[0].length;
      }
      frag.appendChild(document.createTextNode(text.slice(last)));
      node.parentNode.replaceChild(frag, node);
    });
  }

  function styleStars(root) {
    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode: function (n) {
        return /^[★☆]{3}$/.test(n.nodeValue.trim()) && n.parentNode.nodeName !== "SPAN" ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
      }
    });
    var nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    nodes.forEach(function (n) {
      var span = el("span", { "class": "hs-stars", "aria-label": "difficulty " + (n.nodeValue.split("★").length - 1) + " of 3", text: n.nodeValue.trim() });
      n.parentNode.replaceChild(span, n);
    });
  }

  /* ----------------------------------------------------------- table filter
   * <div class="hs-filter" data-hs-filter data-placeholder="..."></div>
   * Filters every table that follows it inside the article. Terms are ANDed; a term can be
   * quoted. Sections whose tables lose every row are collapsed (heading + intro text hidden).
   */
  function headingLevel(node) { var m = /^H([1-6])$/.exec(node.nodeName); return m ? +m[1] : 0; }

  function setupFilters(content) {
    $all(".hs-filter[data-hs-filter]", content).forEach(function (box) {
      if (box.querySelector("input")) return;
      var input = el("input", { type: "search", "class": "hs-filter__input", placeholder: box.getAttribute("data-placeholder") || "Filter...", "aria-label": "Filter table rows", autocomplete: "off", spellcheck: "false" });
      var count = el("span", { "class": "hs-filter__count", "aria-live": "polite" });
      var clear = el("button", { type: "button", "class": "hs-filter__clear", text: "Clear", title: "Clear filter" });
      box.appendChild(input); box.appendChild(count); box.appendChild(clear);

      if (box.getAttribute("data-hs-filter") === "sections") { setupSectionFilter(box, input, count, clear, content); return; }
      var tables = $all("table", content).filter(function (t) {
        return box.compareDocumentPosition(t) & Node.DOCUMENT_POSITION_FOLLOWING;
      });
      var total = tables.reduce(function (n, t) { return n + $all("tbody tr", t).length; }, 0);
      var rows = [];
      tables.forEach(function (t) {
        $all("tbody tr", t).forEach(function (tr) { rows.push({ tr: tr, text: tr.textContent.toLowerCase().replace(/\s+/g, " ") }); });
      });
      count.textContent = total + " rows";

      function terms(q) {
        var out = [], re = /"([^"]+)"|(\S+)/g, m;
        while ((m = re.exec(q)) !== null) out.push((m[1] || m[2]).toLowerCase());
        return out;
      }

      function collapseSections(active) {
        // Walk the article's direct children; hide a heading (and non-table nodes under it) when every table under it is hidden.
        var kids = Array.prototype.slice.call(content.children);
        kids.forEach(function (k) { k.classList.remove("hs-filter-hidden"); });
        if (!active) return;
        for (var i = 0; i < kids.length; i++) {
          var lvl = headingLevel(kids[i]);
          if (!lvl || !(box.compareDocumentPosition(kids[i]) & Node.DOCUMENT_POSITION_FOLLOWING)) continue;
          var j = i + 1, section = [], hasTable = false, visibleTable = false;
          while (j < kids.length && !(headingLevel(kids[j]) && headingLevel(kids[j]) <= lvl)) {
            section.push(kids[j]);
            if (kids[j].nodeName === "TABLE") { hasTable = true; if (!kids[j].classList.contains("hs-filter-hidden")) visibleTable = true; }
            j++;
          }
          if (hasTable && !visibleTable) { kids[i].classList.add("hs-filter-hidden"); section.forEach(function (s) { s.classList.add("hs-filter-hidden"); }); }
        }
      }

      function apply() {
        var q = terms(input.value.trim());
        var shown = 0;
        rows.forEach(function (r) {
          var ok = q.every(function (t) { return r.text.indexOf(t) !== -1; });
          r.tr.classList.toggle("hs-filter-hidden", !ok);
          if (ok) shown++;
        });
        tables.forEach(function (t) {
          var any = $all("tbody tr", t).some(function (tr) { return !tr.classList.contains("hs-filter-hidden"); });
          t.classList.toggle("hs-filter-hidden", !any);
        });
        collapseSections(q.length > 0);
        count.textContent = q.length ? shown + " of " + total + " rows" : total + " rows";
        box.classList.toggle("is-active", q.length > 0);
      }
      input.addEventListener("input", apply);
      clear.addEventListener("click", function () { input.value = ""; apply(); input.focus(); });
      input.addEventListener("keydown", function (e) { if (e.key === "Escape") { input.value = ""; apply(); } });
      // allow ?q= deep links, e.g. /cheatsheets/windows-event-ids/?q=4624
      try {
        var q = new URLSearchParams(location.search).get("q");
        if (q) { input.value = q; apply(); }
      } catch (e) { /* ignore */ }
    });
  }

  /* Section mode: data-hs-filter="sections" filters the h3 (or h4) sections that follow the box,
   * matching against the whole section text (headings, prose and code), and hides h2 groups left empty. */
  function setupSectionFilter(box, input, count, clear, content) {
    var kids = Array.prototype.slice.call(content.children).filter(function (k) { return box.compareDocumentPosition(k) & Node.DOCUMENT_POSITION_FOLLOWING; });
    var level = 0;
    kids.forEach(function (k) { var l = headingLevel(k); if (l >= 3 && (!level || l < level)) level = l; });
    if (!level) return;
    var sections = [], cur = null;
    kids.forEach(function (k) {
      var l = headingLevel(k);
      if (l && l < level) { cur = null; return; }
      if (l === level) { cur = { nodes: [k], text: "" }; sections.push(cur); }
      else if (cur) cur.nodes.push(k);
    });
    sections.forEach(function (s) { s.text = s.nodes.map(function (n) { return n.textContent; }).join(" ").toLowerCase().replace(/\s+/g, " "); });
    count.textContent = sections.length + " patterns";
    function terms(q) { var out = [], re = /"([^"]+)"|(\S+)/g, m; while ((m = re.exec(q)) !== null) out.push((m[1] || m[2]).toLowerCase()); return out; }
    function apply() {
      var q = terms(input.value.trim()), shown = 0;
      sections.forEach(function (s) {
        var ok = q.every(function (term) { return s.text.indexOf(term) !== -1; });
        s.nodes.forEach(function (n) { n.classList.toggle("hs-filter-hidden", !ok); });
        if (ok) shown++;
      });
      // hide parent headings (and their intro paragraphs) that have no visible section left
      for (var i = 0; i < kids.length; i++) {
        var l = headingLevel(kids[i]);
        if (!l || l >= level) continue;
        var j = i + 1, group = [], any = false;
        while (j < kids.length && !(headingLevel(kids[j]) && headingLevel(kids[j]) <= l)) {
          group.push(kids[j]);
          if (headingLevel(kids[j]) === level && !kids[j].classList.contains("hs-filter-hidden")) any = true;
          j++;
        }
        var hide = q.length > 0 && !any && group.some(function (g) { return headingLevel(g) === level; });
        kids[i].classList.toggle("hs-filter-hidden", hide);
        group.forEach(function (g) { if (headingLevel(g) !== level && !g.classList.contains("hs-filter-hidden")) g.classList.toggle("hs-filter-hidden", hide); });
      }
      count.textContent = q.length ? shown + " of " + sections.length + " patterns" : sections.length + " patterns";
      box.classList.toggle("is-active", q.length > 0);
    }
    input.addEventListener("input", apply);
    clear.addEventListener("click", function () { input.value = ""; apply(); input.focus(); });
    input.addEventListener("keydown", function (e) { if (e.key === "Escape") { input.value = ""; apply(); } });
    try { var q0 = new URLSearchParams(location.search).get("q"); if (q0) { input.value = q0; apply(); } } catch (e) { /* ignore */ }
  }

  /* --------------------------------------------------- learning-path progress
   * Chapter pages carry <meta name="hs-track" content="learn"> (see head/custom.html).
   * The learn index has <ol class="hs-progress"> or a table with .hs-progress; links to chapters get a tick.
   */
  var PROGRESS_KEY = "hs.read";

  function pageKey(href) {
    try { var u = new URL(href, location.href); return u.pathname.replace(/index\.html$/, "").replace(/\/?$/, "/"); } catch (e) { return href; }
  }

  function setupProgress(content) {
    var read = store.get(PROGRESS_KEY, {});
    var track = $('meta[name="hs-track"]');
    if (track) {
      var key = pageKey(location.href);
      var bar = el("div", { "class": "hs-readmark" });
      var btn = el("button", { type: "button", "class": "btn btn--inverse btn--small" });
      var note = el("span", { "class": "hs-readmark__note" });
      function paint() {
        var done = !!read[key];
        btn.textContent = done ? "✓ Marked as read" : "Mark chapter as read";
        btn.classList.toggle("is-done", done);
        note.textContent = done ? "Saved in this browser only. " : "Progress is stored in this browser only; nothing is sent anywhere. ";
      }
      btn.addEventListener("click", function () {
        if (read[key]) delete read[key]; else read[key] = Date.now();
        store.set(PROGRESS_KEY, read); paint();
      });
      bar.appendChild(btn); bar.appendChild(note);
      bar.appendChild(el("a", { href: track.getAttribute("data-index") || "../", text: "Back to the learning path" }));
      content.appendChild(bar);
      paint();
    }
    $all(".hs-progress", content).forEach(function (list) {
      var links = $all("a[href]", list).filter(function (a) { return /\/learn\/[^/]+\/$/.test(pageKey(a.href)); });
      var seen = {}, done = 0, total = 0;
      links.forEach(function (a) {
        var k = pageKey(a.href);
        if (seen[k]) return; seen[k] = 1; total++;
        if (read[k]) {
          done++;
          var cell = a.closest("td") || a.parentNode;
          cell.classList.add("hs-progress__done");
          a.insertAdjacentElement("afterend", el("span", { "class": "hs-progress__tick", title: "Read", text: " ✓" }));
        }
      });
      if (!total) return;
      var pct = Math.round(done / total * 100);
      var meter = el("div", { "class": "hs-meter", role: "progressbar", "aria-valuemin": "0", "aria-valuemax": "100", "aria-valuenow": String(pct) }, [
        el("div", { "class": "hs-meter__bar" }, [el("span", { style: "width:" + pct + "%" })]),
        el("div", { "class": "hs-meter__label", text: done + " of " + total + " chapters read (" + pct + "%). Open a chapter and use \"Mark chapter as read\" at the end; stored in this browser only." })
      ]);
      if (done) {
        var reset = el("button", { type: "button", "class": "hs-link-button", text: "Reset progress" });
        reset.addEventListener("click", function () { store.set(PROGRESS_KEY, {}); location.reload(); });
        meter.querySelector(".hs-meter__label").appendChild(document.createTextNode(" ")); meter.querySelector(".hs-meter__label").appendChild(reset);
      }
      list.parentNode.insertBefore(meter, list);
    });
  }

  /* ----------------------------------------------------------- playbook finder
   * The page provides <script type="application/json" id="hs-finder-data">{playbooks:[...], sources:[...]}</script>
   * and an empty <div id="hs-finder"></div>.
   */
  var FINDER_KEY = "hs.finder.sources";

  function setupFinder() {
    var mount = $("#hs-finder"), dataEl = $("#hs-finder-data");
    if (!mount || !dataEl) return;
    var data;
    try { data = JSON.parse(dataEl.textContent); } catch (e) { mount.textContent = "The finder data could not be loaded."; return; }
    var sources = data.sources || [], playbooks = data.playbooks || [];
    var byKey = {}; sources.forEach(function (s) { byKey[s.key] = s; });
    var selected = {};
    (store.get(FINDER_KEY, []) || []).forEach(function (k) { if (byKey[k]) selected[k] = true; });
    var state = { tactic: "", difficulty: "", q: "" };

    // --- controls
    var groups = {};
    sources.forEach(function (s) { (groups[s.group || "Other"] = groups[s.group || "Other"] || []).push(s); });
    var srcWrap = el("div", { "class": "hs-finder__sources" });
    Object.keys(groups).forEach(function (g) {
      var fs = el("fieldset", { "class": "hs-finder__group" }, [el("legend", { text: g })]);
      groups[g].forEach(function (s) {
        var id = "hs-src-" + s.key;
        var cb = el("input", { type: "checkbox", id: id, value: s.key });
        cb.checked = !!selected[s.key];
        cb.addEventListener("change", function () { if (cb.checked) selected[s.key] = true; else delete selected[s.key]; persist(); render(); });
        var n = playbooks.filter(function (p) { return (p.data || []).indexOf(s.key) !== -1; }).length;
        fs.appendChild(el("label", { "class": "hs-finder__source", "for": id, title: s.description || "" }, [cb, el("span", { text: s.label }), el("small", { text: n + " playbook" + (n === 1 ? "" : "s") })]));
      });
      srcWrap.appendChild(fs);
    });
    var quick = el("div", { "class": "hs-finder__quick" });
    [["Select all", function () { sources.forEach(function (s) { selected[s.key] = true; }); }],
     ["Clear", function () { selected = {}; }],
     ["Typical Windows SOC", function () { selected = {}; ["windows-security", "sysmon", "edr", "powershell", "dns", "proxy", "firewall"].forEach(function (k) { if (byKey[k]) selected[k] = true; }); }],
     ["Microsoft 365 + Entra", function () { selected = {}; ["entra-id", "m365-audit", "email", "edr"].forEach(function (k) { if (byKey[k]) selected[k] = true; }); }]
    ].forEach(function (pair) {
      var b = el("button", { type: "button", "class": "hs-chip hs-chip--button", text: pair[0] });
      b.addEventListener("click", function () { pair[1](); syncBoxes(); persist(); render(); });
      quick.appendChild(b);
    });
    function syncBoxes() { $all("input[type=checkbox]", srcWrap).forEach(function (cb) { cb.checked = !!selected[cb.value]; }); }
    function persist() { store.set(FINDER_KEY, Object.keys(selected)); }

    var tactics = []; playbooks.forEach(function (p) { if (p.tactic && tactics.indexOf(p.tactic) === -1) tactics.push(p.tactic); });
    var tacticSel = el("select", { "class": "hs-finder__select", "aria-label": "Filter by tactic" }, [el("option", { value: "", text: "Any tactic" })].concat(tactics.sort().map(function (t) { return el("option", { value: t, text: t }); })));
    var diffSel = el("select", { "class": "hs-finder__select", "aria-label": "Filter by difficulty" }, [el("option", { value: "", text: "Any difficulty" }), el("option", { value: "1", text: "★☆☆ starter" }), el("option", { value: "2", text: "★★☆ intermediate" }), el("option", { value: "3", text: "★★★ advanced" })]);
    var qIn = el("input", { type: "search", "class": "hs-filter__input", placeholder: "Keyword or technique id, e.g. T1059 or Kerberos", "aria-label": "Search playbooks" });
    tacticSel.addEventListener("change", function () { state.tactic = tacticSel.value; render(); });
    diffSel.addEventListener("change", function () { state.difficulty = diffSel.value; render(); });
    qIn.addEventListener("input", function () { state.q = qIn.value.trim().toLowerCase(); render(); });

    var results = el("div", { "class": "hs-finder__results" });
    mount.appendChild(el("div", { "class": "hs-finder__panel" }, [
      el("h3", { text: "1. Tick the telemetry you actually collect" }), quick, srcWrap,
      el("h3", { text: "2. Narrow it down (optional)" }),
      el("div", { "class": "hs-finder__controls" }, [tacticSel, diffSel, qIn])
    ]));
    mount.appendChild(results);

    function stars(d) { return d >= 3 ? "★★★" : d === 2 ? "★★☆" : "★☆☆"; }
    function matchesFilters(p) {
      if (state.tactic && p.tactic !== state.tactic) return false;
      if (state.difficulty && String(p.difficulty) !== state.difficulty) return false;
      if (state.q) {
        var hay = (p.title + " " + p.excerpt + " " + (p.attack || []).join(" ") + " " + p.tactic).toLowerCase();
        if (hay.indexOf(state.q) === -1) return false;
      }
      return true;
    }
    function card(p, missing) {
      var have = (p.data || []).filter(function (k) { return selected[k]; });
      var chips = el("div", { "class": "hs-finder__chips" });
      (p.data || []).forEach(function (k) {
        chips.appendChild(el("span", { "class": "hs-chip " + (selected[k] ? "hs-chip--green" : "hs-chip--muted"), title: selected[k] ? "You have this" : "Missing", text: (byKey[k] ? byKey[k].label : k) }));
      });
      var meta = el("p", { "class": "hs-finder__meta", html: escapeHtml(p.tactic || "") + " · <span class=\"hs-stars\">" + stars(p.difficulty) + "</span> · " + escapeHtml(p.timebox || "") + (p.rules ? " · " + p.rules + " Sigma rule" + (p.rules === 1 ? "" : "s") : "") });
      var c = el("article", { "class": "hs-card hs-finder__card" + (missing.length ? " is-partial" : "") }, [
        el("h4", {}, [el("a", { href: p.url, text: p.title })]),
        meta,
        el("p", { "class": "hs-finder__excerpt", text: p.excerpt || "" }),
        chips
      ]);
      if (missing.length) c.appendChild(el("p", { "class": "hs-finder__missing", text: "Still needs: " + missing.map(function (k) { return byKey[k] ? byKey[k].label : k; }).join(", ") + ". You can run the steps that use " + (have.length ? have.map(function (k) { return byKey[k] ? byKey[k].label : k; }).join(", ") : "nothing yet") + "." }));
      return c;
    }
    function section(title, hint, items) {
      var s = el("section", { "class": "hs-finder__section" }, [el("h3", { html: escapeHtml(title) + " <small>" + items.length + "</small>" }), el("p", { "class": "hs-finder__hint", text: hint })]);
      var grid = el("div", { "class": "hs-cards" });
      items.forEach(function (it) { grid.appendChild(card(it.p, it.missing)); });
      s.appendChild(items.length ? grid : el("p", { "class": "hs-finder__empty", text: "Nothing here with the current filters." }));
      return s;
    }

    function render() {
      results.innerHTML = "";
      var nSel = Object.keys(selected).length;
      var visible = playbooks.filter(matchesFilters);
      if (!nSel) {
        results.appendChild(el("p", { "class": "notice--info hs-finder__intro", html: "Tick at least one data source above. The finder then sorts the <strong>" + visible.length + "</strong> playbooks into ones you can run end to end, ones you can run partially, and tells you which single log source would unlock the most hunts." }));
      }
      var ready = [], partial = [], none = [];
      visible.forEach(function (p) {
        var missing = (p.data || []).filter(function (k) { return !selected[k]; });
        var have = (p.data || []).length - missing.length;
        if (!missing.length) ready.push({ p: p, missing: [] });
        else if (have > 0) partial.push({ p: p, missing: missing });
        else none.push({ p: p, missing: missing });
      });
      partial.sort(function (a, b) { return a.missing.length - b.missing.length; });

      // which missing source unlocks the most playbooks
      var unlock = {};
      visible.forEach(function (p) {
        var missing = (p.data || []).filter(function (k) { return !selected[k]; });
        if (missing.length === 1) unlock[missing[0]] = (unlock[missing[0]] || 0) + 1;
      });
      var unlockList = Object.keys(unlock).sort(function (a, b) { return unlock[b] - unlock[a]; }).slice(0, 4);

      var summary = el("ul", { "class": "hs-stats hs-finder__stats" }, [
        el("li", {}, [el("strong", { text: String(ready.length) }), el("span", { text: "ready to run" })]),
        el("li", {}, [el("strong", { text: String(partial.length) }), el("span", { text: "partially runnable" })]),
        el("li", {}, [el("strong", { text: String(nSel) + "/" + sources.length }), el("span", { text: "data sources ticked" })])
      ]);
      results.appendChild(summary);
      if (nSel && unlockList.length) {
        var ul = el("ul", { "class": "hs-finder__unlock" });
        unlockList.forEach(function (k) {
          var s = byKey[k] || { label: k };
          var li = el("li", {}, [el("strong", { text: s.label }), " would make " + unlock[k] + " more playbook" + (unlock[k] === 1 ? "" : "s") + " fully runnable. "]);
          if (s.how) li.appendChild(el("a", { href: s.how, text: "How to enable it" }));
          ul.appendChild(li);
        });
        results.appendChild(el("section", { "class": "hs-finder__section hs-finder__section--unlock" }, [el("h3", { text: "Biggest visibility win" }), el("p", { "class": "hs-finder__hint", text: "Adding one log source at a time, this is where the next hour of onboarding work pays off most." }), ul]));
      }
      if (nSel) {
        results.appendChild(section("Ready to run", "Every data source the playbook uses is one you ticked. Pick a hypothesis, set a time-box, go.", ready));
        results.appendChild(section("Partially runnable", "You can run some steps now; the missing sources are listed on each card, fewest missing first.", partial));
        if (none.length) results.appendChild(section("Needs telemetry you do not have", "Useful as a visibility backlog: each of these is a reason to onboard a log source.", none));
      } else {
        results.appendChild(section("All playbooks", "Showing everything; tick data sources above to sort them.", visible.map(function (p) { return { p: p, missing: [] }; })));
      }
    }
    render();
  }

  /* ------------------------------------------------- maturity self-assessment
   * Page provides <script type="application/json" id="hs-assess-data"> and <div id="hs-assess"></div>.
   * data = { levels: [names], dimensions: [{ key, name, blurb, link, questions: [{ q, options: [5 strings] }] }] }
   */
  var ASSESS_KEY = "hs.assessment";

  function setupAssessment() {
    var mount = $("#hs-assess"), dataEl = $("#hs-assess-data");
    if (!mount || !dataEl) return;
    var data;
    try { data = JSON.parse(dataEl.textContent); } catch (e) { mount.textContent = "The assessment could not be loaded."; return; }
    var answers = store.get(ASSESS_KEY, {}) || {};
    var form = el("form", { "class": "hs-assess" });
    form.addEventListener("submit", function (e) { e.preventDefault(); });
    var total = 0;
    data.dimensions.forEach(function (d, di) {
      var sec = el("section", { "class": "hs-assess__dimension", id: "assess-" + d.key }, [el("h3", { text: (di + 1) + ". " + d.name }), el("p", { "class": "hs-assess__blurb", text: d.blurb })]);
      d.questions.forEach(function (q, qi) {
        total++;
        var name = d.key + "." + qi;
        var fs = el("fieldset", { "class": "hs-assess__question" }, [el("legend", { text: q.q })]);
        q.options.forEach(function (opt, score) {
          var id = "a-" + name + "-" + score;
          var r = el("input", { type: "radio", name: name, id: id, value: String(score) });
          if (answers[name] === score) r.checked = true;
          r.addEventListener("change", function () { answers[name] = score; store.set(ASSESS_KEY, answers); render(); });
          fs.appendChild(el("label", { "for": id, "class": "hs-assess__option" }, [r, el("span", { "class": "hs-assess__level", text: "L" + score }), el("span", { text: opt })]));
        });
        sec.appendChild(fs);
      });
      form.appendChild(sec);
    });
    var out = el("div", { "class": "hs-assess__result", "aria-live": "polite" });
    var actions = el("div", { "class": "hs-assess__actions" });
    var copyBtn = el("button", { type: "button", "class": "btn btn--primary btn--small", text: "Copy results as Markdown" });
    var resetBtn = el("button", { type: "button", "class": "btn btn--inverse btn--small", text: "Reset answers" });
    resetBtn.addEventListener("click", function () { answers = {}; store.set(ASSESS_KEY, answers); $all("input[type=radio]", form).forEach(function (r) { r.checked = false; }); render(); });
    actions.appendChild(copyBtn); actions.appendChild(resetBtn);
    mount.appendChild(form); mount.appendChild(out); mount.appendChild(actions);

    function dimScore(d) {
      var sum = 0, n = 0;
      d.questions.forEach(function (q, qi) { var a = answers[d.key + "." + qi]; if (typeof a === "number") { sum += a; n++; } });
      return n ? { avg: sum / n, answered: n } : { avg: null, answered: 0 };
    }
    function levelName(x) { return data.levels[Math.max(0, Math.min(data.levels.length - 1, Math.round(x)))]; }
    function render() {
      var answered = Object.keys(answers).length;
      out.innerHTML = "";
      if (!answered) { out.appendChild(el("p", { "class": "hs-finder__hint", text: "Answer the questions above; the scorecard appears here as you go. Answers stay in this browser only." })); return; }
      var rows = data.dimensions.map(function (d) { return { d: d, s: dimScore(d) }; });
      var scored = rows.filter(function (r) { return r.s.avg !== null; });
      var overall = scored.reduce(function (a, r) { return a + r.s.avg; }, 0) / scored.length;
      var weakest = scored.slice().sort(function (a, b) { return a.s.avg - b.s.avg; })[0];
      out.appendChild(el("h3", { text: "Your scorecard" }));
      out.appendChild(el("p", { "class": "hs-assess__overall", html: "Overall: <strong>Level " + overall.toFixed(1) + "</strong> · " + escapeHtml(levelName(overall)) + " · " + answered + " of " + total + " questions answered" + (weakest ? ". Weakest dimension: <strong>" + escapeHtml(weakest.d.name) + "</strong>." : ".") }));
      var bars = el("div", { "class": "hs-assess__bars" });
      rows.forEach(function (r) {
        var pct = r.s.avg === null ? 0 : (r.s.avg / (data.levels.length - 1)) * 100;
        bars.appendChild(el("div", { "class": "hs-assess__bar" }, [
          el("div", { "class": "hs-assess__bar-label", html: "<strong>" + escapeHtml(r.d.name) + "</strong> " + (r.s.avg === null ? "<small>not answered</small>" : "<small>L" + r.s.avg.toFixed(1) + " · " + escapeHtml(levelName(r.s.avg)) + "</small>") }),
          el("div", { "class": "hs-meter__bar" }, [el("span", { style: "width:" + pct + "%" })])
        ]));
      });
      out.appendChild(bars);
      var recs = el("ul", { "class": "hs-assess__recs" });
      rows.slice().sort(function (a, b) { return (a.s.avg === null ? 99 : a.s.avg) - (b.s.avg === null ? 99 : b.s.avg); }).forEach(function (r) {
        if (r.s.avg === null) return;
        var lvl = Math.round(r.s.avg);
        var text = (r.d.next && r.d.next[Math.min(lvl, r.d.next.length - 1)]) || "";
        var li = el("li", {}, [el("strong", { text: r.d.name + ": " }), text + " "]);
        if (r.d.link) li.appendChild(el("a", { href: r.d.link, text: "Read the chapter" }));
        recs.appendChild(li);
      });
      out.appendChild(el("h4", { text: "What to do next, weakest first" }));
      out.appendChild(recs);
      copyBtn.onclick = function () {
        var md = "## Hunt maturity self-assessment\n\nOverall: Level " + overall.toFixed(1) + " (" + levelName(overall) + "), " + answered + "/" + total + " answered\n\n| Dimension | Level | Label |\n|---|---|---|\n";
        rows.forEach(function (r) { md += "| " + r.d.name + " | " + (r.s.avg === null ? "-" : "L" + r.s.avg.toFixed(1)) + " | " + (r.s.avg === null ? "not answered" : levelName(r.s.avg)) + " |\n"; });
        md += "\nGenerated with Hunt-Sage: " + location.href.split("?")[0] + "\n";
        if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(md); else fallbackCopy(md);
        copyBtn.textContent = "Copied"; setTimeout(function () { copyBtn.textContent = "Copy results as Markdown"; }, 1600);
      };
    }
    render();
  }

  /* ------------------------------------------------------- collapsible TOC
   * Below 64em the inline "On this page" list pushes content a screen down; make it a toggle. */
  function setupTocToggle() {
    var toc = $(".sidebar__right .toc");
    if (!toc) return;
    var title = toc.querySelector(".nav__title");
    if (!title) return;
    var mq = window.matchMedia("(max-width: 64em)");
    var collapsedByUser = null;
    function paint() {
      var small = mq.matches;
      title.classList.toggle("hs-toc-toggle", small);
      title.setAttribute("role", small ? "button" : "heading");
      title.setAttribute("tabindex", small ? "0" : "-1");
      toc.classList.toggle("is-collapsed", small && (collapsedByUser === null ? true : collapsedByUser));
    }
    function toggle() { if (!mq.matches) return; collapsedByUser = !toc.classList.contains("is-collapsed") ? true : false; paint(); }
    title.addEventListener("click", toggle);
    title.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
    if (mq.addEventListener) mq.addEventListener("change", paint); else if (mq.addListener) mq.addListener(paint);
    paint();
  }

  /* ---------------------------------------------------------------- boot */
  document.addEventListener("DOMContentLoaded", function () {
    var content = $(".page__content") || document.body;
    enhanceCodeBlocks(content);
    setupFilters(content);
    setupProgress(content);
    setupFinder();
    setupAssessment();
    setupTocToggle();
    linkAttackIds(content);
    styleStars(content);
  });
})();
