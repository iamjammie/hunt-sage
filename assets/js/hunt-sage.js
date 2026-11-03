/* Hunt-Sage page enhancements:
 *  - copy button + language tag on fenced code blocks
 *  - ATT&CK technique ids in tables/lists become links to attack.mitre.org
 *  - ★ difficulty ratings get a consistent style
 * No tracking, no network calls, no dependencies.
 */
(function () {
  "use strict";

  var LANG_LABELS = {
    kql: "KQL", spl: "SPL", powershell: "PowerShell", bash: "bash", sh: "sh", yaml: "YAML", yml: "YAML",
    text: "text", json: "JSON", python: "Python", sql: "SQL", xml: "XML", ini: "ini", console: "console",
    plaintext: "text", shell: "shell", cmd: "cmd", batch: "batch", regex: "regex"
  };

  function enhanceCodeBlocks(scope) {
    var blocks = scope.querySelectorAll("div.highlighter-rouge");
    Array.prototype.forEach.call(blocks, function (div) {
      var m = /language-([a-z0-9_+-]+)/i.exec(div.className);
      if (m) div.setAttribute("data-lang", LANG_LABELS[m[1].toLowerCase()] || m[1]);
      if (div.querySelector(".hs-copy")) return;
      var pre = div.querySelector("pre");
      if (!pre) return;
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "hs-copy";
      btn.textContent = "Copy";
      btn.setAttribute("aria-label", "Copy code to clipboard");
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
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.top = "-1000px";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); } catch (e) { /* ignore */ }
    document.body.removeChild(ta);
  }

  // Link ATT&CK ids (T1059, T1059.001, TA0002) found in plain text inside the article body.
  var ATTACK_RE = /\b(TA\d{4}|T\d{4}(?:\.\d{3})?)\b/g;
  var SKIP = { A: 1, CODE: 1, PRE: 1, SCRIPT: 1, STYLE: 1, BUTTON: 1, H1: 1, H2: 1, H3: 1, H4: 1, H5: 1, H6: 1 };

  function attackUrl(id) {
    if (id.charAt(1) === "A") return "https://attack.mitre.org/tactics/" + id + "/";
    return "https://attack.mitre.org/techniques/" + id.replace(".", "/") + "/";
  }

  function linkAttackIds(root) {
    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode: function (node) {
        if (!ATTACK_RE.test(node.nodeValue)) return NodeFilter.FILTER_REJECT;
        ATTACK_RE.lastIndex = 0;
        for (var el = node.parentNode; el && el !== root; el = el.parentNode) {
          if (SKIP[el.nodeName] || (el.classList && el.classList.contains("hs-no-attack-links"))) {
            return NodeFilter.FILTER_REJECT;
          }
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
        var a = document.createElement("a");
        a.className = "hs-attack";
        a.href = attackUrl(m[1]);
        a.target = "_blank";
        a.rel = "noopener";
        a.title = "Open " + m[1] + " on attack.mitre.org";
        a.textContent = m[1];
        frag.appendChild(a);
        last = m.index + m[0].length;
      }
      frag.appendChild(document.createTextNode(text.slice(last)));
      node.parentNode.replaceChild(frag, node);
    });
  }

  function styleStars(root) {
    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode: function (n) {
        return /^[★☆]{3}$/.test(n.nodeValue.trim()) && n.parentNode.nodeName !== "SPAN"
          ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
      }
    });
    var nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    nodes.forEach(function (n) {
      var span = document.createElement("span");
      span.className = "hs-stars";
      span.setAttribute("aria-label", "difficulty " + (n.nodeValue.split("★").length - 1) + " of 3");
      span.textContent = n.nodeValue.trim();
      n.parentNode.replaceChild(span, n);
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var content = document.querySelector(".page__content") || document.body;
    enhanceCodeBlocks(content);
    linkAttackIds(content);
    styleStars(content);
  });
})();
