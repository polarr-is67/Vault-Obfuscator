/* Vault-Obf web UI logic --------------------------------------------------- */
(function () {
  "use strict";

  var CFG = window.VAULT_CONFIG || { apiBase: "", requestTimeoutMs: 30000 };

  // --- syntax highlighting --------------------------------------------------
  var KEYWORDS = new Set([
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
    "if", "in", "local", "nil", "not", "or", "repeat", "return", "then",
    "true", "until", "while",
    // Luau
    "continue", "export", "type", "typeof",
  ]);

  var GLOBALS = new Set([
    "_G", "_ENV", "assert", "collectgarbage", "coroutine", "debug", "error",
    "getfenv", "getmetatable", "io", "ipairs", "math", "next", "os", "pairs",
    "pcall", "print", "rawequal", "rawget", "rawlen", "rawset", "require",
    "select", "setfenv", "setmetatable", "string", "table", "tonumber",
    "tostring", "type", "unpack", "utf8", "xpcall",
  ]);

  var NUM_RE = /(?:0[xX][0-9a-fA-F]+(?:\.[0-9a-fA-F]*)?(?:[pP][+-]?\d+)?|0[bB][01]+|\d+\.\d*(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?|\d+(?:[eE][+-]?\d+)?)/y;
  var IDENT_RE = /[A-Za-z_]\w*/y;

  var OPS = [
    "...", "..=", "..", "==", "~=", "<=", ">=", "::", "//", "<<", ">>",
    "+=", "-=", "*=", "/=", "%=", "^=", "//=", "->",
    "+", "-", "*", "/", "%", "^", "#", "&", "~", "|", "<", ">", "=", "(",
    ")", "{", "}", "[", "]", ";", ":", ",", ".", "?", "@",
  ];

  function escapeHtml(s) {
    return s.replace(/[&<>]/g, function (c) {
      return c === "&" ? "&amp;" : c === "<" ? "&lt;" : "&gt;";
    });
  }

  function span(cls, text) {
    return '<span class="' + cls + '">' + escapeHtml(text) + "</span>";
  }

  function highlightLua(src) {
    var out = [];
    var n = src.length;
    var i = 0;
    var lastWord = "";
    var prevChar = "";

    function longBracketOpen(pos) {
      if (src[pos] !== "[") return -1;
      var j = pos + 1, eq = 0;
      while (src[j] === "=") { eq++; j++; }
      return src[j] === "[" ? eq : -1;
    }

    while (i < n) {
      var c = src[i];

      // long bracket string [[ ]] / [==[
      if (c === "[") {
        var eq = longBracketOpen(i);
        if (eq >= 0) {
          var close = "]" + "=".repeat(eq) + "]";
          var end = src.indexOf(close, i + eq + 2);
          var stop = end === -1 ? n : end + close.length;
          out.push(span("tok-str", src.slice(i, stop)));
          i = stop; prevChar = "]"; continue;
        }
      }

      // comments
      if (c === "-" && src[i + 1] === "-") {
        var ceq = longBracketOpen(i + 2);
        if (ceq >= 0) {
          var cclose = "]" + "=".repeat(ceq) + "]";
          var cend = src.indexOf(cclose, i + ceq + 4);
          var cstop = cend === -1 ? n : cend + cclose.length;
          out.push(span("tok-com", src.slice(i, cstop)));
          i = cstop; continue;
        }
        var lend = src.indexOf("\n", i);
        if (lend === -1) lend = n;
        out.push(span("tok-com", src.slice(i, lend)));
        i = lend; continue;
      }

      // quoted strings
      if (c === '"' || c === "'") {
        var sj = i + 1;
        while (sj < n) {
          if (src[sj] === "\\") { sj += 2; continue; }
          if (src[sj] === c || src[sj] === "\n") { sj++; break; }
          sj++;
        }
        out.push(span("tok-str", src.slice(i, sj)));
        i = sj; prevChar = '"'; continue;
      }

      // Luau interpolated string
      if (c === "`") {
        var bj = i + 1;
        while (bj < n) {
          if (src[bj] === "\\") { bj += 2; continue; }
          if (src[bj] === "`") { bj++; break; }
          bj++;
        }
        out.push(span("tok-str", src.slice(i, bj)));
        i = bj; prevChar = "`"; continue;
      }

      // numbers
      if (/[0-9]/.test(c) || (c === "." && /[0-9]/.test(src[i + 1] || ""))) {
        NUM_RE.lastIndex = i;
        var nm = NUM_RE.exec(src);
        if (nm && nm[0].length) {
          out.push(span("tok-num", nm[0]));
          i += nm[0].length; prevChar = "0"; continue;
        }
      }

      // identifiers / keywords
      if (/[A-Za-z_]/.test(c)) {
        IDENT_RE.lastIndex = i;
        var im = IDENT_RE.exec(src);
        var word = im[0];
        i += word.length;
        var next = src.slice(i).match(/^\s*(.)/);
        var nextCh = next ? next[1] : "";
        var isCall = nextCh === "(";
        var isField = prevChar === "." || prevChar === ":";
        if (KEYWORDS.has(word)) out.push(span("tok-kw", word));
        else if (lastWord === "function" || isCall || isField) out.push(span("tok-fn", word));
        else if (GLOBALS.has(word)) out.push(span("tok-global", word));
        else out.push(escapeHtml(word));
        lastWord = word; prevChar = "";
        continue;
      }

      // whitespace
      if (/\s/.test(c)) {
        out.push(c);
        i++; continue;
      }

      // operators / punctuation
      var matched = null;
      for (var k = 0; k < OPS.length; k++) {
        if (src.startsWith(OPS[k], i)) { matched = OPS[k]; break; }
      }
      if (matched) {
        out.push(span("tok-op", matched));
        i += matched.length; prevChar = matched;
      } else {
        out.push(escapeHtml(c));
        i++; prevChar = c;
      }
    }
    return out.join("");
  }

  // --- tiny DOM helpers -----------------------------------------------------
  function $(id) { return document.getElementById(id); }

  function api(path) { return CFG.apiBase + path; }

  function setStatus(kind, text) {
    var el = $("status");
    el.className = "pill " + kind;
    el.querySelector(".text").textContent = text;
  }

  function showError(title, detail) {
    var box = $("diag");
    box.className = "diag show";
    box.innerHTML = '<div class="title"></div><div class="body"></div>';
    box.querySelector(".title").textContent = title;
    box.querySelector(".body").textContent = detail || "";
  }

  function clearError() { $("diag").className = "diag"; }

  // --- theme ----------------------------------------------------------------
  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    $("theme-toggle").textContent = theme === "light" ? "Dark" : "Light";
  }

  function initTheme() {
    var saved = null;
    try { saved = localStorage.getItem("vault-theme"); } catch (e) { /* ignore */ }
    var theme = saved || (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
    applyTheme(theme);
  }

  function toggleTheme() {
    var cur = document.documentElement.getAttribute("data-theme");
    var next = cur === "light" ? "dark" : "light";
    applyTheme(next);
    try { localStorage.setItem("vault-theme", next); } catch (e) { /* ignore */ }
  }

  // --- service health -------------------------------------------------------
  function candidateBases() {
    var stored = null;
    try { stored = sessionStorage.getItem("vault-api-base"); } catch (e) { /* ignore */ }
    var list = [stored].concat(CFG.apiCandidates || [CFG.apiBase]);
    var out = [];
    for (var i = 0; i < list.length; i++) {
      var base = list[i] ? String(list[i]).replace(/\/+$/, "") : "";
      if (base && out.indexOf(base) === -1) out.push(base);
    }
    return out;
  }

  function probe(base) {
    return fetch(base + "/health", { cache: "no-store" }).then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    });
  }

  function checkHealth() {
    setStatus("pending", "checking service…");
    var bases = candidateBases();
    var i = 0;
    function next() {
      if (i >= bases.length) {
        setStatus("bad", "service offline");
        return;
      }
      var base = bases[i++];
      probe(base)
        .then(function (d) {
          CFG.apiBase = base;
          try { sessionStorage.setItem("vault-api-base", base); } catch (e) { /* ignore */ }
          setStatus("ok", "service online · v" + d.version);
        })
        .catch(next);
    }
    next();
  }

  // --- source loading -------------------------------------------------------
  var MAX_FILE = 2 * 1024 * 1024;

  function setSource(text, name) {
    $("src").value = text;
    if (name) $("file-name").textContent = name;
    $("file-name").textContent = name || "";
  }

  function loadFile(file) {
    if (!file) return;
    if (file.size > MAX_FILE) {
      showError("File too large", "Files over 2 MB are not supported.");
      return;
    }
    var reader = new FileReader();
    reader.onload = function () { clearError(); setSource(String(reader.result), file.name); };
    reader.onerror = function () { showError("Could not read file", String(reader.error || "")); };
    reader.readAsText(file);
  }

  function wireDropzone() {
    var zone = $("dropzone");
    ["dragenter", "dragover"].forEach(function (ev) {
      zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.add("dragover"); });
    });
    ["dragleave", "drop"].forEach(function (ev) {
      zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.remove("dragover"); });
    });
    zone.addEventListener("drop", function (e) {
      var files = e.dataTransfer && e.dataTransfer.files;
      if (files && files.length) loadFile(files[0]);
    });
    $("file-input").addEventListener("change", function (e) {
      if (e.target.files && e.target.files.length) loadFile(e.target.files[0]);
    });
  }

  // --- overrides ------------------------------------------------------------
  function collectOverrides() {
    var o = {};
    var dispatch = $("adv-dispatch").value;
    if (dispatch) o.dispatch = dispatch;
    var nodes = document.querySelectorAll("[data-override]");
    for (var i = 0; i < nodes.length; i++) {
      var el = nodes[i];
      if (el.type === "checkbox" && el.checked) o[el.getAttribute("data-override")] = true;
    }
    return o;
  }

  // --- stats ----------------------------------------------------------------
  function renderStats(stats) {
    var ratio = stats.source_size ? (stats.output_size / stats.source_size) : 0;
    var items = [
      ["Seed", stats.seed],
      ["Source", stats.source_size + " B"],
      ["Output", stats.output_size + " B"],
      ["Expansion", "×" + ratio.toFixed(2)],
      ["Instructions", stats.instruction_count],
      ["Functions", stats.function_count],
      ["Constants", stats.constant_count],
      ["Bytecode", stats.bytecode_size + " b"],
      ["Compile", stats.compile_time_ms.toFixed(1) + " ms"],
    ];
    var host = $("stats");
    host.innerHTML = "";
    items.forEach(function (pair) {
      var d = document.createElement("div");
      d.className = "stat";
      var k = document.createElement("div"); k.className = "k"; k.textContent = pair[0];
      var v = document.createElement("div"); v.className = "v"; v.textContent = pair[1];
      d.appendChild(k); d.appendChild(v);
      host.appendChild(d);
    });
  }

  // --- build ----------------------------------------------------------------
  var running = false;

  function run() {
    if (running) return;
    running = true;
    clearError();
    $("run").disabled = true;
    $("run").textContent = "Building…";

    var payload = {
      source: $("src").value,
      preset: $("preset").value,
      target: $("target").value,
      seed: Number($("seed").value) || 0,
      pretty: $("format").value === "pretty",
      minify: $("format").value === "minify",
      verify: $("verify").checked,
      debug: $("debug").checked,
      overrides: collectOverrides(),
    };

    var controller = ("AbortController" in window) ? new AbortController() : null;
    var timer = setTimeout(function () { if (controller) controller.abort(); }, CFG.requestTimeoutMs || 30000);

    fetch(api("/obfuscate.json"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller ? controller.signal : undefined,
    })
      .then(function (resp) {
        return resp.json().then(function (data) { return { ok: resp.ok, status: resp.status, data: data }; });
      })
      .then(function (res) {
        if (!res.ok) {
          var detail = res.data && res.data.detail ? res.data.detail : "HTTP " + res.status;
          showError("Build failed", detail);
          return;
        }
        $("output").innerHTML = highlightLua(res.data.output);
        $("output-panel").style.display = "block";
        $("empty-output").style.display = "none";
        renderStats(res.data.stats);
        currentOutput = res.data.output;
        $("copy").disabled = false;
        $("download").disabled = false;
      })
      .catch(function (err) {
        if (err && err.name === "AbortError") {
          showError("Request timed out", "The service did not respond in time.");
        } else {
          var tried = candidateBases().join(", ") || "(none)";
          showError(
            "Service unreachable",
            "Could not reach the Vault-Obf service. Start it with `python -m web` " +
              "(http://127.0.0.1:8080), then retry or press Refresh.\n" +
              "Tried: " + tried + "\n" +
              "To use a different host or port, reload with ?api=http://host:port\n\n" +
              String((err && err.message) || err)
          );
        }
      })
      .then(function () {
        clearTimeout(timer);
        running = false;
        $("run").disabled = false;
        $("run").textContent = "Obfuscate";
      });
  }

  var currentOutput = "";

  function copyOutput() {
    if (!currentOutput) return;
    navigator.clipboard.writeText(currentOutput).then(function () {
      var btn = $("copy"); var old = btn.textContent; btn.textContent = "Copied";
      setTimeout(function () { btn.textContent = old; }, 1200);
    });
  }

  function downloadOutput() {
    if (!currentOutput) return;
    var blob = new Blob([currentOutput], { type: "text/plain;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url; a.download = "obfuscated.lua";
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  var SAMPLES = {
    hello: 'print("hello, vault")\n',
    fib: 'local function fib(n)\n  if n < 2 then return n end\n  return fib(n - 1) + fib(n - 2)\nend\nfor i = 1, 10 do io.write(fib(i), " ") end\nprint()\n',
    luau: '--!strict\nlocal function map<T, U>(xs: {T}, f: (T) -> U): {U}\n  local out = {}\n  for i, v in xs do out[i] = f(v) end\n  return out\nend\ntype Point = { x: number, y: number }\nlocal p: Point = { x = 3, y = 4 }\nprint(map({1, 2, 3}, function(n) return n * n end)[2], p.x + p.y)\n',
  };

  function wireSamples() {
    var sel = $("samples");
    sel.addEventListener("change", function () {
      var v = sel.value;
      if (SAMPLES[v]) { setSource(SAMPLES[v], ""); clearError(); }
      sel.value = "";
    });
  }

  // --- boot -----------------------------------------------------------------
  window.VaultObf = { highlightLua: highlightLua };

  document.addEventListener("DOMContentLoaded", function () {
    initTheme();
    checkHealth();
    wireDropzone();
    wireSamples();
    $("theme-toggle").addEventListener("click", toggleTheme);
    $("run").addEventListener("click", run);
    $("copy").addEventListener("click", copyOutput);
    $("download").addEventListener("click", downloadOutput);
    $("refresh").addEventListener("click", checkHealth);
  });
})();
