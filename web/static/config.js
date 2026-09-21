// Runtime configuration for the Vault-Obf web UI.
//
// The static site can be hosted anywhere (including GitHub Pages) while the
// obfuscation service runs locally.  `python -m web` binds 127.0.0.1:8080.
//
// Resolution order:
//   1. ?api=http://host:port on the page URL (always wins)
//   2. same origin, when the UI is served by the local service itself
//   3. http://127.0.0.1:8080, then legacy http://127.0.0.1:8000
//
// `app.js` probes each candidate's /health and locks onto the first that
// answers, so the hosted UI finds a locally running service automatically.
(function () {
  function normalize(value) {
    return value ? String(value).replace(/\/+$/, "") : "";
  }

  var params = new URLSearchParams(window.location.search);
  var fromQuery = normalize(params.get("api"));

  var host = window.location.hostname;
  var isLocal =
    host === "127.0.0.1" || host === "localhost" || host === "::1" || host === "";
  var sameOrigin = isLocal && window.location.origin ? window.location.origin : "";

  var candidates = [fromQuery, sameOrigin, "http://127.0.0.1:8080", "http://127.0.0.1:8000"];
  var unique = [];
  for (var i = 0; i < candidates.length; i++) {
    var base = normalize(candidates[i]);
    if (base && unique.indexOf(base) === -1) unique.push(base);
  }

  window.VAULT_CONFIG = {
    apiBase: unique[0] || "",
    apiCandidates: unique,
    requestTimeoutMs: 30000,
  };
})();
