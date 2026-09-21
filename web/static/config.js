// Runtime configuration for the Vault-Obf web UI.
//
// The static site can be hosted anywhere (including GitHub Pages) while the
// obfuscation service runs locally. Point `apiBase` at wherever the service
// is listening; the UI probes `<apiBase>/health` on load to show status.
//
// Override without editing this file by appending a query string to the page,
// e.g. ?api=http://127.0.0.1:9000
(function () {
  var params = new URLSearchParams(window.location.search);
  var fromQuery = params.get("api");
  window.VAULT_CONFIG = {
    apiBase: (fromQuery || "http://127.0.0.1:8000").replace(/\/+$/, ""),
    requestTimeoutMs: 30000,
  };
})();
