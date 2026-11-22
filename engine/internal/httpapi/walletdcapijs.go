package httpapi

import (
	"net/http"
	"strings"
)

// walletDCAPIJS asks the browser's Digital Credentials API for the credential the page's
// request names. The button shows only where the browser says it allows the protocol
// (specs/digital-credentials.txt:475-491); the request is in the page already, because
// the call must be made in the click itself, while it is still a user's (:996-999); and
// what comes back, the DigitalCredential's data (:1542-1546), is posted in the page's own
// form, so the answer, the redirect and the session all go through the one browser that
// holds the sign-in's cookie. Same-origin and never inline.
const walletDCAPIJS = `(function () {
  "use strict";
  var box = document.getElementById("wallet-dcapi");
  if (!box || typeof DigitalCredential === "undefined" || !navigator.credentials ||
      typeof DigitalCredential.userAgentAllowsProtocol !== "function") { return; }
  var protocol = box.getAttribute("data-protocol");
  if (!DigitalCredential.userAgentAllowsProtocol(protocol)) { return; }
  var request = JSON.parse(box.getAttribute("data-request"));
  var form = document.getElementById("wallet-dcapi-form");
  var failed = document.getElementById("wallet-dcapi-failed");
  box.hidden = false;
  document.getElementById("wallet-dcapi-go").addEventListener("click", function () {
    failed.hidden = true;
    navigator.credentials.get({ digital: { requests: [{ protocol: protocol, data: request }] } })
      .then(function (credential) {
        if (!credential || !credential.data) { failed.hidden = false; return; }
        form.elements.response.value = JSON.stringify(credential.data);
        form.submit();
      })
      .catch(function () { failed.hidden = false; });
  });
}());
`

func (s *Server) handleWalletDCAPIJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	http.ServeContent(w, r, "wallet-dcapi.js", buildTime, strings.NewReader(walletDCAPIJS))
}
