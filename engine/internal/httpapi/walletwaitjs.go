package httpapi

import (
	"net/http"
	"strings"
)

// walletWaitJS is the cross-device wallet page's one script: it asks the page's wait
// address every two seconds whether the wallet has answered, and goes on to the code
// page when it has, or when the sign-in is gone, where it is told why. Same-origin and
// never inline, so the page's policy grants 'self' and nothing else; without it the page
// still works, by its continue link.
const walletWaitJS = `(function () {
  "use strict";
  var el = document.getElementById("wallet-wait");
  if (!el || !window.fetch) { return; }
  var wait = el.getAttribute("data-wait"), next = el.getAttribute("data-next");
  var tries = 0;
  function ask() {
    tries++;
    if (tries > 300) { return; }
    fetch(wait, { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (a) {
        if (a.answered || a.gone) { window.location.assign(next); return; }
        window.setTimeout(ask, 2000);
      })
      .catch(function () { window.setTimeout(ask, 4000); });
  }
  window.setTimeout(ask, 2000);
}());
`

func (s *Server) handleWalletWaitJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	http.ServeContent(w, r, "wallet-wait.js", buildTime, strings.NewReader(walletWaitJS))
}
