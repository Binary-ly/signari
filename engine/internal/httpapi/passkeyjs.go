package httpapi

import (
	"net/http"
	"strings"
	"time"
)

// The browser half of the WebAuthn ceremonies.
//
// Served from its own path rather than inlined, so the login page's Content
// Security Policy can stay `script-src 'self'`. Inlining would require
// `'unsafe-inline'`, which disables script CSP entirely -- on the one page in
// the product where a script injection is worth the most.
//
// No framework, no build step, no dependency. The whole browser side of WebAuthn
// is two API calls and base64url conversion; anything larger is someone else's
// supply chain running on the sign-in page.

const passkeyJS = `"use strict";
// base64url <-> ArrayBuffer. The WebAuthn API speaks ArrayBuffers and JSON does
// not, so every field crossing that boundary needs converting. Standard base64
// is NOT interchangeable here: '+' and '/' are not URL-safe and the padding
// differs, which produces credentials that fail to verify for reasons that look
// like a server bug.
function b64uToBuf(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}
function bufToB64u(b) {
  const bytes = new Uint8Array(b);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeCreation(o) {
  o.challenge = b64uToBuf(o.challenge);
  o.user.id = b64uToBuf(o.user.id);
  (o.excludeCredentials || []).forEach(c => { c.id = b64uToBuf(c.id); });
  return o;
}
function decodeRequest(o) {
  o.challenge = b64uToBuf(o.challenge);
  (o.allowCredentials || []).forEach(c => { c.id = b64uToBuf(c.id); });
  return o;
}

function encodeAttestation(cred) {
  return {
    id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      attestationObject: bufToB64u(cred.response.attestationObject),
      transports: cred.response.getTransports ? cred.response.getTransports() : []
    }
  };
}
function encodeAssertion(cred) {
  return {
    id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      authenticatorData: bufToB64u(cred.response.authenticatorData),
      signature: bufToB64u(cred.response.signature),
      // May legitimately be null for a non-discoverable credential. Sent as null
      // rather than omitted so the server can tell "no handle" from "field lost
      // in transit".
      userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null
    }
  };
}

async function postJSON(url, body) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    // Ceremony state lives in a __Host- cookie; without this the second half of
    // the ceremony arrives with no challenge and fails as "nothing in progress".
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error_description || r.statusText);
  return r.json();
}

// Registration, from an already signed-in page.
window.signariRegisterPasskey = async function (name) {
  const options = decodeCreation((await postJSON("/account/passkeys/begin")).publicKey);
  const cred = await navigator.credentials.create({ publicKey: options });
  const q = name ? "?name=" + encodeURIComponent(name) : "";
  return postJSON("/account/passkeys/finish" + q, encodeAttestation(cred));
};

// ONE ceremony at a time, shared between conditional UI and the button.
//
// Conditional UI starts a ceremony unprompted on page load. If the button then
// started a second, its /begin would overwrite the ceremony cookie while the
// first get() is still pending -- and whichever assertion arrives is checked
// against the OTHER challenge. The server correctly rejects it with "Error
// validating challenge", which reads like a server fault and is not one.
//
// So the challenge is fetched once and reused, and the outstanding get() is
// aborted before a new one starts: the WebAuthn API permits only one in flight,
// and the second call otherwise rejects the first.
let ceremony = null;
let inflight = null;

function beginOnce() {
  if (!ceremony) {
    ceremony = postJSON("/login/passkey/begin")
      .then(r => decodeRequest(r.publicKey))
      .catch(e => { ceremony = null; throw e; });
  }
  return ceremony;
}

async function passkeySignIn(mediation) {
  const options = await beginOnce();
  if (inflight) inflight.abort();
  inflight = new AbortController();

  const req = { publicKey: options, signal: inflight.signal };
  if (mediation) req.mediation = mediation;

  let cred;
  try {
    cred = await navigator.credentials.get(req);
  } finally {
    inflight = null;
  }
  if (!cred) return null;

  // Spent: the server clears the cookie on both outcomes, so the next attempt
  // must fetch a fresh challenge rather than reuse this one.
  ceremony = null;

  const authz = document.querySelector('input[name="authz"]');
  const q = authz && authz.value ? "?authz=" + encodeURIComponent(authz.value) : "";
  await postJSON("/login/passkey/finish" + q, encodeAssertion(cred));
  window.location.reload();
}

window.signariSignInWithPasskey = function () {
  return passkeySignIn().catch(e => {
    // NotAllowedError is the user cancelling or letting it time out. Surfacing
    // that as an error trains people to ignore real ones.
    if (e && e.name === "NotAllowedError") return;
    console.error(e);
  });
};

// The listener is attached here rather than with an inline onclick= attribute.
// CSP script-src 'self' blocks inline EVENT HANDLERS just as it blocks inline
// <script> -- they would need 'unsafe-inline', which is the thing this file
// exists to avoid. An onclick would have left a button that silently does
// nothing, with the reason visible only in the browser console.
document.addEventListener("DOMContentLoaded", function () {
  const b = document.getElementById("passkey-signin");
  if (!b) return;
  // Revealed here, not in the HTML, and this is the same argument as the one
  // above about inline handlers -- one step further along.
  //
  // Avoiding onclick stopped the button being inert when the CSP blocked the
  // handler. It did not stop the button being inert when there is no JavaScript
  // at all, or no WebAuthn: the markup shipped it visible and this file only
  // ever attached a listener to it. Somebody with scripting off, or on a browser
  // without PublicKeyCredential, saw a button that did nothing when pressed --
  // which is the exact outcome the comment above says it exists to prevent.
  //
  // The sign-in form itself needs no JavaScript and must keep working with none;
  // this is the one control on the page that genuinely cannot.
  if (!window.PublicKeyCredential) return;
  const row = document.getElementById("passkey-row");
  if (row) row.hidden = false;
  b.addEventListener("click", () => window.signariSignInWithPasskey());
});

// Conditional UI: the passkey appears in the username field's autofill dropdown
// instead of behind a button. This is what makes passkeys feel like less work
// than a password rather than more.
//
// Guarded on isConditionalMediationAvailable because calling get() with
// mediation:"conditional" on a browser that lacks it throws, and the whole page
// then looks broken to users on older browsers.
(async function () {
  if (!window.PublicKeyCredential ||
      !PublicKeyCredential.isConditionalMediationAvailable) return;
  try {
    if (!(await PublicKeyCredential.isConditionalMediationAvailable())) return;
    await passkeySignIn("conditional");
  } catch (e) {
    // Silent by design. Conditional UI runs unprompted on page load, so a
    // failure here is not something the user asked for and must not interrupt
    // the password form they can still use.
  }
})();
`

// handlePasskeyJS serves the browser half.
//
// Cached, because it is static and every sign-in page fetches it -- but only for
// an hour, so a fix to the ceremony code reaches users the same day rather than
// whenever their browser happens to revalidate.
func (s *Server) handlePasskeyJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	http.ServeContent(w, r, "passkey.js", buildTime, strings.NewReader(passkeyJS))
}

// buildTime is a fixed modification time so conditional requests work and the
// response is byte-identical across replicas.
var buildTime = time.Unix(0, 0)
