// A minimal relying party, used to demonstrate the logout check.
//
// It exists for two reasons. First, to prove the checker can tell a conformant
// application from a broken one -- a test tool that passes everything is worse
// than none. Second, as a reference: the back-channel handler below is about
// twenty lines, and the reason most applications fail this check is not that it
// is hard but that nobody wrote it.
//
//   node demo-rp.mjs --idp http://localhost:9411 --client-id demo --port 4711
//   node demo-rp.mjs ... --broken     (accepts the notice and ignores it,
//                                      which is what most OIDC clients do)

import { createServer } from "node:http";
import { randomBytes, createHash } from "node:crypto";

// A bare flag (--broken) has no value after it, and a flag at the END of argv has
// no arr[i+1] at all. Treating both as "true" is the difference between running
// the mode you asked for and silently running the other one -- which cost a
// debugging cycle here.
const args = Object.fromEntries(process.argv.slice(2).reduce((a, x, i, arr) => {
  if (!x.startsWith("--")) return a;
  const next = arr[i + 1];
  a.push([x.slice(2), next === undefined || next.startsWith("--") ? "true" : next]);
  return a;
}, []));

const IDP = args.idp || "http://localhost:9411";
const CLIENT = args["client-id"] || "demo";
const PORT = Number(args.port || 4711);
const BROKEN = args.broken === "true" || args.broken === true;
const BASE = `http://localhost:${PORT}`;

// sid -> our own session id. THE data structure that makes back-channel logout
// possible: without a way to find our session from the IdP's sid, a logout token
// arrives and there is nothing to do with it. Most client libraries never build
// this index, which is the real reason logout does not work.
const sessionsBySID = new Map();
const sessions = new Map(); // our cookie -> { sub, sid }
const pkce = new Map();

const b64u = (b) => b.toString("base64url");

createServer(async (req, res) => {
  const url = new URL(req.url, BASE);
  const cookies = Object.fromEntries((req.headers.cookie || "").split(";")
    .map((c) => c.trim().split("=")).filter((p) => p[1]));

  // --- start sign-in ------------------------------------------------------
  if (url.pathname === "/login") {
    const verifier = b64u(randomBytes(32));
    const state = b64u(randomBytes(16));
    pkce.set(state, verifier);
    const challenge = b64u(createHash("sha256").update(verifier).digest());
    const q = new URLSearchParams({
      response_type: "code", client_id: CLIENT, redirect_uri: `${BASE}/callback`,
      scope: "openid email", state, code_challenge: challenge, code_challenge_method: "S256",
    });
    res.writeHead(302, { Location: `${IDP}/oauth2/authorize?${q}` });
    return res.end();
  }

  // --- finish sign-in -----------------------------------------------------
  if (url.pathname === "/callback") {
    const code = url.searchParams.get("code");
    const verifier = pkce.get(url.searchParams.get("state"));
    if (!code || !verifier) { res.writeHead(400); return res.end("bad callback"); }

    const tok = await (await fetch(`${IDP}/oauth2/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code", code, client_id: CLIENT,
        redirect_uri: `${BASE}/callback`, code_verifier: verifier,
      }),
    })).json();
    if (!tok.id_token) { res.writeHead(400); return res.end("token exchange failed"); }

    const claims = JSON.parse(Buffer.from(tok.id_token.split(".")[1], "base64url"));
    const ours = b64u(randomBytes(24));
    sessions.set(ours, { sub: claims.sub, sid: claims.sid });
    // Index by the IdP's sid. This one line is the difference between an
    // application that can be signed out remotely and one that cannot.
    if (claims.sid) sessionsBySID.set(claims.sid, ours);

    res.writeHead(302, { Location: "/account", "Set-Cookie": `rp=${ours}; Path=/; HttpOnly` });
    return res.end();
  }

  // --- the protected page -------------------------------------------------
  if (url.pathname === "/account") {
    const s = sessions.get(cookies.rp);
    if (!s) { res.writeHead(302, { Location: "/login" }); return res.end(); }
    res.writeHead(200, { "Content-Type": "text/html" });
    return res.end(`<h1>Signed in as ${s.sub}</h1>`);
  }

  // --- back-channel logout ------------------------------------------------
  if (url.pathname === "/backchannel-logout" && req.method === "POST") {
    let body = "";
    for await (const chunk of req) body += chunk;
    const token = new URLSearchParams(body).get("logout_token");

    if (BROKEN) {
      // What most applications do: accept the notice, return 200, and change
      // nothing. The IdP records a successful delivery. The user stays signed in.
      // Nobody finds out until they are asked to prove otherwise.
      res.writeHead(200);
      return res.end();
    }

    try {
      const claims = JSON.parse(Buffer.from(token.split(".")[1], "base64url"));
      // A real implementation MUST verify the signature, the issuer, the
      // audience, that events contains the back-channel logout member, and that
      // the token carries no nonce. Skipped here only because this file exists
      // to demonstrate the session-ending half; see the README.
      const ours = claims.sid && sessionsBySID.get(claims.sid);
      if (ours) { sessions.delete(ours); sessionsBySID.delete(claims.sid); }
      res.writeHead(200, { "Cache-Control": "no-store" });
      return res.end();
    } catch {
      res.writeHead(400);
      return res.end();
    }
  }

  // A public page. The conformance checker needs somewhere same-origin to stand
  // while it asks about the protected page; every real application has one.
  if (url.pathname === "/") {
    res.writeHead(200, { "Content-Type": "text/html" });
    return res.end("<h1>Demo RP</h1><p><a href=\"/account\">Account</a></p>");
  }

  res.writeHead(404);
  res.end();
}).listen(PORT, () => {
  console.log(`demo RP on ${BASE}  (back-channel logout: ${BROKEN ? "IGNORED" : "honoured"})`);
});
