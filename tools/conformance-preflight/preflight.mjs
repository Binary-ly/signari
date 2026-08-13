// OIDC conformance preflight.
//
// This is NOT certification. Certification means running the OpenID Foundation's
// suite against a public deployment and submitting the results, which needs a
// human with an account at certification.openid.net.
//
// What this does is find the failures FIRST, cheaply, so that session is spent
// submitting rather than debugging. Every assertion below corresponds to
// something the Basic OP profile checks, expressed against the spec text rather
// than against our own implementation -- an assertion that only agrees with the
// code under test proves nothing.
//
//   node preflight.mjs <issuer> <client_id> <redirect_uri> <username> <password>

import { createHash, randomBytes } from "node:crypto";

const [ISSUER, CLIENT_ID, REDIRECT_URI, USERNAME, PASSWORD] = process.argv.slice(2);
if (!ISSUER || !CLIENT_ID || !REDIRECT_URI || !USERNAME || !PASSWORD) {
  console.error("usage: node preflight.mjs <issuer> <client_id> <redirect_uri> <username> <password>");
  process.exit(2);
}

const results = [];
const check = (spec, name, ok, detail = "") => {
  results.push({ spec, name, ok, detail });
  console.log(`  ${ok ? "PASS" : "FAIL"}  [${spec}] ${name}${detail ? "\n              " + detail : ""}`);
};

const b64u = (b) => Buffer.from(b).toString("base64url");
const jwtPart = (t, i) => JSON.parse(Buffer.from(t.split(".")[i], "base64url").toString());

// A cookie jar, because the authorization endpoint is stateful and the flow
// depends on the session established at the login form.
let jar = new Map();
async function req(url, opts = {}) {
  const cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
  const r = await fetch(url, {
    ...opts,
    redirect: "manual",
    headers: { ...(opts.headers || {}), ...(cookie ? { cookie } : {}) },
  });
  for (const [k, v] of r.headers) {
    if (k.toLowerCase() === "set-cookie") {
      for (const part of v.split(/,(?=[^;]+=)/)) {
        const [nv] = part.split(";");
        const [name, ...rest] = nv.split("=");
        if (name && rest.length) jar.set(name.trim(), rest.join("=").trim());
      }
    }
  }
  return r;
}

async function main() {
  // --- Discovery (OIDC Discovery 1.0 §3) --------------------------------
  const disco = await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json();

  check("Discovery 3", "issuer in the document equals the requested issuer",
    disco.issuer === ISSUER, `${disco.issuer}`);

  // REQUIRED metadata. A missing one breaks clients that read it strictly, and
  // the suite checks each individually.
  for (const f of ["authorization_endpoint", "token_endpoint", "jwks_uri",
    "response_types_supported", "subject_types_supported",
    "id_token_signing_alg_values_supported"]) {
    check("Discovery 3", `REQUIRED metadata: ${f}`, disco[f] !== undefined);
  }
  check("Core 15.1", "RS256 is offered (every RP library supports it)",
    (disco.id_token_signing_alg_values_supported || []).includes("RS256"),
    JSON.stringify(disco.id_token_signing_alg_values_supported));

  // --- JWKS (Core 10.1) --------------------------------------------------
  const jwks = await (await fetch(disco.jwks_uri)).json();
  check("Core 10.1", "JWKS contains keys", Array.isArray(jwks.keys) && jwks.keys.length > 0);
  check("Core 10.1", "every key has a kid (required to select one)",
    jwks.keys.every((k) => !!k.kid));
  check("Core 10.1", "no private key material is published",
    jwks.keys.every((k) => !k.d && !k.p && !k.q),
    "a leaked `d` here would be total compromise");

  // --- Authorization request errors, BEFORE the happy path ----------------
  // Checked first because a server that redirects errors to an unvalidated URI
  // is an open redirector, and that must not be discovered late.
  const bad = await req(`${disco.authorization_endpoint}?response_type=code` +
    `&client_id=${encodeURIComponent(CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent("https://attacker.test/steal")}&scope=openid`);
  const badLoc = bad.headers.get("location") || "";
  check("Core 3.1.2.1", "an unregistered redirect_uri is NOT redirected to",
    !badLoc.startsWith("https://attacker.test"),
    `status ${bad.status}${badLoc ? " -> " + badLoc.slice(0, 60) : ""}`);

  const noRT = await req(`${disco.authorization_endpoint}?client_id=${encodeURIComponent(CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=openid`);
  const noRTLoc = noRT.headers.get("location") || "";
  check("Core 3.1.2.6", "missing response_type returns invalid_request TO THE CLIENT",
    noRTLoc.includes("error=invalid_request"), noRTLoc.slice(0, 90));

  // --- The happy path -----------------------------------------------------
  const verifier = randomBytes(32).toString("hex");
  const challenge = b64u(createHash("sha256").update(verifier).digest());
  const state = randomBytes(12).toString("hex");
  const nonce = randomBytes(12).toString("hex");
  const authz = new URLSearchParams({
    response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
    scope: "openid email", state, nonce,
    code_challenge: challenge, code_challenge_method: "S256",
  });

  const page = await (await req(`${disco.authorization_endpoint}?${authz}`)).text();
  const csrf = /name="csrf_token" value="([^"]*)"/.exec(page)?.[1];
  const parked = /name="authz" value="([^"]*)"/.exec(page)?.[1]
    ?.replace(/&amp;/g, "&").replace(/&#43;/g, "+").replace(/&#34;/g, '"');
  if (!csrf) {
    check("Core 3.1.2", "the authorization endpoint presented a login form", false,
      "no CSRF field found -- is the client id correct?");
    return finish();
  }

  const login = await req(`${ISSUER}/login`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ username: USERNAME, password: PASSWORD, csrf_token: csrf, authz: parked || "" }),
  });
  let loc = login.headers.get("location");
  let cb = "";
  for (let i = 0; i < 5 && loc; i++) {
    if (loc.startsWith(REDIRECT_URI)) { cb = loc; break; }
    const next = await req(loc.startsWith("http") ? loc : ISSUER + loc);
    loc = next.headers.get("location");
  }
  const cbq = new URL(cb || "http://x/").searchParams;

  check("Core 3.1.2.5", "authorization code returned to the registered redirect_uri", !!cbq.get("code"));
  check("Core 3.1.2.5", "state is echoed verbatim (CSRF defence)", cbq.get("state") === state,
    `${cbq.get("state")}`);
  check("RFC 9207", "iss is returned in the authorization response (mix-up defence)",
    cbq.get("iss") === ISSUER, `${cbq.get("iss")}`);

  // --- Token endpoint -----------------------------------------------------
  const code = cbq.get("code");
  const tokenBody = (extra = {}) => new URLSearchParams({
    grant_type: "authorization_code", code, client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI, code_verifier: verifier, ...extra,
  });
  const tr = await fetch(disco.token_endpoint, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: tokenBody(),
  });
  const tok = await tr.json();

  check("Core 3.1.3.3", "token response returns access_token and id_token",
    !!tok.access_token && !!tok.id_token);
  check("Core 3.1.3.3", "token_type is Bearer", tok.token_type === "Bearer", `${tok.token_type}`);
  check("Core 3.1.3.3", "token response is not cacheable",
    (tr.headers.get("cache-control") || "").includes("no-store"),
    tr.headers.get("cache-control") || "(absent)");

  // --- ID token claims (Core 2, 3.1.3.7) ----------------------------------
  const idc = jwtPart(tok.id_token, 1);
  const idh = jwtPart(tok.id_token, 0);
  check("Core 2", "iss matches the issuer exactly", idc.iss === ISSUER, `${idc.iss}`);
  check("Core 2", "aud contains the client id",
    idc.aud === CLIENT_ID || (Array.isArray(idc.aud) && idc.aud.includes(CLIENT_ID)));
  check("Core 2", "sub is present", !!idc.sub);
  check("Core 2", "exp is in the future", idc.exp * 1000 > Date.now());
  check("Core 2", "iat is present", !!idc.iat);
  check("Core 3.1.3.7", "nonce is echoed verbatim (replay defence)", idc.nonce === nonce, `${idc.nonce}`);
  check("Core 3.1.3.7", "the signing kid is published in the JWKS",
    jwks.keys.some((k) => k.kid === idh.kid), `kid=${idh.kid}`);
  check("Core 3.1.3.7", "alg is not none", idh.alg && idh.alg !== "none", `alg=${idh.alg}`);

  // --- Single use (Core 3.1.3.2) ------------------------------------------
  const replay = await fetch(disco.token_endpoint, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: tokenBody(),
  });
  check("Core 3.1.3.2", "an authorization code cannot be replayed", replay.status !== 200,
    `status ${replay.status}`);

  // --- UserInfo (Core 5.3) ------------------------------------------------
  const ui = await fetch(disco.userinfo_endpoint, {
    headers: { authorization: `Bearer ${tok.access_token}` },
  });
  const uij = await ui.json().catch(() => ({}));
  check("Core 5.3.2", "userinfo returns sub", !!uij.sub);
  check("Core 5.3.2", "userinfo sub MATCHES the id_token sub", uij.sub === idc.sub,
    "a mismatch here lets one user's token read another's claims");
  const noAuth = await fetch(disco.userinfo_endpoint);
  check("Core 5.3.1", "userinfo without a token is refused", noAuth.status === 401,
    `status ${noAuth.status}`);

  finish();
}

function finish() {
  const failed = results.filter((r) => !r.ok);
  console.log(`\n  ${results.length - failed.length}/${results.length} passed`);
  if (failed.length) {
    console.log(`\n  Fix these before spending a session on the OIDF suite:`);
    for (const f of failed) console.log(`    [${f.spec}] ${f.name}`);
  }
  process.exit(failed.length ? 1 : 0);
}

main().catch((e) => { console.error("  preflight error:", e.message); process.exit(3); });
