// End-to-end passkey test driven by a REAL browser with a virtual authenticator.
//
// Everything else in this repo tests the server's half of WebAuthn. That proves
// the code is self-consistent and proves nothing about whether a passkey signs
// anyone in: attestation parsing, COSE key decoding, signature verification and
// the signature counter have never seen output from an actual authenticator.
//
// Chrome's DevTools Protocol exposes a virtual authenticator -- a real WebAuthn
// implementation with a software-backed key -- so the whole ceremony runs
// genuinely, through navigator.credentials, over the real wire format, with only
// the hardware simulated.
//
// Usage:  node passkey-e2e.mjs <base-url> <email> <password>

import WebSocket from "ws";
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [BASE, EMAIL, PASSWORD] = process.argv.slice(2);
if (!BASE || !EMAIL || !PASSWORD) {
  console.error("usage: node passkey-e2e.mjs <base-url> <email> <password>");
  process.exit(2);
}

const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const PORT = 9333;
const results = [];
const check = (name, ok, detail = "") => {
  results.push({ name, ok, detail });
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  -- " + detail : ""}`);
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Signed in iff an endpoint that requires a live session accepts us. Reading the
// cookie is not enough: a stale cookie the server no longer honours would look
// like a session and prove nothing.
const isSignedIn = async (evalJS) => (await evalJS(
  `fetch('/account/passkeys/begin', {method:'POST', credentials:'same-origin'}).then(r => r.status)`
)) === 200;

// --- minimal CDP client -----------------------------------------------------
class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    ws.on("message", (raw) => {
      const msg = JSON.parse(raw);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
      }
    });
  }
  send(method, params = {}, sessionId) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params, sessionId }));
      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error(`${method} timed out`));
        }
      }, 30000);
    });
  }
}

async function main() {
  const profile = mkdtempSync(join(tmpdir(), "signari-passkey-"));
  const chrome = spawn(CHROME, [
    `--remote-debugging-port=${PORT}`,
    `--user-data-dir=${profile}`,
    "--headless=new",
    "--no-first-run",
    "--no-default-browser-check",
    // The virtual authenticator needs a secure context; localhost qualifies, so
    // no certificate juggling is required.
    "about:blank",
  ], { stdio: "ignore" });

  try {
    let wsURL;
    for (let i = 0; i < 40 && !wsURL; i++) {
      await sleep(250);
      try {
        const r = await fetch(`http://127.0.0.1:${PORT}/json/version`);
        wsURL = (await r.json()).webSocketDebuggerUrl;
      } catch { /* not up yet */ }
    }
    if (!wsURL) throw new Error("Chrome did not expose a debugging endpoint");

    const ws = new WebSocket(wsURL, { maxPayload: 256 * 1024 * 1024 });
    await new Promise((res, rej) => { ws.once("open", res); ws.once("error", rej); });
    const cdp = new CDP(ws);

    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    const S = (m, p) => cdp.send(m, p, sessionId);

    await S("Page.enable");
    await S("Runtime.enable");

    // A real WebAuthn implementation with a software key. Internal transport and
    // resident keys, matching what the server requires at registration.
    await S("WebAuthn.enable");
    const { authenticatorId } = await S("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    });
    check("virtual authenticator attached", !!authenticatorId);

    const evalJS = async (expr) => {
      const r = await S("Runtime.evaluate", {
        expression: expr, awaitPromise: true, returnByValue: true,
      });
      if (r.exceptionDetails) {
        throw new Error(r.exceptionDetails.exception?.description || "js error");
      }
      return r.result.value;
    };
    const goto = async (url) => {
      await S("Page.navigate", { url });
      await sleep(700);
    };

    // --- 1. sign in with a password so we can register a passkey -------------
    await goto(`${BASE}/login`);
    const signedIn = await evalJS(`(async () => {
      const csrf = document.querySelector('input[name=csrf_token]').value;
      const body = new URLSearchParams({
        username: ${JSON.stringify(EMAIL)},
        password: ${JSON.stringify(PASSWORD)},
        csrf_token: csrf
      });
      const r = await fetch('/login', { method:'POST', body, credentials:'same-origin' });
      return r.status;
    })()`);
    check("password sign-in", signedIn === 200 || signedIn === 302, `status ${signedIn}`);

    // --- 2. register a passkey through the real browser API ------------------
    const reg = await evalJS(`(async () => {
      try { return { ok: true, r: await window.signariRegisterPasskey('E2E key') }; }
      catch (e) { return { ok: false, err: String(e) }; }
    })()`);
    check("passkey registration ceremony", reg.ok, reg.ok ? JSON.stringify(reg.r) : reg.err);

    const creds = await S("WebAuthn.getCredentials", { authenticatorId });
    check("authenticator holds a resident credential",
      creds.credentials.length === 1 && creds.credentials[0].isResidentCredential,
      `${creds.credentials.length} credential(s)`);

    // --- 3. sign out, then sign in with the passkey alone -------------------
    //
    // No explicit button click: the page's conditional UI starts the ceremony on
    // load and the virtual authenticator answers it. That is precisely the flow
    // passkeys exist for -- nobody types an identifier -- so it is the one worth
    // asserting. On success the page reloads itself, which is why the result is
    // read from the session afterwards rather than from the call.
    // Checked BEFORE navigating to /login. Landing on the sign-in page starts
    // conditional UI immediately, which signs the user straight back in -- so
    // asserting "signed out" there races the very feature under test and fails
    // for the best possible reason.
    await evalJS(`fetch('/oauth2/logout', { credentials:'same-origin' })`);
    check("signed out", !(await isSignedIn(evalJS)), "session cleared before the passkey attempt");

    await goto(`${BASE}/login`);
    let signedInByPasskey = false;
    for (let i = 0; i < 20 && !signedInByPasskey; i++) {
      await sleep(400);
      try { signedInByPasskey = await isSignedIn(evalJS); } catch { /* mid-reload */ }
    }
    check("usernameless passkey sign-in (conditional UI)", signedInByPasskey);

    await S("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
    ws.close();
  } finally {
    chrome.kill();
  }

  const failed = results.filter((r) => !r.ok).length;
  console.log(`\n  ${results.length - failed}/${results.length} passed`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error("harness error:", e.message); process.exit(3); });
