// Does a person in a REAL browser get from the sign-in page to where they were going?
// That is an application, or a service provider over the SAML POST binding, or a
// relying party over form_post or WS-Federation: the start URL says which.
//
// Every other test here speaks HTTP, and an HTTP client follows a redirect
// because it was told to. A browser follows it only if the page's Content
// Security Policy agrees, and Chrome applies `form-action` to every redirect that
// follows a form submission. So a sign-in that any client in this repository
// completed could leave a person on the sign-in page with the right password, no
// error, and the application never reached.
//
// This drives the real forms, in Chrome, and passes only if the browser arrives
// at the origin it was meant to. It answers a consent page if one appears.
//
// Needs Node 22 or later for the built-in WebSocket, and nothing else.
//
// Usage:  node form-redirect-e2e.mjs <authorize-url> <arrival-origin> <email> <password>

import { spawn } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [START, ARRIVAL, EMAIL, PASSWORD] = process.argv.slice(2);
if (!START || !ARRIVAL || !EMAIL || !PASSWORD) {
  console.error("usage: node form-redirect-e2e.mjs <authorize-url> <arrival-origin> <email> <password>");
  process.exit(2);
}

const CHROME = process.env.CHROME ||
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const PORT = 9334;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// RFC 6238 with its defaults, SHA-1, 30 seconds, six digits.
function totp(seedHex) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const mac = createHmac("sha1", Buffer.from(seedHex, "hex")).update(counter).digest();
  const at = mac[mac.length - 1] & 0x0f;
  return String((mac.readUInt32BE(at) & 0x7fffffff) % 1000000).padStart(6, "0");
}

class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    ws.addEventListener("message", (event) => {
      const msg = JSON.parse(event.data);
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
      }, 15000);
    });
  }
}

const profile = mkdtempSync(join(tmpdir(), "signari-form-redirect-"));
const chrome = spawn(CHROME, [
  `--remote-debugging-port=${PORT}`,
  `--user-data-dir=${profile}`,
  "--headless=new",
  "--no-first-run",
  "--no-default-browser-check",
  // For a service on https://localhost with a test certificate. The engine's own
  // origin is http://localhost, which a browser treats as secure.
  "--ignore-certificate-errors",
  "about:blank",
], { stdio: "ignore" });

let failed = true;
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

  const ws = new WebSocket(wsURL);
  await new Promise((res, rej) => {
    ws.addEventListener("open", res, { once: true });
    ws.addEventListener("error", rej, { once: true });
  });
  const cdp = new CDP(ws);
  const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
  const S = (m, p) => cdp.send(m, p, sessionId);
  await S("Page.enable");
  await S("Runtime.enable");

  const evalJS = async (expression) => {
    const { result } = await S("Runtime.evaluate", { expression, returnByValue: true });
    return result.value;
  };
  const here = () => evalJS("location.origin + location.pathname").catch(() => "");

  // Recorded on every page, before anything on it can run.
  await S("Page.addScriptToEvaluateOnNewDocument", {
    source: `addEventListener('securitypolicyviolation', (e) =>
      sessionStorage.setItem('violation', e.violatedDirective + ' on ' + e.blockedURI));`,
  });

  await S("Page.navigate", { url: START });
  await sleep(800);
  console.log(`  at        ${await here()}`);

  await evalJS(`(() => {
    const set = (el, v) => { el.focus(); el.value = v; };
    set(document.querySelector('input[name=username]'), ${JSON.stringify(EMAIL)});
    set(document.querySelector('input[name=password]'), ${JSON.stringify(PASSWORD)});
    document.querySelector('input[name=password]').form.querySelector('button').click();
  })()`);

  // Waits for arrival, answering a consent page on the way, and stops when the
  // browser has stopped moving somewhere that is not the arrival.
  let arrived = false, last = "", still = 0, consented = false, answered = false;
  for (let i = 0; i < 60 && !arrived; i++) {
    await sleep(250);
    const at = await here();
    arrived = at.startsWith(ARRIVAL);
    if (arrived) break;
    if (at !== last) {
      console.log(`  at        ${at}`);
      last = at;
      still = 0;
    } else if (++still > 12) {
      break;
    }
    // TOTP_SEED, in hex, answers a second factor as an authenticator would.
    if (process.env.TOTP_SEED && !answered && await evalJS(`!!document.querySelector('input[name=code]')`)) {
      answered = true;
      console.log("  code      answering");
      await evalJS(`(() => {
        const field = document.querySelector('input[name=code]');
        field.value = ${JSON.stringify(totp(process.env.TOTP_SEED))};
        field.form.querySelector('button').click();
      })()`);
      continue;
    }
    if (!consented && at.endsWith("/consent") || (!consented && await evalJS(
      `!!document.querySelector('form[action*="consent"]')`))) {
      consented = true;
      console.log("  consent   allowing");
      await evalJS(`(() => {
        const form = document.querySelector('form[action*="consent"]');
        const buttons = [...form.querySelectorAll('button')];
        (buttons.find((b) => /allow/i.test(b.value + b.textContent)) || buttons[0]).click();
      })()`);
    }
  }

  const violation = await evalJS(`sessionStorage.getItem('violation')`).catch(() => null);
  if (violation) console.log(`  violation ${violation}`);
  failed = !arrived;
  console.log(`  ${arrived ? "PASS" : "FAIL"}  ${arrived
    ? `the browser reached ${ARRIVAL}`
    : `the browser stopped at ${await here()}, short of ${ARRIVAL}`}`);

  // With AFTER set, somewhere to go once arrived, pressing what that page offers:
  // a sign-out, whose frames a test can only see from the other side.
  if (arrived && process.env.AFTER) {
    await S("Page.navigate", { url: process.env.AFTER });
    await sleep(1000);
    await evalJS(`document.querySelector('form button')?.click()`);
    await sleep(2500);
    console.log(`  then      ${await here()}`);
  }
  ws.close();
} catch (err) {
  console.log(`  FAIL  ${err.message}`);
} finally {
  chrome.kill();
  await sleep(300);
  rmSync(profile, { recursive: true, force: true });
}
process.exit(failed ? 1 : 0);
