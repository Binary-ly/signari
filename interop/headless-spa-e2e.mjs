// Does an application with a sign-in page of its own get a person signed in, in a REAL
// browser? CORS is what decides, and no HTTP client feels it: the walk's two routes and
// the token endpoint are called by script from another origin, and the page is reached
// by a redirect the engine chose. So this serves headless-spa/ and has Chrome sign in
// through it, from the button to the tokens.
//
// Needs Node 22 or later for the built-in WebSocket, and nothing else. The client must
// be public, with http://localhost:<port>/ as its redirect URI and its login_ui_url.
//
// Usage:  node headless-spa-e2e.mjs <issuer> <client-id> <port> <email> <password>
//         TOTP_SEED, in hex, answers a second factor as an authenticator would.

import { spawn } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const [ISSUER, CLIENT, PORT, EMAIL, PASSWORD] = process.argv.slice(2);
if (!ISSUER || !CLIENT || !PORT || !EMAIL || !PASSWORD) {
  console.error("usage: node headless-spa-e2e.mjs <issuer> <client-id> <port> <email> <password>");
  process.exit(2);
}

const CHROME = process.env.CHROME ||
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const DEBUG_PORT = 9336;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const page = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "headless-spa", "index.html"));

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

const site = createServer((_, res) => {
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(page);
}).listen(Number(PORT), "127.0.0.1");

const profile = mkdtempSync(join(tmpdir(), "signari-headless-spa-"));
const chrome = spawn(CHROME, [
  `--remote-debugging-port=${DEBUG_PORT}`,
  `--user-data-dir=${profile}`,
  "--headless=new",
  "--no-first-run",
  "--no-default-browser-check",
  "about:blank",
], { stdio: "ignore" });

let failed = true;
try {
  let wsURL;
  for (let i = 0; i < 40 && !wsURL; i++) {
    await sleep(250);
    try {
      const r = await fetch(`http://127.0.0.1:${DEBUG_PORT}/json/version`);
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

  const seen = [];
  cdp.ws.addEventListener("message", (event) => {
    const msg = JSON.parse(event.data);
    if (msg.method === "Runtime.exceptionThrown") {
      seen.push(msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text);
    }
  });
  const evalJS = async (expression) => {
    const { result } = await S("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
    return result.value;
  };
  const text = (selector) => evalJS(`document.querySelector(${JSON.stringify(selector)})?.textContent ?? ''`).catch(() => "");
  const stage = () => text("#stage");
  const until = async (test) => {
    for (let i = 0; i < 40; i++) {
      if (await test()) return true;
      await sleep(250);
    }
    return false;
  };

  await S("Page.navigate", { url: `http://localhost:${PORT}/?issuer=${encodeURIComponent(ISSUER)}&client_id=${CLIENT}` });
  await until(async () => (await text("#start")) !== "");
  await evalJS(`document.querySelector('#start').click()`);
  if (!await until(async () => (await stage()) === "login")) {
    throw new Error(`the application's page never showed the sign-in: ${await evalJS("location.href")}`);
  }
  console.log(`  at        ${await evalJS("location.origin + location.pathname")}, asked: login`);

  await evalJS(`(() => {
    document.querySelector('input[name=username]').value = ${JSON.stringify(EMAIL)};
    document.querySelector('input[name=password]').value = ${JSON.stringify(PASSWORD)};
    document.querySelector('form button').click();
  })()`);

  let done = false;
  for (let i = 0; i < 80 && !done; i++) {
    await sleep(250);
    done = (await text("#signed-in")) !== "";
    if (done) break;
    const now = await stage();
    if (now === "mfa" && process.env.TOTP_SEED && !await evalJS(`document.body.dataset.answered === '1'`)) {
      console.log("  asked     mfa");
      await evalJS(`(() => {
        document.body.dataset.answered = '1';
        document.querySelector('input[name=code]').value = ${JSON.stringify(totp(process.env.TOTP_SEED))};
        document.querySelector('form button').click();
      })()`);
    }
    if (now === "consent" && !await evalJS(`document.body.dataset.consented === '1'`)) {
      console.log("  asked     consent");
      await evalJS(`(() => {
        document.body.dataset.consented = '1';
        [...document.querySelectorAll('button')].find((b) => b.dataset.value === 'allow').click();
      })()`);
    }
  }
  const signedIn = await text("#signed-in");
  const said = await text("#message");
  if (said) console.log(`  said      ${said}`);
  for (const thrown of seen) console.log(`  thrown    ${thrown.split("\n")[0]}`);
  failed = !signedIn.startsWith("signed in as ");
  console.log(`  ${failed ? "FAIL" : "PASS"}  ${failed ? `stopped at ${await stage()}` : "the application has tokens: " + signedIn.slice(0, 24) + "..."}`);
  ws.close();
} catch (err) {
  console.log(`  FAIL  ${err.message}`);
} finally {
  chrome.kill();
  site.close();
  await sleep(300);
  rmSync(profile, { recursive: true, force: true });
}
process.exit(failed ? 1 : 0);
