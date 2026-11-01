// Every page, in a REAL browser: does it render, and does anything on it get stopped?
//
// A page can answer 200 with the right HTML, pass every test here, and do nothing in a
// browser, because a Content Security Policy refused the script it depends on. That has
// happened on this project to the pages that matter most, so this visits each one and
// reports what the browser refused or threw. It presses nothing but the sign-in form.
//
// Needs Node 22 or later for the built-in WebSocket, and nothing else.
//
// Usage:  node page-sweep-e2e.mjs <base-url> <email> <password>

import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [BASE, EMAIL, PASSWORD] = process.argv.slice(2);
if (!BASE || !EMAIL || !PASSWORD) {
  console.error("usage: node page-sweep-e2e.mjs <base-url> <email> <password>");
  process.exit(2);
}

const CHROME = process.env.CHROME ||
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const PORT = 9335;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Nobody signed in, then somebody who is.
const OPEN = ["/login", "/login/accounts", "/signup", "/recover", "/device"];
const SIGNED_IN = ["/account", "/account/profile", "/account/security", "/account/password",
  "/account/recovery", "/account/sessions", "/account/devices", "/account/connected",
  "/account/email", "/account/delete", "/account/mfa/totp", "/account/mfa/email",
  "/account/mfa/sms", "/apps", "/rac/connections", "/device"];

const profile = mkdtempSync(join(tmpdir(), "signari-page-sweep-"));
const chrome = spawn(CHROME, [`--remote-debugging-port=${PORT}`, `--user-data-dir=${profile}`,
  "--headless=new", "--no-first-run", "--no-default-browser-check", "about:blank"], { stdio: "ignore" });

let failures = 0;
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

  let id = 0;
  const pending = new Map();
  let trouble = [];
  ws.addEventListener("message", (event) => {
    const msg = JSON.parse(event.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
    }
    if (msg.method === "Log.entryAdded" && msg.params.entry.level === "error") {
      const { text, url } = msg.params.entry;
      trouble.push({ text: url ? `${text}: ${new URL(url).pathname}` : text, url: url ?? "" });
    }
    if (msg.method === "Runtime.exceptionThrown") {
      const { exception, text } = msg.params.exceptionDetails;
      trouble.push({ text: exception?.description ?? text, url: "" });
    }
  });
  const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const n = ++id;
    pending.set(n, { resolve, reject });
    ws.send(JSON.stringify({ id: n, method, params, sessionId }));
    setTimeout(() => {
      if (pending.has(n)) {
        pending.delete(n);
        reject(new Error(`${method} timed out`));
      }
    }, 15000);
  });

  const { targetId } = await send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
  const S = (m, p) => send(m, p, sessionId);
  await S("Page.enable");
  await S("Runtime.enable");
  await S("Log.enable");
  const evalJS = async (expression) =>
    (await S("Runtime.evaluate", { expression, returnByValue: true })).result.value;

  const visit = async (path) => {
    trouble = [];
    await S("Page.navigate", { url: BASE + path });
    await sleep(700);
    const page = await evalJS(`JSON.stringify({
      status: performance.getEntriesByType('navigation')[0]?.responseStatus,
      title: document.title, path: location.pathname,
      words: document.body.innerText.trim().length,
      styled: getComputedStyle(document.body).fontFamily !== 'Times',
    })`);
    const p = JSON.parse(page ?? "{}");
    // Noise about the favicon is not a page's trouble, and neither is the page itself
    // answering 404: a feature that is off says so.
    const real = trouble.map((t) => t).filter((t) => !/favicon/.test(t.url) &&
      !(p.status === 404 && new URL(t.url || BASE).pathname === path)).map((t) => t.text);
    const blank = p.status === 200 && p.words === 0;
    const bad = real.length > 0 || blank || (p.status >= 500);
    if (bad) failures++;
    console.log(`  ${bad ? "FAIL" : "ok  "}  ${String(p.status).padEnd(4)} ${path.padEnd(24)} ${(p.title ?? "").slice(0, 34)}` +
      `${p.path !== path ? `  -> ${p.path}` : ""}${blank ? "  BLANK" : ""}`);
    for (const t of [...new Set(real)]) console.log(`        ${t.slice(0, 170)}`);
  };

  console.log("nobody signed in");
  for (const path of OPEN) await visit(path);

  await S("Page.navigate", { url: BASE + "/login" });
  await sleep(700);
  await evalJS(`(() => {
    document.querySelector('input[name=username]').value = ${JSON.stringify(EMAIL)};
    document.querySelector('input[name=password]').value = ${JSON.stringify(PASSWORD)};
    document.querySelector('input[name=password]').form.querySelector('button').click();
  })()`);
  await sleep(1500);

  console.log("signed in");
  for (const path of SIGNED_IN) await visit(path);
  ws.close();
} catch (err) {
  failures++;
  console.log(`  FAIL  ${err.message}`);
} finally {
  chrome.kill();
  await sleep(300);
  rmSync(profile, { recursive: true, force: true });
}
console.log(failures ? `${failures} page(s) in trouble` : "every page rendered and nothing was refused");
process.exit(failures ? 1 : 0);
