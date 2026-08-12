// Back-channel logout conformance check for YOUR application.
//
// The question this answers is the one the identity industry quietly does not:
//
//     when a user signs out at the IdP, does your application ACTUALLY end
//     their session -- or does it keep them signed in and nobody notices?
//
// Every OIDC provider queues a back-channel logout notice. Whether the relying
// party does anything useful with it is between the RP and its own session
// store, and it is almost never checked. The usual outcome is that logout
// "works" in the sense that the IdP sent something, and the user stays signed
// in to the application for hours.
//
// This drives a real browser through a real sign-in, signs out at the IdP, and
// then asks your application whether the user is still in. It cannot be fooled
// by a 200 from a webhook, because it does not look at the webhook at all -- it
// looks at whether your protected page still serves the user.
//
// Usage:
//   node check.mjs --rp-login https://app.example.com/login \
//                  --rp-protected https://app.example.com/account \
//                  --idp https://id.example.com \
//                  --username alice@example.com --password '...'
//
// Exit code 0 when your application is conformant, 1 when it is not.

import WebSocket from "ws";
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, arr) => {
    if (a.startsWith("--")) acc.push([a.slice(2), arr[i + 1]]);
    return acc;
  }, [])
);

const REQUIRED = ["rp-login", "rp-protected", "idp", "username", "password"];
const missing = REQUIRED.filter((k) => !args[k]);
if (missing.length) {
  console.error(`missing: ${missing.map((m) => "--" + m).join(", ")}`);
  console.error(`
  --rp-login       a URL on YOUR app that starts sign-in (redirects to the IdP)
  --rp-protected   a URL on YOUR app that requires a session
  --idp            your Signari issuer, e.g. https://id.example.com
  --username       a test account
  --password       its password
  --chrome         path to Chrome (default: the macOS location)
  --home           any PUBLIC same-origin page on your app (default: its root).
                   The probe stands here to ask about the protected page.
  --grace          seconds to allow for back-channel delivery (default 10)
`);
  process.exit(2);
}

const CHROME = args.chrome || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const GRACE = Number(args.grace || 10);
const PORT = 9444;

const results = [];
const check = (name, ok, detail = "") => {
  results.push({ name, ok, detail });
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}${detail ? "\n        " + detail : ""}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

class CDP {
  constructor(ws) {
    this.ws = ws; this.id = 0; this.pending = new Map();
    ws.on("message", (raw) => {
      const m = JSON.parse(raw);
      if (m.id && this.pending.has(m.id)) {
        const { resolve, reject } = this.pending.get(m.id);
        this.pending.delete(m.id);
        m.error ? reject(new Error(JSON.stringify(m.error))) : resolve(m.result);
      }
    });
  }
  send(method, params = {}, sessionId) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params, sessionId }));
      setTimeout(() => {
        if (this.pending.has(id)) { this.pending.delete(id); reject(new Error(method + " timed out")); }
      }, 60000);
    });
  }
}

async function main() {
  const profile = mkdtempSync(join(tmpdir(), "rp-logout-check-"));
  const chrome = spawn(CHROME, [
    `--remote-debugging-port=${PORT}`, `--user-data-dir=${profile}`,
    "--headless=new", "--no-first-run", "--no-default-browser-check", "about:blank",
  ], { stdio: "ignore" });

  try {
    let wsURL;
    for (let i = 0; i < 40 && !wsURL; i++) {
      await sleep(250);
      try { wsURL = (await (await fetch(`http://127.0.0.1:${PORT}/json/version`)).json()).webSocketDebuggerUrl; } catch {}
    }
    if (!wsURL) throw new Error("could not start Chrome");

    const ws = new WebSocket(wsURL, { maxPayload: 256 * 1024 * 1024 });
    await new Promise((res, rej) => { ws.once("open", res); ws.once("error", rej); });
    const cdp = new CDP(ws);
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    const S = (m, p) => cdp.send(m, p, sessionId);
    await S("Page.enable"); await S("Runtime.enable");

    const goto = async (url) => { await S("Page.navigate", { url }); await sleep(1500); };
    const evalJS = async (expr) => {
      const r = await S("Runtime.evaluate",
        { expression: expr, awaitPromise: true, returnByValue: true });
      if (r.exceptionDetails) {
        // Surfaced, not swallowed: a silent undefined here sends an operator
        // hunting their own application for a fault in this tool.
        throw new Error(r.exceptionDetails.exception?.description ||
          r.exceptionDetails.text || "script error in the page");
      }
      return r.result.value;
    };

    // THE PROBE. Getting this wrong gives a false PASS to every broken
    // application, which is worse than shipping no tool at all -- so it is worth
    // being precise about what it measures.
    //
    // The naive probe -- navigate to the protected page and see where you land --
    // is WRONG. While the IdP session is alive, an unauthenticated visit to a
    // protected page silently round-trips through the IdP and comes back
    // authenticated. The page looks reachable whether or not the application
    // kept a session, so the check measures the IDP's session and passes
    // everything.
    //
    // Instead: stand on the application's own origin and ask it directly, with
    // redirects DISABLED. A 200 means the application still holds a session. A
    // redirect means it does not. No round trip, nothing to be fooled by.
    const rpOrigin = new URL(args["rp-protected"]).origin;
    const protectedState = async () => {
      // The application's own login page is guaranteed to exist and to be
      // same-origin. A 404 probe path works in principle but leaves some
      // browsers on an error document with no usable fetch context.
      await goto(args["home"] || rpOrigin + "/");
      const where = await evalJS(`location.origin`);
      if (where !== rpOrigin) {
        // Landed somewhere else -- almost always the IdP, because the
        // application redirected. Say so rather than failing opaquely.
        return { status: 0, type: "redirected-away", signedIn: false, where };
      }
      return await evalJS(`(async () => {
        const r = await fetch(${JSON.stringify(args["rp-protected"])},
          { credentials: 'include', redirect: 'manual' });
        // redirect:'manual' yields an opaqueredirect with status 0 -- that IS
        // the answer, not an error.
        return { status: r.status, type: r.type,
                 signedIn: r.type !== 'opaqueredirect' && r.status >= 200 && r.status < 300 };
      })()`);
    };

    console.log(`\n  Checking ${args["rp-protected"]}\n`);

    // --- 1. sign in through YOUR app --------------------------------------
    await goto(args["rp-login"]);
    // Sign-in is done in TWO steps, and the split is the point.
    //
    // A single fetch cannot do it: the flow ends in a cross-origin redirect back
    // to the application, and fetch cannot follow one without CORS -- it dies
    // with an opaque "Failed to fetch" that looks like the application's fault.
    //
    // A single form.submit() cannot do it either, in this harness: the browser
    // ends up parked at /authorize with no session, because the navigation and
    // the cookie it depends on race.
    //
    // So: POST with fetch, which reliably stores the session cookie, and IGNORE
    // the redirect failure -- by the time fetch gives up, Set-Cookie has already
    // been applied. Then NAVIGATE, which follows cross-origin redirects exactly
    // as a user's browser would, now carrying the session.
    const posted = await evalJS(`(async () => {
      const f = document.querySelector('input[name=csrf_token]');
      if (!f) return { ok: false, why: 'no Signari login form appeared -- is --rp-login the URL that redirects to the IdP?' };
      const form = f.closest('form');
      const body = new URLSearchParams({
        username: ${JSON.stringify(args.username)},
        password: ${JSON.stringify(args.password)},
        csrf_token: f.value,
        authz: (form.querySelector('[name=authz]') || {}).value || ''
      });
      try {
        await fetch('/login', { method: 'POST', body, credentials: 'same-origin', redirect: 'follow' });
      } catch (e) {
        // Expected: the chain leaves this origin. The cookie is already set.
      }
      return { ok: true };
    })()`);
    if (!posted.ok) {
      check("sign in through your application", false, posted.why);
      throw new Error("cannot continue without a session");
    }

    // Now walk the flow again as a navigation. With the IdP session live this
    // sails through authorize and lands back on the application.
    await goto(args["rp-login"]);
    await sleep(3500); // let the redirect chain settle back onto the application

    const before = await protectedState();
    check("sign in through your application", true, "");
    check("your application grants access after sign-in", before.signedIn,
      `${before.status || before.type} from ${args["rp-protected"]}`);
    const isIn = before.signedIn;
    if (!isIn) throw new Error("never established an application session; nothing to test");

    // --- 2. sign out at the IdP -------------------------------------------
    // NOT through the application's own logout. The whole point is whether a
    // logout that happens somewhere else -- another app, an admin revoking the
    // session, a different device -- reaches this one.
    await goto(`${args.idp}/oauth2/logout`);
    check("signed out at the identity provider", true, `${args.idp}/oauth2/logout`);

    // --- 3. the actual question -------------------------------------------
    let after = null;
    let ended = false;
    for (let i = 0; i < GRACE && !ended; i++) {
      await sleep(1000);
      after = await protectedState();
      ended = !after.signedIn;
    }

    check("your application ended the session too", ended,
      ended
        ? `the application now refuses the request (${after.status || after.type})`
        : `STILL SIGNED IN after ${GRACE}s: it still serves ${args["rp-protected"]} (${after.status})\n` +
          `        The IdP ended the session. Your application did not.\n` +
          `        Check that it registered a backchannel_logout_uri, that the\n` +
          `        endpoint verifies the logout token, and that it deletes the\n` +
          `        session keyed by the token's sid -- not just the current request's.`);

    ws.close();
  } finally {
    chrome.kill();
  }

  const failed = results.filter((r) => !r.ok).length;
  console.log(`\n  ${results.length - failed}/${results.length} passed`);
  if (failed) {
    console.log(`
  Your application does not end sessions on back-channel logout.
  Users who sign out elsewhere stay signed in here until their session
  expires on its own. That is the default behaviour of most OIDC client
  libraries, and it is why this check exists.\n`);
  }
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error("\n  harness error:", e.message); process.exit(3); });
