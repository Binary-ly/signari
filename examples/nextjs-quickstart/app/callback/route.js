import { client, config, redirectUri, PENDING, pendingCookie } from "../../lib/signari";

export const dynamic = "force-dynamic";

const escape = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const page = (status, html) => new Response(`<!doctype html><meta charset="utf-8">${html}`,
  { status, headers: { "content-type": "text/html; charset=utf-8" } });

// The callback: the sign-in this browser began, taken once; the code exchanged with the
// verifier; and the ID token's state, nonce, issuer, audience, expiry and signature
// checked before anybody is believed.
export async function GET(request) {
  let held;
  try {
    held = JSON.parse(request.cookies.get(PENDING)?.value ?? "");
  } catch {
    held = null;
  }
  if (!held || held.state !== request.nextUrl.searchParams.get("state")) {
    return page(400, "<p>This sign-in was not started in this browser, or it took too long.</p>");
  }
  let res;
  try {
    const here = new URL(request.nextUrl.pathname + request.nextUrl.search, redirectUri);
    const tokens = await client.authorizationCodeGrant(await config(), here, {
      pkceCodeVerifier: held.verifier,
      expectedState: held.state,
      expectedNonce: held.nonce,
      idTokenExpected: true,
    });
    const claims = tokens.claims();
    res = page(200, `<p>Signed in as ${escape(claims.email ?? claims.sub)}</p>`);
  } catch (err) {
    // The server's own words, which docs/troubleshooting.md explains.
    res = page(400, `<p>The sign-in was refused: ${escape(err.error_description ?? err.message)}</p>`);
  }
  // Used once, whatever the answer.
  res.headers.append("set-cookie", `${PENDING}=; Path=${pendingCookie.path}; Max-Age=0; HttpOnly; SameSite=Lax`);
  return res;
}
