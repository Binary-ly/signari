import { NextResponse } from "next/server";
import { client, config, redirectUri, PENDING, pendingCookie } from "../../lib/signari";

// Made for each request: never prerendered, which would hand everybody one state.
export const dynamic = "force-dynamic";

// The redirect out: a fresh state, nonce and PKCE verifier for this one sign-in. Signari
// requires PKCE of every client, confidential ones included, and S256 only.
export async function GET() {
  const verifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  const nonce = client.randomNonce();
  const url = client.buildAuthorizationUrl(await config(), {
    redirect_uri: redirectUri,
    scope: "openid email profile",
    code_challenge: await client.calculatePKCECodeChallenge(verifier),
    code_challenge_method: "S256",
    state,
    nonce,
  });
  const res = NextResponse.redirect(url);
  res.cookies.set(PENDING, JSON.stringify({ state, nonce, verifier }), pendingCookie);
  return res;
}
