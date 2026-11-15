// The one place this application talks to Signari: discovery once per process, the
// client authenticated with client_secret_basic, or with its client_id alone when public,
// and the ID token's signature checked against the published keys as well as its issuer,
// audience, expiry and nonce. OpenID Connect lets a client trust the TLS connection to the
// token endpoint instead of the signature; this one does both.
import * as client from "openid-client";

const issuer = process.env.SIGNARI_ISSUER;
const clientId = process.env.CLIENT_ID;
export const redirectUri = process.env.REDIRECT_URI;

let configured;

export function config() {
  if (!issuer || !clientId || !redirectUri) {
    throw new Error("set SIGNARI_ISSUER, CLIENT_ID and REDIRECT_URI, and CLIENT_SECRET for a confidential client");
  }
  const secret = process.env.CLIENT_SECRET;
  // Kept once it succeeds. A failure is forgotten, so a request made while the server was
  // not answering yet does not leave this process failing every sign-in after it.
  configured ??= client.discovery(new URL(issuer), clientId, undefined,
    secret ? client.ClientSecretBasic(secret) : client.None(),
    { execute: [client.enableNonRepudiationChecks] }).catch((err) => {
    configured = undefined;
    throw err;
  });
  return configured;
}

// What one sign-in holds between the redirect out and the callback: a cookie of its
// own, httpOnly, for this path, and gone in ten minutes.
export const PENDING = "signari_pending";
export const pendingCookie = { httpOnly: true, sameSite: "lax", path: "/callback", maxAge: 600,
  secure: redirectUri?.startsWith("https:") };

export { client };
