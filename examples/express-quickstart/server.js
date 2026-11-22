// An Express application that signs people in with Signari through openid-client: the
// authorization code flow with PKCE, the state and nonce of each sign-in checked, and the
// ID token's signature checked against the published keys as well as its issuer, audience
// and expiry. See docs/quickstart-express.md.
//
//   SIGNARI_ISSUER=https://id.example.com CLIENT_ID=quickstart CLIENT_SECRET=... \
//   REDIRECT_URI=http://127.0.0.1:3000/callback npm start
import express from "express";
import * as client from "openid-client";

const issuer = process.env.SIGNARI_ISSUER;
const clientId = process.env.CLIENT_ID;
const redirectUri = process.env.REDIRECT_URI;
if (!issuer || !clientId || !redirectUri) {
  console.error("set SIGNARI_ISSUER, CLIENT_ID and REDIRECT_URI, and CLIENT_SECRET for a confidential client");
  process.exit(1);
}
const secret = process.env.CLIENT_SECRET;

// Discovery checks the document's issuer is the one asked for. client_secret_basic for a
// confidential client, the client_id alone for a public one, whose proof is PKCE.
// enableNonRepudiationChecks has the ID token's signature checked against jwks_uri too:
// OpenID Connect lets a client rely on TLS instead for a token from the token endpoint,
// and this one does both.
const config = await client.discovery(new URL(issuer), clientId, undefined,
  secret ? client.ClientSecretBasic(secret) : client.None(),
  { execute: [client.enableNonRepudiationChecks] });

// One sign-in between the redirect out and the callback, by its state, for ten minutes.
const pending = new Map();
const escape = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

const app = express();

app.get("/", (req, res) => {
  res.type("html").send(`<p><a href="/login">Sign in with Signari</a></p>`);
});

app.get("/login", async (req, res) => {
  // Signari requires PKCE of every client, confidential ones included, and S256 only.
  const verifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  const nonce = client.randomNonce();
  pending.set(state, { verifier, nonce, made: Date.now() });
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: redirectUri,
    scope: "openid email profile",
    code_challenge: await client.calculatePKCECodeChallenge(verifier),
    code_challenge_method: "S256",
    state,
    nonce,
  });
  res.redirect(url.href);
});

app.get("/callback", async (req, res) => {
  const state = String(req.query.state ?? "");
  const held = pending.get(state);
  pending.delete(state);
  if (!held || Date.now() - held.made > 10 * 60 * 1000) {
    res.status(400).type("text").send("this sign-in was not started here, or it took too long");
    return;
  }
  try {
    const here = new URL(req.originalUrl, redirectUri);
    const tokens = await client.authorizationCodeGrant(config, here, {
      pkceCodeVerifier: held.verifier,
      expectedState: state,
      expectedNonce: held.nonce,
      idTokenExpected: true,
    });
    const claims = tokens.claims();
    res.type("html").send(`<p>Signed in as ${escape(claims.email ?? claims.sub)}</p>`);
  } catch (err) {
    // The server's own words, which docs/troubleshooting.md explains.
    res.status(400).type("text").send(`the sign-in was refused: ${err.error_description ?? err.message}`);
  }
});

const { port } = new URL(redirectUri);
app.listen(Number(process.env.PORT ?? port ?? 3000), "127.0.0.1");
