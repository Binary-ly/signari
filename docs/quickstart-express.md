# Quickstart: an Express application

[examples/express-quickstart](../examples/express-quickstart/server.js) signs people in
with Signari from an [Express](https://expressjs.com) application, using
[openid-client](https://github.com/panva/openid-client) for the protocol. It is about
eighty lines.

## 1. Register the application

```sh
signari client create -org <org-id> -client-id quickstart -name Quickstart \
  -redirect http://127.0.0.1:3000/callback
```

It prints the client secret once. Keep it. A redirect URI is matched exactly:
scheme, host, port and path.

## 2. Run it

```sh
cd examples/express-quickstart
npm install
SIGNARI_ISSUER=https://id.example.com CLIENT_ID=quickstart CLIENT_SECRET=<the secret> \
  REDIRECT_URI=http://127.0.0.1:3000/callback npm start
```

Open `http://127.0.0.1:3000/login`, sign in, and the page says who signed in. The
versions are pinned in `package.json`.

If the engine's certificate is one your machine does not trust, as on a laptop, give
Node the certificate with `NODE_EXTRA_CA_CERTS=<file.pem>`. Never turn certificate
checking off.

## What it does, and why each step is there

1. **Discovery.** `client.discovery` reads `/.well-known/openid-configuration` and
   refuses an issuer there that is not the one configured.
2. **The redirect out.** `/login` makes a fresh `state`, `nonce` and PKCE verifier
   for this one sign-in and sends `code_challenge_method=S256`. Signari requires
   PKCE of every client by default, confidential ones included.
3. **The callback.** It takes the `state` back once and refuses one it does not
   hold. `authorizationCodeGrant` sends the code and the verifier, authenticating
   with `client_secret_basic`, and checks the ID token's issuer, audience, expiry
   and nonce.
4. **The signature too.** openid-client does not check an ID token's signature by
   default. OpenID Connect lets a client trust the TLS connection to the token
   endpoint instead (Core, section 3.1.3.7). This example turns on
   `enableNonRepudiationChecks`, so the signature is checked against `jwks_uri` as
   well.

A public client has no secret: leave `CLIENT_SECRET` unset, register it with
`-public`, and the example authenticates with its `client_id` alone. PKCE is then its
only proof.

When something is refused, the message is the server's own. What each one means is in
[troubleshooting.md](troubleshooting.md).

## Verified

On 14 November 2026, with Node 24, Express 5.3.0 and openid-client 6.9.0, against a
running engine over TLS. Ada signed in through the engine's own sign-in and consent
pages and the application said "Signed in as ada@staff.test". The engine's access log
showed the discovery document, the token call and, right after it, `/oauth2/jwks`,
fetched for the signature check. A callback with a state the application never gave
was refused.
