# Quickstart: an Express application

## Introduction

This guide connects an [Express](https://expressjs.com) application to Signari, so
that people sign in to it with their Signari account. The example,
[examples/express-quickstart](../examples/express-quickstart/server.js), uses
[openid-client](https://github.com/panva/openid-client) for the protocol. It is
about eighty lines.

You register the application, run the example, and sign in. The last sections
explain what the example does at each step, and why.

> [!NOTE]
> New to Signari? [Your first application](first-application.md) runs this
> example and five others on your own computer, with nothing to register by hand.

## 1. Register the application

Register the example as a confidential client, with the address it listens on as
its redirect URI:

```sh
signari client create -org <org-id> -client-id quickstart -name Quickstart \
  -redirect http://127.0.0.1:3000/callback
```

It prints the client secret once. Keep it. A redirect URI is matched exactly:
scheme, host, port and path.

## 2. Run it

Install the example's dependencies, then run it with Signari's address and the
values from step 1:

```sh
cd examples/express-quickstart
npm ci
SIGNARI_ISSUER=https://id.example.com CLIENT_ID=quickstart CLIENT_SECRET=<the secret> \
  REDIRECT_URI=http://127.0.0.1:3000/callback npm start
```

Open `http://127.0.0.1:3000/login`, sign in, and the page says who signed in. The
versions are pinned in `package.json`, and everything under them in
`package-lock.json`, which `npm ci` installs exactly.

If the engine's certificate is one your machine does not trust, as on a laptop, give
Node the certificate with `NODE_EXTRA_CA_CERTS=<file.pem>`. Never turn certificate
checking off.

## In compose

The `demo` profile of `deploy/docker-compose.yml` runs this example from its
[Dockerfile](../examples/express-quickstart/Dockerfile) as `demo-express`, the public
client `demo-express` of [deploy/demo/client.yaml](../deploy/demo/client.yaml), at
`http://localhost:8091/login`. With the exports the [README](../README.md#quick-start)
gives:

```sh
cd deploy && docker compose --profile first-run --profile demo up -d
```

It trusts the development CA under `deploy/tls` through `NODE_EXTRA_CA_CERTS`.

## What it does, and why each step is there

1. **Discovery.** `client.discovery` reads `/.well-known/openid-configuration` and
   refuses an issuer there that is not the one configured.
2. **The redirect out.** `/login` makes a fresh `state`, `nonce` and Proof Key for
   Code Exchange (PKCE) verifier for this one sign-in and sends `code_challenge_method=S256`. Signari requires
   PKCE of every client by default, confidential ones included.
3. **The callback.** It takes the `state` back once and refuses one it does not
   hold. `authorizationCodeGrant` sends the code and the verifier, authenticating
   with `client_secret_basic`, and checks the ID token's issuer, audience, expiry
   and nonce.
4. **The signature too.** openid-client does not check an ID token's signature by
   default. OpenID Connect lets a client trust the Transport Layer Security (TLS)
   connection to the token
   endpoint instead (Core, section 3.1.3.7). This example turns on
   `enableNonRepudiationChecks`, so the signature is checked against `jwks_uri` as
   well.

A public client has no secret: leave `CLIENT_SECRET` unset, register it with
`-public`, and the example authenticates with its `client_id` alone. PKCE is then its
only proof.

When something is refused, the message is Signari's own. What each one means is in
[Troubleshooting](troubleshooting.md).

## Verified

On 14 November 2026, with Node 24, Express 5.3.0 and openid-client 6.9.0, against a
running engine over TLS. Ada signed in through the engine's own sign-in and consent
pages and the application said "Signed in as ada@staff.test". The engine's access log
showed the discovery document, the token call and, right after it, `/oauth2/jwks`,
fetched for the signature check. A callback with a state the application never gave
was refused.
