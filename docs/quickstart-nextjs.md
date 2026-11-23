# Quickstart: a Next.js application

## Introduction

This guide connects a [Next.js](https://nextjs.org) application, using the App
Router, to Signari, so that people sign in to it with their Signari account. The
example, [examples/nextjs-quickstart](../examples/nextjs-quickstart/lib/signari.js),
uses [openid-client](https://github.com/panva/openid-client) in two route
handlers: `/login` and `/callback`.

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

It prints the client secret once. Keep it. A redirect URI is matched exactly.

## 2. Run it

Install and build the example, then run it with Signari's address and the values
from step 1:

```sh
cd examples/nextjs-quickstart
npm ci && npm run build
SIGNARI_ISSUER=https://id.example.com CLIENT_ID=quickstart CLIENT_SECRET=<the secret> \
  REDIRECT_URI=http://127.0.0.1:3000/callback npm start
```

Open `http://127.0.0.1:3000/login`, sign in, and the page says who signed in. The
versions are pinned in `package.json`, and everything under them in
`package-lock.json`, which `npm ci` installs exactly. For a certificate your machine does not trust,
give Node the certificate with `NODE_EXTRA_CA_CERTS=<file.pem>`.

## In compose

The `demo` profile of `deploy/docker-compose.yml` runs this example from its
[Dockerfile](../examples/nextjs-quickstart/Dockerfile) as `demo-nextjs`, the public client
`demo-nextjs` of [deploy/demo/client.yaml](../deploy/demo/client.yaml), at
`http://localhost:8092/login`. With the exports the [README](../README.md#quick-start)
gives:

```sh
cd deploy && docker compose --profile first-run --profile demo up -d
```

The image runs `next build` once; the settings are read when the container starts,
since both routes are dynamic. It listens on `PORT` (8092 here) and trusts the
development CA under `deploy/tls` through `NODE_EXTRA_CA_CERTS`.

## What it does, and why each step is there

1. **Discovery,** once per process, in `lib/signari.js`. The issuer the document
   names has to be the one configured. A discovery that failed, because the server
   was not answering yet, is not kept, so the next sign-in tries again.
2. **`/login`** makes a fresh `state`, `nonce` and PKCE verifier and keeps them in a
   cookie of their own: httpOnly, for `/callback` alone, ten minutes. A route handler
   cannot rely on memory between two requests. Signari requires PKCE of every client,
   and `S256` only. Both handlers are `force-dynamic`. Prerendered, `/login` would
   hand everybody the one state it was built with.
3. **`/callback`** takes that cookie once, refuses a `state` it does not match, and
   exchanges the code with the verifier over `client_secret_basic`. It checks the ID
   token's issuer, audience, expiry and nonce, and its signature against `jwks_uri`.
   openid-client checks the signature only when told to (`enableNonRepudiationChecks`),
   since OpenID Connect lets a client trust the TLS connection instead.

A public client has no secret: leave `CLIENT_SECRET` unset and register it with
`-public`. The messages a refusal shows are the server's own; see
[troubleshooting.md](troubleshooting.md).

## Verified

On 14 November 2026, with Node 24, Next.js 16.4.6, React 19.3.1 and openid-client
6.9.0, built with `next build` (both routes dynamic) and run with `next start` against a
running engine over TLS. Ada signed in through the engine's pages and the application
said "Signed in as ada@staff.test". The engine's access log showed `/oauth2/jwks` fetched
after the token call. A callback this browser never began was refused.
