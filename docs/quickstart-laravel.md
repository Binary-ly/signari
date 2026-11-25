# Quickstart: a Laravel application

## Introduction

This guide connects a [Laravel](https://laravel.com) application to Signari, so
that people sign in to it with their Signari account. The example,
[examples/laravel-quickstart](../examples/laravel-quickstart/routes/web.php), uses
[jumbojett/openid-connect-php](https://github.com/jumbojett/OpenID-Connect-PHP) for
the protocol. It is a few files to lay over a fresh Laravel application, not an
application of its own.

You register the application, run the example, and sign in. The last sections
explain what the example does at each step, and why.

> [!NOTE]
> New to Signari? [Your first application](first-application.md) runs this
> example and five others on your own computer, with nothing to register by hand.

## 1. Register the application

Register the example as a confidential client, and set it to the signature
algorithm its library can check:

```sh
signari client create -org <org-id> -client-id quickstart -name Quickstart \
  -redirect http://127.0.0.1:8000/callback
signari client set-alg -client-id quickstart -alg RS256
```

It prints the client secret once. Keep it. The second line matters: this library
verifies RSA signatures (RS256, RS384, RS512, PS256, PS512) and not the ES256 Signari
signs with by default. Without it every sign-in is refused with "No support for
signature type: ES256".

## 2. Run it

Make a fresh Laravel application, add the library, and copy the example's files
over it:

```sh
composer create-project laravel/laravel:13.11.0 myapp && cd myapp
composer require jumbojett/openid-connect-php:1.0.2
cp -R <signari>/examples/laravel-quickstart/app <signari>/examples/laravel-quickstart/config \
  <signari>/examples/laravel-quickstart/routes .
```

That adds `app/Support/SignariClient.php`, `app/Support/RedirectTo.php` and
`config/signari.php`, and replaces `routes/web.php`. Then set, in `.env`:

```sh
SIGNARI_ISSUER=https://id.example.com
SIGNARI_CLIENT_ID=quickstart
SIGNARI_CLIENT_SECRET=<the secret>
SIGNARI_REDIRECT_URI=http://127.0.0.1:8000/callback
```

and run `php artisan serve`. Open `http://127.0.0.1:8000/login`, sign in, and the page
says who signed in. For a certificate your machine does not trust, set
`SIGNARI_CA_FILE=<file.pem>`. Never turn certificate checking off.

## In compose

The `demo` profile of `deploy/docker-compose.yml` runs this example from its
[Dockerfile](../examples/laravel-quickstart/Dockerfile) as `demo-laravel`, at
`http://localhost:8095/login`. With the settings that [Your first
application](first-application.md#1-start-signari-and-the-example-applications)
writes to `deploy/.env`, start it:

```sh
cd deploy && docker compose --profile first-run --profile demo up -d
```

The image does what step 2 does, with the settings taken from the container's
environment instead of an `.env`, and sessions kept in files, so there is no database.
It makes an `APP_KEY` each time it starts unless it is given one, so none is built into
it, and runs `php artisan serve`. Its client, `demo-laravel` in
[deploy/demo/client.yaml](../deploy/demo/client.yaml), is public and set to RS256 there,
for the reason step 1 gives. The library authenticates a client with no secret by its
`client_id` and the Proof Key for Code Exchange (PKCE) verifier alone. It trusts the
development CA under
`deploy/tls` through `SIGNARI_CA_FILE`.

## What it does, and why each step is there

1. **The client, made to live in Laravel.** The library keeps a sign-in's state,
   nonce and PKCE verifier in PHP's own session, and sends a redirect by writing a
   header and calling `exit`. `exit` would skip Laravel saving its session.
   `SignariClient` keeps them in Laravel's session instead and hands the redirect back
   to the route as a response. `S256` is set, since Signari requires PKCE of every
   client, confidential ones included.
2. **The callback checks the state first.** The library compares the `state` only
   after it has spent the code at the token endpoint. The route compares it before,
   so a code nobody here asked for is never redeemed.
3. **Then the library** exchanges the code with the verifier over
   `client_secret_basic`, each half form-encoded as Signari decodes them. It checks
   the ID token's signature against `jwks_uri`, then its issuer, audience, expiry and
   nonce.

A public client has no secret: leave `SIGNARI_CLIENT_SECRET` empty and register it with
`-public`. The messages a refusal shows are Signari's own; see
[Troubleshooting](troubleshooting.md).

## Verified

On 14 November 2026, with PHP 8.4, Laravel 13.11.0 (framework 13.42.0) and
jumbojett/openid-connect-php 1.0.2, served by `php artisan serve` against a running
engine over Transport Layer Security (TLS). With the client at ES256 the library refused the ID token, as above.
With `client set-alg ... RS256`, Ada signed in through the engine's pages and the
application said "Signed in as ada@staff.test". The engine's access log showed
`/oauth2/jwks` fetched for the signature. A callback this browser never began was
refused before any code was exchanged.
