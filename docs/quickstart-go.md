# Quickstart: a Go application

[examples/go-quickstart](../examples/go-quickstart/main.go) is an application
that signs people in with Signari using nothing outside Go's standard library.
It is about two hundred lines, and checks everything an application has to
check itself: the authorization code flow with PKCE, then the ID token's
signature against the published keys, its issuer, audience, expiry and nonce.

## 1. Register the application

```sh
signari client create -org <org-id> -client-id quickstart -name Quickstart \
  -redirect http://127.0.0.1:8080/callback
```

It prints the client secret once. Keep it. A redirect URI is matched exactly:
scheme, host, port and path.

## 2. Run it

```sh
cd examples/go-quickstart
SIGNARI_ISSUER=https://id.example.com CLIENT_ID=quickstart CLIENT_SECRET=<the secret> \
  REDIRECT_URI=http://127.0.0.1:8080/callback go run .
```

Open `http://127.0.0.1:8080/login`, sign in, and the page says who signed in.

## What it does, and why each step is there

1. **Discovery.** It reads `/.well-known/openid-configuration` and refuses to
   start when the issuer there is not the one configured. An application that
   took another issuer would accept tokens minted for someone else.
2. **The redirect out.** `/login` makes a fresh `state`, `nonce` and PKCE
   verifier for this one sign-in, keeps them, and sends the browser to the
   authorization endpoint with the verifier's SHA-256 as `code_challenge` and
   `code_challenge_method=S256`. Signari requires PKCE of every client by
   default, confidential ones included, and accepts only `S256`.
3. **The callback.** It takes the `state` back once and refuses one it does not
   hold. It sends the code, the same `redirect_uri` and the verifier to the token
   endpoint, authenticating with `client_secret_basic`, each half form-encoded
   first, as the server decodes them.
4. **The ID token.** It checks the signature with the key the token's `kid`
   names, from `jwks_uri` (ES256 by default; RS256 for a client set to it), then
   `iss`, `aud`, `exp` and `nonce`. Only then does it believe who signed in.

A public client, such as a single-page or native application, has no secret.
Leave `CLIENT_SECRET` unset and register it with `-public`, and it sends its
`client_id` with the code instead. PKCE is then its only proof.

When something is refused, the message is the server's own. What each one means
is in [troubleshooting.md](troubleshooting.md).

## Verified

Run against a running engine: discovery, PKCE `S256`, the sign-in, the code
exchanged for tokens, and an ES256 ID token verified against the published key,
ending in "Signed in as …". With the signature check broken on purpose, the same
sign-in is refused with "no published key verifies it".
