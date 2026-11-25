# Troubleshooting

## Introduction

When something goes wrong, Signari says so in words, and those words are the
quickest way to the cause. Each entry on this page starts from what you see,
quoted exactly as Signari writes it, then gives the cause and the fix.

Search this page for the message you have. If it is not here, search for it in
Signari's source. Every refusal is a literal string there, and most sit next to a
comment that says why the refusal exists.

## When an application cannot sign in

These are the problems people meet first, while connecting their first
application. Each has the same four parts: what you see, why it happens, what to
change, and how to know it worked.

### `redirect_uri is not registered for this client`

**Symptom.** Instead of the sign-in page, Signari shows a page headed **Sign-in
error**, with `invalid_request` and `redirect_uri is not registered for this
client`. The browser never goes back to the application.

**Why.** The application asked Signari to send the browser back to an address
that is not registered for it. Signari compares the address exactly: the scheme,
the host, the port and the path. It never sends anyone to an address it does not
know, so it stops on its own page instead. The usual causes are `http` against
`https`, `localhost` against `127.0.0.1`, a different port, or a slash at the end.

**Fix.** Register the exact address the application sends. The browser's address
bar shows the request Signari refused, and its `redirect_uri` parameter is the
address to register. For a new application, give it to `-redirect` in
`signari client create`. For one already registered, use `signari apply` and a
file that lists it under `redirect_uris` ([configuration as
code](config-as-code.md)), or the Admin API's `PATCH /admin/clients/{id}`. Both
replace the whole list, so give every address the application uses, the new one
among them.

**How to confirm.** Start the sign-in again from the application. Signari shows its
sign-in page instead of the error.

### `unknown client`

**Symptom.** Signari's **Sign-in error** page shows `invalid_client` and `unknown
client`. An application that reaches the token address gets the same pair back as
`error` and `error_description`.

**Why.** No application is registered under the client ID the application sent.
The ID may be misspelt, registered in another Signari deployment, or not
registered at all.

**Fix.** Compare the client ID in the application's settings with the one you
registered, character for character. `signari export org -org <org-id>` writes
every application the organisation has, with its client ID, and the Admin API
answers the same at `GET /admin/clients`.

**How to confirm.** Start the sign-in again. Signari shows its sign-in page.

### `client authentication failed`

**Symptom.** You sign in at Signari and the browser goes back to the application.
Then the application shows an error from its token request: `invalid_client`,
with `client authentication failed`.

**Why.** The application did not prove it is itself. It sent a secret Signari does
not recognise, or proved itself another way than it is registered for. The usual
causes are a secret copied with a character missing, or another application's
secret. Another is an old secret, after `signari client set-keys` moved the
application to signed assertions. Signari tells the application no more than this,
so that nobody can learn anything by guessing. It writes the reason to its own
log, for example `err="the client secret did not match"`.

**Fix.** Give the application the secret printed when it was registered. Signari
keeps only a hash of it, so it cannot show it again. If the secret is lost, the
Admin API's `POST /admin/clients/{clientID}/rotate-secret` makes a new one, shown
once, and the old one stops working at once. An application with no secret, a
public client, must not send one at all: Signari refuses it with `public clients
must not present a client secret`.

**How to confirm.** Sign in again. The application signs you in, and Signari's log
no longer shows `client authentication failed` for its client ID.

### The application says the ID token has expired, or is not valid yet

**Symptom.** You sign in at Signari, and the browser goes back to the application.
Then the application refuses the ID token as expired, or as issued in the future.
The words are the application's own. The [Go example](quickstart-go.md), for
instance, says `the ID token was refused: expired`.

**Why.** The computers' clocks disagree. An ID token says when it was made and
when it expires, five minutes later by default. The application compares those
times with its own clock. If the application's clock is a few minutes away from
Signari's, a token made a moment ago looks expired or not yet made.

**Fix.** Set both machines to keep their clocks synchronised over the network,
with NTP. Do not lengthen the token's lifetime or turn the application's check
off: either hides the problem and weakens the check.

**How to confirm.** Run `date -u` on both machines at the same moment. The times
agree to within a second or two, and the sign-in works.

### `Your sign-in session expired. Please try again.`

**Symptom.** You enter a correct password on Signari's sign-in page, and the page
comes back with `Your sign-in session expired. Please try again.` It happens every
time.

**Why.** Signari's sign-in form is protected by a cookie,
`__Host-signari_csrf`, which must come back with the form. Browsers keep a cookie
whose name starts `__Host-` only from a secure address: `https://`, or
`http://localhost`. If Signari is served over plain HTTP at any other address, or
the browser blocks its cookies, the cookie never comes back. When Signari starts
without Transport Layer Security (TLS), it warns about exactly this: `no TLS configured: browsers will refuse
to store the __Host- session cookie over plaintext on any host except localhost,
so sign-in will silently fail to persist.`

**Fix.** Serve Signari over HTTPS. Give it a certificate with `SIGNARI_TLS_CERT`
and `SIGNARI_TLS_KEY`, or put a reverse proxy that holds one in front of it. Make
the issuer the `https://` address, and allow cookies for Signari's address in the
browser. If the message appeared only once, after the page stayed open across a
browser restart, sign in again. Signari has already given the page a new cookie.

**How to confirm.** In the browser's developer tools, the cookies for Signari's
address include `__Host-signari_csrf`, and `__Host-signari_session` once you have
signed in. The form signs you in.

The full list of what Signari refuses, and where, is in [An application cannot
sign anyone in](#an-application-cannot-sign-anyone-in) below.

## Signari will not start

**`issuer must be https (got "http://…"); set SIGNARI_INSECURE_ISSUER=1 only for local testing`**
The issuer is what every token names and every application checks, so it is
refused over plaintext. Set `SIGNARI_ISSUER` to the https URL that applications
reach. Use `SIGNARI_INSECURE_ISSUER=1` only for a local test.

**`no instance found -- run signari instance create -issuer … first`** and
**`this database has 3 instances; set SIGNARI_ISSUER to name the one to serve`**
An engine serves one instance. With none, make one. With several, Signari
will not guess which is meant, because tokens minted under the wrong issuer
are refused by every application. Set `SIGNARI_ISSUER` to one of those listed.

**`schema version mismatch: database is at 190, this binary expects 195 -- run signari migrate up`**
The binary is newer than the database. Run `signari migrate up` with the new
binary, as `signari_engine`, before it serves. See [Upgrading and rolling back](upgrading.md),
and [Schema versions](schema-versions.md) for what each version changes. A
database *ahead* of the binary is served only when every migration since was
declared compatible with the release before.

**`SIGNARI_ROOT_KEY is unset (32 random bytes, base64), and so is SIGNARI_ROOT_KEY_FILE`**
The root key seals signing keys, OTP seeds and personal attributes, and is
never stored in the database it protects. Generate one with
`head -c 32 /dev/urandom | base64`, and keep it where the database's backups
are not. See [the configuration reference](configuration.md), which also covers
`SIGNARI_ROOT_KEY_FILE` and rotating it.

**`the admin API will not serve plaintext: pass -tls-cert and -tls-key, or -admin-insecure …`**
The Admin API carries bearer tokens, so plaintext has to be asked for by name.
Pass a certificate, or `-admin-insecure` / `SIGNARI_ADMIN_INSECURE=1` when it
is bound to loopback behind a terminator you control.

## An application cannot sign anyone in

### At the authorization request

These six are shown on Signari's own page and are **never sent to the
application**. Until the client and its `redirect_uri` are known to belong
together, redirecting would hand the error, and anything after it, to an
address nobody registered.

| Message | Fix |
|---|---|
| `client_id is required` | Send it |
| `unknown client` | The `client_id` is not registered, or is in another deployment |
| `client is disabled` | Re-enable it: `PATCH /admin/clients/{id}` with `{"enabled": true}` |
| `this organisation is suspended` | Reactivate it: `signari instance org-status`, or `PATCH /admin/organizations/{id}` |
| `redirect_uri is required` | Send it |
| `redirect_uri is not registered for this client` | Register it exactly, with its scheme, host, port and path; there is no prefix or wildcard match. `PATCH /admin/clients/{id}` with `redirect_uris`, or `signari apply`, each of which replaces the whole list, so include the addresses already registered |

Once the client and its redirect URI are known, refusals go back to the
application as `error` and `error_description`:

| `error_description` | Cause and fix |
|---|---|
| `code_challenge is required` | Every client requires Proof Key for Code Exchange (PKCE) by default, confidential ones included. Send a `code_challenge`. For a confidential client that truly cannot, `signari client set-pkce -client-id <id> -require-pkce=false`. A public client cannot opt out |
| `code_challenge_method is required and must be S256` | `plain` is refused. Hash the verifier with SHA-256 |
| `code_challenge must be 43-128 characters of base64url without padding` | Encode the SHA-256 of the verifier as base64url, no `=` |
| `client may not use the authorization_code grant` | The client's grants do not include it. `signari client set-grants` |

### At the token endpoint

| `error`: `error_description` | Cause and fix |
|---|---|
| `invalid_client`: `client authentication failed` | The secret or the assertion is wrong, or the client is not registered to authenticate that way: after `signari client set-keys` it signs a `private_key_jwt` assertion, and its secret is gone |
| `invalid_client`: `public clients must not present a client secret` | A public client authenticates with PKCE alone. Drop the secret |
| `invalid_grant`: `authorization code is unknown or expired`, or `authorization code has expired` | Codes are short-lived and single-use. Exchange the code as soon as the browser returns |
| `invalid_grant`: `authorization code has already been used` | The code was redeemed twice, often by a retry or a second tab. Start the sign-in again |
| `invalid_grant`: `redirect_uri does not match the one used in the authorization request` | Send the same `redirect_uri` to both, byte for byte |
| `invalid_grant`: `code_verifier is invalid` | The verifier is not the one whose challenge was sent. Keep it per sign-in attempt, not per person |

### The application refuses the ID token

- **Issuer.** `iss` is the instance's issuer exactly as configured. A trailing
  slash, a different host, or `http` instead of `https` is a different issuer.
  When moving from another provider, a client can be pinned to an issuer alias:
  `signari client set-issuer-alias`.
- **Signature.** Tokens are signed ES256 by default, and the keys are published
  at the discovery document's `jwks_uri`. An application that only accepts
  RS256, or that has an old key cached, can be given RS256 with
  `signari client set-alg -client-id <id> -alg RS256`. HMAC algorithms are not
  offered at all.

## A person cannot sign in

**`Incorrect username or password.`**
This message is deliberately the same for an unknown account, a wrong password
and a deactivated one. That way it does not tell anyone which addresses exist.
Look at the account instead, with `GET /admin/users?email=<address>`:

- `status` `deactivated`, `locked` or `pending` (a sign-up waiting for approval);
- an imported account whose old hash cannot be verified is skipped at import,
  and named in the import's report;
- repeated failures slow the next attempt down, per organisation
  (`login_free_attempts` and `login_max_delay_s` in the organisation's settings).

**`the passkey was not accepted`**
The passkey was registered under another relying party ID, or under a WebAuthn
`userHandle` that is not the account's. A passkey belongs to the host name it was
made at. An imported one works only when this deployment serves the same
relying party ID, and when the account kept the handle it was registered
under. See [what applications know people by](migrate-from-keycloak.md#what-applications-know-people-by).

## The Admin API refuses a request

| Status, `error` | Cause and fix |
|---|---|
| `412 precondition_failed` | The configuration moved since the version sent as `If-Match`: `expected_version` and `current_version` name both. Read the object again, decide again, and send the new version. Never retry blindly with `current_version`, which is the lost update the precondition exists to stop |
| `429 rate_limited` | Too many requests arrived at once. The request was turned away before it was read, so nothing was done. Wait `Retry-After` seconds and send it again. The [Admin API clients](sdk.md) and the Terraform provider do this |
| `403 insufficient_scope` | The token lacks the scope the operation names in the [Admin API reference](admin-api-reference.md), or is scoped to another organisation |
| `403 privileged_target` | The target may impersonate others, or is in a group that may; the token also needs `privileged-users:write` |
| `401` | No usable bearer token: missing, revoked or expired |
