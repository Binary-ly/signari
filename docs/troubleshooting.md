# Troubleshooting

Each entry starts from what you see, quoted as the server writes it, then
gives the cause and the fix. If a message is not here, search for it in the
source: every refusal is a literal string, and most are next to a comment
saying why it exists.

## The server will not start

**`issuer must be https (got "http://…"); set SIGNARI_INSECURE_ISSUER=1 only for local testing`**
The issuer is what every token names and every application checks, so it is
refused over plaintext. Set `SIGNARI_ISSUER` to the https URL that applications
reach. Use `SIGNARI_INSECURE_ISSUER=1` only for a local test.

**`no instance found -- run signari instance create -issuer … first`** and
**`this database has 3 instances; set SIGNARI_ISSUER to name the one to serve`**
An engine serves one instance. With none, make one. With several, the server
will not guess which is meant, because tokens minted under the wrong issuer
are refused by every application. Set `SIGNARI_ISSUER` to one of those listed.

**`schema version mismatch: database is at 190, this binary expects 195 -- run signari migrate up`**
The binary is newer than the database. Run `signari migrate up` with the new
binary, as `signari_engine`, before it serves. See [upgrading.md](upgrading.md),
and [schema-versions.md](schema-versions.md) for what each version changes. A
database *ahead* of the binary is served only when every migration since was
declared compatible with the release before.

**`SIGNARI_ROOT_KEY is unset (32 random bytes, base64), and so is SIGNARI_ROOT_KEY_FILE`**
The root key seals signing keys, OTP seeds and personal attributes, and is
never stored in the database it protects. Generate one with
`head -c 32 /dev/urandom | base64`, and keep it where the database's backups
are not. See [configuration.md](configuration.md), which also covers
`SIGNARI_ROOT_KEY_FILE` and rotating it.

**`the admin API will not serve plaintext: pass -tls-cert and -tls-key, or -admin-insecure …`**
The Admin API carries bearer tokens, so plaintext has to be asked for by name.
Pass a certificate, or `-admin-insecure` / `SIGNARI_ADMIN_INSECURE=1` when it
is bound to loopback behind a terminator you control.

## An application cannot sign anyone in

### At the authorization request

These six are shown on the server's own page and are **never sent to the
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
| `redirect_uri is not registered for this client` | Register it exactly, with its scheme, host, port and path; there is no prefix or wildcard match. `PATCH /admin/clients/{id}` with `redirect_uris`, or `signari apply` |

Once the client and its redirect URI are known, refusals go back to the
application as `error` and `error_description`:

| `error_description` | Cause and fix |
|---|---|
| `code_challenge is required` | Every client requires PKCE by default, confidential ones included. Send a `code_challenge`. For a confidential client that truly cannot, `signari client set-pkce -client-id <id> -require-pkce=false`. A public client cannot opt out |
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
| `invalid_grant`: `code_verifier is invalid` | The verifier is not the one whose challenge was sent. Keep it per sign-in attempt, not per user |

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
and a deactivated one, so that it does not tell anyone which addresses exist.
Look at the account instead, with `GET /admin/users?email=<address>`:

- `status` `deactivated`, `locked` or `pending` (a sign-up waiting for approval);
- an imported account whose old hash cannot be verified is skipped at import,
  and named in the import's report;
- repeated failures slow the next attempt down, per organisation
  (`login_free_attempts` and `login_max_delay_s` in the organisation's settings).

**`the passkey was not accepted`**
The passkey was registered under another relying party ID, or under a user
handle that is not the account's. A passkey belongs to the host name it was
made at. An imported one works only when this deployment serves the same
relying party ID, and when the account kept the handle it was registered
under. See [migrate-from-keycloak.md](migrate-from-keycloak.md#what-applications-know-people-by).

## The Admin API refuses a request

| Status, `error` | Cause and fix |
|---|---|
| `412 precondition_failed` | The configuration moved since the version sent as `If-Match`: `expected_version` and `current_version` name both. Read the object again, decide again, and send the new version. Never retry blindly with `current_version`, which is the lost update the precondition exists to stop |
| `429 rate_limited` | Too many requests arrived at once. The request was turned away before it was read, so nothing was done. Wait `Retry-After` seconds and send it again. The clients in [sdk.md](sdk.md) and the Terraform provider do this |
| `403 insufficient_scope` | The token lacks the scope the operation names in [admin-api-reference.md](admin-api-reference.md), or is scoped to another organisation |
| `403 privileged_target` | The target may impersonate others, or is in a group that may; the token also needs `privileged-users:write` |
| `401` | No usable bearer token: missing, revoked or expired |
