# Security inventories

OWASP ASVS 5.0 asks for several things to be written down in one place: which
cryptography is in use, every way to authenticate, the session rules, what bounds a
deployment's resources, and what data there is. Each of these was true before this
page, in the code and scattered across reviews, and each was recorded as partial in
[security-review-asvs.md](security-review-asvs.md) for that reason. Nothing here is a
new rule. It is a list, with where each entry can be checked.

[logging-inventory.md](logging-inventory.md) and
[egress-inventory.md](egress-inventory.md) are the two the standard asks for by name.

## Cryptography (V11.1)

| Use | What | Where |
|---|---|---|
| Signing tokens | ES256 by default, RS256 always available. ES384, ES512, RS384, RS512, PS256, PS384, PS512 and EdDSA by choice. Symmetric algorithms are refused everywhere, by test | `engine/internal/keys/keys.go` |
| RSA keys | Generated at 3,072 bits. A client's may be 2,048, FAPI 2.0's floor | `keys.RSABits`, `clientauth.MinRSABits` |
| Sealing what must be read back: private keys, bind passwords, TOTP seeds and the rest | AES-256-GCM with a random nonce, under `SIGNARI_ROOT_KEY`, which is never in the database it protects | `engine/internal/keys/store.go` |
| Deriving from the root key | HKDF-SHA-256 | `engine/internal/keys/store.go` |
| Passwords | Argon2id, with a floor and a calibrated cost. A hash brought in by an import is verified as it is, and upgraded to Argon2id at that person's first sign-in | `engine/internal/passwords/` |
| Secrets only ever compared: tokens, codes, invitations | SHA-256, as they are long and random and a slow hash would buy nothing | `store.HashToken` |
| Session identifiers | 256 bits from the system's random source | `newSID` in `engine/internal/httpapi/session.go` |
| One-time passwords | HMAC-SHA-1 by default, as RFC 6238 says and every app implements. SHA-256 and SHA-512 by choice, and FIPS 140-only mode needs one of them | `engine/internal/mfa/totp.go` |
| Webhook bodies | HMAC-SHA-256 | `engine/internal/hmacsig/` |
| MD5 | Three sites, each required by a protocol it speaks to, and why each stays is in [security-review-asvs.md](security-review-asvs.md) | V11.4.1 there |

Signing keys move from next to active to passive to retired on a schedule, and a
passive key is retired once nothing can still be verifying against it. The root key is
rotated with `signari keys rewrap-root`, which knows every sealed column by test
(`TestEveryEncryptedColumnIsClassified`), so that a rotation cannot orphan one.
[fips.md](fips.md) says what changes under a validated module.

## Ways to authenticate (V6.1, V6.3.4)

Side by side, with what each is recorded as in a token's `amr`, which is what a policy
can require or refuse: see [policy.md](policy.md).

| Pathway | Proves | `amr` |
|---|---|---|
| Password | Something known | `pwd` |
| Passkey, device-bound | Possession, and the person present | `hwk`, with `user` |
| Passkey, synced | The same, but not bound to one device | `swk`, with `user` |
| Authenticator app or hardware token | Possession of a seed | `otp` |
| Text message | Possession of a number, which a SIM swap defeats with no technical exploit | `sms`, deliberately not `otp` |
| Emailed code, first factor | Possession of a mailbox: one factor | `otp`, read as single-factor |
| Recovery code | That it was kept. It stands in for a second factor and proves none | Adds nothing |
| Upstream provider | What that provider says, as far as it is trusted to | `fed`, with `mfa` only where the operator trusts its claim (`idp trust-mfa`) |
| Kerberos | A ticket from a trusted realm | `krb` |
| Duo | That Duo was satisfied, not how | `mfa`, added to what came before |
| An external factor | What that service asserts | What it is registered with |

No sign-in goes through the password form for `ldap`, `radius` or the `jwt-bearer`
grant. Each has a page of its own: [ldap.md](ldap.md), [radius.md](radius.md) and
[jwt-bearer.md](jwt-bearer.md).

## Sessions (V7.1)

| | Default | Bounds | Set with |
|---|---|---|---|
| Session lifetime, from the sign-in | 12 hours | 5 minutes to 30 days | per organisation |
| Inactivity limit | None | At least 5 minutes | per organisation |
| Offline access | 30 days | | per organisation |
| Concurrent sessions | No limit | When set, a new one is refused, by default | per organisation |

Sessions are rows, read on every request and never cached, so ending one takes effect
at once. A person signed in through a provider has a session here whose life is this
table's and not the provider's, unless the provider says by back-channel logout that it
has ended: see [social-login.md](social-login.md). Every session ends through one
function, by test (`TestEverySessionEndsThroughTerminateSessions`).

## Who may do what (V8.1)

The rules are enforced in four places, each with its own page.

| Boundary | Enforced by | Page |
|---|---|---|
| One organisation from another | Row security on every organisation's table, with the database's own role as the backstop, and `requireOrg` in the Admin API | [admin-api.md](admin-api.md) |
| What an admin token may touch | Seventeen scopes, narrowed further to named clients and groups | [admin-tokens.md](admin-tokens.md) |
| What a person may reach | Sign-in policy, and client access by group | [policy.md](policy.md) |
| What an application may decide | Relations, and AuthZEN | [authorization.md](authorization.md) |

The console has no privilege on the engine's tables at all. It reads views and writes
through the Admin API, as [the design](../README.md) sets out.

## Connections and resources (V13.1)

| | Default | Setting |
|---|---|---|
| Database connections, requests | The larger of 4 and the number of CPUs | `SIGNARI_DB_MAX_CONNS` |
| Database connections, background work | 3 | `SIGNARI_DB_WORKER_MAX_CONNS` |
| Reading a request's headers, its whole body, writing the answer, an idle connection | 10, 30, 60 and 120 seconds | Fixed |
| Admin API, all callers and one token | 100 and 50 requests a second | `SIGNARI_ADMIN_RATE`, `SIGNARI_ADMIN_TOKEN_RATE` |
| An organisation's tokens and sign-ins a minute | None until set | `signari instance org-budgets` |
| Outbound request | 8,000 octets a URI or a header field, 5 seconds to connect and 10 to the first byte | Fixed |

What the engine calls out to is in [egress-inventory.md](egress-inventory.md). What
these numbers mean under load is in [performance.md](performance.md).

## Data (V14.1)

| Class | What | How it is kept | How long |
|---|---|---|---|
| Credentials | Passwords, seeds, passkey keys, refresh and access token records | Hashed if only ever compared, sealed if read back, and a public key as it is | As long as the person or the grant, and gone with them on erasure |
| Identity | Names, addresses, attributes, group memberships | In the clear, with row security | Until erased |
| Sessions and sign-in locations | Which device, roughly where, an address only as a keyed hash | In the clear, but for the address | `SIGNARI_RETENTION_SESSIONS`, `SIGNARI_RETENTION_SIGNIN_LOCATIONS` |
| Audit trail | Who did what, in classes `security`, `operational` and `profile` | Hash-chained and append-only | As kept: see [logging-inventory.md](logging-inventory.md) |
| Configuration | Clients, policies, flows | In the clear, but for sealed secrets | Until removed |

[configuration.md](configuration.md) lists every `SIGNARI_RETENTION_` setting. A person
can export their own data at `/account/export` and delete their account at
`/account/delete`. An operator has `GET /admin/subjects/{subjectID}/export` and
`signari erase subject`: see [erasure.md](erasure.md).

## What a browser has to do (V3.1.1)

| Needs | For | Without it |
|---|---|---|
| Cookies, `Secure`, `HttpOnly`, `SameSite=Lax`, with a `__Host-` prefix on the session's | Every sign-in | Nothing signs in, and that is the only safe answer. The session cookie needs HTTPS |
| Content-Security-Policy | Containing what an injection could do | Sign-in works, with one defence fewer |
| `Sec-Fetch-Site`, `Sec-Fetch-Dest` | Knowing a form started a navigation, so that a redirect to an application survives `form-action` | The plain redirect, which Chrome then stops at a strict policy. A proxy stripping these brings that back |
| JavaScript | Passkeys, and a form that posts itself | A password sign-in needs none. A form posting to an application shows a button |
| WebAuthn | Passkeys | Not offered where the instance has no RP ID |

Proved in Chrome 156. Firefox and Safari have not been driven.
