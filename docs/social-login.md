# Federated sign-in providers

```sh
signari idp add -org <uuid> -slug google -name "Google" -kind google \
  -client-id-ext <id> -client-secret <secret>
```

| Kind | |
|---|---|
| `google` | `email_verified` in the ID token is authoritative |
| `microsoft` | The plain `email` claim is never believed; needs the optional `xms_edov` claim |
| `github` | Not OIDC. `/user/emails` is queried so only a confirmed address counts |
| `apple` | No userinfo endpoint. The client secret is a JWT that expires — see below |
| `gitlab` | gitlab.com. For self-managed, use `oidc` with your own issuer |
| `discord` | Consumer accounts with no domain ownership behind them |
| `twitch` | Needs `user:read:email` *and* a claims parameter before it returns an address |
| `linkedin` | Issuer and userinfo are on different hosts, which is unusual and correct |
| `slack` | Scoped to the workspace the app is installed in |
| `atlassian` | Needs `audience=api.atlassian.com` and `prompt=consent` |
| `oidc` | Anything else with a discovery document |
| `saml` | An upstream SAML identity provider |

**Every endpoint above was read from that provider's own
`/.well-known/openid-configuration`**, not from documentation or memory. A
preset with wrong endpoints is worse than no preset: it looks configured and
fails at the moment a user is trying to sign in.

Facebook was considered and **not added** for exactly that reason: its discovery
document omits the token endpoint. Building the preset would have meant filling
that in from memory, which is the thing this rule exists to prevent. Use the
generic `oidc` kind with endpoints you have checked yourself.

## A provider's multi-factor authentication

A sign-in through a provider records `amr: ["fed"]`: the person authenticated
somewhere else, and nothing here says how. Under a sign-in flow with an
unconditional `mfa` stage, somebody with no factor enrolled here is then
refused, however strongly the provider authenticated them.

```sh
signari idp trust-mfa -slug corp -upstream-amr mfa,hwk
signari idp trust-mfa -slug corp -upstream-acr http://schemas.openid.net/pape/policies/2007/06/multi-factor
signari idp trust-mfa -slug corp            # trust nothing again
```

When the provider's verified ID token carries an `amr` value or an `acr` you
named, the sign-in records `amr: ["fed", "mfa"]`, which satisfies the `mfa` stage
and makes the session's `acr` `2`. Values you did not name count for nothing,
so a provider cannot raise itself to multi-factor by adding a claim. Name a
value only for a provider that sets it when, and only when, it checked a second
factor itself. `github` and a `saml` upstream send no ID token to read these
from, and the command refuses to set a list on either.

`signari idp attribute-map` reads a claim by name, then by a dotted path into nested
objects, so `realm.team` finds `{"realm":{"team":"Platform"}}`. A SAML upstream's
attributes are mapped the same way, by the attribute's name. One with several values
maps onto nothing, since nothing here could say which was meant.

The same settings, with taking a provider out of service, its assertions,
whether its `email_verified` is believed and its attribute mapping, are
`PATCH /admin/organizations/{orgID}/identity-providers/{slug}` and its
`attribute-map` in the [Admin API](admin-api.md#organisations), for a console or
automation that has no shell.

## Sending people to their own provider

Three things take somebody past the password box, straight to their provider:

- `idp_hint=<slug>` on an authorization request, for an application that knows which
  provider it wants. A slug that is not an enabled provider of the client's
  organisation is ignored, and the sign-in page is shown.
- `login_hint=ada@corp.example` on an authorization request, when a provider signs in
  that domain.
- A **Continue with single sign-on** button on the sign-in page, when any provider in
  the organisation signs in a domain. The person types their address and presses it.

```sh
signari idp domains -slug corp -domains corp.example,corp.test
```

`PATCH .../identity-providers/{slug}` takes the same list as `login_domains`, as does a
configuration file. A domain belongs to one provider in an organisation. This chooses a
route and nothing else: the provider still authenticates the person, and every linking
rule applies when they come back. A local password in the same domain goes on working
through the ordinary form, so the account that must survive an outage at the provider
can still sign in. Both hints apply only with no session at all: somebody short of a
second factor needs it here, and the provider cannot supply it.

## When somebody signs out at the provider

A provider that sends OpenID Connect back-channel logout can tell this engine:

```
https://<issuer>/login/callback/<slug>/backchannel-logout
```

Register that as the application's back-channel logout URI at the provider. A valid
logout token ends every session the person has here, because a session does not
record which provider it came through, and a person signed out upstream keeping one
here is what this exists to stop. It is a `POST` from the provider, with no cookie
and no user present, so the token is the whole of the authentication. Its signature is
always checked against the provider's own keys, and it must name this application and
carry the logout event, a `jti`, no `nonce`, and an `iat` under five minutes old. A
provider with no fixed issuer cannot use it.

A token has to name a `sub`. One that names only a `sid` is refused, since nothing here
records the provider's session ids. A retry of a token already used, and a subject
nobody here is linked to, are both answered as done.

## Signing in to the provider without a secret

By default this engine sends the client secret in the form at the provider's token
endpoint. A provider set up to refuse that, or with no secret at all, takes one of
the others:

```sh
signari idp auth -slug corp -method client_secret_basic
signari idp auth -slug corp -method private_key_jwt -client-key-file client.key -client-cert-file client.crt
signari idp auth -slug corp -method tls_client_auth -client-key-file client.key -client-cert-file client.crt
```

| Method | What the provider receives |
|---|---|
| `client_secret_post` | The secret in the form. The default |
| `client_secret_basic` | The secret in `Authorization: Basic`, and not in the form |
| `private_key_jwt` | A signed assertion, from this client, for this token endpoint, good for a minute and used once. With a certificate its header names it by `x5t` and `x5t#S256`, for a provider that holds certificates and finds the key by thumbprint; under `fips140=only`, `x5t#S256` alone ([fips.md](fips.md)). RSA, P-256 and Ed25519 keys |
| `tls_client_auth` | The certificate, at the connection. Sent to the token endpoint alone |

The key is sealed under the root key, rewrapped with the rest of it by `keys
rewrap-root`, and never shown again; the listing says only that one is held. A key
and a certificate that do not belong together are refused here rather than at the
provider on somebody's first sign-in, and so is a method with nothing held to prove
it. No secret travels with the last two. Giving a new `-method` keeps the key held.

## Apple, and the secret that expires

Every other provider issues a client secret: a string you paste in and forget.
Apple does not. Apple's client secret is a **JWT that you sign**, with an ECDSA
key downloaded once as a `.p8` file, valid for **at most six months**.

So every Sign in with Apple integration in the world breaks twice a year. It
fails as `invalid_client`, which reads like the credentials are wrong rather
than expired, at a moment nobody changed anything. The usual mitigation is a
calendar reminder, and the usual outcome is that the reminder outlives whoever
set it.

```sh
signari idp apple-secret -slug apple \
  -apple-team ABCDE12345 -apple-key-id KEY1234567 -apple-key ./AuthKey.p8

minted Apple client secret for apple
  services id : com.example.service
  expires     : 2027-02-13 (in 180 days)
```

Run it again before it expires. That is the whole maintenance story.

Two things the errors call out by name, because they are the mistakes people
actually make:

- **The Services ID, not the App ID.** They sit in the same list, look alike, and
  the wrong one produces `invalid_client` without saying which identifier was
  wrong.
- **The `.p8` file as downloaded**, including the BEGIN and END lines. An RSA key
  is refused by naming the key type rather than reporting a parse failure.

Apple also returns the user's **name only on the first authorization**, in the
form post, never again. An account created without capturing it then has no
name, and re-authorizing does not produce one.

## One bug worth recording

Adding these providers worked everywhere except the database: the `kind` column
carries a CHECK constraint enumerating the known providers, and it was a second
list nothing kept in step. The preset was right, the CLI help was right, and
registering one failed with a constraint violation naming nothing useful.

There is now a test that reads the constraint out of the database and compares
it against the presets **in both directions** — a kind the code can produce that
the database refuses, and a kind the database permits that no preset backs.
`Kinds()` is derived from the presets map for the same reason.
