# Federated sign-in providers

## Introduction

Many people already have an account somewhere else, such as Google or their
company's own identity provider. Letting them sign in with that account is
called "federated sign-in", and the other service is the "provider".

Signari sends the person to the provider, checks the answer that comes back, and
links it to an account in Signari. You decide what Signari believes from each
provider: whether an email address is verified, whether a second factor counts,
and which groups follow the person.

You add a provider with `signari idp add`, through the
[Admin API](admin-api.md#organisations), or in a
[configuration file](config-as-code.md).

## Add a provider

To add a provider, give it a slug, a name and its kind, with the client ID and
secret the provider issued for Signari:

```sh
signari idp add -org <uuid> -slug google -name "Google" -kind google \
  -client-id-ext <id> -client-secret <secret>
```

In this example, `-slug google` is the provider's short name, used in commands and
in its sign-in address, `/login/with/google`. `-client-id-ext` is the client ID
the provider issued, not the ID of one of Signari's own applications.

The `-kind` says which provider it is. Some kinds have rules of their own. The
table uses three abbreviations: OpenID Connect ([OIDC](glossary.md#oidc)), JSON
Web Token ([JWT](glossary.md#jwt)) and Security Assertion Markup Language
([SAML](glossary.md#saml)).

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
| `oauth2` | Anything else, with no ID token: see [below](#a-provider-with-no-id-token) |
| `saml` | An upstream SAML identity provider |

**Every endpoint above was read from that provider's own
`/.well-known/openid-configuration`**, not from documentation or memory. That
address is the provider's [discovery document](glossary.md#discovery-document),
which lists its endpoints. A preset with wrong endpoints is worse than no preset.
It looks configured, and fails at the moment a person is trying to sign in.

Facebook was considered and **not added** for exactly that reason: its discovery
document omits the token endpoint. Building the preset would have meant filling
that in from memory, which is the thing this rule exists to prevent. Use the
generic `oauth2` kind with endpoints you have checked yourself.

## A provider with no ID token

Some providers speak OAuth 2.0 but issue no ID token. A code forge, a small
community site or an internal service might be one. It answers who somebody is
from a "userinfo endpoint", an address that returns details of the person signed
in. There is nothing to discover, so you name the endpoints, and you say where
in the answer the person is:

```sh
signari idp add -org <uuid> -slug forge -name "Our forge" -kind oauth2 \
  -client-id-ext <id> -client-secret <secret> \
  -authorize-url https://git.example.com/login/oauth/authorize \
  -token-url https://git.example.com/login/oauth/access_token \
  -userinfo-url https://git.example.com/api/v1/user \
  -idp-scopes read:user -userinfo-subject id -userinfo-name full_name
```

Each path is read the way `idp attribute-map` reads a claim: by name, and then by
a dotted path into nested objects. The paths default to `sub`, `email` and
`name`.

`-userinfo-subject` is what a person is linked by, and its value can be a string
or a whole number. Point it at the provider's stable ID, not at a username,
because a username can be given up and taken by somebody else. A sign-in with
nothing at that path is refused, because nobody is linked by an empty
identifier.

Nothing in this exchange is signed. Who somebody is rests on the Transport Layer
Security ([TLS](glossary.md#tls)) connection to the endpoint you named, and all
three endpoints must be `https`.

An address is not believed verified unless you say so with
`-trust-email-verification`. That flag needs `-userinfo-email-verified`, the path
to a JSON `true` from the provider. Without it, `allow_signup` with
`require_verified_email` refuses such a person, which is the safe way round.

`idp trust-mfa` is refused too, since there is no ID token for an `amr` to be read
from. The `amr` claim says how a person authenticated. The endpoints are set when the
provider is made, and `apply` does not move them.

## A provider's multi-factor authentication

A sign-in through a provider records `amr: ["fed"]`. It says the person
authenticated somewhere else, and nothing in Signari says how. Suppose your
[sign-in flow](flows.md) has an unconditional `mfa` stage. Somebody with no
factor enrolled in Signari is then refused, however strongly the provider
authenticated them.

You can name the provider's values that mean it checked a second factor
itself. These commands trust two `amr` values, then trust one `acr`, then trust
nothing again:

```sh
signari idp trust-mfa -slug corp -upstream-amr mfa,hwk
signari idp trust-mfa -slug corp -upstream-acr http://schemas.openid.net/pape/policies/2007/06/multi-factor
signari idp trust-mfa -slug corp            # trust nothing again
```

An `acr` is an Authentication Context Class Reference ([ACR](glossary.md#acr)),
a value saying how strongly someone signed in. When the provider's verified ID
token carries an `amr` value or an `acr` you named, the sign-in records
`amr: ["fed", "mfa"]`. That satisfies the `mfa` stage, and makes the session's
`acr` `2`.

Values you did not name count for nothing, so a provider cannot raise itself to
multi-factor by adding a claim. Name a value only for a provider that sets it
when, and only when, it checked a second factor itself. `github` and a `saml`
upstream send no ID token to read these from, and the command refuses to set a
list on either.

`signari idp attribute-map` reads a claim by name, then by a dotted path into
nested objects, so `realm.team` finds `{"realm":{"team":"Platform"}}`. A SAML
upstream's attributes are mapped the same way, by the attribute's name. One with
several values maps onto nothing, since nothing in Signari could say which was
meant.

A console or automation that has no shell can make the same settings through the
[Admin API](admin-api.md#organisations). There,
`PATCH /admin/organizations/{orgID}/identity-providers/{slug}` and its
`attribute-map` also take a provider out of service, and set its assertions,
whether its `email_verified` is believed and its attribute mapping.

## A provider's groups

A group in Signari decides what its members reach, so a provider grants one only
because somebody said so. You map a group at the provider to a group in Signari,
and can say which claim carries the provider's groups:

```
signari idp group-map -slug corp -remote-group Engineering -group engineering
signari idp group-claim -slug corp -claim roles    # `groups` until told otherwise
```

Otherwise, nothing is created and nothing is joined. At each sign-in, the groups
a mapping names become what the claim says. Somebody in `Engineering` at the
provider joins `engineering` in Signari, and somebody no longer in it leaves,
however they were added. A group no mapping names is none of the provider's
business. A SAML upstream's attribute is read the same way, by name.

A claim that is **absent** changes nothing. A claim that is present and **empty**
leaves every mapped group. Providers leave a claim out for reasons that say
nothing about membership. Having too many groups to fit in a token is the usual
one. A provider that has stopped sending the claim therefore stops taking
people out of groups.

A group whose members may [impersonate](impersonation.md) cannot be mapped, and a
mapped group cannot be given impersonation afterwards. Whoever administers the
provider decides who is in the remote group, and could otherwise add themselves
and act as anybody.

A sign-in that cannot apply the mapping is refused, since a group the provider
took away would otherwise outlive that. Removing a mapping takes nobody out of
the group. Each change is audited as `federation.groups_synced`, with how many
people joined and left.

## Sending people to their own provider

Three things take somebody past the password box, straight to their provider:

- `idp_hint=<slug>` on an authorization request, for an application that knows
  which provider it wants. A slug that is not an enabled provider of the
  application's organisation is ignored, and the sign-in page is shown.
- `login_hint=ada@corp.example` on an authorization request, when a provider signs
  in that domain.
- A **Continue with single sign-on** button on the sign-in page, when any provider
  in the organisation signs in a domain. The person types their address and
  presses it.

To say which email domains a provider signs in, give it a list:

```sh
signari idp domains -slug corp -domains corp.example,corp.test
```

`PATCH .../identity-providers/{slug}` takes the same list as `login_domains`, as
does a configuration file. A domain belongs to one provider in an organisation.

This chooses a route and nothing else. The provider still authenticates the
person, and every linking rule applies when they come back. A local password in
the same domain goes on working through the ordinary form. So the account that
must survive an outage at the provider can still sign in.

Both hints apply only with no session at all. Somebody short of a second factor
needs it from Signari, and the provider cannot supply it.

## Telling the provider what the application asked

By default, a provider is told nothing about the request that sent somebody to
it. An application that wants a fresh sign-in or a second factor gets it from
Signari's side at best. You can tell the provider, one parameter at a time:

```
signari idp forward -slug corp -forward prompt,login_hint,acr_values
signari idp forward -slug corp            # tell it nothing again
```

Each parameter you name reaches the provider like this:

| Named | What the provider gets |
|---|---|
| `prompt` | `login`, `consent` and `select_account`, when the request asked for them. `none` never gets this far: a request that may not interact is answered here |
| `login_hint` | The hint, as it came |
| `acr_values` | When the request wants a second factor, the values `idp trust-mfa -upstream-acr` trusts from this provider, because a request's values mean something only here. With none trusted, nothing is sent |

Asking changes nothing about what is believed. What comes back is held to
`idp trust-mfa` as ever, so a provider that ignores the `acr_values` it was sent
gains nothing. It gets no credit for a factor it did not use, and the sign-in
asks for one in Signari or is refused.

## When somebody signs out at the provider

A provider that supports OpenID Connect
[Back-Channel Logout](glossary.md#back-channel-logout) can tell Signari when a
person signs out there. It sends a `logout_token`, a signed message naming the
person, to this address:

```
https://<issuer>/login/callback/<slug>/backchannel-logout
```

At the provider, Signari is registered as an application. Register that address
as the application's back-channel logout URI.

A valid `logout_token` ends every session the person has in Signari. A session
does not record which provider it came through. And a person signed out at the
provider who keeps a session in Signari is what this exists to stop.

It is a `POST` from the provider, with no cookie and no person present, so the
token is the whole of the authentication. Its signature is always checked
against the provider's own keys. It must name Signari's application, and carry the
`http://schemas.openid.net/event/backchannel-logout` event, a `jti`, no `nonce`,
and an `iat` under five minutes old. The `jti`
is the token's unique identifier, and the `iat` is the time it was issued. A
provider with no fixed issuer cannot use it.

A token has to name a `sub`, the person's subject identifier at the provider. One
that names only a `sid`, the provider's session ID, is refused, since nothing in
Signari records the provider's session IDs. A retry of a token already used, and
a subject nobody in Signari is linked to, are both answered as done.

## Calling the provider's API as the person

Some applications sign in with a provider so that they can then use it, such as
reading a person's repositories or their calendar. The token for that is the one
the provider handed over at sign-in, which is normally thrown away. To keep it:

```sh
signari idp store-tokens -slug github
```

Then declare a scope named `broker.<slug>`, in a
[configuration file](config-as-code.md) or with
`PUT /admin/organizations/{orgID}/scopes`:

```yaml
scopes:
  - name: broker.github
    display_name: Use your GitHub account
```

From each person's next sign-in, what the provider hands over is kept, sealed
under the [root key](glossary.md#root-key). There is one row for each person at
each provider. An application then asks for it with an access token carrying
that scope, which you grant an application as you would any other:

```
GET /account/broker/github/token
Authorization: Bearer <an access token with the scope broker.github>

{"access_token": "gho_…", "token_type": "bearer", "scope": "repo", "expires_in": 3600}
```

The scope names one provider, so being allowed a person's GitHub is not being
allowed their Google. The application gets the access token and nothing else: no
refresh token and no ID token.

A token with less than thirty seconds left is renewed first, if the provider gave
a refresh token. A provider that gave none, or will not renew it, is
`409 reauthentication_required`: the person has to sign in at the provider again.
Ask the provider for offline access in `-idp-scopes` if you want to avoid that.
Two requests renewing the same token at once can lose one to a provider that
rotates refresh tokens, and that request gets the same answer.

Every read is recorded as `federation.token_read`. The tokens go when the person
is [erased](erasure.md), or when the link is removed, by them or by you. They go
for everybody at the provider with
`signari idp store-tokens -slug github -store-tokens=false`. A SAML upstream
hands over no token, so it cannot be set.

> [!WARNING]
> Think before turning this on. These are credentials at somebody else's service,
> held in Signari until they end. An application that may ask for the scope can
> act as the person there.

## Signing in to the provider without a secret

By default, Signari sends its client secret in the form it posts to the
provider's token endpoint. A provider set up to refuse that, or with no secret
at all, takes one of the other methods:

```sh
signari idp auth -slug corp -method client_secret_basic
signari idp auth -slug corp -method private_key_jwt -client-key-file client.key -client-cert-file client.crt
signari idp auth -slug corp -method tls_client_auth -client-key-file client.key -client-cert-file client.crt
```

Each method sends the provider this:

| Method | What the provider receives |
|---|---|
| `client_secret_post` | The secret in the form. The default |
| `client_secret_basic` | The secret in `Authorization: Basic`, and not in the form |
| `private_key_jwt` | A signed assertion, from this client, for this token endpoint, good for a minute and used once. With a certificate its header names it by `x5t` and `x5t#S256`, for a provider that holds certificates and finds the key by thumbprint; under `fips140=only`, `x5t#S256` alone ([FIPS 140-3](fips.md)). RSA, P-256 and Ed25519 keys |
| `tls_client_auth` | The certificate, at the connection. Sent to the token endpoint alone |

The key is sealed under the root key, and rewrapped with the rest of it by
`signari keys rewrap-root`. It is never shown again, and the listing says only
that one is held.

A key and a certificate that do not belong together are refused by Signari,
rather than by the provider on somebody's first sign-in. So is a method with
nothing held to prove it. No secret travels with the last two methods. Giving a
new `-method` keeps the key held.

## Apple, and the secret that expires

A client secret is usually a string you paste in and forget. Apple's is not.
Apple's client secret is a **JWT that you sign**, with an ECDSA (Elliptic Curve
Digital Signature Algorithm) key downloaded once as a `.p8` file. It is valid for
**at most six months**.

So a Sign in with Apple integration breaks twice a year unless its secret is made
again. It fails as `invalid_client`, which reads as if the credentials are wrong rather
than expired, at a moment when nobody changed anything. The usual mitigation is
a calendar reminder, and the usual outcome is that the reminder outlives
whoever set it.

`signari idp apple-secret` makes the secret from your key file, and says when it
expires:

```sh
signari idp apple-secret -slug apple \
  -apple-team ABCDE12345 -apple-key-id KEY1234567 -apple-key ./AuthKey.p8

minted Apple client secret for apple
  services id : com.example.service
  expires     : 2027-02-13 (in 180 days)
```

Run it again before it expires. That is the whole maintenance story.

The errors call out two mistakes by name, because they are the ones people
actually make:

- **The Services ID, not the App ID.** They sit in the same list and look alike.
  The wrong one produces `invalid_client` without saying which identifier was
  wrong.
- **The `.p8` file as downloaded**, including the BEGIN and END lines. An RSA key
  is refused by naming the key type rather than reporting a parse failure.

Apple also returns the person's **name only on the first authorization**, in the
form post, and never again. An account created without capturing it then has no
name, and authorizing again does not produce one.

## One bug worth recording

Adding these providers worked everywhere except the database. The `kind` column
carries a CHECK constraint that lists the known providers, and it was a second
list that nothing kept in step. The preset was right and the command-line help
was right, but registering one failed with a constraint violation that named
nothing useful.

There is now a test that reads the constraint out of the database and compares it
against the presets **in both directions**. It catches a kind the code can
produce that the database refuses, and a kind the database permits that no
preset backs. `Kinds()` is derived from the presets map for the same reason.
