# Cross-application access (ID-JAG)

## Introduction

When Ada has signed in to Acme's chat application through Signari, the chat
application can reach another application on her behalf. There is no redirect and
no second consent screen. The chat application gets a signed grant from Signari, a
JSON Web Token (JWT, see the [glossary](glossary.md#jwt)) called an **Identity
Assertion JWT Authorization Grant** (ID-JAG).

It trades that grant at the other application's "authorization server", the
service that issues its tokens, for an access token. The other application takes
Signari's word for who Ada is. That is what a company's identity provider is for:
an administrator decides which application may reach which, and nobody clicks
through a popup.

This follows
[draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/).
Signari does both halves, and you can use one of them or both. As the identity
provider, you allow each application with `signari client id-jag-allow`.

## As the identity provider

Signari issues nothing until you write down which application may ask, for which
authorization server, and the most it may carry there. These commands allow
`chat-app` one entry, list its entries, and remove the entry again:

```sh
signari client id-jag-allow -client-id chat-app \
  -audience https://as.files.example/ -remote-client-id f53f191f \
  -resources https://api.files.example/ -scopes files.read
signari client id-jag-audiences -client-id chat-app
signari client id-jag-forget -client-id chat-app -audience https://as.files.example/
```

`-audience` is the other authorization server's issuer identifier.
`-remote-client-id` is what that server calls this application, which need not be
what it is called at Signari.

Grants are signed with RS256, which the draft makes mandatory, unless
`-alg ES256` says otherwise. An entry is refused unless the instance holds an
active key of that algorithm.

The application then makes a token exchange, authenticated, with the
[ID token](glossary.md#id-token) it was given at sign-in:

```
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
requested_token_type=urn:ietf:params:oauth:token-type:id-jag
audience=https://as.files.example/
resource=https://api.files.example/
scope=files.read
subject_token=<the ID token>
subject_token_type=urn:ietf:params:oauth:token-type:id_token
```

It gets back a grant good for five minutes, in `access_token`. Its `token_type` is
`N_A`, because it is not an access token.

Signari checks all of these:

- The application is confidential and authenticated. A public client gets
  `invalid_client`.
- The subject token is an ID token Signari issued to this application, and in
  date. An access token, a grant or a signed userinfo response is refused. So is
  one from another application.
- **The sign-in behind it still stands.** The session is read at the request. So
  somebody signed out or deactivated since gets nothing from an ID token that has
  not expired yet.
- There is an entry for this application and that audience. A request for an
  authorization server nobody here has a relationship with is `invalid_target`.
  One that another application has an entry for is `access_denied`. So the
  application can tell a wrong request from one to take up with whoever hands out
  access.
- Each `resource` and `scope` is on the entry. Scopes mean what the other server
  says, so nothing on the entry is read as OpenID Connect's. Asking for none
  grants none.
- A person who withdrew this application's access on their account page gets
  `access_denied`. Your [access policy](policy.md) is asked, as it is for any
  grant.

The grant carries these claims:

- `sub`, the person's identifier at Signari, whatever the application's ID token
  said;
- `client_id`, the application's name over there;
- `tenant`, the organisation, since an instance can hold several;
- `email`;
- `auth_time`, `acr` and `amr`, from the sign-in.

Each grant issued is recorded as `oauth.id_jag_issued`, with its audience,
resources and scopes. That is how an application reaching for somewhere new shows
up.

The discovery document names `identity_chaining_requested_token_types_supported`
once there is an entry.

## As the application's authorization server

Here Signari is the receiving side. A grant from another identity provider is
presented as an RFC 7523 assertion. So it arrives the way a
[jwt-bearer grant](jwt-bearer.md) assertion does, and everything that grant
requires holds:

- The issuer is a provider you registered and enabled for that grant.
- The application is paired with it.
- The signature verifies against that provider's keys.
- The person is linked and active.

A `typ` of `oauth-id-jag+jwt` adds to that:

- `aud` is Signari's issuer, not its token endpoint as a plain assertion may say.
- `client_id` is the application that authenticated, or the grant was issued to
  somebody else.
- Each `resource` is one this organisation [governs](resource-indicators.md), and
  the access token is restricted to those.
- `scope` buys no more than the application is registered for. `openid` is never
  available, since nobody signed in here. With no `scope`, it gets the
  application's registration.

No refresh token comes back. The grant is what an application presents again, and
it can do that once, since each grant's `jti` is spent. Another grant is a token
exchange away.

The discovery document names `authorization_grant_profiles_supported`. That says
the profile is implemented, and nothing about whose grants are taken.

**Who the person is here** comes from the provider's link to `sub`. So somebody
who has never signed in through that provider is refused. No account is created
from a grant's `email`.

## What is not here

- A **refresh token**, or an **assertion** in Security Assertion Markup Language
  (SAML), as `subject_token`. The draft requires only that an identity assertion
  is taken, and ID tokens are. An application whose ID token has expired gets
  another by refreshing.
- **`authorization_details`** in a grant, which is refused. Nothing here has a
  policy for what to allow of them with no person looking.
- **`actor_token`**, which the draft leaves to future work and which is ignored.
- A **sender-constrained grant** (§9.11). Both ends always authenticate the
  application, and a grant carrying `cnf` is refused, since the proof it asks for
  cannot be checked here.
- **An issuer that serves several organisations**, on the accepting side. A
  provider is one issuer. So a provider whose organisations, its "tenants", share
  an issuer cannot be told apart by `tenant`. `aud_tenant` and `sub_id` are not
  read.
