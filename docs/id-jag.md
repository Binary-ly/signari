# Cross-app access

An application a person signed in to here can reach another application on their behalf,
with no redirect and no second consent screen. The first gets an **Identity Assertion JWT
Authorization Grant** (ID-JAG) from this server and trades it at the second's authorization
server for an access token. The second takes this server's word for who the person is,
which is what an enterprise's identity provider is for: an administrator decides which
application may reach which, and nobody clicks through a popup.

This follows
[draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/).
This server does both halves, and you may want one of them or both.

## As the identity provider

Nothing is issued until you write down which client may ask, for which authorization server,
and the most it may carry there:

```sh
signari client id-jag-allow -client-id chat-app \
  -audience https://as.files.example/ -remote-client-id f53f191f \
  -resources https://api.files.example/ -scopes files.read
signari client id-jag-audiences -client-id chat-app
signari client id-jag-forget -client-id chat-app -audience https://as.files.example/
```

`-audience` is the other server's issuer identifier, and `-remote-client-id` is what it
calls this client, which need not be what it is called here. Grants are signed with RS256,
which the draft makes mandatory, unless `-alg ES256` says otherwise, and an entry is refused
unless the instance holds an active key of that algorithm.

The client then makes a token exchange, authenticated, with the ID token it was given at
sign-in:

```
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
requested_token_type=urn:ietf:params:oauth:token-type:id-jag
audience=https://as.files.example/
resource=https://api.files.example/
scope=files.read
subject_token=<the ID token>
subject_token_type=urn:ietf:params:oauth:token-type:id_token
```

and gets back a grant good for five minutes, in `access_token`, with a `token_type` of `N_A`
because it is not an access token.

What is checked:

- The client is confidential and authenticated. A public client gets `invalid_client`.
- The subject token is an ID token this server issued to this client, and in date. An access
  token, a grant or a signed userinfo response is refused. So is one from another client.
- **The sign-in behind it still stands.** The session is read at the request, so somebody
  signed out or deactivated since gets nothing from an ID token that has not expired yet.
- There is an entry for this client and that audience. A server nobody here has a relationship
  with is `invalid_target`; one another client has an entry for is `access_denied`, so the
  client can tell a wrong request from one to take up with whoever hands out access.
- Each `resource` and `scope` is on the entry. Scopes mean what the other server says, so
  nothing on the entry is read as OpenID Connect's, and asking for none grants none.
- A person who withdrew this client's access on their account page gets `access_denied`, and
  your [access policy](policy.md) is asked as it is for any grant.

The grant carries `sub` (the person's identifier here, whatever the client's ID token said),
`client_id` (the name over there), `tenant` (the organisation, since an instance can hold
several), `email`, and `auth_time`, `acr` and `amr` from the sign-in. Each one issued is
recorded as `oauth.id_jag_issued` with its audience, resources and scopes, which is how a
client reaching for somewhere new shows up.

Discovery names `identity_chaining_requested_token_types_supported` once there is an entry.

## As the application's authorization server

A grant from another identity provider is presented as an RFC 7523 assertion, so it arrives
the way a [jwt-bearer](jwt-bearer.md) assertion does, and everything that requires holds:
the issuer is a provider you registered and enabled for that grant, the client is paired with
it, the signature verifies against that provider's keys, the person is linked and active.
A `typ` of `oauth-id-jag+jwt` adds to that:

- `aud` is this server's issuer, not its token endpoint as a plain assertion may say.
- `client_id` is the client that authenticated, or the grant was issued to somebody else.
- Each `resource` is one this organisation [governs](resource-indicators.md), and the access
  token is restricted to those.
- `scope` buys no more than the client is registered for, and `openid` is never available,
  since nobody signed in here. With no `scope` it gets the client's registration.

No refresh token comes back: the grant is what a client presents again, and it can do that
once, since each grant's `jti` is spent. Another one is a token exchange away. Discovery names
`authorization_grant_profiles_supported`, which says the profile is implemented and nothing
about whose grants are taken.

**Who the person is here** comes from the provider's link to `sub`, so somebody who has never
signed in through that provider is refused. There is no creating accounts from a grant's
`email`.

## What is not here

- A **refresh token** or **SAML assertion** as `subject_token`. The draft requires only that
  an identity assertion is taken, and ID tokens are. A client whose ID token has expired gets
  another by refreshing.
- **`authorization_details`** in a grant, which is refused: nothing here has a policy for what
  to allow of them with no person looking.
- **`actor_token`**, which the draft leaves to future work and which is ignored.
- A **sender-constrained grant** (§9.11). Both ends always authenticate the client, and a
  grant carrying `cnf` is refused, since the proof it asks for cannot be checked here.
- **A multi-tenant issuer** on the accepting side. A provider is one issuer, so one whose
  tenants share an issuer cannot be told apart by `tenant`, and `aud_tenant` and `sub_id` are
  not read.
