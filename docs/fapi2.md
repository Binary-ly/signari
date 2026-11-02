# FAPI 2.0 Security Profile

[FAPI 2.0](https://openid.net/specs/fapi-security-profile-2_0-final.html) is a high-security
profile of OAuth 2.0 for applications where a stolen token is expensive: open banking,
payments, health records. Most of it is restrictions a deployment turns on, not behaviour
that is wrong by default, so it is held **per client**. One deployment can have a banking
API held to the profile and an ordinary web application that is not.

```sh
signari client set-profile -client-id bank-api -security-profile fapi2
```

This is refused until the client meets the profile, and the refusal says everything that
is missing. **The OpenID Foundation's conformance plan has not been run against this.**
Every requirement below has a test here, and the profile is not certified.

## What a client has to be

| Requirement | Set with |
|---|---|
| Confidential | `signari client create` without `-public` |
| Authenticates by `private_key_jwt` or mutual TLS | `client set-keys`, `client set-tls` |
| Access tokens sender-constrained, by DPoP or mutual TLS | `client set-dpop`, `client set-tls` |
| Pushed authorization requests required | `client set-par` |
| PKCE required | on by default |
| `response_type=code` alone | `client set-hybrid` off |
| Tokens signed with PS256, ES256 or EdDSA | `client set-alg`, which needs [a key of that algorithm](key-rotation.md) |
| No `http` redirect URI but a loopback address | `client create -redirect`, the Admin API's `redirect_uris`, or `signari apply` |

Each of these can be changed afterwards. A change through `client set-par`, `client set-alg`
and the other settings written through `PATCH /admin/clients/{clientID}` or `signari apply`
is refused if it would leave the profile. A change through a command that has no notion of
one is not, so **a client out of its profile is refused at the token endpoint and the
pushed authorization endpoint** with `unauthorized_client`, and `signari doctor` says which
client and why. It does not go on being served as if nothing had happened.

## What changes for a client held to it

- **A client assertion is addressed to the issuer alone, as a string.** Elsewhere the token
  endpoint's URL or a list is accepted too. Signed with PS256, ES256 or EdDSA.
- **A token request must prove a key.** A DPoP proof, signed with one of the same three, or
  a client certificate on the connection. Without either the request is refused, where a
  client otherwise set for certificate binding is given a bearer token during a cutover.
- **A refresh token does not rotate.** The same token goes on working and the answer carries
  no new one, so an answer lost on the way back costs the client nothing. It keeps the
  lifetime it was issued with, and ends with its family as any refresh token does.

## What every client already gets

These hold for all clients, and the profile asks nothing more of them: an authorization
code lasts 60 seconds and is single use; `S256` is the only PKCE method; a pushed request
must carry a `redirect_uri`, expires in five minutes and gives one code; `iss` is in every authorization
response; a client assertion dated more than 10 seconds ahead, or a DPoP proof more than 30,
is refused; codes are bound to the DPoP key; `none` and symmetric algorithms are refused
everywhere; and there is no password grant.

## What it does not cover

- **The resource server.** The profile has requirements on it that this server cannot meet
  for you: it has to check the DPoP proof or the certificate binding on every call.
- **The whole server.** Discovery still advertises everything the deployment does, because
  other clients use it. A deployment that must offer nothing else has to turn it off.

## FAPI 2.0 Message Signing

A separate profile on top of this one, for when each side has to be able to prove what
the other sent. `fapi2-message-signing` is everything above and the following:

```sh
signari client set-signed-requests -client-id bank-api
signari client set-alg -client-id bank-api -response-alg ES256
signari client set-profile -client-id bank-api -security-profile fapi2-message-signing
```

It is refused until the client requires signed requests and has a response algorithm of
PS256, ES256 or EdDSA, and a client that stops meeting that is refused as above.

| | |
|---|---|
| **Requests** | [Signed](jar.md), at the pushed authorization endpoint alone, with PS256, ES256 or EdDSA. `aud` is the issuer, and `nbf` and `exp` are both required, at most 60 minutes apart |
| **Responses** | [Signed](jarm.md), with `response_mode=jwt`. Anything else is refused |
| **Introspection** | A resource server asks for [a signed answer](response-encryption.md#signed-introspection) with its `Accept` header. It is signed as the client's tokens are unless it sets otherwise, because RFC 9701's default of RS256 is one this profile rules out |
| **ID tokens** | Signed already |

Not here is `response_modes`, the client metadata that lists the modes a client may use.
It is optional, and a client held to this profile is limited to signed ones anyway.

[The review](security-review-fapi2.md) goes through the specification requirement by
requirement. It covers the Security Profile. The OpenID Foundation's Message Signing plan
has not been run either.
