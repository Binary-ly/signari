# MCP as an authorization server

## Introduction

The Model Context Protocol (MCP) is an open protocol that connects applications
built on language models, such as AI agents, to outside tools and data. An "MCP
server" offers those tools and data. Before an agent's client can call one, it needs an
access token, and the MCP authorization specification (2025-06-18) says how it
gets one.

That specification defines how an MCP server acts as an OAuth 2.1 "resource
server", the service that accepts a token, and how clients reach it. Signari's
role in that picture is the **authorization server**, the service that issues the
token.

You register each MCP server with `signari resource add`, as [Registering an MCP
server](#registering-an-mcp-server) shows.

## What MCP requires of an authorization server

Each row is one requirement the specification places on the authorization server,
and how Signari meets it:

| Requirement | Level | Signari |
|---|---|---|
| Implement OAuth 2.1 with measures for confidential and public clients | MUST | yes |
| Provide OAuth 2.0 Authorization Server Metadata (RFC 8414) | MUST | yes, at `/.well-known/oauth-authorization-server` (inserted before the issuer's path, §3.1) as well as the OpenID location |
| Support Dynamic Client Registration (RFC 7591) | SHOULD | yes, opt-in per deployment |
| Only accept tokens valid for use with their own resources | MUST | yes — enforced at `/oauth2/userinfo` |
| Rotate refresh tokens for public clients | MUST | yes, with reuse detection |
| Validate exact redirect URIs against pre-registered values | MUST | yes |
| Redirect URIs `localhost` or HTTPS only | MUST | yes |
| All endpoints over HTTPS | MUST | yes |
| Issue short-lived access tokens | SHOULD | 5 minutes by default; per client from one minute to an hour (`signari client set-lifetimes`) |
| Honour RFC 8707 `resource` at both endpoints | — | yes, and it becomes `aud`, for an MCP server the organisation registered with `signari resource add` ([resource indicators](resource-indicators.md)) |

Most of this was already true. Several rows became true earlier in this review,
rather than by aiming at MCP. The audience enforcement at Signari's own resource
came from RFC 9700 §2.3. The Proof Key for Code Exchange (PKCE, see the
[glossary](glossary.md#pkce)) conformance fixes came from OAuth 2.1 §4.1.3.

That is worth stating plainly. Being MCP-ready was mostly a consequence of being
OAuth 2.1-correct. That is what the specification says MCP is: *"based on
established specifications... but implements a selected subset of their
features"*.

## The gap: RFC 9728 Protected Resource Metadata

The MCP specification requires this of MCP servers and clients:

> MCP servers **MUST** implement OAuth 2.0 Protected Resource Metadata (RFC9728).
> MCP clients **MUST** use OAuth 2.0 Protected Resource Metadata for
> authorization server discovery.

> MCP servers **MUST** use the HTTP header `WWW-Authenticate` when returning a
> *401 Unauthorized* to indicate the location of the resource server metadata
> URL.

Signari is not only an authorization server. It is also a protected resource, for
its own `/oauth2/userinfo`, which takes an access token and returns claims.
Neither the document nor the header existed.

The consequence is not cosmetic. An MCP client's discovery flow **starts** with a
401. The client reads `resource_metadata` from the challenge, fetches that
document, and finds `authorization_servers`. Only then does it begin an OAuth
flow. Without the header, a client that was never configured for Signari has
nowhere to begin.

### Verified end to end

These are the three steps a conformant client takes, made against a running
Signari.

**1.** The first request, with no token, gets this answer:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="signari",
  resource_metadata="http://127.0.0.1:8078/.well-known/oauth-protected-resource",
  DPoP realm="signari", algs="RS256 ... EdDSA"
```

**2.** The metadata it names says:

```json
{
  "resource": "http://127.0.0.1:8078",
  "authorization_servers": ["http://127.0.0.1:8078"],
  "scopes_supported": ["openid", "profile", "email", "groups"],
  "bearer_methods_supported": ["header"],
  "dpop_signing_alg_values_supported": ["RS256", ..., "EdDSA"],
  "resource_documentation": "http://127.0.0.1:8078/.well-known/openid-configuration"
}
```

**3.** The authorization server metadata it points to gives the issuer, the
authorization and token endpoints, and
`code_challenge_methods_supported: ["S256"]`.

### Details worth noting

The document is built from the **configured issuer, never the Host header**. It
tells a client which authorization servers to trust for this resource. A caller
who could influence that address would be choosing the answer to the question the
document exists to answer. A test sends `Host: evil.example` and asserts it does
not appear in the output.

`dpop_signing_alg_values_supported` comes from the same allow-list `dpop.Verify`
enforces, so the advertisement cannot drift from the policy. It is the same
arrangement as the Demonstrating Proof of Possession ([DPoP](dpop.md))
`WWW-Authenticate` challenge.

There is deliberately **no** `dpop_bound_access_tokens: true`. Signari accepts a
token without `cnf` as an ordinary bearer token. So claiming otherwise would tell
a client that Signari enforces something it does not.

A "mutation" is a deliberate break in the code, made to prove that a test
notices. Each of these was caught by the test beside it:

| Mutation | Test that caught it |
|---|---|
| Drop `authorization_servers` | `TestTheProtectedResourceMetadataCarriesWhatDiscoveryNeeds` |
| Build the document from the Host header | `TestTheMetadataIgnoresTheHostHeader` |
| Drop `resource_metadata` from the 401 | `TestTheUnauthenticatedChallengePointsAtTheMetadata` |

## What is not built

The MCP specification places most of its remaining requirements on **clients**,
and on **MCP servers** acting as resource servers:

- token audience validation at the MCP server;
- no token passthrough;
- the `resource` parameter on every request.

Those belong to whoever writes the MCP server, not to the authorization server.

## Registering an MCP server

An MCP server is registered as a resource. That is what lets a client's
`resource` for it become the token's audience. One that is not registered is
refused.

To register an MCP server with two scopes, and then list what is registered, run:

```sh
signari resource add -org <uuid> -resource https://mcp.acme.example/sse -name Tools \
    -scopes tools.read,tools.run
signari resource list -org <uuid>
```

`resource list` gives each one a metadata URL on this deployment. That document is
RFC 9728's. It carries the MCP server's own identifier as `resource`, this
deployment as its authorization server, and the `-scopes` and `-name` you gave. So
an MCP server need publish nothing of its own.

Name the URL in the MCP server's 401 answer, like this:

```
WWW-Authenticate: Bearer resource_metadata="https://id.acme.example/.well-known/oauth-protected-resource/resources/<id>"
```

An MCP server that would rather publish its own document can, and names this
deployment as its authorization server. The `-scopes` are only an offer: they
decide nothing, and leaving them out of a later `resource add` keeps them.

The address is public and unauthenticated, as metadata is. The ID in it is the
only way to it, so it does not list what an organisation has registered. It is
served for five minutes at a time, so a removal can take that long to reach a
client that has cached it.
