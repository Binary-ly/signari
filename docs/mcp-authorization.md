# MCP as an authorization server

The Model Context Protocol authorization specification (2025-06-18) defines how
an MCP server acts as an OAuth 2.1 resource server and how clients reach it.
Signari's role in that picture is the **authorization server**.

## What MCP requires of an authorization server

| Requirement | Level | Signari |
|---|---|---|
| Implement OAuth 2.1 with measures for confidential and public clients | MUST | yes |
| Provide OAuth 2.0 Authorization Server Metadata (RFC 8414) | MUST | yes |
| Support Dynamic Client Registration (RFC 7591) | SHOULD | yes, opt-in per deployment |
| Only accept tokens valid for use with their own resources | MUST | yes — enforced at `/oauth2/userinfo` |
| Rotate refresh tokens for public clients | MUST | yes, with reuse detection |
| Validate exact redirect URIs against pre-registered values | MUST | yes |
| Redirect URIs `localhost` or HTTPS only | MUST | yes |
| All endpoints over HTTPS | MUST | yes |
| Issue short-lived access tokens | SHOULD | 5 minutes |
| Honour RFC 8707 `resource` at both endpoints | — | yes, and it becomes `aud` |

Most of this was already true, and several rows became true earlier in this
review rather than by aiming at MCP: the audience enforcement at our own resource
came from RFC 9700 §2.3, and the PKCE conformance fixes came from OAuth 2.1
§4.1.3.

That is worth stating plainly — being MCP-ready was mostly a consequence of being
OAuth 2.1-correct, which is what the specification says it is: *"based on
established specifications... but implements a selected subset of their
features"*.

## The gap: RFC 9728 Protected Resource Metadata

> MCP servers **MUST** implement OAuth 2.0 Protected Resource Metadata (RFC9728).
> MCP clients **MUST** use OAuth 2.0 Protected Resource Metadata for
> authorization server discovery.

> MCP servers **MUST** use the HTTP header `WWW-Authenticate` when returning a
> *401 Unauthorized* to indicate the location of the resource server metadata
> URL.

Signari is not only an authorization server — it is a protected resource for its
own `/oauth2/userinfo`, which takes an access token and returns claims. Neither
the document nor the header existed.

The consequence is not cosmetic. An MCP client's discovery flow **starts** with a
401: it reads `resource_metadata` from the challenge, fetches that document,
finds `authorization_servers`, and only then begins an OAuth flow. Without the
header there is nowhere for a client that was never configured for this server to
begin.

### Verified end to end

Against a running server, the three steps a conformant client takes:

**1. First request, no token:**

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="signari",
  resource_metadata="http://127.0.0.1:8078/.well-known/oauth-protected-resource",
  DPoP realm="signari", algs="RS256 ... EdDSA"
```

**2. The metadata it names:**

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

**3. The authorization server metadata it points to** — issuer, authorization and
token endpoints, `code_challenge_methods_supported: ["S256"]`.

### Details worth noting

The document is built from the **configured issuer, never the Host header**. It
tells a client which authorization servers to trust for this resource; a caller
who could influence that address would be choosing the answer to the question the
document exists to answer. A test sends `Host: evil.example` and asserts it does
not appear in the output.

`dpop_signing_alg_values_supported` comes from the same allow-list `dpop.Verify`
enforces, so the advertisement cannot drift from the policy — the same
arrangement as the DPoP `WWW-Authenticate` challenge.

There is deliberately **no** `dpop_bound_access_tokens: true`. We accept a token
without `cnf` as an ordinary bearer token, so claiming otherwise would tell a
client we enforce something we do not.

| Mutation | Test that caught it |
|---|---|
| Drop `authorization_servers` | `TestTheProtectedResourceMetadataCarriesWhatDiscoveryNeeds` |
| Build the document from the Host header | `TestTheMetadataIgnoresTheHostHeader` |
| Drop `resource_metadata` from the 401 | `TestTheUnauthenticatedChallengePointsAtTheMetadata` |

## What is not built

The MCP specification places most of its remaining requirements on **clients**
and on **MCP servers** acting as resource servers — token audience validation at
the MCP server, no token passthrough, the `resource` parameter on every request.
Those belong to whoever writes the MCP server, not to the authorization server.

What Signari could add and has not: a first-class notion of an MCP server as a
registered resource, so that one deployment can publish protected-resource
metadata *on behalf of* several MCP servers and audience-restrict tokens to each.
Today an MCP server integrating with Signari publishes its own RFC 9728 document
and names Signari as its authorization server, which works and is what the
specification describes.
