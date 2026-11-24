# Resource indicators

## Introduction

An access token says which API it is for, in its `aud` claim, its "audience". An
API, which the protocols call a "resource server", checks that claim before it
serves a request. By default, the audience is the application's own client ID.

An application can ask for a token meant for one API instead, by sending RFC
8707's `resource` parameter. Signari accepts a resource only when the
application's organisation has registered it. You register one with
`signari resource add`.

## Asking for a resource

An application can send `resource` at `/oauth2/authorize`, at `/oauth2/par`, at
`/oauth2/device_authorization`, or at the token endpoint with the
`client_credentials` grant. The values it sends become the token's `aud`, which is
what a resource server checks before it serves the request. With no `resource`,
the audience is the application's own client ID.

Because the audience is what makes a token acceptable to an API, an application
can only name a resource server **its organisation has registered**. You add,
list and remove the registered resource servers like this:

```sh
signari resource add -org <uuid> -resource https://api.example.com -name "Billing API"
signari resource list -org <uuid>
signari resource remove -org <uuid> -resource https://api.example.com
```

The Admin API has the same three: `GET`, `PUT` and `DELETE` on
`/admin/organizations/{orgID}/resource-servers` (see [the Admin
API](admin-api.md)).

A resource is an absolute `http` or `https` URI with no fragment. It is compared
byte for byte, exactly as a resource server compares the audience. Register it as
the API will check it: `https://api.example.com` and `https://api.example.com/`
are different audiences.

## What is refused, and where

Signari refuses these requests in these places:

| | |
|---|---|
| A `resource` the organisation has not registered | `invalid_target`: redirected to the client from `/oauth2/authorize`, answered directly from `/oauth2/par` and `/oauth2/device_authorization` |
| A malformed one, or more than eight | `invalid_target`, at the same places |
| A resource removed after a code or refresh token was issued for it | `invalid_target` at `/oauth2/token`: the check runs again as each token is minted, so removing a resource stops new tokens for it, refreshes included |

The registration is per organisation, not per application. The resource is the
API being protected, and the organisation decides which of its APIs Signari issues
tokens for. Any of its applications can then ask for one.

That is what lets a [dynamically registered](dynamic-registration.md)
application, such as a Model Context Protocol ([MCP](mcp-authorization.md))
client, ask for the MCP server it was pointed at. It can do so once an
administrator has registered that MCP server.

Token exchange keeps its own, narrower allow-list. The audiences an application
may exchange for are set per application with `signari client set-exchange`.

## Upgrading

Until October 2026 any http(s) URI was accepted. So an application could have a
token minted for any API that trusts this issuer, another organisation's included.

After upgrading, an application that sends `resource` is refused until its
resource servers are registered. `signari resource list` with nothing registered
says so.

`client_credentials` used to ignore `resource`, and set the token's audience to
the application, the Admin API's audience aside. So a service sending one for a
resource nobody registered was given a token. It is now refused `invalid_target`.
A service sending a registered resource now gets a token with that audience, no
longer with its own client ID.
