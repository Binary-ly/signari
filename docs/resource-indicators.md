# Resource indicators

A client may ask for an access token meant for one API rather than for itself,
by sending RFC 8707's `resource` parameter at `/oauth2/authorize`, at
`/oauth2/par` or at `/oauth2/device_authorization`. The values it sends become
the token's `aud`, which is what a resource server checks before it serves the
request. With no `resource`, the audience is the client's own id.

Because the audience is what makes a token acceptable to an API, a client may
only name a resource server **its organisation has registered**:

```sh
signari resource add -org <uuid> -resource https://api.example.com -name "Billing API"
signari resource list -org <uuid>
signari resource remove -org <uuid> -resource https://api.example.com
```

The Admin API has the same three: `GET`, `PUT` and `DELETE` on
`/admin/organizations/{orgID}/resource-servers` (see [admin-api.md](admin-api.md)).

A resource is an absolute `http` or `https` URI with no fragment, compared byte
for byte, exactly as a resource server compares the audience. Register it as
the API will check it: `https://api.example.com` and `https://api.example.com/`
are different audiences.

## What is refused, and where

| | |
|---|---|
| A `resource` the organisation has not registered | `invalid_target`: redirected to the client from `/oauth2/authorize`, answered directly from `/oauth2/par` and `/oauth2/device_authorization` |
| A malformed one, or more than eight | `invalid_target`, at the same places |
| A resource removed after a code or refresh token was issued for it | `invalid_target` at `/oauth2/token`: the check runs again as each token is minted, so removing a resource stops new tokens for it, refreshes included |

The registration is per organisation, not per client. The resource is the API
being protected, and the organisation decides which of its APIs this server
issues tokens for; any of its clients may then ask for one. That is what lets a
dynamically registered client, such as an [MCP](mcp-authorization.md) client,
ask for the server it was pointed at once an operator has registered that
server.

Token exchange keeps its own, narrower allow-list: the audiences a client may
exchange for are set per client with `signari client set-exchange`.

## Upgrading

Until October 2026 any http(s) URI was accepted, so a client could mint a token
audienced to any API that trusts this issuer, another organisation's included.
After upgrading, a client that sends `resource` is refused until its resource
servers are registered. `signari resource list` with nothing registered says
so.
