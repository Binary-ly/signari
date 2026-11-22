# Grant Management

An OAuth client normally knows what it was given only by what its tokens can do, and can
end it only token by token. With Grant Management what a person authorized has an identifier
the client can come back to: add to it, replace it, read it back, or revoke it and everything
issued under it.

This follows Grant Management for OAuth 2.0, `oauth-v2-grant-management-03`, a draft from 2023.
It is for confidential clients; a public one naming an action is refused. Nothing needs
turning on, and a client that never asks is treated as it always was.

## Making and changing a grant

These happen in an authorization request, because they almost always need the person. Add
`grant_management_action`:

| Action | With | What happens |
|---|---|---|
| `create` | nothing else | A new grant. `grant_id` comes back in the token response |
| `merge` | `grant_id` | What is authorized now is added to what the grant holds |
| `replace` | `grant_id` | The grant becomes only what is authorized now |

A grant comes to exist when the code is redeemed, so a code nobody claims leaves nothing
behind. The tokens from a merge carry the whole grant, not only what this request asked for.

**A merge or a replace ends the tokens issued under the grant before**, refresh and access
alike. A replace can take permissions away, and a token that outlived it would keep them.

A `grant_id` that is unknown, belongs to another client, or belongs to somebody other than the
person signed in answers `invalid_grant_id`, on the redirect like any other error, at the
point the person is known.

## Reading and revoking

Both are at `/oauth2/grants/{grant_id}`, named in discovery as `grant_management_endpoint`,
with a bearer token from the client that holds the grant. The token needs
`grant_management_query` to read and `grant_management_revoke` to revoke, so register those
scopes on the client.

```
GET /oauth2/grants/TSdqirmAxDa0_-DB_1bASQ

{
  "scopes": [{"scope": "openid profile", "resource": ["https://api.example.com/"]}],
  "created_at": 1356123600,
  "last_updated": 1356123600,
  "updated_by": "client"
}
```

`DELETE` answers `204` and ends the grant, and with it every refresh token and every access
token issued under it, including an access token that came with no refresh token. Tokens
stay revocable that way because a managed grant always has a lineage behind it.

A grant of another client is `404`, the same as one that does not exist: the identifier is
public and can leak, so knowing one proves nothing. A token without the scope is `403`, and no
valid token is `401`.

## A person's say

A person who disconnects the application on their account page, or has it done for them,
removes its grants as well as its tokens. A grant left behind could be merged into later and
hand back what was taken away. Deleting a person or a client removes theirs. Grants are
included in a person's data export.

A grant nothing has touched for six months and no token still stands on is swept. A client
coming back to one gets `invalid_grant_id` and creates another.

## What is not here

- **`grant_management_action_required`**. A client is never required to name an action.
- **The grant's `claims`**, which `GET` leaves out. The `scopes` say what was granted.
- **`updated_by: authorization_server`**, since nothing here changes a grant on its own.
- **Grants shared between client IDs** (§8.1). A grant is one client's.
- **CIBA** and the device flow, which take neither parameter. It is the authorization code
  flow, pushed or not.
