# Grant management

## Introduction

When Ada lets an application act for her, she gives it a "grant": the set of
permissions she approved. An OAuth application normally knows what it was given
only by what its tokens can do. It can end the grant only token by token.

With Grant Management, what a person authorised has an identifier the application
can come back to. The application can add to the grant, replace it, read it back,
or revoke it and everything issued under it.

This follows Grant Management for OAuth 2.0, `oauth-v2-grant-management-03`, a
draft from 2023. It is for confidential clients: a public one naming an action is
refused. Nothing needs turning on, and an application that never asks is treated
as it always was.

## Making and changing a grant

These happen in an authorization request, because they almost always need the
person. The application adds `grant_management_action`:

| Action | With | What happens |
|---|---|---|
| `create` | nothing else | A new grant. `grant_id` comes back in the token response |
| `merge` | `grant_id` | What is authorized now is added to what the grant holds |
| `replace` | `grant_id` | The grant becomes only what is authorized now |

A grant comes to exist when the code is redeemed, so a code nobody claims leaves
nothing behind. The tokens from a merge carry the whole grant, not only what this
request asked for.

**A merge or a replace ends the tokens issued under the grant before**, refresh and
access alike. A replace can take permissions away, and a token that outlived it
would keep them.

A `grant_id` can be unknown, belong to another application, or belong to somebody
other than the person signed in. Each of those answers `invalid_grant_id`, on the
redirect like any other error, at the point the person is known.

## Reading and revoking

Both are at `/oauth2/grants/{grant_id}`, named in discovery as
`grant_management_endpoint`. The application that holds the grant calls it with
one of its bearer tokens. A "bearer token" is an access
token that works for whoever presents it.

The token needs `grant_management_query` to read, and `grant_management_revoke` to
revoke. So register those scopes on the application.

Reading a grant answers with the scopes it holds:

```
GET /oauth2/grants/TSdqirmAxDa0_-DB_1bASQ

{
  "scopes": [{"scope": "openid profile", "resource": ["https://api.example.com/"]}],
  "created_at": 1356123600,
  "last_updated": 1356123600,
  "updated_by": "client"
}
```

`DELETE` answers `204` and ends the grant. With it end every refresh token and
every access token issued under it, including an access token that came with no
refresh token. Tokens stay revocable that way, because a managed grant always has
a lineage behind it.

A grant of another application is `404`, the same as one that does not exist. The
identifier is public and can leak, so knowing one proves nothing. A token without
the scope is `403`, and no valid token is `401`.

## A person's say

A person may disconnect the application on their account page, or have it done for
them. Either way, that removes its grants as well as its tokens. A grant left
behind could be merged into later, and hand back what was taken away.

Deleting a person or an application removes theirs. Grants are included in a
person's data export.

A grant that nothing has touched for six months, and that no token still stands
on, is swept. An application coming back to one gets `invalid_grant_id`, and
creates another.

## What is not here

- **`grant_management_action_required`**. An application is never required to
  name an action.
- **The grant's `claims`**, which `GET` leaves out. The `scopes` say what was
  granted.
- **`updated_by: authorization_server`**, since nothing here changes a grant on
  its own.
- **Grants shared between client IDs** (§8.1). A grant is one application's.
- **Client-Initiated Backchannel Authentication** ([CIBA](ciba.md)) and the
  [device flow](device-flow.md), which take neither parameter. It is the
  authorization code flow, [pushed](par.md) or not.
