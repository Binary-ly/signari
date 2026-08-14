# Groups

```sh
signari group create -org <uuid> -group engineering
signari group member -org <uuid> -group engineering -email-member alice@example.com
signari group release -org <uuid> -client-id my-app          # or -only engineering
```

Membership reaches applications three ways:

| protocol | how |
|---|---|
| OIDC | `groups` claim in the ID token and from `/oauth2/userinfo` |
| SAML | an attribute in the assertion, named per provider |
| LDAP | `memberOf`, as full DNs |

## Group claims are authorization data

Everything else this directory emits describes who somebody *is*. A group claim
is different: downstream applications gate on it. `groups: ["admin"]` is not a
description, it is a grant — enforced by software we do not control and cannot
audit.

Two properties follow, and both are tested against the running server.

### Membership is read at issuance, never cached

There is deliberately no copy of group membership on the session, in a cookie,
or anywhere near `core.sessions`. A session established this morning must not
still mint tokens claiming a group somebody was removed from at lunchtime.

It costs one indexed query per token. That is the right price for a value other
systems make access decisions on. Verified:

```
remove alice from oncall
  id_token groups -> (absent)      # next token, immediately
```

**The honest caveat**, which the CLI prints on every removal: tokens *already
issued* keep their claims until they expire. New ones do not. Cutting off access
immediately means ending the session, and saying so is the difference between an
operator who knows that and one who assumes removal was instant.

### Release is an allow-list, per client

Asking for the `groups` scope is not enough. An operator must also release
groups to that client, and may restrict *which* groups it sees.

```
before release                 -> (absent)
release -only oncall           -> ['oncall']
release (all)                  -> ['engineering', 'oncall']
```

Two gates, and only one of them is the client's to pass. The scope is requested
by the client; the release is decided by you. Without this, any client can learn
the shape of your organisation by adding a word to its scope parameter — and the
first third-party application anyone integrates would do exactly that.

`groups` appears in `scopes_supported` because it now works. Advertising it does
not mean a client gets anything.

## Smaller decisions

**Names are constrained** to `[a-zA-Z0-9._-]{1,64}` by a CHECK. The value
travels through JSON arrays, SAML attribute values and LDAP filters; a name
carrying a delimiter means something different in one of them.

**Name and display name are separate.** Renaming a group in the console must not
silently revoke access in every application that matched on the old string.

**LDAP publishes full DNs** (`cn=engineering,ou=groups,<base>`), which is what
directory-aware software matches on. A bare name works with some clients and
silently matches nothing in others.

**LDAP releases every group**, unlike OIDC. An LDAP listener is configured per
organisation by an operator; there is no third party to withhold them from.

**Membership records who granted it.** A group membership is a privilege grant
and needs the same provenance as any other one.

## A bug worth recording

Releasing *all* groups failed while releasing *specific* groups worked. A nil Go
slice encodes as SQL `NULL`, not an empty array, and the column is `NOT NULL` —
so the "no filter" case was the broken one. Found by running both paths rather
than one.
