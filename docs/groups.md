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

## Groups inside groups

```sh
signari group nest -org <uuid> -group oncall-eu -in oncall
signari group nest -org <uuid> -group oncall -in engineering
signari group nest -org <uuid> -group oncall-eu -in oncall -remove
```

A group can be a member of another. Whoever is in `oncall-eu` is then in `oncall`,
and whoever is in `oncall` is in `engineering`, so a person put in one group is in
every group above it. That holds everywhere a group means something: the `groups`
claim and SAML attribute, LDAP `memberOf` and a group entry's members, a `memberOf=`
filter, the access policy's `groups` and `any_group`, relations granted to a group,
remote-access connections, RADIUS authorisation, forward auth, impersonation, the
reach of a role delegated over a group, and the people a SCIM target is sent for a
group or a scope. In a configuration file:

```yaml
groups:
  - name: oncall
    member_of: [engineering]
```

`member_of` left out keeps what the group is inside; `member_of: []` takes it out of
everything.

**Read at the moment it is asked, as membership is.** Taking `oncall-eu` out of
`oncall` takes everybody who was in `oncall` only through it out of `oncall` and
`engineering` on their next token, with the same caveat as removing a person: tokens
already issued keep their claims until they expire.

**A loop is refused when it is made.** `engineering` inside `oncall-eu` would put
every one of the three inside the others, which nobody means. The database refuses it
for every writer (the CLI, the Admin API, a configuration file), holding off other
nestings in the organisation while it checks, so two that would close a loop together
cannot both pass. A configuration file whose own `member_of` makes a loop is refused
by `signari plan` before anything is applied. Both groups must be the same
organisation's.

**Only an organisation-wide administrator nests.** A nesting changes who is in every
group above it, so it reaches people the caller never named. A token narrowed to named
groups, or a role delegated over some, is refused both ways. A group inside one that
may impersonate gives every one of its members that power, so the Admin API treats it
as the group above: adding a member to it, or putting a group in it, needs
`privileged-users:write`. `signari group nest` says when a nesting grants impersonation
the members did not have.

**What stays direct.** The Admin API's member list, `GET .../members`, is the people
put in the group by name, because that is what can be removed there; `GET
.../member-groups` is the groups put in it. A directory or identity provider sync, an
inbound SCIM source, and an import keep the direct memberships they manage and leave
nesting alone. A SCIM target is sent people, never a group inside a group, because not
every target can hold one.

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
