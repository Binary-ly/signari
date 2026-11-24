# Groups

## Introduction

Acme's wiki lets only its engineers edit pages, and its chat application gives
the on-call team a channel of their own. To do that, each application needs to
know which groups a person is in.

A "group" in Signari is a named set of people, such as `engineering`. Signari
tells an application about a person's groups only after an administrator
releases groups to that application. A group can also sit inside another group,
and its members then belong to both.

You manage groups with the `signari group` commands, through the
[Admin API](admin-api.md#groups), or in a [configuration file](config-as-code.md).

## Create a group and release it

These three commands create a group, add a person to it, and release groups to
an application:

```sh
signari group create -org <uuid> -group engineering
signari group member -org <uuid> -group engineering -email-member alice@example.com
signari group release -org <uuid> -client-id my-app          # or -only engineering
```

In this example, `<uuid>` is the organisation's ID, and `my-app` is the
application's "client ID", the name it gives when it talks to Signari. Without
`-only`, the release covers every group. With `-only engineering`, the
application sees that group alone.

Each application learns about groups in the protocol it speaks. The table below
names three of them: OpenID Connect ([OIDC](glossary.md#oidc)), Security
Assertion Markup Language ([SAML](glossary.md#saml)) and Lightweight Directory
Access Protocol ([LDAP](glossary.md#ldap)). A "DN", or distinguished name, is an
entry's full name in an LDAP directory.

Membership reaches applications three ways:

| protocol | how |
|---|---|
| OIDC | `groups` claim in the ID token and from `/oauth2/userinfo` |
| SAML | an attribute in the assertion, named per provider |
| LDAP | `memberOf`, as full DNs |

## Group claims are authorization data

Everything else Signari tells an application describes who a person *is*, such
as their name or email address. A group [claim](glossary.md#claim) is different,
because applications decide access on it. `groups: ["admin"]` is not a
description. It is a grant, enforced by software that Signari does not control
and cannot audit.

Two rules follow from that, and both are tested against a running Signari.

### Membership is read at issuance, never cached

Signari reads a person's groups each time it issues a token. There is
deliberately no copy of group membership on the session, in a cookie, or
anywhere near `core.sessions`. Suppose Ada signs in this morning and is removed
from a group at lunchtime. Her session must not still make tokens that claim the
group she was removed from.

Reading membership costs one indexed database query for each token. That is the
right price for a value that other systems make access decisions on. It was
verified against a running Signari, where the next ID token after a removal no
longer carried the group:

```
remove alice from oncall
  id_token groups -> (absent)      # next token, immediately
```

**The honest caveat**, which the command line prints on every removal: tokens
*already issued* keep their claims until they expire. New ones do not. Cutting off
access immediately means ending the person's session. Saying so is the difference
between an administrator who knows that and one who assumes removal was instant.

### Release is an allow-list, per application

Asking for the `groups` scope is not enough. A "scope" is a short name an
application asks for, which brings certain claims with it. An administrator must
also release groups to that application, and can restrict *which* groups it
sees.

This is the `groups` claim an application received before its release, with one
group released, and with all of them released:

```
before release                 -> (absent)
release -only oncall           -> ['oncall']
release (all)                  -> ['engineering', 'oncall']
```

So there are two gates, and only one of them is the application's to pass. The
application requests the scope, and you decide the release. Without the release,
any application can learn the shape of your organisation by adding one word to
the scopes it asks for. The first third-party application anyone connects would
do exactly that.

`groups` appears in `scopes_supported`, the list of scopes in Signari's
[discovery document](glossary.md#discovery-document), because the scope now
works. Advertising it does not mean an application gets anything.

## Groups inside groups

You can put one group inside another with `signari group nest`. These commands
put `oncall-eu` inside `oncall`, put `oncall` inside `engineering`, and then take
`oncall-eu` out again:

```sh
signari group nest -org <uuid> -group oncall-eu -in oncall
signari group nest -org <uuid> -group oncall -in engineering
signari group nest -org <uuid> -group oncall-eu -in oncall -remove
```

A group can be a member of another. Whoever is in `oncall-eu` is then in
`oncall`, and whoever is in `oncall` is in `engineering`. So a person put in one
group is in every group above it.

That holds everywhere a group means something:

- the `groups` claim and the SAML attribute;
- LDAP `memberOf` and a group entry's members;
- a `memberOf=` filter;
- the [access policy](policy.md)'s `groups` and `any_group`;
- [relations](authorization.md) granted to a group;
- [remote-access](remote-access.md) connections;
- authorisation over RADIUS (Remote Authentication Dial-In User Service), as for
  Acme's VPN;
- [forward authentication](forward-auth.md);
- [impersonation](impersonation.md);
- the reach of a [role delegated](admin-api.md#administrative-roles) over a
  group;
- the people a SCIM (System for Cross-domain Identity Management)
  [target](scim.md) is sent for a group or a scope.

In a configuration file, a group names the groups it is inside with `member_of`:

```yaml
groups:
  - name: oncall
    member_of: [engineering]
```

If you leave `member_of` out, the group stays inside whatever it is in now.
`member_of: []` takes it out of everything.

**Read at the moment it is asked, as membership is.** Say you take `oncall-eu`
out of `oncall`. Everybody who was in `oncall` only through `oncall-eu` is out of
`oncall` and `engineering` from their next token. The caveat is the same as for
removing a person: tokens already issued keep their claims until they expire.

**A loop is refused when it is made.** Putting `engineering` inside `oncall-eu`
would put each of the three groups inside the others, which nobody means. The
database refuses it from every writer: the command line, the Admin API and a
configuration file. While it checks, it holds off other nestings in the
organisation, so two nestings that would close a loop together cannot both pass.
A configuration file whose own `member_of` makes a loop is refused by
`signari plan` before anything is applied. Both groups must be the same organisation's.

**Only an organisation-wide administrator nests.** A nesting changes who is in
every group above it, so it reaches people the caller never named. A token
[narrowed](admin-tokens.md#narrowing-a-token-to-named-objects) to named groups is
refused both ways, putting a group in or taking one out. So is a person whose
role is delegated over some groups.

A group inside one that may impersonate gives every one of its members that
power. So the Admin API treats it as the group above: adding a member to it, or
putting a group in it, needs `privileged-users:write`. `signari group nest` says
when a nesting grants impersonation the members did not have.

**What stays direct.** The Admin API's member list, `GET .../members`, is the
people put in the group by name. Those are the memberships you can remove there.
`GET .../member-groups` is the groups put in it.

Some things manage memberships for you: a [directory sync](directory-sync.md), a
sync from another identity provider, an inbound [SCIM source](scim-source.md) and
an import. Each keeps the direct memberships it manages, and leaves nesting
alone. A SCIM target is sent people,
never a group inside a group, because not every target can hold one.

## Smaller decisions

**Names are constrained** to `[a-zA-Z0-9._-]{1,64}` by a CHECK in the database:
letters, digits, dot, underscore or hyphen, from 1 to 64 characters. A group's name
travels through JSON arrays, SAML attribute values and LDAP filters. A name
carrying a delimiter means something different in one of them.

**Name and display name are separate.** The `groups` claim carries the name.
Renaming a group in the console must not silently revoke access in every
application that matched on the old string.

**LDAP publishes full DNs**, such as `cn=engineering,ou=groups,<base>`, because
that is what directory-aware software matches on. A bare name works with some
LDAP clients and silently matches nothing in others.

**LDAP releases every group**, unlike OIDC. An administrator configures each LDAP
listener for one organisation, so there is no third party to withhold groups
from.

**Membership records who granted it.** A group membership grants privilege. It
needs the same record of where it came from as any other grant.

## A bug worth recording

Releasing *all* groups failed, while releasing *specific* groups worked. A nil Go
slice encodes as SQL `NULL`, not as an empty array, and the column is `NOT NULL`.
So the "no filter" case was the broken one. It was found by running both paths,
not one.
