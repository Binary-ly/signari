# Pairwise subjects

## Introduction

Every token names the person it is about in its `sub` claim, their "subject" (see
the [glossary](glossary.md#subject)). By default, a person's `sub` is their ID, and
it is the same in every token. So any two applications can tell they have the same
customer by comparing notes.

Set an application to "pairwise" subjects, and it is told an identifier of its own
instead, which means nothing anywhere else. You set it for each application with
`signari client set-subject-type`.

## Turning it on

To give an application identifiers of its own, run:

```sh
signari client set-subject-type -client-id web-app -subject-type pairwise
```

Use this for an application you do not fully trust with the fact that its
customers are also somebody else's. That might be a partner, a third-party
integration, or anything a person would not expect to be linked to the rest.

## Sectors

A pairwise subject belongs to a **sector**, not to one application, so that an
organisation's own applications can agree on who somebody is. Applications with
the same sector get the same subject for a person. Applications with different
sectors get different ones.

When an application's redirect URIs are on only one host, that host is its sector.
Name the sector yourself in these cases:

- The application's redirect URIs are on several hosts.
- It is a native application whose redirect is a loopback address or a custom
  scheme, which say nothing of whose it is.
- Applications should share one.

For example, to put a web application and a mobile application in one sector,
run:

```sh
signari client set-subject-type -client-id web-app -subject-type pairwise -sector apps.example.com
signari client set-subject-type -client-id mobile  -subject-type pairwise -sector apps.example.com
```

The sector is stored when it is set, and is not worked out again. So a change to a
redirect URI does not change what the application calls anybody.

Its value is yours. It is a host name in shape, and Signari does not fetch
anything from it. An application registering itself names its sector differently,
with a `sector_identifier_uri` (below).

## Clients that register themselves

An application using [dynamic registration](dynamic-registration.md) asks for
pairwise subjects with `subject_type`. With one host across its redirect URIs,
that host is its sector.

With several hosts, or a loopback address, it names a `sector_identifier_uri`
instead. That is an `https` address serving a JSON array that holds every one of
its redirect URIs, exactly as registered. The host of that address is then the
sector. A registration might ask like this:

```json
{
  "redirect_uris": ["https://app.example.com/cb", "https://m.example.net/cb"],
  "subject_type": "pairwise",
  "sector_identifier_uri": "https://example.com/redirect_uris.json"
}
```

The document is read once, at registration. It goes through the same outbound
checks as every address a stranger chooses. So there is no private address, no
plaintext and no redirect to plaintext, and the document is at most 64 KiB.

It is refused when any redirect URI is missing from it, compared character for
character, with no case folding. Nothing it holds is kept.

An update made with the registration access token is held to the sector the
application already has. New redirect URIs are where that sector's subjects will
be sent. So they must be vouched for in the same way: listed in a document on the
same host, or sharing the application's one host.

A registrant cannot move a pairwise application onto an address its sector never
named, and keep the subjects. To change the sector, register a new application.

## What it changes

Everything that names a person to the application names them this way, and they
all agree:

- The ID token and the access token, whichever [format](opaque-access-tokens.md)
  it is in.
- Userinfo and introspection, for an access token and a refresh token alike.
- An `id_token_hint`, or a `sub` asked for in `claims`, which are read as the
  application's.
- The token sent in a [back-channel sign-out](logout.md), and the security events
  on the application's stream.
- `act.sub`, the person acting, when an impersonator or a delegate is.
- A credential issued on the application's token.

A token exchanged into a pairwise application names the person as that
application does.

Inside Signari nothing changes. A verified token is read back to the person before
anything looks at it. So revocation, sessions, policy and the audit trail all see
one ID. A token whose person has been erased is refused, as the identifier went
with them.

## What it does not change

**It hides an ID, not a person.** An `email`, a `preferred_username` or a mapped
claim says who somebody is equally well. An application that is given one can link
them with it. Pairwise subjects are only as private as the scopes and claims
released alongside them.

**A `sid` is the session's**. Two applications a person is signed in to in one
session see the same `sid` for as long as it lasts.

**The `sub` a proxy forwards is the person's ID.** `X-Forwarded-Sub` goes to an
application behind [forward authentication](forward-auth.md), which is yours and
not a client.

**A client set to pairwise is refused a Transaction Token naming a person**. A
[Txn-Token](transaction-tokens.md) names its subject by the one ID the
deployment's own workloads share. So giving it to such an application would hand
over the thing it was set up not to see.

## Changing it

Changing an application's subject type, or its sector, changes what it calls
**everybody**. It will not recognise anybody it knew by the old subject. Tokens
already issued go on saying what they said until they end.

Do it before an application has people using it, or plan the migration on its
side.

Going back to public keeps the sector and the identifiers. So setting pairwise
again gives everybody the subject they had. Erasing a person removes theirs.
