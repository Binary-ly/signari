# Pairwise subjects

A person's `sub` is their id by default, and it is the same in every token, so any two
applications can tell they have the same customer by comparing notes. Set a client to
pairwise and it is told an identifier of its own instead, which means nothing anywhere else:

```sh
signari client set-subject-type -client-id web-app -subject-type pairwise
```

Use this for an application you do not fully trust with the fact that its users are also
somebody else's: a partner, a third-party integration, anything a person would not expect
to be linked to the rest.

## Sectors

A pairwise subject belongs to a **sector**, not a client, so that an organisation's own
applications can agree on who somebody is. Clients with the same sector get the same
subject for a person, and clients with different sectors get different ones.

The sector is the one host of the client's redirect URIs when it has only one. Name it when
it has several, when it is a native application whose redirect is a loopback address or a
custom scheme, which say nothing of whose it is, or when clients should share one:

```sh
signari client set-subject-type -client-id web-app -subject-type pairwise -sector apps.example.com
signari client set-subject-type -client-id mobile  -subject-type pairwise -sector apps.example.com
```

The sector is stored when it is set and is not worked out again, so a change to a redirect
URI does not change what the client calls anybody. Its value is yours: it is a host name in
shape, and this server does not fetch anything from it. A client registering itself names
its sector differently, with a `sector_identifier_uri` (below).

## Clients that register themselves

A client using [dynamic registration](dynamic-registration.md) asks for pairwise subjects
with `subject_type`. With one host across its redirect URIs, that host is its sector. With
several, or a loopback address, it names a `sector_identifier_uri` instead: an `https`
address serving a JSON array that holds every one of its redirect URIs, exactly as
registered. The host of that address is then the sector:

```json
{
  "redirect_uris": ["https://app.example.com/cb", "https://m.example.net/cb"],
  "subject_type": "pairwise",
  "sector_identifier_uri": "https://example.com/redirect_uris.json"
}
```

The document is read once, at registration, through the same outbound checks as every
address a stranger chooses: no private address, no plaintext, no redirect to plaintext, and
at most 64 KiB. It is refused when any redirect URI is missing from it, compared character
for character, with no case folding. Nothing it holds is kept.

An update made with the registration access token is held to the sector the client already
has. New redirect URIs are where that sector's subjects will be sent, so they must be
vouched for in the same way: listed in a document on the same host, or sharing the client's
one host. A registrant cannot move a pairwise client onto an address its sector never named
and keep the subjects. To change the sector, register a new client.

## What it changes

Everything that names a person to the client names them this way, and they all agree:

- the ID token and the access token, whichever [format](opaque-access-tokens.md) it is in
- userinfo and introspection, for an access token and a refresh token alike
- an `id_token_hint`, or a `sub` asked for in `claims`, which are read as the client's
- a back-channel logout token, and the security events on the client's stream
- `act.sub`, the person acting, when an impersonator or a delegate is
- a credential issued on the client's token

A token exchanged into a pairwise client names the person as that client does.

Inside this server nothing changes: a verified token is read back to the person before
anything looks at it, so revocation, sessions, policy and the audit trail all see one id.
A token whose person has been erased is refused, as the identifier went with them.

## What it does not change

**It hides an id, not a person.** An `email`, a `preferred_username` or a mapped claim says
who somebody is just as well, and a client that is given one can link them with it. Pairwise
subjects are only as private as the scopes and claims released alongside them.

**A `sid` is the session's.** Two clients a person is signed in to in one session see the
same `sid` for as long as it lasts.

**The `sub` a proxy forwards is the person's id.** `X-Forwarded-Sub` goes to an application
behind [forward auth](forward-auth.md), which is yours and not a client.

**A client set to pairwise is refused a Transaction Token naming a person.** A Txn-Token
names its subject by the one id the deployment's own workloads share, so giving it to such a
client would hand over the thing it was set up not to see.

## Changing it

Changing a client's subject type, or its sector, changes what it calls **everybody**. It
will not recognise anybody it knew by the old subject, and tokens already issued go on
saying what they said until they end. Do it before a client has users, or plan the
migration on its side.

Going back to public keeps the sector and the identifiers, so setting pairwise again gives
everybody the subject they had. Erasing a person removes theirs.
