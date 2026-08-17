# Outposts

A Signari binary serving LDAP, RADIUS or forward auth somewhere the database
must not be reachable from — a DMZ, a branch office, an airgapped segment.

It holds **no database credentials**. Every credential question goes to the core
over HTTPS.

```sh
# On the core:
signari outpost create -org <uuid> -name dmz-ldap -kind-outpost ldap

  SIGNARI_OUTPOST_TOKEN=KzQPR10mXH9SrVbMgat4zP-Nmd1JazLVh7jr86y6kpE

# Where the protocol is needed, with no database anywhere near it:
signari outpost run -core https://auth.example.com \
  -outpost-token $SIGNARI_OUTPOST_TOKEN -kind-outpost ldap \
  -addr :389 -ldap-base-dn dc=example,dc=com
```

## Why this is a small feature here

`internal/ldapd` and `internal/radius` were written against a narrow
`Authenticator` interface and have no database references at all. An outpost is
therefore a second implementation of that interface — one that speaks HTTP —
rather than a second architecture.

The comparable feature elsewhere in this field needs its own component, its own
container image and its own lifecycle, because the core and the protocol servers
are written in different languages. Ours is one binary started with different
flags.

## What an outpost token is worth

It is a **password-verification oracle**. Whoever holds one can ask "is this
password correct for this user" as fast as the core answers. That is unavoidable
— it is the entire function — so the work is in making it worth nothing else:

- **Bound to one protocol.** A token issued for an LDAP outpost is refused for
  RADIUS. A leak costs one protocol rather than all of them.
- **Rate limited per outpost**, on top of the per-user throttling the credential
  path already applies.
- **Every call updates `last_seen`, with the address.** A token being exercised
  from somewhere new is visible rather than inferred.
- It cannot change anything, mint a session, or read more of the directory than
  a client bound to the local listener could.

Revocation is immediate: `enabled = false` and the next bind is refused.

## It checks before it listens

```
signari: the core refused this outpost token. It may have been revoked, or
issued for a different protocol -- a token created for one protocol is not
accepted for another (core said 401 Unauthorized)
```

The token is verified against the core **before any listener opens**. An outpost
that starts anyway and discovers the problem when the first person tries to log
in has turned a configuration error into an outage, and the person who finds out
is a user.

## An unreachable core is not a wrong password

If the core cannot be reached, the outpost says so. It does not refuse the
credential.

Answering "wrong password" during a network outage sends an entire office to
reset passwords they typed correctly, which turns a five-minute outage into an
afternoon.

## Liveness

```sh
signari outpost list -org <uuid>

  dmz-ldap    ldap    enabled   last seen 18s ago from 203.0.113.7
```

An outpost that stops calling is an outage nobody is told about otherwise: the
protocol simply stops answering somewhere the operator is not looking.

## Status

**LDAP outposts work**, verified with a real LDAP client binding and searching
through one started in a shell with no database credentials in its environment.

**RADIUS outposts are not runnable yet.** RADIUS needs the shared secret for
each network device, and those are not carried by the outpost token — deciding
how they reach the outpost is a real decision rather than an oversight, and
`signari outpost run -kind-outpost radius` says so instead of starting something
half-configured.

**Forward-auth outposts** are unnecessary in the same sense: `/proxy/verify` is
already an HTTP endpoint a reverse proxy anywhere can call, so a proxy-kind
token exists mainly to be refused where it should be.
