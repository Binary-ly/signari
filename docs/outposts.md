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
  -tls-cert ldap.pem -tls-key ldap-key.pem -ldap-base-dn dc=example,dc=com
```

## LDAPS

An LDAP outpost serves LDAPS, on `:636` unless `-addr` says otherwise, and
**refuses to start without `-tls-cert` and `-tls-key`**. Every simple bind
carries a password. The outpost already refuses a plaintext `-core`, so the
password is never in the clear between the outpost and the core; a plaintext
listener would put it in the clear on the way in instead.

StartTLS is not offered. The listener refuses the extended operation rather
than answer success without upgrading the connection, so clients connect with
`ldaps://`.

`-ldap-insecure` (or `SIGNARI_OUTPOST_LDAP_INSECURE=1`) serves plaintext on
`:389`, and logs a warning saying so. It exists for a listener bound to loopback
behind something that terminates TLS, the same case `-admin-insecure` serves.
Before this, plaintext was the only mode, so an outpost that ran without a
certificate now needs one, or that flag.

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
- It cannot change anything or mint a session, and **on its own it reads nobody's
  entry.** A successful bind through an LDAP outpost returns a signed bind proof
  naming the person and the outpost. A lookup or a list must carry one, and the
  core answers for that person as they stand now: their own entry, or the whole
  directory when they are in the outpost's **search group**. The group is
  recorded on the registration and enforced by the core:

  ```sh
  signari outpost create -org <uuid> -name dmz-ldap -kind-outpost ldap -search-group ldap-readers
  signari outpost search-group -org <uuid> -name dmz-ldap -search-group ldap-readers   # or "" to clear
  ```

  With no group set, everybody behind the outpost sees only their own entry.
  The outpost reads the group from the core when it starts, so restart it after
  a change. `SIGNARI_LDAP_SEARCH_GROUP` is for the engine's own LDAP listener; an
  outpost ignores it and logs that it did. **Until migration 0142** the outpost
  enforced its group itself, and the token used directly against the core listed
  every account in the organisation.

  A bind proof lasts eight hours. That limit is not the control: the person it
  names is read again, status and groups, on every use. After eight hours the
  outpost's searches fail and the client binds again. An outpost older than its
  core sends no proof, so it can still bind but not search until it is upgraded.
- **Somebody under an MFA mandate is refused** when their organisation is set to
  `refuse_when_mfa`, which is the default since migration 0128. LDAP and RADIUS
  carry only a password. See
  [a password alone, and a second factor](ldap.md#a-password-alone-and-a-second-factor).

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
