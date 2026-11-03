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

The Admin API registers outposts, takes them out of service, rotates and removes
them and sets their search group the same way under
`/admin/organizations/{orgID}/outposts`; see
[admin-api.md](admin-api.md).

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

## Taking one out of service

```sh
signari outpost disable -org <uuid> -name dmz-ldap   # refused from its next call; settings kept
signari outpost enable  -org <uuid> -name dmz-ldap
signari outpost rotate  -org <uuid> -name dmz-ldap   # a new token, once; the old one stops at once
signari outpost remove  -org <uuid> -name dmz-ldap   # the registration and its token, for good
```

Each takes effect on the next call, and the same goes through the Admin API. A
disabled outpost is answered `403 outpost_disabled`, a rotated or removed token
`401` with `WWW-Authenticate: Bearer error="invalid_token"`. Neither is a wrong
password to anybody behind the outpost: they are told the directory is unavailable,
as they are in an outage. After a rotation the outpost answers nobody until it is
restarted with the new token.

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
credential: a bind or a search is answered `unavailable` (52), and a search does
not come back empty.

Answering "wrong password" during a network outage sends an entire office to
reset passwords they typed correctly, which turns a five-minute outage into an
afternoon. Until November 2026 that is what a bind did: the outpost knew the
difference and the directory in front of it did not.

A RADIUS outpost that cannot ask the core answers nothing at all, so a device goes
on to its next server. An Access-Reject would tell the person their password is
wrong and tell the device not to bother.

## Liveness

```sh
signari outpost list -org <uuid>

  dmz-ldap    ldap    enabled   search: own entry only   last seen 18s ago from 203.0.113.7, running 1.4.0
  branch-2    radius  STALE                              last seen 41m0s ago from 198.51.100.4, running 1.3.2
```

An outpost that stops calling is an outage nobody is told about otherwise: the
protocol simply stops answering somewhere the operator is not looking. So a
running outpost says hello to the core once a minute whether anybody is using it
or not, with the release it is, and logs when it loses the core and when it gets
it back. After three minutes of silence it is reported `STALE` here, by `stale`
in the Admin API and by `signari doctor`. One that has never called, one taken out
of service, and the kinds nothing runs are not reported.

It warns at start when it and its core are different releases, and starts anyway,
since a rolling upgrade looks exactly like that.

## Where a bind came from

An outpost tells the core the address a bind reached it from. The socket at the
core is the outpost's, so without this everybody behind it had no per-address
budget, and one host could go on guessing by changing usernames. Now the failed
sign-in budget applies to that address as it does on the engine's own listener,
and when it is spent the client is answered `busy`.

It is the outpost's word for it. Whoever holds a stolen token can name any address,
which costs them that budget and nothing else: the budget on each account and the
limit on the outpost still hold.

RADIUS sends no address, because the peer there is the device, and one budget
across everybody on an access point would lock a building out.

Each password an outpost checks is recorded once in the audit trail, as
`login.succeeded` or `login.failed` with `via` set to the protocol it arrived on
(`ldap` or `radius`), `outpost` to the outpost's name, and for a failure the
`reason`. Until November 2026 a RADIUS outpost's sign-ins were recorded as LDAP
binds naming no outpost, and every wrong password twice, which the sign-in counts
on `/metrics` doubled too.

## RADIUS

```sh
signari outpost create -org <uuid> -name branch-2 -kind-outpost radius

# devices.conf: name, the network it sends from, its shared secret
#   ap-floor-2   10.20.0.0/24   a-long-random-shared-secret

chmod 600 devices.conf
signari outpost run -core https://auth.example.com \
  -outpost-token $SIGNARI_OUTPOST_TOKEN -kind-outpost radius -radius-clients devices.conf
```

It listens on `:1812` unless `-addr` says otherwise, and answers password requests
through the core. Each device's secret is in a local file because a secret is a
credential for that device, and this is the machine by design less trusted than
the core: it holds the secrets of the devices it serves and no others. The file is
refused if anybody but its owner can read it, and it is read once, at start, so
restart the outpost after changing it.

What a RADIUS outpost does not do: EAP-TLS, a challenge for a second factor, and the
VLAN attributes of [network authorisation](radius.md). Those need the engine's own
listener. Somebody under an MFA mandate is refused, as they are through an LDAP
outpost.

## Running it as a service

Nothing here needs a database, or anything from the core but the token:

```ini
# /etc/systemd/system/signari-outpost.service
[Unit]
Description=Signari outpost
After=network-online.target
# An outpost exits when it cannot reach its core. Without this, five quick
# failures and systemd stops trying, and a core back a minute later finds it dead.
StartLimitIntervalSec=0

[Service]
# SIGNARI_OUTPOST_TOKEN=..., owned by root and mode 600
EnvironmentFile=/etc/signari/outpost.env
ExecStart=/usr/local/bin/signari outpost run -core https://auth.example.com \
  -kind-outpost ldap -ldap-base-dn dc=example,dc=com \
  -tls-cert /etc/signari/ldap.pem -tls-key /etc/signari/ldap-key.pem
User=signari
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

The key `-tls-key` names is read as `User=signari`, so it is that user's, mode 600.
This unit was run as written on Ubuntu 24.04 with systemd 255, against a core on
another machine: LDAPS binds were answered, an outpost killed was started again,
and with its core unreachable for thirty seconds it kept trying and served again
when the core came back. Until November 2026 the unit had neither
`StartLimitIntervalSec=0` nor `RestartSec`, and in that run systemd stopped after
five quick failures ("Start request repeated too quickly") and left the outpost
down after the core returned.

```yaml
# compose.yaml, with the image built from engine/Dockerfile
services:
  outpost:
    build: ./engine
    command: [outpost, run, -core, "https://auth.example.com", -kind-outpost, radius,
              -radius-clients, /run/secrets/devices]
    environment:
      SIGNARI_OUTPOST_TOKEN: ${SIGNARI_OUTPOST_TOKEN}
    # devices.conf is 600, so this is its owner.
    user: "1000:1000"
    secrets: [devices]
    ports: ["1812:1812/udp"]
    restart: always
secrets:
  devices:
    file: ./devices.conf
```

A core whose certificate an internal authority issued needs that authority given
to the outpost: one more secret, `ca`, from its PEM file, and
`SIGNARI_CA_BUNDLE: /run/secrets/ca` beside the token. Until November 2026 the
outpost trusted the system's roots alone and could not reach such a core at all.
This template was run that way, in a Linux VM against a core on its host: a RADIUS
client's right password was answered Access-Accept and a wrong one Access-Reject,
each with a correct Response Authenticator and Message-Authenticator, and a
request under the wrong shared secret was not answered.

## What is not run

**Desktop and decision tokens** are presented by something else: the credential
provider or PAM module of [desktop login](desktop-login.md), or the application
asking the [evaluation API](authorization.md). `outpost run` says so.

**Forward-auth outposts** are unnecessary: `/proxy/verify` is already an HTTP
endpoint a reverse proxy anywhere can call, so a proxy-kind token exists mainly to
be refused where it should be.
