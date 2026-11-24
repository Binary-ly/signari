# Remote access (RDP, VNC and SSH in the browser)

## Introduction

Reaching a desktop or a shell on a machine inside a network usually takes a virtual
private network (VPN) and client software. It can also take a separate set of
credentials for each host.

With Signari's remote access, a person signs in to Signari and opens a list of the
machines they are allowed to reach. They get a desktop or a shell in a browser tab,
with no VPN, no client software, and no separate credentials for each host. It speaks
Remote Desktop Protocol (RDP), Virtual Network Computing (VNC) and Secure Shell (SSH)
through guacd, the Apache Guacamole daemon.

You run guacd beside the engine and point the engine at it with
`SIGNARI_GUACD_ADDR`. Then you register each machine with `signari rac add`.

## Status: usable, and run against a real guacd

Read this before planning around it.

**What works and is verified:** the Guacamole protocol, the guacd handshake and the
authorization chain. So do the WebSocket proxy with instruction-aligned framing, the
connection registry, session records, and the browser client. The browser client
covers the machine list, the viewer page, rendering, and mouse and keyboard input.

**Run end to end in November 2026** against guacd 1.5.5 and a Debian machine serving
all three protocols, signed in through the engine in Chrome. An SSH shell, a VNC
display and an RDP session were each drawn. A command typed in the browser ran on
the machine, and its output came back on screen.

A VNC connection holding no password asked for one in the viewer's form, and opened
with the answer. An SSH connection holding nothing asked in the terminal. A wrong
answer ended the session with guacd's reason on screen. An RDP host with a
self-signed certificate is refused until it is trusted; see [RDP and the host's
certificate](#rdp-and-the-hosts-certificate).

Rendering was checked by looking at it, not by assuming. A harness (see below) feeds
the real client a real scene, and the vector drawing and the PNG image stream both
appear. Mouse clicks arrive at the far end with coordinates translated into the
remote display's space. Keystrokes arrive as X11 keysyms.

**Until October 2026 no session opened through the engine itself.** The harness
serves the proxy without the engine's middleware. One of those middlewares, the
panic recovery every request passes through, hid the connection a WebSocket upgrade
takes over. So a signed-in person opening a connection got `501 Not Implemented`,
and the session was recorded as `upgrade failed`, on every deployment.

Checked against a running engine with a guacd stand-in, it now answers
`101 Switching Protocols`, with metrics on or off. Every response wrapper passes the
connection through, and a test fails on any that does not.

**What is not done:**

- **Not run against Windows.** The RDP host above was xrdp. A Windows host, and any
  host that requires Network Level Authentication, has not been tried.
- **No session replay.** Recordings can be written, because `recording-path` is
  passed through. But nothing plays them back, and who may watch one is an
  unanswered policy question, not a missing button.
- **No clipboard, audio, or file transfer.** The protocol carries all three, and the
  client library supports them. None is wired up. Each is a decision about what may
  cross the boundary, rather than a feature to switch on.

## Verifying the browser side without guacd

Run the harness, then open its page:

```
go run ./internal/rac/harness
open http://127.0.0.1:4830
```

That runs a fake guacd that draws a recognisable scene, and a server that uses the
*real* proxy and serves the *real* page and script. It is deliberately not a copy of
them. A harness that reimplements what it tests will agree with itself while
production is broken.

`GET /harness/input` returns what the browser sent back, so mouse and keyboard can be
checked without reading a log. `http://127.0.0.1:4830/prompt` is a connection holding
no credentials, for checking the form the viewer asks for them with.

## What Signari provides and what guacd provides

`guacd` is the Apache Guacamole daemon. It is a mature C program that has spoken RDP,
VNC and SSH for over a decade. Reimplementing it would be a project rather than a
feature, so Signari wraps it.

What guacd does **not** have is any notion of who is using it. It connects to
whatever host it is told to, with whatever credentials it is given. Everything that
makes remote access safe lives on this side:

1. a signed-in session — *who*
2. the access policy — *may they be here at all, right now*
3. the connection's group — *is this machine theirs to reach*
4. an audit entry — *written before a single byte moves*
5. guacd

Steps 2 and 3 are separate deliberately. Policy answers whether this person, on this
device, from this network is permitted at all. The group answers whether this
particular machine is theirs. Collapsing them would mean either every host shares
one rule, or the policy language grows its own copy of group membership.

The audit entry is written *before* the connection is opened, not after it succeeds.
An entry written on success misses every attempt that failed at guacd. That is the
half somebody investigating an incident wants.

## Deploying guacd

Run guacd in a container, listening on loopback only:

```
docker run -d --name guacd -p 127.0.0.1:4822:4822 guacamole/guacd
```

Then point the engine at it:

```
SIGNARI_GUACD_ADDR=127.0.0.1:4822
```

Absent that variable, the remote access endpoint answers 503 and says so. It does not
answer 404. An administrator who has registered connections, and not set the address,
should be told which half is missing.

**Bind guacd to loopback.** It will connect wherever it is asked, so anything that
can reach guacd can reach every host guacd can. A guacd on `0.0.0.0:4822` is an
unauthenticated proxy into the estate.

Signari does not talk to a container runtime, and does not need a mounted Docker
socket. That socket is root on the host, handed to a service that accepts
connections from browsers.

**A guacd on another machine is reached over Transport Layer Security
([TLS](glossary.md#tls)).** The protocol carries a target's username and password in
the clear. So a guacd that is not on loopback runs with `-C` and `-K`, and the engine
is told to expect it:

```
SIGNARI_GUACD_ADDR=guacd.internal:4822
SIGNARI_GUACD_TLS=1
SIGNARI_GUACD_CA=/etc/signari/guacd-ca.pem
```

The certificate has to name the host in the address.
`SIGNARI_GUACD_CA` is for a private certificate authority (CA), and is left out for
one the system already trusts.

There is no setting that skips the check. A certificate that cannot be verified
would protect the credentials from nobody who could read them. And guacd, unlike the
machines behind it, can be given a certificate of its own.

## Registering a connection

Register a machine, the credentials guacd signs in to it with, and the group that
may reach it:

```
signari rac add \
  -org <org-uuid> \
  -slug finance-desk \
  -name "Finance desktop" \
  -protocol rdp \
  -host 10.0.4.21 \
  -login svc-desk \
  -password-file /run/secrets/finance-desk \
  -group finance
```

`-group` is the group requirement. Without it, every signed-in person in the
organisation may reach the host, subject to policy.

The password is read from a file. A command line can be read by anybody on the
machine for as long as the command runs. There is no flag that takes the value
itself. One trailing newline in the file is ignored. An empty file is refused,
because it would register a connection asking for a password somebody meant it to
hold.

An SSH connection can sign in with a key instead, or as well:

```
signari rac add -org <org-uuid> -slug build -protocol ssh -host build.internal \
  -login deploy -private-key-file ./deploy.pem -passphrase-file ./deploy.pass
```

The key is a PEM block. A connection of another protocol refuses one, because guacd
would refuse it at the first connect instead.

Credentials are sealed with the root key, and unsealed only at the moment a
connection is made. So a database read is not a set of working credentials for the
estate. They are merged into the parameter set inside `Resolve` and nowhere else.
They exist in memory for the length of one handshake, rather than for the lifetime of
a struct somebody might log.

**A connection that holds no password asks the person who opens it**. Leave the
credentials out, or give only `-login`, and guacd sends the viewer the names of what
it still needs. The viewer shows a form, and sends each answer back on a stream of
its own. It keeps nothing: not in the page, not in a URL, and not in the engine. The
engine carries the answers to guacd along with every other byte of the session. Each
person signs in to the machine as themselves, so the machine's own logs say who it
was.

An SSH connection with neither asks in the terminal instead, inside the session,
because that is where guacd asks. The form is for RDP and VNC.

Against xrdp, which does not require Network Level Authentication, guacd asked
nothing for RDP. The person signed in on the host's own sign-in screen instead. A
wrong answer ends the session with what guacd said, and nothing retries it. All of
this was run against guacd 1.5.5.

guacd does not always say why. About half the refused RDP sessions against 1.5.5
reached the browser with no reason at all. The viewer then says the session ended
before it started, rather than "Disconnected.", which reads like a session somebody
closed.

Until November 2026 the viewer said "Disconnected." even when guacd had given a
reason. It wrote over the reason as the session closed. guacd's own log has the reason either way.

### RDP and the host's certificate

guacd checks the certificate an RDP host presents. A host whose certificate it
cannot verify is refused, and the viewer says "SSL/TLS connection failed
(untrusted/self-signed certificate?)". xrdp's own self-signed certificate was refused
so. Either give the host a certificate guacd can verify, or tell guacd not to check:

```
signari rac set-parameters -org <org-uuid> -slug finance-desk -rac-params ignore-cert=true
```

`ignore-cert=true` accepts any certificate on the leg from guacd to the host. So
whoever can stand in the middle of that leg can pose as the host to guacd, and to
whoever signs in. Version 1.5.5 of guacd offers nothing between the two: its RDP
client has no parameter for pinning one certificate.

`signari rac list` shows what is registered, in every organisation. Until October
2026 this page gave the password as `-password`, which is `user create`'s flag. The
command took it, ignored it, and registered the connection with no password. Each
command now refuses a flag it does not take.

The Admin API registers connections, takes them out of service and replaces their
guacd parameters the same way, under `/admin/organizations/{orgID}/rac-connections`.
See the [Admin API reference](admin-api.md).

Two settings stay with the command, run from a shell on the deployment:
`-recording-path`, and any parameter whose name contains `path`. Each is a location
on the machine guacd runs on, so choosing one decides where that machine writes.
That belongs to whoever runs the deployment, rather than to an organisation's
administrator.

## Limiting a connection

Limit how many people may hold a connection at once, and how long one session may
last:

```
signari rac limits -org <org-uuid> -slug finance-desk -max-connections 2 -max-duration 8h
```

`-max-connections` is how many may hold the connection at once. A place is taken
before guacd is asked, so the machine is never asked for one more than it has room
for. The next person gets `429 connection_full`.

A session that is already over gives its place back straight away. So does one whose
process died without saying so, three minutes after anybody last saw it. That is
because an open channel says it is still there every thirty seconds.

`-max-duration` is how long one session may last. It ends the channel at the first
check after that time, so a session can run up to thirty seconds over. It is recorded
with that reason in `core.rac_sessions` and in `rac.session_ended`.

The person can connect again. This limits one session, not how long they may work,
which is what the access policy and the group are for.

A new limit does not end anybody's session for being over a new cap. A session
already open keeps the duration it started with. The Admin API sets both as
`max_connections` and `max_duration_seconds`, and so does a configuration file.

## The API

The engine serves these addresses for remote access:

| | |
|---|---|
| `GET /rac/connections` | What the signed-in user may reach: slug, name, protocol. Deliberately no parameters and no credentials — it answers "what may I reach", not "how does the server reach it" |
| `GET /rac/connect/{slug}` | WebSocket, subprotocol `guacamole`. Query: `width`, `height`, `dpi` |
| `GET /rac` | The machine list, as a page |
| `GET /rac/view/{slug}` | The viewer |

A connection the person may not use answers **404**, the same as one that does not
exist. Distinguishing them would let anybody enumerate the estate, by asking for each
machine in turn.

Cross-origin upgrades are refused. The session cookie travels with a WebSocket
handshake like any other request. So an unchecked origin here would be a cross-site
remote desktop.

## The browser client

`/rac` lists the machines a person may reach. `/rac/view/{slug}` is the viewer.

The client is Apache Guacamole's own `guacamole-common-js`, vendored with its
checksum recorded in `engine/internal/rac/static/PROVENANCE.md`. That is a deliberate
exception to this project's rule that browser code carries no dependency. The
reasoning is in that file.

In short, it is the counterpart of guacd, from the same project. Declining the client
while trusting the daemon with every credential in the estate would be a distinction
with no security content.

The page's Content-Security-Policy is `script-src 'self'`, with nothing inline.

Every state the session can be in says so on screen. A remote desktop that fails to a
black rectangle is the worst possible outcome. The person cannot tell a policy
refusal from a dead host from a bug, and neither can whoever they report it to.

## Three protocol details worth writing down

**Lengths are in characters, not bytes.** The wire format is
`LENGTH.VALUE,LENGTH.VALUE…;`, and `len()` on a Go string is bytes. Counting bytes
works perfectly until a hostname or a username has an accent in it. Then guacd reads
the stream as truncated and abandons it. The connection dies during the handshake,
with nothing useful logged.

**Each WebSocket message must contain whole instructions.** The browser's tunnel
parses every message on its own, and holds nothing over. So a message that ends
part-way through an instruction loses the remainder, and the tunnel reports a broken
stream.

A proxy that forwards whatever a read happened to return, an arbitrary TCP boundary,
therefore works until an instruction is bigger than the buffer. On RDP that is every
screen update, since image data is the bulk of the traffic. Signari batches whole
instructions per message, and never cuts one. The failure this avoids looks like a
corrupt display rather than a framing fault, which is what would have made it
expensive.

**`connect` supplies values positionally**, in the order guacd listed them in `args`.
That list differs between protocols, and between versions of guacd. So an
implementation that hardcodes the order sends the password where the hostname belongs
the day somebody upgrades.

Signari looks values up by *name* from what guacd actually asked for. It refuses a
parameter guacd did not ask for, rather than silently ignoring it. An ignored setting
is discovered much later than a refused one.

## Sessions

`core.rac_sessions` records who connected to what, when it ended, and why. The reason
is recorded because "the session closed", with no reason, tells an administrator
nothing about whether the person left or the host died.

Closing sends `disconnect` to guacd before closing the socket, so the remote session
is torn down rather than left to time out. On RDP, that can leave a signed-in desktop
running for minutes after the browser has gone.

**An open channel is asked again every 30 seconds**. These are the three questions:

- Is the sign-in session behind it still live?
- Does the access policy still allow `rac:<slug>`?
- Is the person still in the connection's group?

When any answer is no, the channel ends, with that answer as its recorded reason. So
each of these ends an open desktop within half a minute:

- Signing out.
- An administrator revoking the session.
- Deactivating the account, which revokes every session.
- A new deny rule.
- A removed membership.

A check that cannot be made, because the database is unreachable, ends the channel
too, rather than assuming it would have passed. Until October 2026 a channel asked
nothing after it opened, and stayed open until the browser tab closed.

The session's own absolute lifetime bounds a channel's length, because an expired
session fails the first of the three questions.
