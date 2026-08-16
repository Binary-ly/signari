# Remote access (RDP, VNC and SSH in the browser)

A user signs in to Signari, opens a list of machines they are allowed to reach,
and gets a desktop or a shell in a browser tab. No VPN, no client software, and
no separate set of credentials for each host.

## Status: usable, not yet proven against a real desktop

Read this before planning around it.

**What works and is verified:** the Guacamole protocol, the guacd handshake, the
authorization chain, the WebSocket proxy with instruction-aligned framing, the
connection registry, session records, and the browser client — the machine list,
the viewer page, rendering, and mouse and keyboard input.

Rendering was checked by looking at it, not by assuming: a harness (see below)
feeds the real client a real scene, and the vector drawing and the PNG image
stream both appear. Mouse clicks arrive at the far end with coordinates
translated into the remote display's space. Keystrokes arrive as X11 keysyms.

**What is not done:**

- **Not verified against a real guacd.** The harness speaks the handshake
  faithfully and does not speak RDP, VNC or SSH. Nothing here proves those
  work, and that is the one thing left that needs real apparatus.
- **No session replay.** Recordings can be written — `recording-path` is passed
  through — but nothing plays them back, and who may watch one is an unanswered
  policy question, not a missing button.
- **No clipboard, audio, or file transfer.** The protocol carries all three and
  the client library supports them; none is wired up, and each is a decision
  about what may cross the boundary rather than a feature to switch on.

## Verifying the browser side without guacd

```
go run ./internal/rac/harness
open http://127.0.0.1:4830
```

That runs a fake guacd that draws a recognisable scene, and a server that uses
the *real* proxy and serves the *real* page and script. It is deliberately not a
copy of them: a harness that reimplements what it tests will agree with itself
while production is broken.

`GET /harness/input` returns what the browser sent back, so mouse and keyboard
can be checked without reading a log.

## What Signari provides and what guacd provides

`guacd` is the Apache Guacamole daemon. It is a mature C program that has spoken
RDP, VNC and SSH for over a decade, and reimplementing it would be a project
rather than a feature — so Signari wraps it.

What guacd does **not** have is any notion of a user. It connects to whatever
host it is told to, with whatever credentials it is given. Everything that makes
remote access safe lives on this side:

1. a signed-in session — *who*
2. the access policy — *may they be here at all, right now*
3. the connection's group — *is this machine theirs to reach*
4. an audit entry — *written before a single byte moves*
5. guacd

Steps 2 and 3 are separate deliberately. Policy answers whether this person, on
this device, from this network is permitted at all; the group answers whether
this particular machine is theirs. Collapsing them would mean either every host
shares one rule, or the policy language grows its own copy of group membership.

The audit entry is written *before* the connection is opened, not after it
succeeds. An entry written on success misses every attempt that failed at
guacd — which is the half somebody investigating an incident wants.

## Deploying guacd

```
docker run -d --name guacd -p 127.0.0.1:4822:4822 guacamole/guacd
```

Then point the engine at it:

```
SIGNARI_GUACD_ADDR=127.0.0.1:4822
```

Absent that variable, the remote access endpoint answers 503 and says so rather
than 404 — an operator who has registered connections and not set the address
should be told which half is missing.

**Bind guacd to loopback.** It will connect wherever it is asked, so anything
that can reach guacd can reach every host guacd can. A guacd on `0.0.0.0:4822`
is an unauthenticated proxy into the estate. Signari does not talk to a
container runtime and does not need a mounted Docker socket — that is root on
the host, handed to a service that accepts connections from browsers.

## Registering a connection

```
signari rac add \
  -org <org-uuid> \
  -slug finance-desk \
  -name "Finance desktop" \
  -protocol rdp \
  -host 10.0.4.21 \
  -username svc-desk \
  -password '…' \
  -group finance
```

`-group` is the group requirement. Without it every signed-in user in the
organisation may reach the host, subject to policy.

Credentials are sealed with the root key and unsealed only at the moment a
connection is made, so a database read is not a set of working logins to the
estate. They are merged into the parameter set inside `Resolve` and nowhere
else — they exist in memory for the length of one handshake rather than for the
lifetime of a struct somebody might log.

`signari rac list -org <uuid>` shows what is registered.

## The API

| | |
|---|---|
| `GET /rac/connections` | What the signed-in user may reach: slug, name, protocol. Deliberately no parameters and no credentials — it answers "what may I reach", not "how does the server reach it" |
| `GET /rac/connect/{slug}` | WebSocket, subprotocol `guacamole`. Query: `width`, `height`, `dpi` |
| `GET /rac` | The machine list, as a page |
| `GET /rac/view/{slug}` | The viewer |

A connection the user may not use answers **404**, the same as one that does not
exist. Distinguishing them would let anybody enumerate the estate by asking for
each machine in turn.

Cross-origin upgrades are refused. The session cookie travels with a WebSocket
handshake like any other request, so an unchecked origin here would be a
cross-site remote desktop.

## The browser client

`/rac` lists the machines a user may reach. `/rac/view/{slug}` is the viewer.

The client is Apache Guacamole's own `guacamole-common-js`, vendored with its
checksum recorded in `engine/internal/rac/static/PROVENANCE.md`. That is a
deliberate exception to this project's rule that browser code carries no
dependency — the reasoning is in that file. In short: it is the counterpart of
guacd, from the same project, and declining the client while trusting the daemon
with every credential in the estate would be a distinction with no security
content.

The page's Content-Security-Policy is `script-src 'self'` with nothing inline.

Every state the session can be in says so on screen. A remote desktop that fails
to a black rectangle is the worst possible outcome: the user cannot tell a
policy refusal from a dead host from a bug, and neither can whoever they report
it to.

## Three protocol details worth writing down

**Lengths are in characters, not bytes.** The wire format is
`LENGTH.VALUE,LENGTH.VALUE…;`, and `len()` on a Go string is bytes. Counting
bytes works perfectly until a hostname or a username has an accent in it, at
which point guacd reads the stream as truncated and abandons it — a connection
that dies during the handshake with nothing useful logged.

**Each WebSocket message must contain whole instructions.** The browser's
tunnel parses every message on its own and holds nothing over, so a message that
ends part-way through an instruction loses the remainder and the tunnel reports
a broken stream. A proxy that forwards whatever a read happened to return — an
arbitrary TCP boundary — therefore works until an instruction is bigger than the
buffer, which on RDP is every screen update, since image data is the bulk of the
traffic. Signari batches whole instructions per message and never cuts one. The
failure this avoids looks like a corrupt display rather than a framing fault,
which is what would have made it expensive.

**`connect` supplies values positionally**, in the order guacd listed them in
`args`. That list differs between protocols and between versions of guacd, so an
implementation that hardcodes the order sends the password where the hostname
belongs the day somebody upgrades. Signari looks values up by *name* from what
guacd actually asked for, and refuses a parameter guacd did not ask for rather
than silently ignoring it — an ignored setting is discovered much later than a
refused one.

## Sessions

`core.rac_sessions` records who connected to what, when it ended, and why. The
reason is recorded because "the session closed" with no reason tells an operator
nothing about whether the user left or the host died.

Closing sends `disconnect` to guacd before closing the socket, so the remote
session is torn down rather than left to time out — on RDP that can leave a
logged-in desktop running for minutes after the browser has gone.
