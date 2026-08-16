# Remote access (RDP, VNC and SSH in the browser)

A user signs in to Signari, opens a list of machines they are allowed to reach,
and gets a desktop or a shell in a browser tab. No VPN, no client software, and
no separate set of credentials for each host.

## Status: server side only

Read this before planning around it.

**What works and is tested:** the Guacamole protocol, the guacd handshake, the
authorization chain, the WebSocket proxy, the connection registry, and the
session records. Verified end to end against a faithful fake guacd — a browser's
WebSocket reaches the daemon through authentication, policy and group checks,
instructions flow both ways, and a connection the user may not use is refused.

**What is not done:**

- **No browser client.** Nothing renders a desktop yet. The endpoint speaks the
  protocol correctly; something has to draw it, and `guacamole-common-js` has
  not been integrated. Until then a user cannot reach this feature, which by
  this project's own definition means it is not finished.
- **Not verified against real guacd.** The fake speaks the handshake faithfully
  and does not speak RDP, VNC or SSH. Nothing here proves those work.
- **No session replay UI.** Recordings can be written (`recording-path` is
  passed through), but nothing plays them back.

So: a foundation, honestly labelled. It is in the tree because the parts that
are done are done and tested, not because remote access is shipped.

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

A connection the user may not use answers **404**, the same as one that does not
exist. Distinguishing them would let anybody enumerate the estate by asking for
each machine in turn.

Cross-origin upgrades are refused. The session cookie travels with a WebSocket
handshake like any other request, so an unchecked origin here would be a
cross-site remote desktop.

## Two protocol details worth writing down

**Lengths are in characters, not bytes.** The wire format is
`LENGTH.VALUE,LENGTH.VALUE…;`, and `len()` on a Go string is bytes. Counting
bytes works perfectly until a hostname or a username has an accent in it, at
which point guacd reads the stream as truncated and abandons it — a connection
that dies during the handshake with nothing useful logged.

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
