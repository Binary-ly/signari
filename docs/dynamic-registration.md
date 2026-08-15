# Dynamic client registration

RFC 7591, with RFC 7592 management. For ecosystems where clients appear without
an operator registering each one — MCP servers, agent tooling, dynamic
deployments.

```sh
signari registration enable -org <uuid> -max-clients 100
signari registration token  -org <uuid> -name "ci pipeline" -uses 3
```

```
POST   /oauth2/register                 register
GET    /oauth2/register/{client_id}     read it back
DELETE /oauth2/register/{client_id}     remove it
```

## Off by default, and why

An open registration endpoint lets anybody create clients on your identity
provider:

- **Unbounded rows**, created by anyone who can reach it.
- **A phishing surface.** The registrant chooses `client_name`, and that name
  goes on a consent screen. "Microsoft 365 wants access to your account" is
  convincing, and it came from whoever registered.
- **Enumeration.** Register, read back what was accepted, learn what the
  deployment supports.

So it is opt-in per organisation, and even then normally requires an **initial
access token**. Open registration exists because some ecosystems genuinely need
it, but it is a deliberate decision with the limits below in front of you.

`registration_endpoint` is advertised in discovery **only when some organisation
has enabled it**. A document naming an endpoint that answers 401 to every
possible caller is the "advertised before it works" mistake this project refuses
elsewhere — the client tries, fails, and blames its own configuration.

## The limits

| | |
|---|---|
| ceiling per organisation | 100 by default, configurable |
| scopes | intersected with an allow-list, default `openid profile email` |
| client type | public unless `allow_confidential` |
| initial access tokens | optional use count, optional expiry, revocable |
| rate limit | shared with the device endpoint |

**Refuse, never evict.** At the ceiling, registration is refused — deleting
somebody's working client to make room for a stranger's is worse than refusing
the stranger.

Scopes are **intersected rather than rejected**, which RFC 7591 §3.2.1 permits: a
client asking for more gets what it may have and sees the difference in the
response. Asking for `openid profile email admin` returns `openid profile email`.

Registered clients are **public by default**. A secret handed to a caller who
appeared thirty seconds ago and cannot be identified is a formality, not a
credential.

## Redirect URIs are held to the same standard

A self-registered client gets no leniency an operator-registered one would not:

```
http://evil.test/cb        refused — must be https, loopback, or private-use
https://app.test/*         refused — wildcard
https://app.test/cb#frag   refused — fragment
com.example.app:/cb        accepted — RFC 8252 private-use scheme
http://127.0.0.1:9000/cb   accepted — RFC 8252 loopback
https://ok.test/cb         accepted
```

## Management, and the check that matters

The registration access token manages **that client and nothing else**. The
lookup requires both a matching token *and* `dynamically_registered = true` —
without the second condition a leaked registration token could be pointed at an
operator-created client id and read it back.

```
read with the right token            -> 200, metadata
read with the wrong token            -> 401
that token, aimed at an operator's
  client id                          -> 401
```

Wrong token, wrong client and never-registered all answer identically, so this
cannot be used to discover which client ids exist. So do "not enabled here", "no
token" and "bad token" at registration — distinguishing them would let a caller
map where registration is open.

## Verified end to end

A client that registered itself completed a real login:

```
POST /oauth2/register            -> 201, client_id dyn_LoxEUrkC0B…
                                    scope "openid profile email" (admin dropped)
                                    token_endpoint_auth_method "none"
GET  /oauth2/authorize           -> sign-in
POST /login                      -> resumes the parked request
                                 -> https://app.test/cb?code=…&iss=…&state=xyz
POST /oauth2/token (PKCE)        -> Bearer, scope "openid profile"
                                    id_token aud dyn_LoxEUrkC0B…
```

`state` preserved, RFC 9207 `iss` present, PKCE enforced, audience correct.

The ceiling was tested by registering past it: `created`, then
`this organisation has reached its limit of 5`.

## A note on the parked-return redirect

While testing this I saw `&amp;` in a `Location` header and thought I had found a
bug. I had not: the `authz` value is HTML-escaped in the form, a browser
unescapes it before submitting, and `curl` does not — my extraction posted the
escaped text and the server echoed it back.

Worth stating because it looks alarming, and because it put user-influenced data
in a `Location`. That path is guarded by `parkedReturn`, which requires a
same-origin path and refuses `//host`, `/\host`, backslashes anywhere, and any
value carrying its own scheme or host.
