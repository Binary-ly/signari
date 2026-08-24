# Backchannel authentication (CIBA)

OpenID Connect Client-Initiated Backchannel Authentication Flow — Core 1.0,
**Final, 1 September 2021**.

The client asks the server to authenticate somebody who is **not in front of
it**, and polls until that person approves on their own device. A call-centre
agent confirming a transaction on the customer's phone; a point-of-sale
terminal; a bank asking "did you just try to move £4,000".

```
POST /oauth2/backchannel          → auth_req_id
     client authenticates; scope=openid; login_hint=alice@example.com

POST /oauth2/token                → authorization_pending
     grant_type=urn:openid:params:grant-type:ciba                (…wait…)
     auth_req_id=…                → access_token, id_token
```

The person answers at **`/account/requests`**.

## All three delivery modes

§7.3 defines three, and `backchannel_token_delivery_modes_supported` lists all
three: `["poll", "ping", "push"]`. The mode is **per client**, set when the client
is registered.

- **`poll`** — the client polls the token endpoint with its `auth_req_id`. The
  default, and the only one that needs nothing from the client's network.
- **`ping`** — we call an endpoint the client hosts to say "it is ready"; the
  client then collects at the token endpoint as it would when polling.
- **`push`** — we deliver the tokens to the client's endpoint directly.

Ping and push mean outbound HTTP from inside the identity provider to a
client-supplied URL — a request-forgery surface, and a delivery that has to be
retried and parked when it fails. Both go through the same `internal/outbox`
machinery as back-channel logout, so they inherit its private-address refusal,
its retry schedule and its parked-failure queue rather than opening a second
delivery path with its own bugs.

`client_notification_token` is checked **in both directions**, and the second is
the one implementations skip. A `poll` client that sends one is refused — it
expects a callback that will never arrive. A `ping` or `push` client that omits
one is also refused: §7.1 makes that token the means by which the notification is
authenticated to the client, so without it the callback could be delivered but
never proven to have come from us.

Likewise `backchannel_user_code_parameter_supported` is an explicit `false`
rather than an omitted field, and the endpoint refuses a `user_code`. A client
reading an absent field has to guess; one reading `false` knows.

## What it shares with the device flow, and why that is a correctness argument

A CIBA request is stored in `core.device_authorizations` with `flow = 'ciba'`,
and polled by the **same** `PollDeviceCode`.

That is not thrift. CIBA §11 and RFC 8628 §3.5 specify the same polling
discipline in the same words, down to the four error codes —
`authorization_pending`, `slow_down`, `expired_token`, `access_denied` — and
"the interval MUST be increased by at least 5 seconds". Two implementations
would be two chances to get the ordering wrong, and the one used less often
would be the one that drifted.


**Sharing a table means the two must be distinguished where it matters.** Both
keep their secret in `device_code_hash`, so `PollDeviceCode` takes the flow and
filters on it — otherwise a `device_code` would be redeemable through the CIBA
grant. Nothing terrible follows from that confusion, but it is grant confusion,
and the fix is one `WHERE` clause rather than an argument about whether it
matters. `TestADeviceCodeCannotBeRedeemedThroughTheCIBAGrant` fails if the
filter is removed.

## The properties this flow rests on

**The endpoint is never open.** It causes a prompt to appear on a stranger's
phone. Unauthenticated, it is a way to make somebody's device buzz on demand —
a nuisance, and a phishing primitive, because a person trained to approve
prompts eventually approves one that was not theirs. §7.1 requires the client's
registered authentication method; public clients are refused outright rather
than falling through to a secret check that would pass on an empty string.

**Only the named subject can approve.** The client names a person, we resolve
them, and the user id goes into the `WHERE` clause of the approval statement —
not into a check the handler has to remember. Another signed-in user cannot
approve a request naming somebody else, and a failed attempt does not consume
it.

**The `auth_req_id` is single use and client-bound.** Redeeming twice gets
`expired_token`; presenting it as a different client gets `invalid_grant` and
does *not* burn the real client's approval.

**`slow_down` actually slows down.** The interval is incremented and persisted,
so it is a rule rather than advice. A server that returns `slow_down` without
applying it cannot tell a client that obeys from one that ignores it.

**The binding message cannot restructure the approval screen.** §7.1 asks for
"a limited set of plain text characters"; we enforce that, refusing line breaks,
control characters and bidirectional overrides with the dedicated
`invalid_binding_message` code. This string renders beside "do you want to allow
this", to a person about to approve access to their own account — a
right-to-left override in it can make the screen read as something other than
what it says.

## Limits, stated

- **`login_hint` only.** `login_hint_token` and `id_token_hint` are parsed and
  refused with `invalid_request`. Treating them as a `login_hint` would resolve
  an opaque token as an email address, find nobody, and report `unknown_user_id`
  for a request that was in fact unsupported.
- **No ping or push**, as above.
- **No `user_code`**, as above.
- `requested_expiry` is honoured **downwards only**, capped at 15 minutes. A
  longer pending authorization is a longer window in which a prompt somebody has
  forgotten about can still be approved. The response says what the client
  actually got.


## See also

- [device-flow.md](device-flow.md) — the sibling flow, and where the polling
  discipline is documented
