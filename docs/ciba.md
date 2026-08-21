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

## Poll mode only, and discovery says so

§7.3 defines three delivery modes. We implement `poll`, and
`backchannel_token_delivery_modes_supported` is exactly `["poll"]`.

Ping and push have the authorization server call an endpoint the *client* hosts.
That is outbound HTTP to a client-supplied URL from inside the IdP — a request
forgery surface needing an allow-list, plus a delivery guarantee needing retries
and a parked-failure queue. We have that machinery for back-channel logout
(`internal/outbox`), so it is buildable. It is not built, so it is not
advertised.

A client sending `client_notification_token` is **refused**, not ignored: a
client that receives an `auth_req_id` concludes the mode it asked for was
accepted, and would wait forever for a callback.

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
