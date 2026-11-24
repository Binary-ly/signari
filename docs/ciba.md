# Backchannel authentication (CIBA)

## Introduction

Sometimes an application needs a person's approval while that person is not in
front of it. A call-centre agent confirms a transaction on the customer's phone. A
point-of-sale terminal asks for a payment to be approved. A bank asks whether the
person really tried to move £4,000.

Client-Initiated Backchannel Authentication (CIBA, see the
[glossary](glossary.md#ciba)) handles this. The application asks Signari to
authenticate somebody who is **not in front of it**. It then polls until that
person approves on their own device. Signari implements OpenID Connect
Client-Initiated Backchannel Authentication Flow — Core 1.0,
**Final, 1 September 2021**.

An application can use CIBA only once you give it the grant with
`signari client set-grants`. The grant is off by default.

## How a request travels

The application starts a request, then polls the token endpoint for the answer:

```
POST /oauth2/backchannel          → auth_req_id
     client authenticates; scope=openid; login_hint=alice@example.com

POST /oauth2/token                → authorization_pending
     grant_type=urn:openid:params:grant-type:ciba                (…wait…)
     auth_req_id=…                → access_token, id_token
```

In this example, `login_hint` names the person, and `auth_req_id` is the
request's identifier. The person answers at **`/account/requests`**.

An application uses CIBA only once it has the grant, which defaults to off. To
give an application the grant, run:

```sh
signari client set-grants -client-id call-centre \
    -grant-types urn:openid:params:grant-type:ciba
```

Until October 2026 `set-grants` refused this grant type, so no application could
be given it. An application without it is refused with `unauthorized_client`.

## All three delivery modes

CIBA §7.3 defines three delivery modes, and
`backchannel_token_delivery_modes_supported` lists all three:
`["poll", "ping", "push"]`. The mode is **per application**, set when the
application is registered.

- **`poll`**: the application polls the token endpoint with its `auth_req_id`.
  This is the default, and the only one that needs nothing from the application's
  network.
- **`ping`**: Signari calls an endpoint the application hosts, to say "it is
  ready". The application then collects at the token endpoint, as it would when
  polling.
- **`push`**: Signari delivers the tokens to the application's endpoint directly.

Ping and push mean outbound HTTP from inside the identity provider to a URL the
application supplied. That is a request-forgery surface. It is also a delivery
that has to be retried, and parked when it fails.

Both go through the same `internal/outbox` machinery as the back-channel messages
of a [sign-out](logout.md). So they inherit its private-address refusal, its retry
schedule and its parked-failure queue, rather than opening a second delivery path
with its own bugs.

The delivery is parked when the request arrives, and released when the person
answers on `/account/requests`:

- Approving makes a ping due. For push, it mints the tokens once, seals them into
  the parked row and makes it due.
- Refusing makes a ping due, since §10 notifies on the result, not only on
  approval. It drops a push, which has no tokens to deliver.

**Until October 2026 the answer was recorded and nothing was released**. Both
modes were advertised and parked a delivery, and neither ever told its
application anything. The tests approved by writing the decision directly, which
skipped the page where the release was missing. They now go through that page.

`client_notification_token` is checked **in both directions**, and the second is
the one implementations skip. A `poll` application that sends one is refused,
because it expects a callback that will never arrive. A `ping` or `push`
application that omits one is also refused.

§7.1 makes that token the means by which the notification is authenticated to the
application. Without it, the callback could be delivered but never proven to have
come from Signari.

That token is the application's bearer credential: the application accepts it
from whoever presents it. It is kept in one place only: the parked delivery,
sealed under the root key together with the `auth_req_id`. The worker opens it at
the moment it sends.

It was once also copied into the request row in the clear, and never read back.
Migration 0132 dropped that column.

Likewise `backchannel_user_code_parameter_supported` is an explicit `false`,
rather than an omitted field, and the endpoint refuses a `user_code`. An
application reading an absent field has to guess. One reading `false` knows.

## What it shares with the device flow, and why that is a correctness argument

A CIBA request is stored in `core.device_authorizations` with `flow = 'ciba'`. It
is polled by the **same** `PollDeviceCode` as the [device flow](device-flow.md).

That is not thrift. CIBA §11 and RFC 8628 §3.5 specify the same polling discipline
in the same words. They share the four error codes, `authorization_pending`,
`slow_down`, `expired_token` and `access_denied`, and
"the interval MUST be increased by at least 5 seconds". Two implementations would
be two chances to get the ordering wrong. The one used less often would be the one
that drifted.

**Sharing a table means the two must be distinguished where it matters.** Both
keep their secret in `device_code_hash`. So `PollDeviceCode` takes the flow and
filters on it. Otherwise a `device_code` would be redeemable through the CIBA
grant.

Nothing terrible follows from that confusion, but it is grant confusion. The fix
is one `WHERE` clause, rather than an argument about whether it matters.
`TestADeviceCodeCannotBeRedeemedThroughTheCIBAGrant` fails if the filter is
removed.

## The properties this flow rests on

**The endpoint is never open.** It causes a prompt to appear on a stranger's
phone. Unauthenticated, it is a way to make somebody's device buzz on demand. That
is a nuisance, and a phishing primitive, because a person trained to approve
prompts eventually approves one that was not theirs.

§7.1 requires the application's registered authentication method. Public clients
are refused outright, rather than falling through to a secret check that would
pass on an empty string.

**Only the named subject can approve.** The application names a person, and
Signari resolves them. The person's ID goes into the `WHERE` clause of the
approval statement, not into a check the handler has to remember. Another
signed-in person cannot approve a request naming somebody else, and a failed
attempt does not consume it.

**The `auth_req_id` is single use and client-bound.** Redeeming it twice gets
`expired_token`. Presenting it as a different application gets `invalid_grant`,
and does *not* burn the real application's approval.

**`slow_down` actually slows down.** The interval is incremented and persisted, so
it is a rule rather than advice. An identity provider that returns `slow_down`
without applying it cannot tell an application that obeys from one that ignores
it.

**The binding message cannot restructure the approval screen**. The "binding
message" is a short text the application sends, shown on both devices so the
person can tell the request is theirs. CIBA §7.1 asks for "a limited set of plain
text characters". Signari enforces that, refusing line breaks, control characters and
bidirectional overrides with the dedicated `invalid_binding_message` code.

This string renders beside "do you want to allow this", to a person about to
approve access to their own account. A right-to-left override in it can make the
screen read as something other than what it says.

**`acr_values` holds the approval to them.** §8 has the provider authenticate the
user "in line with the Client's requests regarding acr_values". So a request
asking for multi-factor is not approved from a session that signed in with a
password alone. The request stays pending, and the person is told to sign in
again with their second factor and approve it.

An acr value Signari does not implement is never treated as met. Until October
2026 the values were stored "so the approval can be held to them", and nothing
read them.

## Limits, stated

- **`login_hint` only.** `login_hint_token` and `id_token_hint` are parsed and
  refused with `invalid_request`. Treating them as a `login_hint` would resolve an
  opaque token as an email address and find nobody. It would then report
  `unknown_user_id` for a request that was in fact unsupported.
- **No `user_code`**, as above.
- `requested_expiry` is honoured **downwards only**, capped at 15 minutes. A
  longer pending authorization is a longer window in which a forgotten prompt can
  still be approved. The response says what the application actually got.
- **Five prompts per person per ten minutes from each application.** A sixth from
  the same application is refused with `403 access_denied`. That is the code CIBA
  §13 gives for a request the identity provider has decided to deny.

Without that last limit, any application allowed CIBA could keep filling one
person's queue until they approved something to make it stop. The count is per
application because it was once per person only. Then one application spending
the allowance denied that person CIBA from every other application.

## See also

- [Devices with no browser](device-flow.md), the sibling flow, and where the
  polling discipline is documented
