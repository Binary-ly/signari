# Invitations and self-signup

Two ways for a person to get an account without an administrator learning their
password.

## Invitations

```sh
signari invite create -org <uuid> \
  -email newhire@acme.com \
  -groups engineering,staff \
  -expires 48h

invitation cd3fadae-…
  https://auth.acme.com/signup?invite=DtEFdBs6g6w7duqnKsjaw…
  only newhire@acme.com may accept it
  joins: engineering, staff
  expires in 48h0m0s

The link is shown once. It is stored hashed, so it cannot be printed again.
```

**The token is never stored** — only its SHA-256. An invitation creates an
account in the organisation, so it is a credential, and a database read must not
yield working ones for the same reason it must not yield working passwords.

**Bind it to an address.** Without `-email` anyone holding the link may use it,
and emailed links leak the ordinary ways: forwarded threads, shared mailboxes,
mail scanners that follow URLs. A bound invitation that leaks is useless to
whoever finds it.

**Groups are checked when the invitation is issued**, not when it is accepted. A
group named here that does not exist would otherwise produce an account with
fewer permissions than intended, and nobody would find out until the person
could not reach something.

**Expiry is capped at 90 days.** An invitation that outlives the reason it was
sent is a standing way in.

`signari invite list -org <uuid>` shows what is outstanding, used, expired or
revoked, and `signari invite revoke` closes one.

**Or have the engine mail it.** `-send`, with `-email`, prints no link. The
engine's outbox mails it to the bound address instead, in the deployment's
language, and makes the token only as the mail goes out, so the link exists
nowhere but in that mail. A retried delivery makes a new one, and only the
newest mail's link works. The same invitations can be made, listed and revoked
through the Admin API (`/admin/invitations`, [admin-api](admin-api.md)), held to
what adding a member to each named group is held to. Until October 2026 they
were the CLI's alone, and every link was printed for an operator to pass on.

## Claiming is atomic, and reversible on failure

Accepting is a single `UPDATE` that both filters on "not yet used" and marks it
used. Two people following the same forwarded link at the same moment cannot
both succeed — the second finds no row.

The claim happens **before** the account is created, so a crash between the two
leaves the invitation spent rather than reusable. That is the correct direction
for a credential.

A signup that then fails for an ordinary reason — the address is taken, the
password is too short, the address does not match the binding — puts the
invitation **back**. A typo should not cost somebody the invitation they were
sent.

## Self-signup is a rule, not a switch

```sh
signari signup enable -org <uuid> -domains acme.com,acme.co.uk -groups staff
```

An organisation with no rule does not accept self-signup at all. That is the
default and it does not have to be chosen.

`-domains` is required. Open signup with no restriction lets anyone on the
internet create an account in the organisation, and that is not something to
enable by leaving a flag off — pass `-domains '*'` if it is genuinely what you
want, so it appears in the shell history of whoever did it.

"Anyone may sign up" is almost never what an organisation means. "Anyone with an
`@acme.com` address" usually is, and a checkbox cannot express the difference.

### Approval before the first sign-in

`signup enable -require-approval` keeps every account self-signup makes
**pending** until an administrator lets it in. The account exists and holds its
password, and signs nobody in: every way in (the sign-in form, an emailed code,
a passkey, LDAP and RADIUS binds, a reset link) reads `status = 'active'`. The
sign-up page says the account waits for approval, and offers no sign-in. An
administrator approves it with `signari user approve -email <addr>`, with the
Admin API's `PATCH /admin/users/{userID}` and `active: true`, or with the
console's **Approve**. The person is then told by mail that they can sign in.
Accounts made by invitation or by an administrator are never pending: somebody
already chose them. `user.created` records `pending`, so a subscription to it
([events](events.md)) can tell whoever approves. Until October 2026 an
organisation that wanted to look first could only turn self-signup off.

### The address is proved before the first sign-in

A domain in the rule is only what somebody typed until a message sent to the
address comes back. So, by default, an account self-signup creates cannot sign
in until it has: its first sign-in is held at the sign-in flow's `verify_email`
stage, a six-digit code goes to the address, and the session is issued when the
code is entered. The address is then verified, and ID tokens and `/userinfo`
say `email_verified: true`. Later sign-ins are not held.

A code works for ten minutes, "send another" waits a minute between codes, and
a wrong one counts against the same per-account budget as a second factor.
Twenty wrong codes, across codes, close the confirmation; resetting the password
from its emailed link then proves the address instead, as any completed reset
does for the address its link was sent to.

```sh
signari signup enable -org <uuid> -domains acme.com -verify-email=false
```

turns it off, so new accounts sign straight in on an address nobody has proved
and their tokens say `email_verified: false`.

### Changing the address later

A person moves their account to another address at `/account/email`, from a
recent sign-in. A code goes to the new address, and the account keeps its old
one — for sign-in, for recovery, and as the address its tokens carry — until the
code comes back; then the new address is the account's, verified by that proof,
and the old address and every channel the account has are told, naming
neither. An address another account in the organisation uses is refused, a
wrong code counts against the second-factor budget and twenty close that
change, and the change can be abandoned with the address untouched. Audited
`user.email_changed`. Usernames are not changeable by their owner: many
organisations assign them from a directory, and that needs a per-organisation
switch that does not exist yet. Accounts made by invitation or by
an administrator are never held. Until October 2026 the rule's setting existed,
was on, and was consulted by nothing: anybody could sign up, and straight in,
as any address at an allowed domain.

A self-signup never joins a group whose members may impersonate, even when
`-groups` names one. The rule's groups go to anyone at an allowed domain, so
that group would hand impersonation to whoever signs up. The account is created
without that membership, the engine logs an error naming the group, and the
`user.created` audit record lists only the groups that were actually joined.
An invitation names one person and is sent by an operator, so its groups are
joined as written.

### An application asking for a new account

An application can send people straight to the sign-up form with
`prompt=create` on its authorization request
([Initiating User Registration via OpenID Connect 1.0](https://openid.net/specs/openid-connect-prompt-create-1_0.html)).
Where the application's organisation takes self-signup, the request goes to
`/signup` and is carried through the form. The finished page's **Sign in** link
then leads to a sign-in for that request, and the application gets its answer
as from any sign-in. `create` is taken out of the request at that point, so the
sign-in does not send the person back to the form. Where the organisation takes
no self-signup, the person is shown the sign-in form with a note that accounts
cannot be created there.

Discovery lists `prompt_values_supported`: `none`, `login`, `consent`,
`select_account` and `create`. A prompt value outside that list is refused with
`invalid_request`, case included, so `prompt=Login` is an error rather than a
request that silently re-authenticates nobody. Until October 2026 `create` was
ignored, and so was any value the server did not know.

## Rate limiting

Ten signups per address per hour. This endpoint writes rows and, where mail is
configured, sends messages; ten is far above what a person needs and far below
what makes a useful flooding tool.

## What this cost to get right

Two bugs, both found by running it rather than reading it, and both worth
recording because the class recurs.

**Row-level security hid the invitations from the engine.** The new tables were
given the policy that predates migration 0018 — `org_id = core.current_org_id()`
— but the engine sets no org context, so the policy evaluated against NULL and
returned nothing. It was invisible in development because a development DSN
names a superuser and superusers bypass row-level security entirely. There is
now a test asserting that *every* policy admits the engine or is explicitly
`USING (true)` with the reasoning written down.

**A CHECK constraint forbade the protocol in the same migration.** It asserted
that `used_at` and `used_by` are set together, which contradicts claiming before
the account exists. Every claim failed, and the endpoint reported "that
invitation link is not valid" — because the handler treated any error as a
refusal. A constraint violation and a spent link are not the same thing, and the
handler now logs the difference.
