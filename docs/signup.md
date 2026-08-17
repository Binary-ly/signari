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
revoked.

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
