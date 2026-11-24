# Invitations and self-signup

## Introduction

A new person needs an account before they can sign in. An administrator could
create it and choose a password for them, but then the administrator knows that
password.

Signari gives you two ways for a person to get an account without an
administrator learning their password. An "invitation" is a link you send to one
person, which lets them create their own account. "Self-signup" lets people
create an account on their own, when their email address is at a domain you
allow.

You make invitations with `signari invite create`, and you allow self-signup
with `signari signup enable`. The [Admin API](admin-api.md) can do both.

## Invitations

To invite a person, create an invitation bound to their email address. This one
also adds them to two groups, and expires after 48 hours:

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

In this example, the link is what you send to the new person. Signari shows it
once.

**The token is never stored.** Signari keeps only its SHA-256 hash. An
invitation creates an account in the organisation, so it is a credential. A
database read must not yield working invitations, for the same reason it must
not yield working passwords.

**Bind it to an address.** Without `-email`, anyone holding the link can use it.
Emailed links leak in ordinary ways: forwarded threads, shared mailboxes, and
mail scanners that follow links. A bound invitation that leaks is useless to
whoever finds it.

**Groups are checked when the invitation is issued**, not when it is accepted.
Otherwise, a group named here that does not exist would produce an account with
fewer permissions than intended. Nobody would find out until the person could
not reach something.

**Expiry is capped at 90 days.** An invitation that outlives the reason it was
sent is a way in that stays open.

`signari invite list -org <uuid>` shows which invitations are outstanding, used,
expired or revoked. `signari invite revoke` closes one.

**Or have the engine mail it.** With `-send` and `-email`, Signari prints no
link. Instead, the engine's outbox mails the link to the bound address, in the
deployment's language. The engine makes the token only as the mail goes out, so
the link exists nowhere but in that mail. A retried delivery makes a new link,
and only the newest mail's link works.

You can also make, list and revoke invitations through the Admin API, at
`/admin/invitations` (see [the Admin API](admin-api.md)). There, an invitation
is held to what adding a member to each named group is held to. Until October
2026, invitations belonged to the command line alone, and it printed every link
for an administrator to pass on.

## Claiming is atomic, and reversible on failure

Accepting an invitation is "atomic": it happens in one step that cannot be
split. That step is a single `UPDATE` statement, which finds the invitation only
if it is not yet used and marks it used. If two people follow the same
forwarded link at the same moment, they cannot both succeed. The second finds
no row.

The claim happens **before** the account is created. So a crash between the two
leaves the invitation spent, not reusable. For a credential, that is the correct
direction to fail in.

A sign-up can then fail for an ordinary reason, such as an address that is
taken or a password that is too short. It can also fail because the address
does not match the binding. Signari then puts the invitation **back**. A typo should not cost somebody the invitation
they were sent.

## Self-signup is a rule, not a switch

To let people sign themselves up, give the organisation a self-signup rule. This
one accepts addresses at two domains, and adds each new account to the `staff`
group:

```sh
signari signup enable -org <uuid> -domains acme.com,acme.co.uk -groups staff
```

An organisation with no rule does not accept self-signup at all. That is the
default, so you do not have to choose it.

`-domains` is required. Open sign-up with no restriction lets anyone on the
internet create an account in the organisation. Signari does not let you turn
that on by leaving a flag off. If it is genuinely what you want, pass
`-domains '*'`, so that it appears in the shell history of whoever did it.

"Anyone may sign up" is almost never what an organisation means. "Anyone with an
`@acme.com` address" usually is, and a checkbox cannot express the difference.

A self-signup never joins a group whose members may act as other people, which
is called "impersonation" (see [support access](impersonation.md)). This holds
even when `-groups` names such a group. The rule's groups go to anyone at an
allowed domain, so that group would hand impersonation to whoever signs up.
Signari creates the account without that membership, and the engine logs an
error naming the group. The `user.created` audit record lists only the groups
that were actually joined.

An invitation names one person and is sent by an administrator, so its groups
are joined as written.

### Approval before the first sign-in

With `signup enable -require-approval`, every account that self-signup makes
stays **pending** until an administrator lets it in. A pending account exists
and holds its password, but it signs nobody in. Every way in reads
`status = 'active'`. That covers the sign-in form, an emailed code, a passkey
and a reset link. It also covers binds over the
[Lightweight Directory Access Protocol (LDAP)](ldap.md) and the
[Remote Authentication Dial-In User Service (RADIUS)](radius.md).

The sign-up page tells the person that their account waits for approval, and
offers no sign-in. An administrator approves the account in one of three ways:

- with `signari user approve -email <addr>`;
- with the Admin API's `PATCH /admin/users/{userID}` and `active: true`;
- with **Approve** in the console.

Signari then tells the person by mail that they can sign in.

Accounts made by invitation or by an administrator are never pending, because
somebody already chose them. `user.created` records `pending`, so a
subscription to it ([events](events.md)) can tell whoever approves. Until
October 2026, an organisation that wanted to look first could only turn
self-signup off.

### The address is proved before the first sign-in

An address at an allowed domain is only what somebody typed, until a message
sent to it comes back. So by default, an account that self-signup creates
cannot sign in until its address is proved.

Its first sign-in is held at the sign-in flow's `verify_email` stage, and a
six-digit code goes to the address. The session is issued when the person
enters the code. The address is then verified, and ID tokens and `/userinfo`
say `email_verified: true`. Later sign-ins are not held.

A code works for ten minutes, and "send another" waits a minute between codes.
A wrong code counts against the same per-account budget as a second factor.
Twenty wrong codes, across all the codes sent, close the confirmation.
Resetting the password from its emailed link then proves the address instead,
as any completed reset does for the address its link was sent to.

Accounts made by invitation or by an administrator are never held. Until
October 2026, the rule's setting existed and was on, but nothing consulted it.
Anybody could sign up, and sign straight in, as any address at an allowed
domain.

You can turn the check off with `-verify-email=false`:

```sh
signari signup enable -org <uuid> -domains acme.com -verify-email=false
```

New accounts then sign straight in on an address nobody has proved, and their
tokens say `email_verified: false`.

### Changing the address later

A person can move their account to another address at `/account/email`, from a
recent sign-in. A code goes to the new address. Until the code comes back, the
account keeps its old address: for sign-in, for recovery, and as the address
its tokens carry.

Once the code comes back, the new address is the account's, verified by that
proof. Signari then tells the old address and every channel the account has, in
a message that names neither address.

Signari refuses an address that another account in the organisation uses. A
wrong code counts against the second-factor budget, and twenty wrong codes close
that change. The person can also abandon the change, and the address stays
untouched. The change is audited as `user.email_changed`.

Usernames cannot be changed by their owner. Many organisations assign them from
a directory, and that needs a per-organisation switch that does not exist yet.

### An application asking for a new account

An application can send people straight to the sign-up form. It adds
`prompt=create` to its authorization request, the request that starts a sign-in
([Initiating User Registration via OpenID Connect 1.0](https://openid.net/specs/openid-connect-prompt-create-1_0.html)).

Where the application's organisation accepts self-signup, the request goes to
`/signup` and is carried through the form. The **Sign in** link on the finished
page then leads to a sign-in for that request. The application gets its answer
as it would from any sign-in. Signari takes `create` out of the request at that
point, so the sign-in does not send the person back to the form.

Where the organisation accepts no self-signup, the person sees the sign-in form,
with a note that accounts cannot be created there.

The discovery document lists `prompt_values_supported`: `none`, `login`,
`consent`, `select_account` and `create`. Signari refuses a prompt value outside
that list with `invalid_request`, and the case must match too. So
`prompt=Login` is an error, not a request that silently re-authenticates
nobody. Until October 2026, Signari ignored `create`, and it also ignored any
value it did not know.

## Rate limiting

Signari accepts ten sign-ups per network address per hour. This endpoint writes
rows and, where mail is configured, sends messages. Ten is far above what a
person needs, and far below what makes a useful flooding tool.

## What this cost to get right

Two bugs were found by running this feature, not by reading it. Both are worth
recording, because the same kind of bug recurs.

**Row-level security hid the invitations from the engine.** The new tables were
given the policy that predates migration 0018, `org_id = core.current_org_id()`.
But the engine sets no organisation context, so the policy evaluated against
NULL and returned nothing. Nobody saw it in development. A development data
source name (DSN) names a superuser, and superusers bypass
[row-level security](glossary.md#rls) entirely. A test now asserts that *every*
policy admits the engine, or is explicitly `USING (true)` with the reasoning
written down.

**A CHECK constraint forbade the protocol in the same migration.** It asserted
that `used_at` and `used_by` are set together. That contradicts claiming the
invitation before the account exists. Every claim failed, and the endpoint
reported "that invitation link is not valid", because the handler treated any
error as a refusal. A constraint violation and a spent link are not the same
thing, and the handler now logs the difference.
