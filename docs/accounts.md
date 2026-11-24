# Several accounts in one browser

## Introduction

Some people have more than one account, such as a work one and a personal one.
They want to be signed in with both in the same browser, and to choose which one
an application gets.

Signari keeps both signed in, and lets the person choose between them. Signing
in as one no longer signs the other out. Before October 2026 it did, and
`prompt=select_account` could only ask for a fresh sign-in.

An application asks the person to choose by sending `prompt=select_account`,
as described under [Choosing](#choosing).

## What the browser holds

A "cookie" is a small piece of data that a browser keeps for a site, and sends
back to it with each request. Signari's session cookie holds the account in use.
Each other account signed in on the browser is kept in one of two more cookies,
according to how it signed in:

| cookie | holds | lasts |
|---|---|---|
| `__Host-signari_session` | the account in use | until the browser closes, or for what the session has left if it was signed in to stay signed in |
| `__Host-signari_accounts` | other accounts that were not | until the browser closes |
| `__Host-signari_accounts_kept` | other accounts signed in to stay signed in | for what the longest of them has left |

So an account keeps the lifetime it was signed in with, wherever the browser
holds it. "Stay signed in" is recorded on the session (`sessions.persistent`),
because the cookie that holds the account changes when the person switches.

At most four accounts are kept beside the one in use. Signing in with a sixth
signs out the one set aside longest ago. That way, no session is left live with
nothing in the browser to end it.

Signing in again as the same person still ends that person's earlier session in
this browser, whichever cookie it was in. The Application Security Verification
Standard (ASVS) V7.2.4 asks this of a re-authentication. Another person's
session is left alone.

## Choosing

A person can choose an account in two places, and can cancel a sign-in:

- **When an application asks.** An application sends `prompt=select_account`.
  The person is shown the accounts this browser holds in that application's
  organisation, and picks one. The request then continues with that account, as
  if it had been in use all along, with its own `acr` and `max_age` checks.
  **Use another account** goes to the sign-in form. **Cancel** sends the
  application `error=account_selection_required` (OpenID Connect Core
  §3.1.2.1). With no account to choose, the prompt asks for a sign-in, which is
  the choice.
- **From the sign-in page.** The sign-in page links to the same chooser,
  **Choose an account you are signed in with**, whenever the browser holds one.
  That is how a person switches accounts from their account page.
- **Cancelling a sign-in.** A sign-in an application started has a **Cancel** too. It
  sends the application `error=access_denied` with its `state`, as the OAuth 2.0
  standard, RFC 6749 §4.1.2.1, describes. Until November 2026, the only way out
  was to close the page, and the application waited on an answer that never
  came.

Every account offered is checked against its session row each time. So an
account that was signed out elsewhere, deactivated or expired is never offered.

Showing the list does not count as using the sessions in it, so it moves no idle
deadline. Choosing one does.

Only an account this browser holds can be chosen, whatever the form posts.

An impersonation session is never kept or offered. An administrator leaves one
through its own end, not by switching (see [support access](impersonation.md)).

## Signing out

A sign-out ends every account the browser holds, not only the one in use
(see [signing out](logout.md)). On a shared computer, signing out should leave nobody
signed in.
