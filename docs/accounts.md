# Several accounts in one browser

A person with two accounts, say a work one and a personal one, can be signed in
with both in the same browser and choose between them. Signing in as one no
longer signs the other out. Before October 2026 it did, and
`prompt=select_account` could only ask for a fresh sign-in.

## What the browser holds

The session cookie holds the account in use. Each other account signed in on
the browser is kept in one of two more cookies, according to how it signed in:

| cookie | holds | lasts |
|---|---|---|
| `__Host-signari_session` | the account in use | until the browser closes, or for what the session has left if it was signed in to stay signed in |
| `__Host-signari_accounts` | other accounts that were not | until the browser closes |
| `__Host-signari_accounts_kept` | other accounts signed in to stay signed in | for what the longest of them has left |

So an account keeps the lifetime it was signed in with wherever the browser
holds it. "Stay signed in" is recorded on the session (`sessions.persistent`),
because the cookie that holds it changes when the person switches. At most four
accounts are kept beside the one in use. Signing in with a sixth signs out the
one set aside longest ago, so no session is left live with nothing in the
browser to end it.

Signing in again as the same person still ends that person's earlier session in
this browser, as ASVS V7.2.4 asks of a re-authentication, whichever cookie it
was in. Another person's session is left alone.

## Choosing

- An application sends `prompt=select_account`. The person is shown the
  accounts this browser holds in that application's organisation and picks
  one. The request then continues with that account, with its own `acr` and
  `max_age` checks, as if it had been in use all along. **Use another account**
  goes to the sign-in form. **Cancel** sends the application
  `error=account_selection_required` (OpenID Connect Core §3.1.2.1). With no
  account to choose, the prompt asks for a sign-in, which is the choice.
- The sign-in page links to the same chooser, **Choose an account you are signed
  in with**, whenever the browser holds one. That is how a person switches
  accounts from their account page.

Every account offered is checked against its session row each time, so one
signed out elsewhere, deactivated or expired is never offered. Showing the list
does not count as using the sessions in it, so it moves no idle deadline;
choosing one does. Only an account this browser holds can be chosen, whatever
the form posts. An impersonation session is never kept or offered: an
administrator leaves one through its own end
([impersonation](impersonation.md)), not by switching.

## Signing out

A sign-out ends every account the browser holds, not only the one in use
([logout](logout.md)). On a shared computer, signing out should leave nobody
signed in.
