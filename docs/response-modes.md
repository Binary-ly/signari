# Response modes and hybrid flow

For applications being migrated in that cannot be changed first.

| | |
|---|---|
| `response_mode=query` | The default for `code`. Unchanged |
| `response_mode=fragment` | The default when an `id_token` is returned |
| `response_mode=form_post` | An auto-submitting form, for keeping the response out of URLs |
| `response_type=code id_token` | Off per client, enabled deliberately |

## What is refused, permanently

Anything containing `token`: `code token`, `id_token token`, and bare `token`.

Those put an **access token** in the browser's address bar, where it lands in
history, in referrers, and in every log between here and the application. OAuth
2.1 removes them for that reason, and no migration deadline changes what the
token is worth to whoever reads it out of a proxy log.

`code id_token` is a different proposition. The ID token asserts *who signed
in*; it is bound to the authorization code by `c_hash`; and the access token
still only ever crosses the back channel. That is a real distinction, not a
technicality, which is why one is supported and the others are not.

## Enabling hybrid

```sh
signari client set-hybrid -client-id legacy-portal -review-by 2026-12-31
```

`-review-by` is required:

```
signari: give -review-by, a date when this should be revisited. Hybrid exists
here for applications being migrated in; an exemption with no date on it is a
permanent one that nobody decided to make
```

The date is **reported, not enforced**. An identity provider that starts
refusing logins on a date nobody remembers setting is worse than the thing it
was protecting against.

## The rules that make a front-channel ID token safe

**A nonce is mandatory.** For the code flow it is optional — the token arrives
over the back channel, tied to a code only this client can exchange. Here it
arrives through the browser, and the nonce is what stops it being replayed into
somebody else's session.

**`query` cannot carry an ID token.** A query string is written to the
application's access log, to every proxy in between, and to browser history. An
authorization code there is single-use and PKCE-bound; a signed assertion about
who someone is, is not.

**`c_hash` binds the ID token to the code.** Anyone in the redirect's path can
substitute an ID token; `c_hash` ties it to the specific code that arrived with
it, so a swapped one no longer matches the code the client is about to exchange.
The front-channel token carries `c_hash` and no `at_hash` — there is no access
token to hash, and there never will be.

**`response_type` is a set.** `id_token code` and `code id_token` are the same
request. Comparing raw strings accepts one spelling and refuses the other for no
reason a client can discover, which is a bug this had until a test caught it.

## form_post

An HTML page that posts itself to the redirect URI.

The auto-submit script runs under a **per-response CSP nonce**, not
`'unsafe-inline'` — the page carries a code and a signed assertion, and
`'unsafe-inline'` would let anything injected into it run too. `form-action` is
narrowed to the redirect URI's own origin.

There is a real `<noscript>` button rather than an apology, so a browser with
script disabled still completes the sign-in one click later.

## Discovery

`response_modes_supported` lists all three. `response_types_supported` stays
`["code"]`: hybrid is per-client and off by default, and advertising it globally
would invite every client to try something nearly all of them are refused for.
