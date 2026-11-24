# Response modes and hybrid flow

## Introduction

An application normally receives its authorization code in the query string of
its redirect URI. Some older applications expect it another way: in the URL's
fragment, in a form posted to them, or with an ID token beside the code. That last
one is called the "hybrid flow".

Signari supports these "response modes" for applications being migrated in that
cannot be changed first. Each mode can also carry the response signed, as a JSON
Web Token (JWT). That is JWT-Secured Authorization Response Mode (JARM, see the
[glossary](glossary.md#jarm)). It refuses, permanently, every response type that would
put an access token in the browser.

Hybrid is off for each application until you turn it on with
`signari client set-hybrid`.

## The modes and types

Each mode and type does this:

| | |
|---|---|
| `response_mode=query` | The default for `code`. Unchanged |
| `response_mode=fragment` | The default when an `id_token` is returned |
| `response_mode=form_post` | An auto-submitting form, for keeping the response out of URLs |
| `response_mode=jwt`, `query.jwt`, `fragment.jwt`, `form_post.jwt` | The same three with the response signed: see [JARM](jarm.md) |
| `response_type=code id_token` | Off per client, enabled deliberately |

A refusal travels the way the response would have. For a hybrid request it goes in
the fragment, unless another mode was asked for. For `form_post` it goes through
the form. It used to go in the query whatever was asked, where an application
listening at a fragment saw nothing.

That includes the refusal of a type Signari never issues. An application that
asked for `code token` is answered `unsupported_response_type` in the fragment,
which is where it is listening (OpenID Connect (OIDC) Core §3.3.2.6).

A fragment is encoded once. Until November 2026 it was encoded twice. So a script
reading `location.hash` found `iss` still percent-encoded. Checking it as RFC 9207
says, the script refused every hybrid response as a mix-up.

This repository's own tests decoded twice, and agreed with it. The OpenID
Foundation's Hybrid plan, decoding once as a browser does, is what found it.

A registered redirect URI may not have a fragment of its own. RFC 6749 §3.1.2 says
the endpoint URI "MUST NOT include a fragment component". Until November 2026,
dynamic registration refused one, and every other way of registering an
application accepted it.

## What is refused, permanently

Anything containing `token`: `code token`, `id_token token`, and bare `token`.

Those put an **access token** in the browser's address bar. There it lands in
history, in referrers, and in every log between here and the application. OAuth
2.1 removes them for that reason. No migration deadline changes what the token is
worth to whoever reads it out of a proxy log.

`code id_token` is a different proposition:

- The ID token asserts *who signed in*.
- It is bound to the authorization code by `c_hash`.
- The access token still only ever crosses the back channel, the direct
  connection between the application's server and Signari.

That is a real distinction, not a technicality. It is why one is supported and
the others are not.

## Enabling hybrid

To allow the hybrid flow for one application, with a date to review it by, run:

```sh
signari client set-hybrid -client-id legacy-portal -review-by 2026-12-31
```

`-review-by` is required. Without it, the command answers:

```
signari: give -review-by, a date when this should be revisited. Hybrid exists
here for applications being migrated in; an exemption with no date on it is a
permanent one that nobody decided to make
```

The date is **reported, not enforced**. An identity provider that starts refusing
sign-ins on a date nobody remembers setting is worse than the thing it was
protecting against.

## The rules that make a front-channel ID token safe

The "front channel" is the browser, which carries the hybrid flow's ID token.

**A nonce is mandatory.** A "nonce" is a random value the application sends and
expects back inside the ID token (see the [glossary](glossary.md#nonce)). For the
code flow it is optional, because the token arrives over the back channel, tied to
a code only this application can exchange. Here it arrives through the browser.
The nonce is what stops it being replayed into somebody else's session.

**`query` cannot carry an ID token.** A query string is written to the
application's access log, to every proxy in between, and to browser history. An
authorization code there is single-use and bound by Proof Key for Code Exchange
(PKCE, see the [glossary](glossary.md#pkce)). A signed assertion about who
someone is, is not.

**`c_hash` binds the ID token to the code.** Anyone in the redirect's path can
substitute an ID token. `c_hash` ties it to the specific code that arrived with
it. So a swapped one no longer matches the code the application is about to
exchange.

The front-channel token carries `c_hash` and no `at_hash`. There is no access
token to hash, and there never will be.

**`response_type` is a set.** `id_token code` and `code id_token` are the same
request. Comparing raw strings accepts one spelling and refuses the other, for no
reason an application can discover. Signari had that bug until a test caught it.

## form_post

`form_post` answers with an HTML page that posts itself to the redirect URI.

A page's Content Security Policy (CSP) says which scripts may run on it. The
auto-submit script runs under a **per-response CSP nonce**, not
`'unsafe-inline'`. The page carries a code and a signed assertion, and `'unsafe-inline'` would let anything injected
into it run too.

There is no `form-action` rule. Browsers apply it to every redirect a form starts.
So naming the redirect URI's origin would stop a callback from redirecting to
another of the application's own addresses. A gateway in front of an application
does exactly that, and by then the code has already been delivered.

There is a real `<noscript>` button rather than an apology. So a browser with
script disabled still completes the sign-in one click later.

## Discovery

`response_modes_supported` lists all three. `response_types_supported` is
`["code", "code id_token"]`. OpenID Connect Discovery 1.0 §3 defines it as "the
OAuth 2.0 response_type values that this OP supports". Signari supports the hybrid
type for an application permitted it.

Leaving it out did not keep other applications from asking, since they are refused
at the authorization endpoint either way. It kept the migrating applications the
type exists for from asking. A library that checks discovery first concludes the
type is unavailable.

No type that returns an access token in the front channel is listed. A test fails
if one is, or if anything listed is refused.

---

## Full pass — 24 August 2026

`responsemode.go` and the `response_mode`/`response_type` validation in
`oauth/authorize.go` were read line by line, with the git history. `4bd9436` added
form_post + fragment + per-client hybrid, and `5f63363` moved to 303 for the
[FAPI 2.0](fapi2.md) security profile, §5.3.2.2.

### One defect, and it was a stale comment

The `response_mode` validation block still carried the pre-hybrid comment:
"`query` only", "form_post is REFUSED", "removed from discovery too". Every clause
was false as of `4bd9436`. The code directly below it accepts `fragment` and
`form_post`, and discovery advertises all three.

In this codebase, where the comment carries the argument, a comment contradicting
the code is worse than none. A reviewer cannot tell which is the bug. The comment
was rewritten to state the actual rules. No behaviour changed, since the behaviour
was already correct.

### Verified correct and, where checked, ahead

- **`iss` on every response** (RFC 9207), across query, fragment and form_post.
- **303, never 302 or 307** (FAPI 2.0 §5.3.2.2). A POSTed credential cannot be
  replayed to the redirect target.
- **No access token in the front channel, structurally.** `responseParams` has no
  access-token field, so hybrid *cannot* leak one, however it is called. A hybrid
  implementation that merely *declines* to put a token in the fragment is one
  refactor away from doing it. This one has nowhere to put it.
- **form_post CSP is a per-response nonce**, not `'unsafe-inline'`, with
  `default-src 'none'`. So even with a code and a signed assertion on the page,
  nothing but the page's own script runs, and nothing else loads. CSS background
  loads fall back to `default-src 'none'`. The fields are escaped.
- **`query` + id_token is refused** (OIDC MUST). Unknown modes are refused, rather
  than silently treated as query.

### One deliberate posture worth recording

Discovery advertises `response_types_supported: ["code"]` while authorize accepts
`code id_token` for applications with `AllowHybrid`. This is intentional, not an
under-advertisement. Hybrid is a per-application migration escape hatch, off by
default. An application without it that asks for `code id_token` gets a clear
`unsupported_response_type`.

The administrator who enables it with `signari client set-hybrid` is configuring
deliberately, not discovering. An identity provider whose hybrid support is general
would advertise the hybrid types. This one is code-first by design, and
advertising them would invite their use.

*Revised 19 October 2026:* discovery now lists `code id_token`. The posture above
kept the type from the migrating applications that need it, whose libraries read
discovery before asking. Meanwhile every application not permitted it is refused
at the authorization endpoint, whether or not it is listed. See
[Discovery](#discovery).

### Verdict

Sound and conformant. One stale comment was fixed. The behaviour was already
correct. On front-channel token safety, it is enforced by the shape of the type,
rather than by a rule that has to be remembered.
