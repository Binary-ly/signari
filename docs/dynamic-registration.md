# Dynamic client registration

## Introduction

Usually an administrator registers each application in Signari before it can sign
anybody in. Some ecosystems do not work that way. Model Context Protocol
([MCP](mcp-authorization.md)) servers, agent tooling and dynamic deployments
create applications as they go, with no administrator registering each one.

"Dynamic client registration" lets such an application register itself, as RFC
7591 defines. It can then read, change and remove its registration, as RFC 7592
defines.

Signari keeps it off by default, because an open registration endpoint lets
anybody create applications. You turn it on for one organisation at a time with
`signari registration enable`. You then hand out "initial access tokens", which
let a caller register, with `signari registration token`.

## Turning it on

To turn registration on for an organisation, with a ceiling of 100 applications,
and to make a token that can register three of them, run:

```sh
signari registration enable -org <uuid> -max-clients 100
signari registration token  -org <uuid> -name "ci pipeline" -uses 3
```

An application then registers and manages itself at these addresses:

```
POST   /oauth2/register                 register
GET    /oauth2/register/{client_id}     read it back
PUT    /oauth2/register/{client_id}     replace its name, redirects and scope
DELETE /oauth2/register/{client_id}     remove it
```

`PUT` takes the `client_id`, `redirect_uris`, `client_name` and `scope`. It is held
to what registering was: the same redirect rules, and scopes intersected with the
policy as it stands now. So a policy tightened since then narrows the application.

A secret cannot be chosen, and the "registration access token" stays as it is.
That token is the one Signari gave the application when it registered, for
managing its registration. Nothing else the application registered with changes.

## The name in other languages

An application can name itself in several languages, alongside the untagged
`client_name`. RFC 7591 section 2.2 writes this as
`"client_name#ja": "クライアント名"`. For example:

```json
{"redirect_uris": ["https://rp.example/cb"], "client_name": "My Client",
 "client_name#ja-Jpan-JP": "クライアント名", "client_name#de": "Mein Client"}
```

Each tag is a BCP 47 language tag, compared without regard to case. So `#de` and
`#DE` are one name, and sending both is refused (`invalid_client_metadata`). So is
a tag that is not a language tag, or a member that is not a string.

At most 32 languages are allowed. Each name is cleaned as `client_name` is, and cut
to sixty characters. The registration, the read and the update answer with the
members as they were sent. An update replaces them, so a name it leaves out is
gone.

Every page that names an application shows the name in a language the person
asked for. Those pages are:

- the consent screen;
- the device and back-channel approvals;
- the User-Managed Access ([UMA](uma.md)) claims page;
- the application portal;
- the connected applications page.

The language is the application's `ui_locales` first, then the language the
person chose at Signari, then their browser's. The language must be the same: a
reader asking for `pt` gets `pt-BR`, never another language because it is the
closest there is.

With no such name, the untagged one is shown as it is. That is what the section
says a value with no tag must be. A language does not need these pages to be
translated into it.

Only the name is used. The other fields the section lists are `logo_uri`,
`tos_uri`, `policy_uri` and `client_uri`. They are not shown anywhere here, so they
are ignored with or without a tag, as RFC 7591 section 2 has unknown metadata
ignored.

An administrator names an application the same way with `signari client name`,
the Admin API's `localized_names`, or `localized_names:` in a configuration file.

## Off by default, and why

An open registration endpoint lets anybody create applications in your identity
provider:

- **Unbounded rows**, created by anyone who can reach it.
- **A phishing surface.** The registrant chooses `client_name`, and that name
  goes on a consent screen. "Microsoft 365 wants access to your account" is
  convincing, and it came from whoever registered. Control characters are taken
  out of the name, and so are the marks that reverse the text around them
  (U+202A to U+202E, U+2066 to U+2069). So it cannot rearrange the screen it is
  shown on, and the screen shows the `client_id` beside it. Neither makes the name
  trustworthy.
- **Enumeration.** Register, read back what was accepted, and learn what the
  deployment supports.

So it is opt-in per organisation, and even then normally requires an **initial
access token**. Open registration exists because some ecosystems genuinely need
it. But it is a deliberate decision, made with the limits below in front of you.

`registration_endpoint` is advertised in discovery **only when some organisation
has enabled it**. Picture a document naming an endpoint that answers 401 to every
possible caller. That is the "advertised before it works" mistake this project
refuses elsewhere: the application tries, fails, and blames its own
configuration.

## The limits

Registration is held to these limits:

| | |
|---|---|
| ceiling per organisation | 100 by default, configurable |
| scopes | intersected with an allow-list, default `openid profile email` |
| client type | public unless `-allow-confidential` |
| initial access tokens | optional use count, optional expiry, revocable with `registration revoke` |
| rate limit | 20 attempts per address per hour, counted before anything else, then a shared allowance of three a second that only a caller allowed to register can spend. The shared allowance used to be spent before that check, so anybody could exhaust it with garbage |

**Refuse, never evict.** At the ceiling, registration is refused. Deleting
somebody's working application to make room for a stranger's is worse than
refusing the stranger.

Scopes are **intersected rather than rejected**, which RFC 7591 §3.2.1 permits. An
application asking for more gets what it may have, and sees the difference in the
response. Asking for `openid profile email admin` returns `openid profile email`.

Registered applications are **public by default**. A secret handed to a caller who
appeared thirty seconds ago, and cannot be identified, is a formality, not a
credential.

Where registrants are identified, by an initial access token you issued them,
`registration enable -allow-confidential` gives them secrets. A registrant that
asks for a `token_endpoint_auth_method` other than `none` gets a client secret in
the response.

The whole policy is written each time `registration enable` runs, so leaving the
flag off turns it off again. Nothing could set it before, so every registered
application was public whatever the policy said.

## Redirect URIs are held to the same standard

A self-registered application gets no leniency that an application an
administrator registered would not. Signari answers these redirect URIs like
this:

```
http://evil.test/cb        refused — must be https, loopback, or private-use
https://app.test/*         refused — wildcard
https://app.test/cb#frag   refused — fragment
com.example.app:/cb        accepted — RFC 8252 private-use scheme
http://127.0.0.1:9000/cb   accepted — RFC 8252 loopback
https://ok.test/cb         accepted
```

## Pairwise subjects

A registrant can ask with `subject_type: pairwise` for subjects that mean nothing
to any other application. A "subject" is the identifier a token uses for a
person. Its "sector" is the one host of its redirect URIs.

Where there are several hosts, or a loopback address, it must name a
`sector_identifier_uri`. That document is fetched once, through the outbound
checks, and has to list every redirect URI. An update cannot move the redirect
URIs out of the sector the application already has.

[Pairwise subjects](pairwise-subjects.md#clients-that-register-themselves) has the
rules. Every response says the application's `subject_type`. Before, the field
was dropped, so an application that asked for pairwise was handed the ID that
every other application sees.

## Management, and the check that matters

The registration access token manages **that application and nothing else**. The
lookup requires both a matching token *and* `dynamically_registered = true`.
Without the second condition, a leaked registration token could be pointed at the
client ID of an application an administrator created, and read it back.

These are the answers to each kind of read:

```
read with the right token            -> 200, metadata
read with the wrong token            -> 401
that token, aimed at an operator's
  client id                          -> 401
```

Wrong token, wrong application and never-registered all answer identically. So
this cannot be used to discover which client IDs exist.

At registration, "not enabled here", "no token" and "bad token" also answer
identically. Distinguishing them would let a caller map where registration is
open.

## Verified end to end

An application that registered itself completed a real sign-in:

```
POST /oauth2/register            -> 201, client_id dyn_LoxEUrkC0B…
                                    scope "openid profile email" (admin dropped)
                                    token_endpoint_auth_method "none"
GET  /oauth2/authorize           -> sign-in
POST /login                      -> resumes the parked request
                                 -> https://app.test/cb?code=…&iss=…&state=xyz
POST /oauth2/token (PKCE)        -> Bearer, scope "openid profile"
                                    id_token aud dyn_LoxEUrkC0B…
```

In this example, `state` was preserved and the RFC 9207 `iss` was present. Proof
Key for Code Exchange (PKCE, see the [glossary](glossary.md#pkce)) was enforced,
and the audience was correct.

The ceiling was tested by registering past it: `created`, then
`this organisation has reached its limit of 5`.

## A note on the parked-return redirect

While this was being tested, `&amp;` appeared in a `Location` header and looked
like a bug. It was not. The `authz` value is HTML-escaped in the form, and a
browser unescapes it before submitting, but `curl` does not. The test's extraction
posted the escaped text, and Signari echoed it back.

This is worth stating because it looks alarming, and because it put data a person
can influence into a `Location`. That path is guarded by `parkedReturn`. It
requires a same-origin path, and refuses `//host`, `/\host`, backslashes anywhere,
and any value carrying its own scheme or host.
