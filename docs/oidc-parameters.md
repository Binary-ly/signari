# Authorization request parameters

## Introduction

When an application sends a person to Signari to sign in, it sends an
"authorization request". That is an address carrying parameters that say what
the application wants. Every request needs a few of them, such as the client ID and
the redirect URI. OpenID Connect (OIDC) defines several more that an application
can add (see the [glossary](glossary.md#oidc)).

This page says what Signari does with those optional parameters. Each is worth
knowing about, because a parameter quietly ignored is an application that
believes it asked for something.

## What happens to each parameter

Signari treats each optional parameter like this:

| Parameter | What happens |
|---|---|
| `login_hint` | Fills in the sign-in box, and sends the person to the provider that signs in its domain when there is one ([sending people to their own provider](social-login.md#sending-people-to-their-own-provider)). A suggestion: it can be typed over, and it proves nothing |
| `id_token_hint` | An ID token this server issued to this client, naming who is expected. See below |
| `claims` | A request for claims, read as a request for the scopes that release them. See below |
| `display` | Not read. There is one page, and it suits `page`, `popup` and `touch`, which is what discovery lists as `display_values_supported` |
| `prompt`, `max_age`, `acr_values` | Held to the session on every request; see [sign-in flows](flows.md) and [several accounts](accounts.md) |

In this table, "this server" is Signari, and "this client" is the application
sending the request.

## `id_token_hint`

Signari checks the token as one of its own: its signature, its issuer, and that it
was issued to this application. A token past its expiry is fine, since an expired
ID token is the usual one an application has to hand. A token that fails any of
those checks gets `invalid_request`, sent back to the application.

Then Signari holds the person's session to the token:

| The session is | The answer |
|---|---|
| The person it names | As any other request |
| Somebody else, with `prompt=none` | `login_required` |
| Somebody else, otherwise | The sign-in page, saying so. A code for the wrong person never comes back |
| Nobody | As any other request with no session |

## `claims`

A "claim" is one statement about the person, such as their email address. A
"scope" is a short name that brings certain claims with it (see [scopes, claims
and consent](how-signari-works.md#scopes-claims-and-consent)).

There is one way a claim is released here, which is by scope. That way there is
one consent screen and one release rule. A request for a claim becomes a request
for the scope that carries it:

| Claim | Scope |
|---|---|
| `email`, `email_verified` | `email` |
| `name`, `given_name`, `family_name`, `preferred_username` | `profile` |
| `groups` | `groups` |

So the parameter cannot release anything the application is not registered for,
or that the person did not consent to. A claim whose scope the application is not
registered for does not come back, essential or not, and that is not an error.

Two claims in the request do more than ask:

- An `acr` marked essential in `id_token` is added to `acr_values`, and held as
  they are. `acr` says how strongly the person signed in (see the
  [glossary](glossary.md#acr)).
- A `sub` with a value holds the session to that person, as `id_token_hint` does.

The cost is precision. Asking for `email` under `userinfo` alone puts it in the ID
token too, because the scope does. An application gets what its scopes would give
it, not exactly what it listed.

OpenID Connect Core is not among the specifications held in this repository. So
this page describes what Signari does, and not what the specification says. The
OpenID Foundation's conformance suite is what would hold Signari to the text. See
[the conformance notes](../deploy/conformance/README.md) for what has been run.
