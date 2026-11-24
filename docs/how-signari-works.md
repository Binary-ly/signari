# How Signari works

## Introduction

The rest of these pages use a small number of ideas over and over. This page
explains each one in plain words, using the same example company throughout.

Acme has a wiki, a chat application and a VPN. Ada works at Acme. Acme runs
Signari at `https://login.example.com`, and all three applications send Ada there
to sign in.

You do not need to read this page before your [first
application](first-application.md). Come back to it when a word on another page
is new to you, or look the word up in the [glossary](glossary.md).

## Instance and issuer

An "instance" is one identity provider as the outside world sees it. Its most
important property is its "issuer": the web address every token it creates
carries, and every application checks. Acme's issuer is
`https://login.example.com`.

Applications compare the issuer character by character. To them,
`https://login.example.com/` with a trailing slash is a different issuer, and
they refuse its tokens. Choose the issuer once, and write it the same way
everywhere.

A running Signari server serves one instance unless you name more. When the
database holds more than one, `SIGNARI_ISSUER` says which one to serve.
`SIGNARI_ADDITIONAL_ISSUERS` can name others to serve beside it, each at its own
host. See [several instances in one
process](configuration.md#several-instances-in-one-process).

## Organisation

An "organisation" is a group of people and the applications they use, kept
apart from every other organisation. Acme is one organisation. Some identity
products call this a "tenant" or a "realm".

Most deployments have one organisation. If you serve several companies from one
Signari, each gets its own, and none can see another's people.

## Application

An "application" is anything that sends people to Signari to sign in, such as
Acme's wiki. The protocols call an application a "client", and so do Signari's
commands, such as `signari client create`. The two words mean the same thing.

Each application has:

- a "client ID", the name it gives when it talks to Signari, such as `wiki`;
- one or more "redirect URIs", the exact addresses Signari may send the browser
  back to after sign-in;
- a "client secret", if it can keep one.

An application that runs on a server, such as the wiki, can keep a secret.
It is a "confidential client". An application that runs on a person's own device
cannot keep a secret from that person. A mobile application is one, and so is a
page of JavaScript. It is a "public client", and it proves itself another way, with
Proof Key for Code Exchange ([PKCE](glossary.md#pkce)).

Signari matches a redirect URI exactly: the scheme, host, port and path must all
be the same. This stops anyone from having Ada sent to an address the wiki does
not own.

## Person and group

A "person" is someone who can sign in, such as Ada. Signari keeps their email
address, their name, and how they prove who they are: a password, a passkey, or
an authenticator app.

A "group" is a set of people, such as `engineering`. Groups can sit inside other
groups. An application learns about a group only when an administrator releases
that group to it. The chat application never hears of groups it has no use for.
See [groups](groups.md).

When Ada leaves, an administrator deactivates her. Signari checks this on every
request and never remembers an earlier yes, so it refuses her from the next one.
It also ends her sessions, and tells the applications that listen. An
application's own session, or an access token it checks itself, lasts until it
ends or expires.

## Signing in

When Ada opens the wiki, the wiki does not ask for her password. It sends her
browser to Signari. Signari checks who she is, then sends her back to the wiki
with proof. [What happens when you click Sign
in](first-application.md#what-happens-when-you-click-sign-in) follows this one
step at a time.

A "sign-in flow" sets what Signari asks Ada for. It is an ordered list of steps,
such as a password and then a code from her authenticator app. A flow is a file
you can test before you use it. See [sign-in flows](flows.md).

## Session

Once Ada has signed in, Signari remembers her with a "session". It is held in a
cookie in her browser, and recorded in the database.

The session is what makes single sign-on work. When Ada opens the chat
application after the wiki, Signari sees her session and does not ask for her
password again.

A session lasts 12 hours by default. An administrator can change that, and can
also end a session early, for example when Ada reports a lost laptop. Each
application usually keeps a session of its own as well, for as long as it
chooses.

## Tokens

A "token" is a short piece of text that Signari gives an application. Signari's ID
tokens are "JWTs" (JSON Web Tokens). So are its access tokens, unless an
administrator gives an application opaque ones with
`signari client set-token-format`. A JWT is signed data: anyone holding it can read it,
but only Signari can make it. That is how an application can check a token is
genuine without asking Signari.

There are three kinds, and each has one job.

### ID token

The "ID token" tells the application who signed in. It holds "claims", which are
statements about Ada, such as `"email": "ada@example.com"`. The application checks
the token's signature, its issuer, who it was issued to and when it expires.
Then it treats Ada as signed in.

### Access token

The "access token" lets an application call an API on Ada's behalf, such as the
chat application calling Acme's calendar service. The API checks the token, not
Ada's password. Access tokens last five minutes by default, so a stolen one is
soon useless.

### Refresh token

The "refresh token" lets an application get a new access token without sending
Ada to sign in again. Each time it is used, Signari replaces it with a new one,
and a used one cannot be used again. Refresh tokens last 30 days by default.

## Scopes, claims and consent

An application asks for what it needs with "scopes", short names such as `email`
or `profile`. Each scope brings claims with it. The `email` scope brings Ada's
email address.

Before an application receives anything, Signari may show a "consent" screen
that asks Ada to allow it. You can skip that screen for an application your own
organisation runs, with `signari client set-first-party` ([every
command](cli.md#clients)). The parameters an application can send are in
[authorization request parameters](oidc-parameters.md).

## Signing keys and the root key

Signari signs every token with a private "signing key". It publishes the matching
public keys at `https://login.example.com/oauth2/jwks`, so any application can
check a signature without asking Signari. It signs with ES256 by default, and
also publishes RS256 keys for applications that need them.

Signing keys change over time, a process called "rotation". A new key is
published before it is used, so applications learn it in advance. See [key
rotation](key-rotation.md).

The private signing keys are stored in the database, encrypted with the "root
key". The root key is 32 random bytes that you keep outside the database, in an
environment variable or a file. Without it, the secrets sealed in the database
cannot be read. That is the point: a stolen database backup does not reveal the
signing keys, or anything else sealed with the root key. It also means that
losing the root key loses every one of those secrets.

> [!WARNING]
> Back up the root key separately from the database, and keep both. A database
> restored without its root key cannot sign a single token. See [backup and
> restore](runbook-backup-restore.md).

## The console and the Admin API

The "console" is Signari's web interface for administrators. It shows people,
applications, groups and settings, and lets you change them.

The "Admin API" is a set of web addresses for making changes. The console makes
its changes through it, and so can your own automation. Most `signari` commands
write to the database directly instead. Some go through the Admin API when given
`-admin-url`, and `signari api` sends it any request. It listens on its own
address, separate from the sign-in pages, so you can keep it
on a private network. Each caller needs a token that says what it may change. See
[the Admin API](admin-api.md).

You can also keep an organisation's applications and groups in a file.
`signari plan` shows what the file would change, and `signari apply` makes the
change. See [configuration as code](config-as-code.md).

## How the database keeps organisations apart

Signari keeps everything in one PostgreSQL database. The database itself, not
only Signari's code, keeps organisations apart.

Every table that holds an organisation's data has a "row-level security" rule.
The rule shows a connection only the rows of the organisation it has named. A
connection that names no organisation sees no rows at all.

Different parts of Signari connect as different database roles:

1. The engine, Signari's server program, connects as `signari_engine`. Migration
   0018 lets this one role see every organisation, because it must find an
   application before it knows which organisation the application belongs to.
2. The console connects as `signari_admin`. It has no access to the engine's
   tables at all. It reads through views that apply the rule above, so it sees
   only the organisation it is working on.
3. A PostgreSQL superuser ignores row-level security entirely. Signari needs one
   to create its roles, and a backup needs one, because a backup must read every
   organisation. The engine itself never needs one.

> [!WARNING]
> Never run the engine as a PostgreSQL superuser. Row-level security does not
> apply to a superuser, so the database would stop keeping organisations apart.
> Run the engine as `signari_engine`.

## Next steps

- [Which protocol do I need?](protocols-explained.md) explains how each kind of
  application talks to Signari.
- [Your first application](first-application.md) shows a sign-in from start to
  finish.
- The [glossary](glossary.md) lists every term these pages use.
