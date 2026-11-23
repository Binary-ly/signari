# What Signari is

## Introduction

Imagine a company called Acme. Acme has a wiki, a chat application and a VPN. Each
of them needs to know who you are before it lets you in.

Without help, each application keeps its own list of people and passwords. Ada,
who works at Acme, has three passwords to remember. When she leaves the company,
someone has to remember to remove her from three places. If they forget one, Ada
can still read the wiki months after her last day.

An "identity provider" solves this. It is one service that keeps the list of
people and checks who they are. The wiki, the chat application and the VPN stop
asking for passwords. They send Ada to the identity provider instead, and believe
its answer. Ada signs in once and reaches all three. When she leaves, one change
stops the identity provider vouching for her anywhere.

Signari is an identity provider that you run yourself. It is one program and one
PostgreSQL database.

## What Signari does

Signari keeps the people of your organisation, their groups and how they sign in.
When an application asks "who is this?", Signari answers in a form the
application can check for itself.

In practice, Signari:

- shows the sign-in page, and checks a password, a passkey or a code from an
  authenticator app;
- signs people in once for every application, which is called "single sign-on";
- tells each application who signed in, and which groups they belong to;
- refuses a person at every application from the moment an administrator
  deactivates them, and tells the applications that ask to be told;
- creates and removes accounts in other applications as people join and leave;
- keeps a record of who did what, linked so that an edit afterwards shows.

You can manage it from a web console, or from the `signari` command line. Other
programs can manage it too, through its Admin API: a set of web addresses they can
call.

## What Signari does not do

Signari is not a hosted service. You run it on your own server, and you are
responsible for that server, its database and its backups.

Signari decides who a person is and what they may reach. It does not store your
applications' own data, and it does not replace the permissions inside each
application. The wiki still decides who may edit which page.

> [!NOTE]
> Signari is at its first release, v0.1.0. It is tested, but not yet certified or
> independently audited. Read the [security review](security-review-asvs.md)
> before you trust it with anything that matters.

## What Signari speaks

Applications and devices talk to an identity provider in a few standard
languages, called "protocols". Signari speaks these:

| Protocol | In plain words |
|---|---|
| OpenID Connect (OIDC) and OAuth 2.0 | How most modern web and mobile applications sign people in and call APIs |
| SAML 2.0 | An older, widely used way for business software to sign people in |
| WS-Federation | An older Microsoft way of signing in, kept for applications not yet moved off it |
| LDAP | How older software checks a username and password against a company directory |
| RADIUS | How VPNs, wifi and network equipment check who may connect |
| SCIM | How accounts are created and removed in other applications automatically |
| Kerberos | How people whose computers are signed in to a Windows domain sign in to web applications without a password |

It also speaks several newer standards, for digital credentials, federations of
organisations and sharing security events. [Which protocol do I
need?](protocols-explained.md) explains each one, and tells you which to choose
for each kind of application.

## What you need

To run Signari, you need:

- a Linux server, or a computer with Docker, to run it on;
- PostgreSQL 16 or later, for its database;
- a web address for people to sign in at, such as `https://login.example.com`;
- a TLS certificate for that address, because Signari serves sign-in only over
  HTTPS.

To try it on your own computer first, you need Docker and a copy of the Signari
repository. [Your first application](first-application.md) starts everything for
you.

## Next steps

- [Install Signari](installation.md) on a server.
- [Sign in to your first application](first-application.md) on your own
  computer.
- [Learn how Signari works](how-signari-works.md): the handful of ideas the rest
  of these pages build on.
- [Look up a word](glossary.md) you have not met before.
