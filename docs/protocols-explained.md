# Which protocol do I need?

## Introduction

Every application has to ask an identity provider the same question: who is this
person? The way it asks is its "protocol". Different kinds of software grew up
with different protocols, so an identity provider has to speak several.

You rarely choose the protocol yourself. The application has usually chosen
already, and its settings page tells you which one it speaks. Your job is to
recognise it, then register the application in Signari the matching way.

At Acme, the wiki speaks OpenID Connect, and the chat application speaks Security
Assertion Markup Language (SAML). The VPN speaks Remote Authentication Dial-In User
Service (RADIUS). Ada signs in to all three with the same account.

## The short answer

Find the row that describes your application or device:

| Your application or device is… | Use | Guide |
|---|---|---|
| A web application you are writing yourself | OpenID Connect | [Your first application](first-application.md), then the framework guides such as [Go](quickstart-go.md) |
| Software whose settings mention "OpenID Connect (OIDC)" or "OAuth" | OpenID Connect | [Your first application](first-application.md) |
| A mobile application, or a web page that runs entirely in the browser | OpenID Connect, as a public client | [Quickstart: a Go application](quickstart-go.md), which covers the public-client case |
| A program that calls an API with no person present | OAuth 2.0 client credentials | [Client authentication](client-authentication.md) |
| A television, a command-line tool or another device with no browser | The OAuth device flow | [Device authorization grant](device-flow.md) |
| Business software whose settings mention "SAML" | SAML 2.0 | [SAML 2.0](saml.md) |
| SharePoint, or an older .NET application federated to ADFS | WS-Federation | [WS-Federation](ws-federation.md) |
| Software that asks for a Lightweight Directory Access Protocol (LDAP) server, a "bind DN" or a "base DN" | LDAP | [LDAP](ldap.md) |
| A VPN, a wifi controller or a network switch | RADIUS | [RADIUS](radius.md), and [EAP-TLS](eap-tls.md) for certificates |
| Software that should have accounts created and removed for you | System for Cross-domain Identity Management (SCIM) | [SCIM provisioning](scim.md) |
| Computers already signed in to a Windows domain or FreeIPA realm | Kerberos | [Kerberos](kerberos.md) |
| An internal tool with no sign-in of its own | Forward authentication, through your reverse proxy | [Forward authentication](forward-auth.md) |
| A Windows or Linux sign-in screen, or a kiosk | An outpost | [Desktop and workstation sign-in](desktop-login.md) |

If the application speaks more than one, choose OpenID Connect. It is the most
modern of the ways to sign in, and the OpenID Foundation's conformance plans run
against Signari whole in its continuous integration.

## OpenID Connect and OAuth 2.0

OAuth 2.0 is a way for an application to get permission to act for a person,
without ever seeing that person's password. OpenID Connect (OIDC) is built on top
of it, and adds the part that says who the person is.

The application sends the person's browser to Signari. Signari checks who they
are and sends the browser back with a short-lived code. The application swaps the
code for tokens, including an ID token that names the person. [What happens when
you click Sign in](first-application.md#what-happens-when-you-click-sign-in)
follows each step.

Use it for any new web or mobile application. Acme's wiki uses it.

## SAML 2.0

SAML is an older way for business software to sign people in. The idea is the
same as OpenID Connect: the browser goes to Signari and comes back with proof.
The proof is a signed XML document, called an "assertion", instead of a token.

Many established business applications offer SAML and nothing newer. Acme's chat
application is one of them. In SAML's words, Signari is the "identity provider"
and the application is a "service provider". See [SAML 2.0](saml.md).

## WS-Federation

WS-Federation is an older Microsoft protocol that works much like SAML. Signari
speaks it so that applications built on it, such as SharePoint, keep working
while an organisation moves to Signari. Do not choose it for anything new. See
[WS-Federation](ws-federation.md).

## LDAP

LDAP is how older software checks a username and password against a company
directory. The application connects to Signari and asks it directly whether a
username and password are right. This is called a "bind". No browser is involved,
and Ada types her password into the application itself.

Use it only for software that offers nothing else. Signari's LDAP listener is off
until you turn it on. See [LDAP](ldap.md).

> [!NOTE]
> Signari can also read people from an existing LDAP directory, such as Active
> Directory. That is the opposite direction, and it is described in [LDAP as a
> source](ldap-source.md).

## RADIUS

RADIUS is how network equipment asks whether someone may connect. A VPN, a wifi
controller or a switch sends Signari the person's username and password, and
Signari answers yes or no. A second factor can follow the password.

Acme's VPN uses it. With EAP-TLS, a device can prove itself with a certificate
instead of a password, which suits company laptops on the office wifi. See
[RADIUS](radius.md) and [EAP-TLS](eap-tls.md).

## SCIM

SCIM is not a way to sign in. It is a way to keep accounts in step. When Ada
joins Acme, SCIM creates her account in the applications that keep a copy of
their own. When she leaves, SCIM deactivates it there too.

Signari can send SCIM to applications, and receive it from another system that
holds your people. See [SCIM provisioning](scim.md) and [receiving
SCIM](scim-source.md).

## Kerberos

Kerberos is how Windows domains and FreeIPA realms sign people in to their
computers. A person signed in that way already holds a Kerberos "ticket". Their
browser shows that ticket to Signari through Simple and Protected GSS-API
Negotiation Mechanism (SPNEGO). They sign in with no password and no prompt. See
[Kerberos](kerberos.md).

## Applications that speak none of these

Some internal tools have no sign-in at all, or a weak one of their own. You can
still put Signari in front of them. Your reverse proxy, such as nginx, asks
Signari about every request before passing it on. Signari answers whether the
person is signed in and allowed. See [forward authentication](forward-auth.md).

An "outpost" runs this, or LDAP or RADIUS, in a place that must not reach your
database, such as a branch office. See [outposts](outposts.md).

## When your people already live somewhere else

Your organisation may already keep its people in another system. Signari can
work with that system instead of replacing it:

| Your people are in… | Signari can… | Guide |
|---|---|---|
| Google Workspace, Microsoft Entra ID or an LDAP directory | Copy them in, and keep them in step | [Directory sync](directory-sync.md) |
| Another identity provider that speaks OpenID Connect | Let people sign in through it | [Federated sign-in providers](social-login.md) |
| Another identity provider that speaks SAML | Let people sign in through it | [SAML as a source](saml-source.md) |
| A system that sends SCIM | Receive them | [Receiving SCIM](scim-source.md) |

## Newer standards

Signari also speaks several newer standards. You need these only when an
application or a partner asks for one by name:

| Standard | What it is for | Guide |
|---|---|---|
| Client-Initiated Backchannel Authentication (CIBA) | Approving a request on your phone, started by someone else, such as a call centre | [Backchannel authentication](ciba.md) |
| OpenID for Verifiable Credential Issuance (OID4VCI) | Issuing digital credentials into a person's wallet app | [OID4VCI](oid4vci.md) |
| OpenID for Verifiable Presentations (OpenID4VP) | Signing in by showing a credential from a wallet app | [Signing in with a wallet](wallet-sign-in.md) |
| OpenID Federation | Trusting other organisations' servers through a shared authority | [OpenID Federation](openid-federation.md) |
| User-Managed Access (UMA) 2.0 | Letting a person share their own resources with someone else | [UMA 2.0](uma.md) |
| AuthZEN | Asking "may this person do this?" through a standard API | [The authorization layer](authorization.md) |
| Shared Signals and Continuous Access Evaluation Profile (CAEP) | Telling applications at once when a session or an account changes | [Shared Signals and CAEP](ssf-caep.md) |

[Emerging standards](emerging-standards.md) lists every draft standard Signari
implements, with the status of each.

## Next steps

- [Your first application](first-application.md) signs you in with OpenID
  Connect on your own computer.
- [How Signari works](how-signari-works.md) explains applications, tokens and
  sessions.
- The [glossary](glossary.md) explains each term on this page in one line.
