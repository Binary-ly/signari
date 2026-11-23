# Glossary

## Introduction

Identity has a lot of vocabulary, and much of it is abbreviations. This page
explains every term these pages use, in one or two plain sentences, and links to
where it is explained in full.

Each entry is marked in one of two ways:

- **General term**: a word the whole industry uses. You can search the web for it
  and find the same meaning.
- **Signari term**: a word with a meaning particular to Signari, or a name for one
  of its parts.

Where Acme appears, it is the example company used throughout these pages: its
wiki, chat application and VPN all sign people in through Signari.

## A

### Access token

**General term.** A short-lived token an application sends to an API, to act for
the person who signed in. Signari's last five minutes by default. See [how
Signari works](how-signari-works.md#access-token).

### ACR

**General term.** Authentication Context Class Reference: a value saying how
strongly someone signed in, such as with one factor or with two. See [sign-in
flows](flows.md).

### Admin API

**Signari term.** The set of web addresses through which every change to
Signari's configuration is made. The console, the command line and your own
automation all use it. See [the Admin API](admin-api.md).

### Admin token

**Signari term.** A credential for the Admin API. Its "scopes" say what it may
change, and it expires after ninety days unless you say otherwise. See [Admin API
access](admin-tokens.md).

### AGPL

**General term.** The GNU Affero General Public License, Signari's licence. If you
change Signari and let others use your changed version over a network, you must
offer them its source. Applications that sign in through Signari are not affected.

### Application

**Signari term.** In these pages, anything that sends people to Signari to sign
in, such as Acme's wiki. The protocols call it a "client". See [how Signari
works](how-signari-works.md#application).

### Assertion

**General term.** In SAML, the signed XML document that says who signed in. It
does the job an ID token does in OpenID Connect. See [SAML 2.0](saml.md).

### Audit trail

**Signari term.** Signari's record of sign-ins and changes. Each entry is linked to
the one before it, so a removed or edited entry shows. See [audit
export](audit-export.md).

### Authorization code

**General term.** A one-time code Signari gives the browser at the end of a
sign-in, which the application swaps for tokens. Signari's codes work once,
within 60 seconds. See [what happens when you click Sign
in](first-application.md#what-happens-when-you-click-sign-in).

### AuthZEN

**General term.** An OpenID Foundation standard for asking a service "may this
person do this to that?", and getting a yes or a no. See [the authorization
layer](authorization.md).

## B

### Back-channel logout

**General term.** Signari telling an application directly, from server to server,
that a person's session has ended. See [logout](logout.md).

### Bind

**General term.** In LDAP, a request that checks a name and a password. An
application that "binds" to Signari asks it whether a password is right. See
[LDAP](ldap.md).

### Bootstrap

**Signari term.** The first run of a new deployment, `signari bootstrap`. It makes
the instance, the organisation, and a one-time link for the first person. See
[every command](cli.md#instances-organisations-users).

### Brand

**Signari term.** The product name, logo, support link and colours on the pages
people see. See [brands](brands.md).

## C

### CAEP

**General term.** Continuous Access Evaluation Profile: security events, such as
"this session was ended", sent to applications as they happen. It travels over
Shared Signals. See [Shared Signals and CAEP](ssf-caep.md).

### CIBA

**General term.** Client-Initiated Backchannel Authentication. An application asks
Signari to confirm a person who is not in front of it, and that person approves on
their own device. See [backchannel authentication](ciba.md).

### Claim

**General term.** One statement about a person inside a token, such as
`"email": "ada@example.com"`. See [how Signari
works](how-signari-works.md#id-token).

### Client

**General term.** The protocols' word for an application. Signari's commands use
it, as in `signari client create`. See [how Signari
works](how-signari-works.md#application).

### Client credentials

**General term.** The way a program with no person present gets an access token
for itself, by proving who it is. See [client
authentication](client-authentication.md).

### Client ID

**General term.** The name an application gives when it talks to Signari, such as
`wiki`. See [how Signari works](how-signari-works.md#application).

### Client secret

**General term.** A password that an application on a server uses to prove it is
itself. Signari shows it once, when the application is registered. See [your
first application](first-application.md#5-register-an-application-of-your-own).

### Confidential client

**General term.** An application that runs on a server and can keep a secret, such
as Acme's wiki. See [how Signari works](how-signari-works.md#application).

### Configuration as code

**Signari term.** Keeping an organisation's applications, groups and providers in a
file. `signari plan` shows what the file would change, and `signari apply` makes
the change. See [configuration as code](config-as-code.md).

### Consent

**General term.** The screen that asks a person whether an application may receive
information about them. See [how Signari
works](how-signari-works.md#scopes-claims-and-consent).

### Console

**Signari term.** Signari's web interface for administrators. It reads through
views limited to one organisation, and makes changes through the Admin API. See
[configuration screens in the console](console-configuration.md).

### CORS

**General term.** Cross-Origin Resource Sharing: the browser's rule for whether a
page on one site may call an address on another. See [CORS](cors.md).

### CSRF

**General term.** Cross-site request forgery: a page on another site making your
browser submit a form to Signari. Signari's forms carry a token, held in a cookie,
to refuse that. See [troubleshooting](troubleshooting.md#your-sign-in-session-expired-please-try-again).

## D

### Deactivate

**Signari term.** Turning a person's account off. Signari refuses them at every
application from the next request, and keeps their account. See [how Signari
works](how-signari-works.md#person-and-group).

### Device flow

**General term.** How a device with no browser, such as a television, signs
someone in. It shows a short code, which the person types on another device. See
[device authorization grant](device-flow.md).

### Discovery document

**General term.** A page at `/.well-known/openid-configuration` that lists an
identity provider's addresses and what it supports. Applications read it first.
See [quickstart: a Go application](quickstart-go.md).

### Doctor

**Signari term.** `signari doctor`, the command that checks whether a deployment
is sound, and says how to fix each problem it finds. See [doctor](doctor.md).

### DPoP

**General term.** Demonstrating Proof of Possession. It ties a token to a key the
application holds, so a stolen token is useless without that key. See
[DPoP](dpop.md).

### DSN

**General term.** Data source name: the connection string for a database, such as
`postgres://signari_engine@db.example.com/signari`. Signari reads it from
`SIGNARI_DSN`. See [configuration](configuration.md).

## E

### EAP-TLS

**General term.** A way for a device to join wifi or a network by showing a
certificate instead of a password. Signari checks it over RADIUS. See
[EAP-TLS](eap-tls.md).

### EdDSA

**General term.** A modern signature algorithm. Signari signs with it only for an
application set to use it, with `signari client set-alg`. See [every
command](cli.md#clients).

### Engine

**Signari term.** The Signari server itself: the program that serves the sign-in
pages and the protocols. The console is a separate program. See
[installation](installation.md).

### Erasure

**Signari term.** Removing a person by destroying the key their data was encrypted
with, so it stays unreadable even in old backups. See [erasing a
subject](erasure.md).

### ES256

**General term.** The signature algorithm Signari signs tokens with by default:
ECDSA on the P-256 curve, with SHA-256. See [key rotation](key-rotation.md).

## F

### FAPI 2.0

**General term.** A stricter security profile of OAuth, written for valuable APIs
such as banking. See [FAPI 2.0](fapi2.md).

### Federated sign-in

**General term.** Letting people sign in through another identity provider, such
as their company's existing one. See [federated sign-in
providers](social-login.md).

### First-party application

**Signari term.** An application your own organisation runs. Signari can skip the
consent screen for it. See [every command](cli.md#clients).

### Flow

**Signari term.** A sign-in flow: the ordered steps a person is asked for when
they sign in, such as a password and then a code. It is a file you can test. See
[sign-in flows](flows.md).

### Forward authentication

**General term.** A reverse proxy asking Signari about every request before it
passes the request to an application. It protects tools that have no sign-in of
their own. See [forward authentication](forward-auth.md).

## G

### Grant

**General term.** In OAuth, one of the ways of getting a token, such as with an
authorization code or a refresh token. It also means the permission a person gave
an application. See [grant management](grant-management.md).

### Group

**General term.** A set of people, such as `engineering`. Signari tells an
application about a group only when an administrator releases the group to it.
See [groups](groups.md).

## H

### HSM

**General term.** Hardware security module: a device that keeps signing keys
inside it, so they can be used but never copied out. Signari talks to one through
the PKCS#11 standard. See [signing keys in a hardware
module](signing-keys-in-a-module.md).

## I

### ID token

**General term.** The token that tells an application who signed in. It is a JWT,
and the application checks it before believing it. See [how Signari
works](how-signari-works.md#id-token).

### Identity provider

**General term.** A service that keeps a list of people and checks who they are,
so that other applications do not have to. Often written IdP. Signari is one. See
[what Signari is](introduction.md).

### Impersonation

**Signari term.** An administrator acting as another person, for support, in a
way that is visible and recorded. See [support access](impersonation.md).

### Instance

**Signari term.** One identity provider as the outside world sees it, named by its
issuer. See [how Signari works](how-signari-works.md#instance-and-issuer).

### Introspection

**General term.** An API asking Signari whether a token is still valid, and what it
says. See [opaque access tokens](opaque-access-tokens.md).

### Issuer

**General term.** The web address that every token from an identity provider
carries, such as `https://login.example.com`. Applications refuse tokens from any
other issuer. See [how Signari works](how-signari-works.md#instance-and-issuer).

## J

### JAR

**General term.** JWT-Secured Authorization Request: a sign-in request the
application signs, so nobody can change it on the way. See [signed authorization
requests](jar.md).

### JARM

**General term.** JWT-Secured Authorization Response Mode: Signari signs its answer
to a sign-in request. See [signed authorization responses](jarm.md).

### JWKS

**General term.** JSON Web Key Set: the list of public keys an identity provider
publishes, so anyone can check its signatures. Signari's is at `/oauth2/jwks`. See
[how Signari works](how-signari-works.md#signing-keys-and-the-root-key).

### JWT

**General term.** JSON Web Token: a standard shape for signed data. Anyone holding
one can read it, but only the signer can make one. See [how Signari
works](how-signari-works.md#tokens).

## K

### Kerberos

**General term.** How Windows domains and FreeIPA realms sign people in to their
computers. Signari accepts a Kerberos ticket from the browser through SPNEGO. See
[Kerberos](kerberos.md).

### Key rotation

**General term.** Replacing signing keys on a schedule. Signari publishes a new key
before it uses it, so applications learn it in advance. See [key
rotation](key-rotation.md).

### Keytab

**General term.** A file holding the Kerberos keys that a service uses to accept
tickets. See [Kerberos](kerberos.md).

## L

### LDAP

**General term.** Lightweight Directory Access Protocol: how older software checks
a username and password against a company directory. See [LDAP](ldap.md), and
[LDAP as a source](ldap-source.md) for reading an existing directory.

## M

### MFA

**General term.** Multi-factor authentication: proving who you are in two
different ways, such as a password and a code from your phone. See [sign-in
flows](flows.md).

### Migration

**Signari term.** A numbered change to the database's structure. A new release
brings its migrations, and `signari migrate up` applies them. See
[upgrading](upgrading.md).

### Mutual TLS

**General term.** An application proving who it is with a certificate, during the
encrypted connection itself. Often written mTLS. See [mutual-TLS client
authentication](mutual-tls.md).

## N

### Nonce

**General term.** A random value an application puts in its sign-in request and
expects back inside the ID token. It stops an old token being replayed. See [what
happens when you click Sign
in](first-application.md#what-happens-when-you-click-sign-in).

## O

### OAuth 2.0

**General term.** A standard way for an application to get permission to act for a
person, without seeing their password. See [which protocol do I
need?](protocols-explained.md#openid-connect-and-oauth-20).

### OIDC

**General term.** OpenID Connect: the layer on top of OAuth 2.0 that tells an
application who signed in. It is the protocol most new applications use. See
[which protocol do I
need?](protocols-explained.md#openid-connect-and-oauth-20).

### OID4VCI

**General term.** OpenID for Verifiable Credential Issuance: putting a digital
credential, such as a staff card, into a person's wallet app. See
[OID4VCI](oid4vci.md).

### OpenID Federation

**General term.** A way for organisations to trust each other's servers through a
shared authority, instead of registering each one by hand. See [OpenID
Federation](openid-federation.md).

### OpenID4VP

**General term.** OpenID for Verifiable Presentations: signing in by showing a
credential from a wallet app. See [signing in with a wallet](wallet-sign-in.md).

### Organisation

**Signari term.** A group of people and the applications they use, kept apart from
every other organisation. Acme is one. See [how Signari
works](how-signari-works.md#organisation).

### Outpost

**Signari term.** A Signari program that serves LDAP, RADIUS or forward
authentication somewhere that must not reach the database, such as a branch
office. See [outposts](outposts.md).

## P

### PAR

**General term.** Pushed Authorization Requests: the application sends its
sign-in request to Signari directly first, and the browser carries only a
reference to it. See [pushed authorization requests](par.md).

### Passkey

**General term.** A sign-in credential kept on a device or in a password manager,
and unlocked with a fingerprint, a face or a PIN. It replaces a password. See
[WebAuthn Level 3 signals](passkey-signals.md).

### PKCE

**General term.** Proof Key for Code Exchange. The application sends a hash of a
secret value when sign-in starts, and the value itself when it collects its
tokens. A stolen authorization code is then useless. See [what happens when you
click Sign in](first-application.md#what-happens-when-you-click-sign-in).

### Policy

**Signari term.** Access rules, such as "only engineering may use this
application", kept as a file you can review and test. See [access
policy](policy.md).

### Provider

**Signari term.** A service you run that Signari calls at a named point, such as
when it decides whether to allow a sign-in. See [extending the
engine](extensibility.md).

### Provisioning

**General term.** Creating, changing and removing accounts in other applications
automatically, as people join, move and leave. See [provisioning users
out](provisioning.md).

### Public client

**General term.** An application that runs on a person's own device, such as a
mobile app, and so cannot keep a secret. It proves itself with PKCE alone. See
[how Signari works](how-signari-works.md#application).

## R

### RADIUS

**General term.** Remote Authentication Dial-In User Service: how VPNs, wifi and
network equipment ask whether someone may connect. Acme's VPN uses it. See
[RADIUS](radius.md).

### Redirect URI

**General term.** The exact address Signari sends the browser back to after
sign-in. It must match a registered one character for character. See [how Signari
works](how-signari-works.md#application).

### Refresh token

**General term.** A token that lets an application get a new access token without
sending the person to sign in again. Signari's last 30 days, and each one works
once. See [how Signari works](how-signari-works.md#refresh-token).

### Relying party

**General term.** Another name for an application that relies on an identity
provider to sign people in. These pages say "application". See [how Signari
works](how-signari-works.md#application).

### RLS

**General term.** Row-level security: a PostgreSQL rule that shows each
connection only the rows it is allowed to see. Signari uses it to keep
organisations apart. See [how Signari
works](how-signari-works.md#how-the-database-keeps-organisations-apart).

### Root key

**Signari term.** The secret that encrypts every sensitive value Signari stores,
kept outside the database. Lose it, and those values are gone for good. See
[backup and restore](runbook-backup-restore.md).

### RS256

**General term.** An older, widely supported signature algorithm, RSA with
SHA-256. Signari publishes RS256 keys beside its ES256 ones, for applications that
need them. See [key rotation](key-rotation.md).

## S

### SAML

**General term.** Security Assertion Markup Language: an older, widely used way
for business software to sign people in, with signed XML. Acme's chat application
uses it. See [SAML 2.0](saml.md).

### Scope

**General term.** A short name an application asks for, such as `email`, which
brings certain claims with it. See [how Signari
works](how-signari-works.md#scopes-claims-and-consent).

### SCIM

**General term.** System for Cross-domain Identity Management: a standard for
creating and removing accounts in other applications automatically. See [SCIM
provisioning](scim.md).

### SD-JWT

**General term.** Selective Disclosure JWT: a signed credential whose holder can
reveal some of its claims and keep others hidden. See [OID4VCI](oid4vci.md).

### Service provider

**General term.** SAML's name for an application. See [SAML 2.0](saml.md).

### Session

**General term.** How Signari remembers that someone has signed in, through a
cookie in their browser. It is what makes single sign-on work. See [how Signari
works](how-signari-works.md#session).

### Shared Signals

**General term.** A standard for sending security events between services as they
happen. CAEP is one kind of event it carries. Often written SSF. See [Shared
Signals and CAEP](ssf-caep.md).

### Signing key

**General term.** The private key an identity provider signs its tokens with.
Applications check the signatures with the matching public key. See [how Signari
works](how-signari-works.md#signing-keys-and-the-root-key).

### Single sign-on

**General term.** Signing in once and reaching every application, without a
password for each. Often written SSO. See [what Signari is](introduction.md).

### SPNEGO

**General term.** Simple and Protected GSS-API Negotiation Mechanism. It is how a
browser hands a Kerberos ticket to a website, so the person signs in without a
password. See [Kerberos](kerberos.md).

### State

**General term.** A random value an application sends when sign-in starts, and
checks when the browser returns. It makes sure the application accepts only
sign-ins it began. See [what happens when you click Sign
in](first-application.md#what-happens-when-you-click-sign-in).

### Subject

**General term.** The identifier a token uses for a person, in its `sub` claim. It
does not change when their email address does. See [pairwise
subjects](pairwise-subjects.md).

### Superuser

**General term.** A PostgreSQL role that may do anything, and that row-level
security does not apply to. Signari's server must never run as one. See [how
Signari works](how-signari-works.md#how-the-database-keeps-organisations-apart).

## T

### Tenant

**General term.** Another word for an organisation, used by many products. See
[how Signari works](how-signari-works.md#organisation).

### Theme

**Signari term.** Your own versions of the HTML pages Signari shows during
sign-in. See [theming](theming.md).

### TLS

**General term.** Transport Layer Security: the encryption behind every `https://`
address. Signari serves sign-in only over it. See
[installation](installation.md).

### Token

**General term.** A short piece of text that Signari gives an application, such as
an ID token or an access token. See [how Signari
works](how-signari-works.md#tokens).

### TOTP

**General term.** Time-based one-time password: the six-digit code an
authenticator app shows, which changes every 30 seconds. See [TOTP
enrolment](totp-qr.md).

## U

### UMA

**General term.** User-Managed Access 2.0: a standard for letting a person share
something they own, such as a document, with someone else. See [UMA
2.0](uma.md).

### Userinfo

**General term.** An address, `/oauth2/userinfo`, where an application can ask for
the claims about the person who signed in, using its access token. See
[groups](groups.md).

## W

### WebAuthn

**General term.** The browser standard behind passkeys and security keys. See
[WebAuthn Level 3 signals](passkey-signals.md).

### WS-Federation

**General term.** An older Microsoft protocol for signing in, much like SAML.
Signari speaks it for applications that have not yet moved off it. See
[WS-Federation](ws-federation.md).
