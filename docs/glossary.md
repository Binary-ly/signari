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

### AAGUID

**General term.** A 128-bit identifier for a model of passkey or security key,
short for Authenticator Attestation Globally Unique Identifier. See
[passkeys](passkey-signals.md).

### AAL

**General term.** Authenticator assurance level: NIST's measure, from 1 to 3, of
how strongly a sign-in proves who someone is. See [the NIST SP 800-63B
review](security-review-nist-800-63b.md).

### Access token

**General term.** A short-lived token an application sends to an API, to act for
the person who signed in. Signari's last five minutes by default. See [how
Signari works](how-signari-works.md#access-token).

### Access-Accept

**General term.** The RADIUS answer that lets a device connect. See
[RADIUS](radius.md).

### Access-Challenge

**General term.** The RADIUS answer that asks the device for something more,
such as a one-time code, before it decides. See [RADIUS](radius.md).

### ACR

**General term.** Authentication Context Class Reference: a value saying how
strongly someone signed in, such as with one factor or with two. See [sign-in
flows](flows.md).

### ACS URL

**General term.** The address on a SAML application that receives the assertion,
short for Assertion Consumer Service URL. Signari sends assertions only to a
registered one. See [SAML 2.0](saml.md).

### `act` claim

**General term.** The claim in an exchanged token that names who is acting on the
subject's behalf, from RFC 8693. See [support access](impersonation.md).

### Admin API

**Signari term.** The set of web addresses through which every change to
Signari's configuration is made. The console, the command line and your own
automation all use it. See [the Admin API](admin-api.md).

### Admin token

**Signari term.** A credential for the Admin API. Its "scopes" say what it may
change, and it expires after ninety days unless you say otherwise. See [Admin API
access](admin-tokens.md).

### AGPL

**General term.** GNU Affero General Public License: Signari's licence. If you
change Signari and let others use your changed version over a network, you must
offer them its source. Applications that sign in through Signari are not affected.

### AMR

**General term.** Authentication Methods References: the `amr` claim, which lists
how someone signed in, such as `pwd` and `otp`. See [sign-in flows](flows.md).

### Application

**Signari term.** In these pages, anything that sends people to Signari to sign
in, such as Acme's wiki. The protocols call it a "client". See [how Signari
works](how-signari-works.md#application).

### ASN

**General term.** Autonomous system number: the number of the network an IP
address belongs to, such as an internet provider's. See [access
policy](policy.md).

### Assertion

**General term.** In SAML, the signed XML document that says who signed in. It
does the job an ID token does in OpenID Connect. See [SAML 2.0](saml.md).

### Attestation

**General term.** A signed statement about where a key or an application comes
from, such as "this key is held in hardware". See [proving an application is
genuine](attestation-based-client-auth.md).

### Audience

**General term.** The `aud` claim: whom a token is for. A service refuses a token
whose audience is not itself. See [limiting which APIs a token
reaches](resource-indicators.md).

### Audit checkpoint

**Signari term.** A recorded declaration that a broken audit chain is not vouched
for before this point, and that verification starts again here. It repairs
nothing. See [the audit chain fork](audit-chain-fork.md).

### Audit trail

**Signari term.** Signari's record of sign-ins and changes. Each entry is linked to
the one before it, so a removed or edited entry shows. See [audit
export](audit-export.md).

### Authorization code

**General term.** A one-time code Signari gives the browser at the end of a
sign-in, which the application swaps for tokens. Signari's codes work once,
within 60 seconds. See [what happens when you click Sign
in](first-application.md#what-happens-when-you-click-sign-in).

### Authorization server

**General term.** OAuth's name for the service that issues tokens. Signari is one.
See [how Signari works](how-signari-works.md#tokens).

### AuthZEN

**General term.** An OpenID Foundation standard for asking a service "may this
person do this to that?", and getting a yes or a no. See [the authorization
layer](authorization.md).

## B

### Back channel

**General term.** A message sent from one server straight to another, without the
person's browser. See [signing out](logout.md).

### Back-channel logout

**General term.** Signari telling an application directly, from server to server,
that a person's session has ended. See [signing out](logout.md).

### Bearer token

**General term.** A token that works for whoever holds it, like cash. A token tied
to a key, with DPoP or mutual TLS, does not. See [DPoP](dpop.md).

### Bind

**General term.** In LDAP, a request that checks a name and a password. An
application that "binds" to Signari asks it whether a password is right. See
[LDAP](ldap.md).

### Binding message

**General term.** A short text shown on the device that asked and on the person's
phone. It lets them tell that the two requests are the same one. See
[CIBA](ciba.md).

### Bootstrap

**Signari term.** The first run of a new deployment, `signari bootstrap`. It makes
the instance, the organisation, and a one-time link for the first person. See
[every command](cli.md#instances-organisations-users).

### Brand

**Signari term.** The product name, logo, support link and colours on the pages
people see. See [brands](brands.md).

### Break-glass account

**Signari term.** The console account that signs in with a password and a second
factor of its own, for when Signari itself is what is down. See [the
console](console-configuration.md).

### Breach corpus

**General term.** A list of passwords known from data breaches. With the breach
check on, Signari refuses a password found in one. See [password policy](password-policy.md).

## C

### CAEP

**General term.** Continuous Access Evaluation Profile: security events, such as
"this session was ended", sent to applications as they happen. It travels over
Shared Signals. See [Shared Signals and CAEP](ssf-caep.md).

### CAPTCHA

**General term.** A challenge on a page that a person can answer and a script
cannot, to slow down automated sign-in attempts. See [stopping scripted
sign-ins](captcha.md).

### CIBA

**General term.** Client-Initiated Backchannel Authentication. An application asks
Signari to confirm a person who is not in front of it, and that person approves on
their own device. See [backchannel authentication](ciba.md).

### CIDR

**General term.** Classless Inter-Domain Routing: a way of writing a range of IP
addresses, such as `10.0.0.0/8`. See [impossible travel](impossible-travel.md).

### Claim

**General term.** One statement about a person inside a token, such as
`"email": "ada@example.com"`. See [how Signari
works](how-signari-works.md#id-token).

### Claim mapper

**Signari term.** A rule that adds a claim to the tokens of one application, or of
every application, from what Signari knows about the person. See [configuration
as code](config-as-code.md).

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

### Client metadata document

**General term.** A JSON document an application publishes at its own URL, which
it then uses as its client ID. See [applications known by their
URL](client-metadata-documents.md).

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

### Configuration version

**Signari term.** A number every configuration change moves. The Admin API sends it
as an `ETag`, and refuses a write whose `If-Match` names an older one. See [the
Admin API](admin-api.md).

### Connection pooler

**General term.** A program, such as PgBouncer, that shares a few database
connections among many clients. In transaction mode, each transaction may run on
a different connection. See [connection pooling](connection-pooling.md).

### Consent

**General term.** The screen that asks a person whether an application may receive
information about them. See [how Signari
works](how-signari-works.md#scopes-claims-and-consent).

### Console

**Signari term.** Signari's web interface for administrators. It reads through
views limited to one organisation, and makes changes through the Admin API. See
[configuration screens in the console](console-configuration.md).

### Cookie

**General term.** A small value a website asks the browser to keep and send back.
Signari's session lives in one. See [how Signari works](how-signari-works.md#session).

### Core

**Signari term.** The Signari engine an outpost asks, over HTTP, whenever it needs
to check a password or look someone up. See [outposts](outposts.md).

### CORS

**General term.** Cross-Origin Resource Sharing: the browser's rule for whether a
page on one site may call an address on another. See [CORS](cors.md).

### Credential offer

**General term.** In OID4VCI, the link or QR code that invites a wallet to collect a
credential. See [issuing credentials to wallets](oid4vci.md).

### Crypto-shredding

**General term.** Making data unreadable by destroying the key it was encrypted
with, instead of finding and deleting every copy. See [erasing a
person](erasure.md).

### CSRF

**General term.** Cross-site request forgery: a page on another site making your
browser submit a form to Signari. Signari's forms carry a token, held in a cookie,
to refuse that. See [troubleshooting](troubleshooting.md#your-sign-in-session-expired-please-try-again).

### CWE

**General term.** Common Weakness Enumeration: the public catalogue of kinds of
software weakness, each with a number such as CWE-436. See [the CWE Top 25
review](security-review-cwe-top25.md).

## D

### Deactivate

**Signari term.** Turning a person's account off. Signari refuses them at every
application from the next request, and keeps their account. See [how Signari
works](how-signari-works.md#person-and-group).

### Device flow

**General term.** How a device with no browser, such as a television, signs
someone in. It shows a short code, which the person types on another device. See
[device authorization grant](device-flow.md).

### Device posture

**General term.** What is known about the device someone signs in from, such as
whether it is managed by the company and meets its rules. See [device
posture](device-posture.md).

### Directory sync

**Signari term.** Reading people and groups from a directory, such as Google
Workspace, Microsoft Entra ID or LDAP, and keeping Signari's accounts in step with
it. See [directory sync](directory-sync.md).

### Discovery document

**General term.** A page at `/.well-known/openid-configuration` that lists an
identity provider's addresses and what it supports. Applications read it first.
See [quickstart: a Go application](quickstart-go.md).

### DN

**General term.** The full name of an entry in an LDAP directory, such as
`uid=ada,ou=people,dc=example,dc=com`, short for distinguished name. The base DN
is the part every entry ends with. See [LDAP](ldap.md).

### Doctor

**Signari term.** `signari doctor`, the command that checks whether a deployment
is sound, and says how to fix each problem it finds. See [doctor](doctor.md).

### DPoP

**General term.** Demonstrating Proof of Possession. It ties a token to a key the
application holds, so a stolen token is useless without that key. See
[DPoP](dpop.md).

### Dry run

**General term.** Working out what a change would do, and showing it, without
making it. Signari's provisioning syncs are dry runs until you say otherwise. See
[provisioning](provisioning.md).

### DSN

**General term.** Data source name: the connection string for a database, such as
`postgres://signari_engine@db.example.com/signari`. Signari reads it from
`SIGNARI_DSN`. See [configuration](configuration.md).

### Dwell

**Signari term.** How long a signing key stays published after it stops signing,
so tokens it signed can still be checked. See [rotating signing
keys](key-rotation.md).

## E

### EAP-TLS

**General term.** A way for a device to join wifi or a network by showing a
certificate instead of a password. Signari checks it over RADIUS. See
[EAP-TLS](eap-tls.md).

### ECH

**General term.** Encrypted Client Hello: a TLS extension that hides which site a
browser is connecting to from anyone watching the network. See [Encrypted Client
Hello](encrypted-client-hello.md).

### EdDSA

**General term.** A modern signature algorithm. Signari signs with it only for an
application set to use it, with `signari client set-alg`. See [every
command](cli.md#clients).

### Engine

**Signari term.** The Signari server itself: the program that serves the sign-in
pages and the protocols. The console is a separate program. See
[installation](installation.md).

### Entity Configuration

**General term.** In OpenID Federation, the signed document an entity publishes
about itself, with its keys, its metadata and the authorities above it. See [OpenID
Federation](openid-federation.md).

### Entity ID

**General term.** The name a SAML application or identity provider gives itself,
usually a URL. See [SAML 2.0](saml.md).

### Erasure

**Signari term.** Removing a person by destroying the key their data was encrypted
with, so it stays unreadable even in old backups. See [erasing a
person](erasure.md).

### ES256

**General term.** The signature algorithm Signari signs tokens with by default:
ECDSA on the P-256 curve, with SHA-256. See [key rotation](key-rotation.md).

### Event subscription

**Signari term.** A URL of yours that Signari posts chosen events to, each one
signed, also called a webhook. See [event subscriptions](events.md).

### External factor

**Signari term.** A sign-in step that Signari hands to your own service, which
answers whether the person passed it. See [steps answered by your own
service](external-factors.md).

## F

### Fail closed and fail open

**General term.** What a check does when it cannot get an answer. Failing closed
refuses, and failing open allows. See [extending Signari with your own
service](extensibility.md).

### FAPI 2.0

**General term.** A stricter security profile of OAuth, written for valuable APIs
such as banking. See [FAPI 2.0](fapi2.md).

### Federated sign-in

**General term.** Letting people sign in through another identity provider, such
as their company's existing one. See [federated sign-in
providers](social-login.md).

### FIPS 140-3

**General term.** The US government's standard for cryptographic modules. A
program that must meet it uses only the algorithms a validated module approves.
See [running under FIPS 140-3](fips.md).

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

### Front channel

**General term.** A message that travels through the person's browser, such as a
redirect or a hidden frame. See [signing out](logout.md).

### Fuzzing

**General term.** Testing code by feeding it large amounts of random and malformed
input, to find what makes it fail. See [fuzzing](fuzzing.md).

## G

### GeoIP

**General term.** A database that maps an IP address to a rough location, such as a
country. Signari reads one to check impossible travel. See [impossible
travel](impossible-travel.md).

### Grant

**General term.** In OAuth, one of the ways of getting a token, such as with an
authorization code or a refresh token. It also means the permission a person gave
an application. See [grant management](grant-management.md).

### Group

**General term.** A set of people, such as `engineering`. Signari tells an
application about a group only when an administrator releases the group to it.
See [groups](groups.md).

## H

### HMAC

**General term.** A message authentication code made from a hash and a shared
secret, short for hash-based message authentication code. Signari signs event
deliveries with one. See [event subscriptions](events.md).

### Holder

**General term.** The person who keeps a verifiable credential in their wallet, and
shows it when asked. See [issuing credentials to wallets](oid4vci.md).

### HSM

**General term.** Hardware security module: a device that keeps signing keys
inside it, so they can be used but never copied out. Signari talks to one through
the PKCS#11 standard. See [signing keys in a hardware
module](signing-keys-in-a-module.md).

### Hybrid flow

**General term.** An OpenID Connect sign-in whose response carries an ID token or a
token straight away, beside the authorization code. See [older response
modes](response-modes.md).

## I

### ID token

**General term.** The token that tells an application who signed in. It is a JWT,
and the application checks it before believing it. See [how Signari
works](how-signari-works.md#id-token).

### ID-JAG

**General term.** Identity Assertion JWT Authorization Grant: a signed grant from
Signari that one application trades at another's authorization server for an
access token. See [cross-application access](id-jag.md).

### Identity provider

**General term.** A service that keeps a list of people and checks who they are,
so that other applications do not have to. Often written IdP. Signari is one. See
[what Signari is](introduction.md).

### Impersonation

**Signari term.** An administrator acting as another person, for support, in a
way that is visible and recorded. See [support access](impersonation.md).

### Initial access token

**General term.** A token an administrator hands out that lets an application
register itself. Registering returns a registration access token, which lets it
change that registration later. See [applications that register
themselves](dynamic-registration.md).

### Instance

**Signari term.** One identity provider as the outside world sees it, named by its
issuer. See [how Signari works](how-signari-works.md#instance-and-issuer).

### Introspection

**General term.** An API asking Signari whether a token is still valid, and what it
says. See [opaque access tokens](opaque-access-tokens.md).

### Invitation

**Signari term.** A one-time link that lets someone make an account, optionally
bound to one address and with groups to join. It lasts seven days unless set
otherwise. See [invitations and sign-up](signup.md).

### Issuer

**General term.** The web address that every token from an identity provider
carries, such as `https://login.example.com`. Applications refuse tokens from any
other issuer. See [how Signari works](how-signari-works.md#instance-and-issuer).

## J

### JAR

**General term.** JWT-Secured Authorization Request: a sign-in request the
application signs, so nobody can change it on the way. See [signed authorization
requests](jar.md).

### Janitor

**Signari term.** The background job that deletes what has expired, such as old
codes and pushed requests. `signari janitor once` runs it by hand. See [every
command](cli.md).

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

### KDC

**General term.** Key Distribution Center: the Kerberos server that issues tickets.
See [Kerberos](kerberos.md).

### Kerberos

**General term.** How Windows domains and FreeIPA realms sign people in to their
computers. Signari accepts a Kerberos ticket from the browser through SPNEGO. See
[Kerberos](kerberos.md).

### Kerberos realm

**General term.** Kerberos's own unit of administration, written in capitals, such
as `CORP.EXAMPLE.COM`. One organisation can have several. See
[Kerberos](kerberos.md).

### Key rotation

**General term.** Replacing signing keys on a schedule. Signari publishes a new key
before it uses it, so applications learn it in advance. See [key
rotation](key-rotation.md).

### Key states

**Signari term.** The stages a signing key passes through: `next` (published,
signing nothing), `active` (signing), `passive` (published, no longer signing) and
`retired`. See [rotating signing keys](key-rotation.md).

### Keytab

**General term.** A file holding the Kerberos keys that a service uses to accept
tickets. See [Kerberos](kerberos.md).

### KMS

**General term.** Key management service: a cloud or network service that holds
keys and uses them on request. See [signing keys in a hardware
module](signing-keys-in-a-module.md).

## L

### LDAP

**General term.** Lightweight Directory Access Protocol: how older software checks
a username and password against a company directory. See [LDAP](ldap.md), and
[LDAP as a source](ldap-source.md) for reading an existing directory.

### Logout token

**General term.** The signed `logout_token` an identity provider sends an
application's back-channel address when a session ends. See [proving sign-out
works](logout-conformance.md).

## M

### MCP

**General term.** Model Context Protocol: an open protocol that connects
applications built on language models to outside tools and data. See [MCP servers
and agents](mcp-authorization.md).

### mdoc

**General term.** A mobile document in the ISO 18013-5 format, such as a digital
driving licence, kept in a wallet. See [signing in with a wallet](wallet-sign-in.md).

### MDM

**General term.** Mobile device management: software a company uses to manage and
check its laptops and phones. See [device posture](device-posture.md).

### Message catalogue

**Signari term.** The file holding every sentence Signari's pages show, in one
language. See [languages](i18n.md).

### MFA

**General term.** Multi-factor authentication: proving who you are in two
different ways, such as a password and a code from your phone. See [sign-in
flows](flows.md).

### Migration

**Signari term.** A numbered change to the database's structure. A new release
brings its migrations, and `signari migrate up` applies them. See
[upgrading](upgrading.md).

### Migration source

**Signari term.** The system people are moving from, which Signari asks to check a
password at a person's first sign-in. See [keeping passwords when you
migrate](password-migration.md).

### Mutation testing

**General term.** Breaking code on purpose, one change at a time, to check that a
test fails each time. A test that still passes was not checking that code. See
[receiving security events](shared-signals-receiver.md), whose reviews record
their passes.

### Mutual TLS

**General term.** An application proving who it is with a certificate, during the
encrypted connection itself. Often written mTLS. See [mutual-TLS client
authentication](mutual-tls.md).

## N

### NameID

**General term.** The identifier for the person inside a SAML assertion. See [SAML
2.0](saml.md).

### Nested JWT

**General term.** A JWT carried inside another, such as a signed token that is then
encrypted. See [signed and encrypted responses](response-encryption.md).

### NIST SP 800-63B

**General term.** The US National Institute of Standards and Technology's
guideline for passwords, second factors and sessions. See [the NIST SP 800-63B
review](security-review-nist-800-63b.md).

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

### Opaque access token

**General term.** An access token that is a random string, a "handle", instead of a
readable JWT. An API learns what it means by asking Signari. See [opaque access
tokens](opaque-access-tokens.md).

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

### Origin

**General term.** The scheme, host and port of a web page, such as
`https://wiki.example.com`. Browsers keep pages of different origins apart. See
[calling Signari from a browser](cors.md).

### OTLP

**General term.** OpenTelemetry Protocol: the standard way to send traces to a
collector, the service that gathers them. See [tracing](tracing.md).

### Outbox

**Signari term.** Signari's queue of messages to deliver, such as sign-out notices
and events. Each is retried, and one that keeps failing is parked where you can see
it. See [event subscriptions](events.md).

### Outpost

**Signari term.** A Signari program that serves LDAP, RADIUS or forward
authentication somewhere that must not reach the database, such as a branch
office. See [outposts](outposts.md).

### OWASP ASVS

**General term.** The Open Worldwide Application Security Project's Application
Security Verification Standard: a checklist of security requirements for web
applications. See [the OWASP ASVS review](security-review-asvs.md).

## P

### PAR

**General term.** Pushed Authorization Requests: the application sends its
sign-in request to Signari directly first, and the browser carries only a
reference to it. See [pushed authorization requests](par.md).

### Pairwise subject

**General term.** A subject identifier that differs for each application, so two
applications cannot tell they share a person. A "sector" is a set of applications
that share one. See [a different identifier for each
application](pairwise-subjects.md).

### Passkey

**General term.** A sign-in credential kept on a device or in a password manager,
and unlocked with a fingerprint, a face or a PIN. It replaces a password. See
[WebAuthn Level 3 signals](passkey-signals.md).

### PAT

**General term.** Protection API access token: the token a resource server uses to
register resources at a UMA authorization server. See [sharing resources with
UMA](uma.md).

### PCT

**General term.** Persisted claims token: a UMA token that lets a requesting party
skip giving the same claims again. See [sharing resources with UMA](uma.md).

### PDP

**General term.** Policy decision point: the service that answers whether an
action is allowed. See [asking whether an action is allowed](authorization.md).

### Pending account

**Signari term.** An account made by self-signup that waits for an administrator's
approval before it can sign in. See [invitations and sign-up](signup.md).

### PEP

**General term.** Policy enforcement point: the code that asks a PDP whether an
action is allowed, and acts on the answer. See [asking whether an action is
allowed](authorization.md).

### Permission ticket

**General term.** In UMA, a handle the resource server gets for a requested access,
which the client trades for an RPT. See [sharing resources with UMA](uma.md).

### PKCE

**General term.** Proof Key for Code Exchange. The application sends a hash of a
secret value when sign-in starts, and the value itself when it collects its
tokens. A stolen authorization code is then useless. See [what happens when you
click Sign in](first-application.md#what-happens-when-you-click-sign-in).

### PKCS#11

**General term.** The standard interface programs use to talk to a hardware
security module. See [signing keys in a hardware
module](signing-keys-in-a-module.md).

### PKI

**General term.** Public key infrastructure: the authorities and certificates that
let one party trust another's key. See [certificates for
applications](mutual-tls.md).

### Point-in-time recovery

**General term.** Restoring a PostgreSQL database to a chosen moment, from a base
backup and the write-ahead log (WAL) kept since. See [backing up and
restoring](runbook-backup-restore.md).

### Policy

**Signari term.** Access rules, such as "only engineering may use this
application", kept as a file you can review and test. See [access
policy](policy.md).

### Pre-authorized code

**General term.** In OID4VCI, a code inside a credential offer that a wallet trades
for an access token without a separate sign-in. See [issuing credentials to
wallets](oid4vci.md).

### Preflight

**General term.** The `OPTIONS` request a browser sends before some cross-origin
calls, to ask whether the call is allowed. See [calling Signari from a
browser](cors.md).

### Principal

**General term.** In Kerberos, the name of a person or service, such as
`ada@CORP.EXAMPLE.COM`. See [Kerberos](kerberos.md).

### Prompt

**Signari term.** A question or notice shown during sign-in, such as new terms to
accept. See [questions and notices during sign-in](prompts.md).

### Provider

**Signari term.** A service you run that Signari calls at a named point, such as
when it decides whether to allow a sign-in. See [extending Signari with your own
service](extensibility.md).

### Provisioning

**General term.** Creating, changing and removing accounts in other applications
automatically, as people join, move and leave. See [provisioning to other
services](provisioning.md).

### Public client

**General term.** An application that runs on a person's own device, such as a
mobile application, and so cannot keep a secret. It proves itself with PKCE alone. See
[how Signari works](how-signari-works.md#application).

## R

### RADIUS

**General term.** Remote Authentication Dial-In User Service: how VPNs, wifi and
network equipment ask whether someone may connect. Acme's VPN uses it. See
[RADIUS](radius.md).

### RAR

**General term.** Rich Authorization Requests: asking for detailed permissions,
such as a payment of a given amount, instead of a scope. See [detailed permissions
in a request](rich-authorization-requests.md).

### Receiver

**General term.** In Shared Signals, the service that accepts security events. The
transmitter is the one that sends them. See [receiving security
events](shared-signals-receiver.md).

### Reconciliation

**General term.** Comparing what a target system holds with what it should hold,
and working out the changes. See [provisioning to other services](provisioning.md).

### Redirect URI

**General term.** The exact address Signari sends the browser back to after
sign-in. It must match a registered one character for character. See [how Signari
works](how-signari-works.md#application).

### Refresh family

**Signari term.** Every refresh token descended from one grant. Presenting a spent
one again, outside the application's retry grace, ends the whole family. See [how Signari
works](how-signari-works.md#refresh-token).

### Refresh token

**General term.** A token that lets an application get a new access token without
sending the person to sign in again. Signari's last 30 days, and each one works
once. See [how Signari works](how-signari-works.md#refresh-token).

### Relying party

**General term.** Another name for an application that relies on an identity
provider to sign people in. These pages say "application". See [how Signari
works](how-signari-works.md#application).

### Request Object

**General term.** A sign-in request sent as a signed JWT, so nothing can change it
on the way. See [signed authorization requests](jar.md).

### Requesting party

**General term.** In UMA, the person asking for access to something another person
owns. See [sharing resources with UMA](uma.md).

### Resource server

**General term.** OAuth's name for an API that accepts access tokens. See [limiting
which APIs a token reaches](resource-indicators.md).

### Response mode

**General term.** How a sign-in's answer travels back to the application: in the
query string, in the fragment, or in a posted form. See [older response
modes](response-modes.md).

### RISC

**General term.** Risk Incident Sharing and Coordination: Shared Signals events
about accounts, such as an account being disabled. See [receiving security
events](shared-signals-receiver.md).

### RLS

**General term.** Row-level security: a PostgreSQL rule that shows each
connection only the rows it is allowed to see. Signari uses it to keep
organisations apart. See [how Signari
works](how-signari-works.md#how-the-database-keeps-organisations-apart).

### Root key

**Signari term.** The secret that encrypts every sensitive value Signari stores,
kept outside the database. Lose it, and those values are gone for good. See
[backup and restore](runbook-backup-restore.md).

### RPT

**General term.** Requesting party token: the UMA access token that lets a
requesting party reach a resource. See [sharing resources with UMA](uma.md).

### RS256

**General term.** An older, widely supported signature algorithm, RSA with
SHA-256. Signari publishes RS256 keys beside its ES256 ones, for applications that
need them. See [key rotation](key-rotation.md).

## S

### SAML

**General term.** Security Assertion Markup Language: an older, widely used way
for business software to sign people in, with signed XML. Acme's chat application
uses it. See [SAML 2.0](saml.md).

### SAML binding

**General term.** The way a SAML message travels: in a redirect, in a form the
browser posts, or from server to server. See [SAML 2.0](saml.md).

### SAML metadata

**General term.** An XML document listing a SAML party's addresses and
certificates, so the other side can be set up from it. See [registering SAML
partners from metadata](saml-metadata.md).

### SBOM

**General term.** Software bill of materials: the list of every component a release
is built from. See [third-party dependencies](dependencies.md).

### Schema fingerprint

**Signari term.** A hash of the database's structure. A release can be pinned to
one, and then refuses to start on a database whose structure differs. See
[pinning a release to its schema](schema-pinning.md).

### Scope

**General term.** A short name an application asks for, such as `email`, which
brings certain claims with it. See [how Signari
works](how-signari-works.md#scopes-claims-and-consent).

### SCIM

**General term.** System for Cross-domain Identity Management: a standard for
creating and removing accounts in other applications automatically. See [SCIM
provisioning](scim.md).

### SCIM source

**Signari term.** A system that writes accounts into Signari over SCIM. A SCIM
target is the other way round: a system Signari writes accounts into. See
[receiving SCIM](scim-source.md).

### SD-JWT

**General term.** Selective Disclosure JWT: a signed credential whose holder can
reveal some of its claims and keep others hidden. See [OID4VCI](oid4vci.md).

### SD-JWT VC

**General term.** A verifiable credential written as an SD-JWT, with a type that
says what it is. See [issuing credentials to wallets](oid4vci.md).

### Self-signup

**Signari term.** People making their own accounts, when an organisation's sign-up
rule allows it. See [invitations and sign-up](signup.md).

### Service account

**General term.** An account a program uses instead of a person, such as an
application that binds to LDAP to look people up. See [LDAP](ldap.md).

### Service provider

**General term.** SAML's name for an application. See [SAML 2.0](saml.md).

### Session

**General term.** How Signari remembers that someone has signed in, through a
cookie in their browser. It is what makes single sign-on work. See [how Signari
works](how-signari-works.md#session).

### SET

**General term.** Security Event Token: a signed JWT describing one security event,
as Shared Signals sends them. See [receiving security
events](shared-signals-receiver.md).

### Shared secret

**General term.** A password that two systems both know, such as the one a RADIUS
device and Signari share. See [RADIUS](radius.md).

### Shared Signals

**General term.** A standard for sending security events between services as they
happen. CAEP is one kind of event it carries. Often written SSF. See [Shared
Signals and CAEP](ssf-caep.md).

### Signing key

**General term.** The private key an identity provider signs its tokens with.
Applications check the signatures with the matching public key. See [how Signari
works](how-signari-works.md#signing-keys-and-the-root-key).

### Single Logout

**General term.** SAML's way of signing a person out of every application in one
go. See [SAML 2.0](saml.md).

### Single sign-on

**General term.** Signing in once and reaching every application, without a
password for each. Often written SSO. See [what Signari is](introduction.md).

### SMS

**General term.** A text message sent to a phone number. A code sent that way is a
weak second factor. See [SMS codes](sms.md).

### Span

**General term.** One timed piece of work in a trace, such as a database query. See
[tracing](tracing.md).

### SPNEGO

**General term.** Simple and Protected GSS-API Negotiation Mechanism. It is how a
browser hands a Kerberos ticket to a website, so the person signs in without a
password. See [Kerberos](kerberos.md).

### SSRF

**General term.** Server-side request forgery: tricking a server into making a
request somewhere it should not. See [every outbound
connection](egress-inventory.md).

### Stage

**Signari term.** One step of a sign-in flow, such as `password` or `mfa`. See
[sign-in flows](flows.md).

### State

**General term.** A random value an application sends when sign-in starts, and
checks when the browser returns. It makes sure the application accepts only
sign-ins it began. See [what happens when you click Sign
in](first-application.md#what-happens-when-you-click-sign-in).

### Step-up

**General term.** Asking a person who is already signed in to sign in more strongly,
such as with a second factor, before a sensitive action. See [sign-in
flows](flows.md).

### Subject

**General term.** The identifier a token uses for a person, in its `sub` claim. It
does not change when their email address does. See [pairwise
subjects](pairwise-subjects.md).

### Subject identifier

**General term.** In Shared Signals, the way an event names a person, such as an
issuer and subject pair, or an email address. See [receiving security
events](shared-signals-receiver.md).

### Superuser

**General term.** A PostgreSQL role that may do anything, and that row-level
security does not apply to. Signari's server must never run as one. See [how
Signari works](how-signari-works.md#how-the-database-keeps-organisations-apart).

### Supplicant

**General term.** The software on a device that joins a network with 802.1X, such
as with EAP-TLS. See [EAP-TLS](eap-tls.md).

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

### Transaction token

**General term.** A short-lived token that carries who made a request, and why,
between the services inside one trust domain. Often written Txn-Token. See
[transaction tokens](transaction-tokens.md).

### Transit engine

**General term.** The part of Vault or OpenBao that signs and encrypts with keys it
keeps. Signari can sign with one. See [signing keys in a hardware
module](signing-keys-in-a-module.md).

### Transmitter

**General term.** In Shared Signals, the service that sends security events. See
[Shared Signals and CAEP](ssf-caep.md).

### Trust Anchor

**General term.** In OpenID Federation, the authority at the top that every
participant trusts. See [OpenID Federation](openid-federation.md).

### Trust Chain

**General term.** In OpenID Federation, the signed statements leading from an entity
up to a Trust Anchor. See [OpenID Federation](openid-federation.md).

### Trust domain

**General term.** A group of services that share the same security controls, such
as the services behind one company's API. See [transaction
tokens](transaction-tokens.md).

### Trust Mark

**General term.** In OpenID Federation, a signed statement that an entity meets
some requirement. See [trust marks](trust-marks.md).

## U

### UMA

**General term.** User-Managed Access 2.0: a standard for letting a person share
something they own, such as a document, with someone else. See [UMA
2.0](uma.md).

### Upstream

**General term.** The identity provider people sign in through, seen from
Signari's side. See [signing in through another provider](social-login.md).

### Userinfo

**General term.** An address, `/oauth2/userinfo`, where an application can ask for
the claims about the person who signed in, using its access token. See
[groups](groups.md).

### UUID

**General term.** A 128-bit identifier written as 36 characters, short for
universally unique identifier. Signari names organisations and people by one. See
[how Signari works](how-signari-works.md#organisation).

## V

### Verifiable credential

**General term.** A signed digital document, such as a staff card, that a person
keeps in a wallet and shows to whoever needs to check it. See [issuing credentials
to wallets](oid4vci.md).

### Verifier

**General term.** The party that checks a credential a wallet shows. Signari is
one when people sign in with a wallet. See [signing in with a
wallet](wallet-sign-in.md).

## W

### WAL

**General term.** Write-ahead log: PostgreSQL's record of every change, which
point-in-time recovery replays. See [backing up and
restoring](runbook-backup-restore.md).

### WebAuthn

**General term.** The browser standard behind passkeys and security keys. See
[WebAuthn Level 3 signals](passkey-signals.md).

### Webhook

**General term.** A URL that one service posts events to as they happen. See
[event subscriptions](events.md).

### WS-Federation

**General term.** An older Microsoft protocol for signing in, much like SAML.
Signari speaks it for applications that have not yet moved off it. See
[WS-Federation](ws-federation.md).

## X

### XSS

**General term.** Cross-site scripting: getting a page to run a script someone else
wrote. See [brands](brands.md).
