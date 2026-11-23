# Documentation

One document per capability, about a hundred and forty in all. This page is the
way in.

**New to Signari?** Start with [Introduction](introduction.md), then sign in
to an example application on your own computer with
[Your first application](first-application.md). [The full list of
pages](documentation.md) gives every page in reading order.

**Running it already:** [Configuration](configuration.md) for every setting,
[Every command](cli.md) for every command, [Checking a deployment](doctor.md) to
find out whether a deployment is sound. Those three are kept complete by tests
rather than by discipline — the engine's `internal/docsync` package fails the
build when a command or an environment variable exists in code and not on its
page.

## Getting started

| | |
|---|---|
| [Introduction](introduction.md) | What an identity provider is, and what Signari does and does not do |
| [Installation](installation.md) | Installing on a server, with Docker, or from source |
| [Your first application](first-application.md) | A real sign-in to an example application, on your own computer |
| [How Signari works](how-signari-works.md) | Instances, organisations, applications, sessions, tokens and keys, in plain words |
| [Which protocol do I need?](protocols-explained.md) | Which protocol each kind of application or device needs |
| [Glossary](glossary.md) | Every term these pages use, in one or two lines |
| [Writing the docs](writing-docs.md) | The house style these pages are written in |

## Running it

| | |
|---|---|
| [Configuration](configuration.md) | Every environment variable, in one place |
| [Every command](cli.md) | Every command the `signari` binary dispatches |
| [Checking a deployment](doctor.md) | The pre-flight check: what is wrong with this deployment |
| [Configuration as code](config-as-code.md) | `signari plan` / `apply` — clients, groups and providers from a file |
| [Pinning a build to its schema](schema-pinning.md) | Pinning a release binary to the schema it was built for |
| [Upgrading](upgrading.md) | Upgrading, rolling back, and which migrations the previous release may run against |
| [Troubleshooting](troubleshooting.md) | What a refusal means, quoted as the server writes it, and what to do about it |
| [Go](quickstart-go.md) | A Go application signing people in, standard library only, every check it must make itself |
| [Express](quickstart-express.md) | An Express application signing people in with openid-client, the ID token's signature checked too |
| [Next.js](quickstart-nextjs.md) | A Next.js application (App Router) signing people in with openid-client in two route handlers |
| [Django](quickstart-django.md) | A Django application signing people in with Authlib, no database needed |
| [Spring Boot](quickstart-spring.md) | A Spring Boot application signing people in, with the PKCE and ES256 settings Spring does not assume |
| [Laravel](quickstart-laravel.md) | A Laravel application signing people in, its library kept to Laravel's session and checked for state first |
| [Schema versions](schema-versions.md) | What each schema version changed, newest first, generated from the migrations |
| [Connection pooling](connection-pooling.md) | The two pools a node opens, and running behind PgBouncer |
| [Running more than one instance](high-availability.md) | Several servers on one database and one issuer, with no leader election, cache invalidation or sticky sessions to arrange |
| [Kubernetes and other artefacts](deployment-artefacts.md) | The Helm chart, and what is deliberately not built |
| [Backup and restore](runbook-backup-restore.md) | Backup and restore, and why the root key changes everything |
| [Running the conformance suite](runbook-public-conformance.md) | Exposing a deployment to the OIDF conformance suite |
| [Performance](performance.md) | What one instance does under load |
| [Tracing](tracing.md) | OpenTelemetry spans to a collector, and what no span carries |
| [Static analysis](security-scanning.md) | `govulncheck`, `gosec`, and the findings left visible on purpose |
| [Fuzzing](fuzzing.md) | The fuzz target of every parser that reads a stranger's input, and how they are run continuously |
| [Third-party dependencies](dependencies.md) | Third-party inventory (ASVS V15.1.2) |

## The sign-in experience

| | |
|---|---|
| [Sign-in flows](flows.md) | The sequence somebody is asked for, as a file you can test in CI |
| [Steps answered by your own service](external-factors.md) | A sign-in stage answered by a service you run, believed because it signed the answer |
| [Questions and notices during sign-in](prompts.md) | Terms acceptance, extra fields, notices |
| [Invitations and sign-up](signup.md) | Invitations and self-service sign-up |
| [Password policy](password-policy.md) | One gate, called by every path that sets a password |
| [CAPTCHA](captcha.md) | Off by default, adaptive when on |
| [Theming the pages](theming.md) | Every page is an HTML file you can replace |
| [Brands: name, logo and colours](brands.md) | Product name, logo, colours — with WCAG contrast enforced |
| [Email](mail.md) | Both parts of every message, no buttons, and an organisation's own sender |
| [Languages](i18n.md) | Adding a language is adding one file |
| [The application portal](app-portal.md) | `/apps` — what a user can reach, and why not the rest |

## Second factors

| | |
|---|---|
| [Passkeys](passkey-signals.md) | WebAuthn Level 3 signals, keeping authenticators in step |
| [Authenticator apps](totp-qr.md) | TOTP enrolment and the QR code |
| [Email codes](email-otp.md) | A six-digit code by email |
| [SMS codes](sms.md) | The weakest factor here, and the page says so |
| [Duo](duo.md) | Duo Universal Prompt |

## OAuth 2.0 and OpenID Connect

| | |
|---|---|
| [How an application proves who it is](client-authentication.md) | How a confidential client proves who it is |
| [Certificates for applications (mutual TLS)](mutual-tls.md) | RFC 8705 — certificate-bound tokens |
| [Encrypted Client Hello](encrypted-client-hello.md) | RFC 9849 — the name a browser asks for, encrypted |
| [Client attestation](attestation-based-client-auth.md) | Client attestation, current draft |
| [Pushed authorization requests](par.md) | RFC 9126 — Pushed Authorization Requests |
| [Signed authorization requests](jar.md) | Signed authorization requests (RFC 9101), by value or pushed, and requiring them |
| [Signed authorization responses](jarm.md) | Signed authorization responses, and holding a client to them |
| [Signed and encrypted responses](response-encryption.md) | Signed userinfo, and encrypting ID tokens, userinfo and authorization responses to a client's key |
| [Tokens tied to a key (DPoP)](dpop.md) | RFC 9449 — sender-constrained tokens |
| [Limiting which APIs a token reaches](resource-indicators.md) | RFC 8707 — which APIs a token may be audienced to |
| [Opaque access tokens](opaque-access-tokens.md) | Access tokens that say nothing to whoever holds them, introspected per client |
| [A different identifier for each application](pairwise-subjects.md) | A subject that means nothing outside the application it was given to, so applications cannot compare notes |
| [The FAPI 2.0 security profile](fapi2.md) | Holding a client to the FAPI 2.0 Security Profile, and what that changes |
| [Devices with no browser](device-flow.md) | RFC 8628 — televisions, CLIs, headless boxes |
| [Approving on another device (CIBA)](ciba.md) | Backchannel authentication |
| [Applications that register themselves](dynamic-registration.md) | RFC 7591/7592 |
| [Older response modes](response-modes.md) | `form_post` and hybrid, for migrations |
| [Your own sign-in page](headless-sign-in.md) | A sign-in page of the application's own, walked over JSON |
| [Detailed permissions in a request](rich-authorization-requests.md) | RFC 9396 — when a scope string is not enough |
| [Machine sign-in with a signed assertion](jwt-bearer.md) | RFC 7523 §2.1 — GitHub Actions, Kubernetes |
| [Transaction tokens](transaction-tokens.md) | Per-transaction tokens inside a call chain |
| [MCP servers and agents](mcp-authorization.md) | Acting as an authorization server for MCP |
| [Rotating signing keys](key-rotation.md) | next → active → passive → retired |
| [Signing keys in a hardware module](signing-keys-in-a-module.md) | Signing keys made and kept in an HSM, through PKCS#11 |
| [Signing out](logout.md) | Three mechanisms, because none reaches everything |
| [Several accounts in one browser](accounts.md) | Several accounts in one browser, and `prompt=select_account` |
| [Authorization request parameters](oidc-parameters.md) | `login_hint`, `id_token_hint`, `display` and the `claims` parameter |
| [Sign-ins from a new device](new-device-sign-in.md) | Telling a person their account was signed in to from somewhere new |
| [Proving sign-out works](logout-conformance.md) | Proving a relying party actually honours it |
| [CORS](cors.md) | Which endpoints, and the one that must never have it |
| [Draft standards implemented](emerging-standards.md) | Every non-settled specification implemented, with its draft status |

## Verifiable credentials and federation

| | |
|---|---|
| [Issuing credentials to wallets (OID4VCI)](oid4vci.md) | The authorization server's half of credential issuance |
| [OpenID Federation](openid-federation.md) | The Entity Configuration, metadata policy, and being a Trust Anchor or Intermediate |
| [Applications known by their URL](client-metadata-documents.md) | Letting an application that is its own URL sign people in, such as an MCP client, with no registration step |
| [Keeping what a person approved](grant-management.md) | A client holding on to what a person authorized under an identifier: adding to it, replacing it, reading it back and revoking it |
| [Cross-app access](id-jag.md) | Cross-app access: one application reaching another for somebody who signed in here, with no second consent screen |
| [Trust marks](trust-marks.md) | Signed conformance statements |
| [User-Managed Access (UMA)](uma.md) | UMA 2.0, the Kantara Recommendation of January 2018, with Federated Authorization for the permission endpoint |

## Other protocols

| | |
|---|---|
| [SAML 2.0](saml.md) | Signari as a SAML identity provider |
| [Signing in through a SAML provider](saml-source.md) | Consuming somebody else's assertions |
| [SAML metadata](saml-metadata.md) | Registering a partner from its metadata, signature checked, and reading it again |
| [WS-Federation](ws-federation.md) | SharePoint and pre-SAML .NET |
| [LDAP](ldap.md) | Applications that authenticate by binding |
| [LDAP as a source](ldap-source.md) | Reading an existing directory |
| [RADIUS](radius.md) | VPNs, wireless controllers, switches |
| [Certificate wifi and network sign-in (EAP-TLS)](eap-tls.md) | Certificate-based wifi and network login |
| [Kerberos](kerberos.md) | SPNEGO for domain-joined machines |

## Users, groups and provisioning

| | |
|---|---|
| [Sending accounts out with SCIM](scim.md) | Pushing users into downstream applications |
| [Receiving SCIM](scim-source.md) | Receiving users from an upstream |
| [Provisioning to other services](provisioning.md) | SCIM, Google Workspace and Entra as targets |
| [Directory sync](directory-sync.md) | Google, Entra and LDAP as sources |
| [Signing in through another provider](social-login.md) | Federated sign-in providers |
| [Signing in with a wallet](wallet-sign-in.md) | Signing in with a credential from a digital identity wallet (OpenID4VP) |
| [Groups](groups.md) | Membership, and which clients may see it |
| [Erasing a person](erasure.md) | Crypto-shredding a subject |
| [Exporting a person's data](data-export.md) | Everything kept about a person, for them or for a request on their behalf |

## Access control

| | |
|---|---|
| [Access policy](policy.md) | Access rules as a reviewable, testable file |
| [Seeing the policy as a diagram](policy-diagram.md) | Rendering the policy as a diagram |
| [Asking whether an action is allowed (AuthZEN)](authorization.md) | The AuthZEN authorization API |
| [Device posture](device-posture.md) | Device trust as a line in the policy file |
| [Chrome Enterprise device trust](chrome-device-trust.md) | Managed Chrome as a posture source |
| [Impossible travel](impossible-travel.md) | London, then São Paulo eleven minutes later |
| [Support access](impersonation.md) | An administrator acting as a user, visibly |

## Reaching things that do not speak OIDC

| | |
|---|---|
| [Forward authentication](forward-auth.md) | Putting Signari in front of an app that knows nothing about OIDC |
| [Outposts](outposts.md) | LDAP, RADIUS or forward auth where the database must not be reachable |
| [Remote desktops and shells in the browser](remote-access.md) | RDP, VNC and SSH in a browser tab |
| [Desktop and workstation sign-in](desktop-login.md) | Windows credential providers, PAM, kiosks |

## Audit and events

| | |
|---|---|
| [Event subscriptions](events.md) | Telling other systems what happened |
| [Sending Shared Signals and CAEP](ssf-caep.md) | Shared Signals and CAEP, outbound |
| [Receiving Shared Signals](shared-signals-receiver.md) | Security Event Tokens another service posts here, at `/ssf/receive` |
| [Exporting the audit trail](audit-export.md) | Exporting the trail |
| [Streaming the audit trail](audit-streaming.md) | Forwarding to syslog or a SIEM |
| [How the audit chain forked, and the fix](audit-chain-fork.md) | How the hash chain forked under concurrency, and the fix |
| [What is logged](logging-inventory.md) | What is logged where (ASVS V16.1.1) |
| [Every outbound connection](egress-inventory.md) | Every outbound connection (ASVS V13.1.1) |
| [Security inventories](security-inventories.md) | The cryptography, the ways to authenticate, the session rules, the limits and the data, each in one place |

## Compliance evidence

| | |
|---|---|
| [OWASP ASVS review](security-review-asvs.md) | OWASP ASVS 5.0, requirement by requirement |
| [CWE Top 25 review](security-review-cwe-top25.md) | MITRE's 2025 CWE Top 25, each held where, by file and line |
| [RFC 9700 review](security-review-rfc9700.md) | RFC 9700 (BCP 240) |
| [FAPI 2.0 review](security-review-fapi2.md) | FAPI 2.0 Security Profile |
| [NIST SP 800-63B review](security-review-nist-800-63b.md) | NIST SP 800-63B revision 4 |
| [FIPS 140-3](fips.md) | What survives a FIPS 140-3 build, and what cannot |

## The admin console

| | |
|---|---|
| [The console](console-configuration.md) | What each screen answers, and why they are read-only |
| [The Admin API](admin-api.md) | The write surface, its endpoints, and conditional writes |
| [Admin API clients](sdk.md) | The Go and TypeScript clients generated from [the OpenAPI document](admin-openapi.json) |
| [Every Admin API operation](admin-api-reference.md) | Every Admin API operation, its scope, and the fields it takes and answers, generated from the same document |
| [Extending Signari with your own service](extensibility.md) | Extending a decision with your own service |
| [Admin API access](admin-tokens.md) | Credentials for the Admin API |
| [Two-person approvals](approvals.md) | A second person for an erasure or an org-owner grant |

## Migrating in

| | |
|---|---|
| [Checking old passwords at first sign-in](password-migration.md) | Verifying migrating people against the old directory or provider at their first sign-in |
| [From Keycloak](migrate-from-keycloak.md) | Importing a realm |
| [From authentik](migrate-from-authentik.md) | Importing an installation |
| [From Zitadel](migrate-from-zitadel.md) | Importing an organisation |
| [From Auth0](migrate-from-auth0.md) | Importing a tenant's people |
| [From Okta](migrate-from-okta.md) | Importing an org's people |
| [From Microsoft Entra ID](migrate-from-entra.md) | Importing a tenant's people |
