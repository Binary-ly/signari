# Documentation

Ninety-odd documents, one per capability. This page is the way in.

**Start here:** [configuration.md](configuration.md) for every setting,
[cli.md](cli.md) for every command, [doctor.md](doctor.md) to find out whether a
deployment is sound. Those three are kept complete by tests rather than by
discipline — the engine's `internal/docsync` package fails the build when a
command or an environment variable exists in code and not on its page.

## Running it

| | |
|---|---|
| [configuration.md](configuration.md) | Every environment variable, in one place |
| [cli.md](cli.md) | Every command the `signari` binary dispatches |
| [doctor.md](doctor.md) | The pre-flight check: what is wrong with this deployment |
| [config-as-code.md](config-as-code.md) | `signari plan` / `apply` — clients, groups and providers from a file |
| [schema-pinning.md](schema-pinning.md) | Pinning a release binary to the schema it was built for |
| [high-availability.md](high-availability.md) | Running more than one instance |
| [deployment-artefacts.md](deployment-artefacts.md) | The Helm chart, and what is deliberately not built |
| [runbook-backup-restore.md](runbook-backup-restore.md) | Backup and restore, and why the root key changes everything |
| [runbook-public-conformance.md](runbook-public-conformance.md) | Exposing a deployment to the OIDF conformance suite |
| [performance.md](performance.md) | What one instance does under load |
| [security-scanning.md](security-scanning.md) | `govulncheck`, `gosec`, and the findings left visible on purpose |
| [dependencies.md](dependencies.md) | Third-party inventory (ASVS V15.1.2) |

## The sign-in experience

| | |
|---|---|
| [flows.md](flows.md) | The sequence somebody is asked for, as a file you can test in CI |
| [prompts.md](prompts.md) | Terms acceptance, extra fields, notices |
| [signup.md](signup.md) | Invitations and self-service sign-up |
| [password-policy.md](password-policy.md) | One gate, called by every path that sets a password |
| [captcha.md](captcha.md) | Off by default, adaptive when on |
| [theming.md](theming.md) | Every page is an HTML file you can replace |
| [brands.md](brands.md) | Product name, logo, colours — with WCAG contrast enforced |
| [i18n.md](i18n.md) | Adding a language is adding one file |
| [app-portal.md](app-portal.md) | `/apps` — what a user can reach, and why not the rest |

## Second factors

| | |
|---|---|
| [passkey-signals.md](passkey-signals.md) | WebAuthn Level 3 signals, keeping authenticators in step |
| [totp-qr.md](totp-qr.md) | TOTP enrolment and the QR code |
| [email-otp.md](email-otp.md) | A six-digit code by email |
| [sms.md](sms.md) | The weakest factor here, and the page says so |
| [duo.md](duo.md) | Duo Universal Prompt |

## OAuth 2.0 and OpenID Connect

| | |
|---|---|
| [client-authentication.md](client-authentication.md) | How a confidential client proves who it is |
| [mutual-tls.md](mutual-tls.md) | RFC 8705 — certificate-bound tokens |
| [attestation-based-client-auth.md](attestation-based-client-auth.md) | Client attestation, current draft |
| [par.md](par.md) | RFC 9126 — Pushed Authorization Requests |
| [dpop.md](dpop.md) | RFC 9449 — sender-constrained tokens |
| [device-flow.md](device-flow.md) | RFC 8628 — televisions, CLIs, headless boxes |
| [ciba.md](ciba.md) | Backchannel authentication |
| [dynamic-registration.md](dynamic-registration.md) | RFC 7591/7592 |
| [response-modes.md](response-modes.md) | `form_post` and hybrid, for migrations |
| [rich-authorization-requests.md](rich-authorization-requests.md) | RFC 9396 — when a scope string is not enough |
| [jwt-bearer.md](jwt-bearer.md) | RFC 7523 §2.1 — GitHub Actions, Kubernetes |
| [transaction-tokens.md](transaction-tokens.md) | Per-transaction tokens inside a call chain |
| [mcp-authorization.md](mcp-authorization.md) | Acting as an authorization server for MCP |
| [key-rotation.md](key-rotation.md) | next → active → passive → retired |
| [logout.md](logout.md) | Three mechanisms, because none reaches everything |
| [logout-conformance.md](logout-conformance.md) | Proving a relying party actually honours it |
| [cors.md](cors.md) | Which endpoints, and the one that must never have it |
| [emerging-standards.md](emerging-standards.md) | Every non-settled specification implemented, with its draft status |

## Verifiable credentials and federation

| | |
|---|---|
| [oid4vci.md](oid4vci.md) | The authorization server's half of credential issuance |
| [openid-federation.md](openid-federation.md) | The Entity Configuration and metadata policy |
| [trust-marks.md](trust-marks.md) | Signed conformance statements |
| [uma.md](uma.md) | User-Managed Access 2.0 |

## Other protocols

| | |
|---|---|
| [saml.md](saml.md) | Signari as a SAML identity provider |
| [saml-source.md](saml-source.md) | Consuming somebody else's assertions |
| [ws-federation.md](ws-federation.md) | SharePoint and pre-SAML .NET |
| [ldap.md](ldap.md) | Applications that authenticate by binding |
| [ldap-source.md](ldap-source.md) | Reading an existing directory |
| [radius.md](radius.md) | VPNs, wireless controllers, switches |
| [eap-tls.md](eap-tls.md) | Certificate-based wifi and network login |
| [kerberos.md](kerberos.md) | SPNEGO for domain-joined machines |

## Users, groups and provisioning

| | |
|---|---|
| [scim.md](scim.md) | Pushing users into downstream applications |
| [scim-source.md](scim-source.md) | Receiving users from an upstream |
| [provisioning.md](provisioning.md) | SCIM, Google Workspace and Entra as targets |
| [directory-sync.md](directory-sync.md) | Google, Entra and LDAP as sources |
| [social-login.md](social-login.md) | Federated sign-in providers |
| [groups.md](groups.md) | Membership, and which clients may see it |
| [erasure.md](erasure.md) | Crypto-shredding a subject |

## Access control

| | |
|---|---|
| [policy.md](policy.md) | Access rules as a reviewable, testable file |
| [policy-diagram.md](policy-diagram.md) | Rendering the policy as a diagram |
| [authorization.md](authorization.md) | The AuthZEN authorization API |
| [device-posture.md](device-posture.md) | Device trust as a line in the policy file |
| [chrome-device-trust.md](chrome-device-trust.md) | Managed Chrome as a posture source |
| [impossible-travel.md](impossible-travel.md) | London, then São Paulo eleven minutes later |
| [impersonation.md](impersonation.md) | An administrator acting as a user, visibly |

## Reaching things that do not speak OIDC

| | |
|---|---|
| [forward-auth.md](forward-auth.md) | Putting Signari in front of an app that knows nothing about OIDC |
| [outposts.md](outposts.md) | LDAP, RADIUS or forward auth where the database must not be reachable |
| [remote-access.md](remote-access.md) | RDP, VNC and SSH in a browser tab |
| [desktop-login.md](desktop-login.md) | Windows credential providers, PAM, kiosks |

## Audit and events

| | |
|---|---|
| [events.md](events.md) | Telling other systems what happened |
| [ssf-caep.md](ssf-caep.md) | Shared Signals and CAEP, outbound |
| [shared-signals-receiver.md](shared-signals-receiver.md) | Receiving Shared Signals |
| [audit-export.md](audit-export.md) | Exporting the trail |
| [audit-streaming.md](audit-streaming.md) | Forwarding to syslog or a SIEM |
| [audit-chain-fork.md](audit-chain-fork.md) | How the hash chain forked under concurrency, and the fix |
| [logging-inventory.md](logging-inventory.md) | What is logged where (ASVS V16.1.1) |
| [egress-inventory.md](egress-inventory.md) | Every outbound connection (ASVS V13.1.1) |

## Compliance evidence

| | |
|---|---|
| [security-review-asvs.md](security-review-asvs.md) | OWASP ASVS 5.0, requirement by requirement |
| [security-review-rfc9700.md](security-review-rfc9700.md) | RFC 9700 (BCP 240) |
| [security-review-fapi2.md](security-review-fapi2.md) | FAPI 2.0 Security Profile |
| [security-review-nist-800-63b.md](security-review-nist-800-63b.md) | NIST SP 800-63B revision 4 |
| [fips.md](fips.md) | What survives a FIPS 140-3 build, and what cannot |

## The admin console

| | |
|---|---|
| [console-configuration.md](console-configuration.md) | What each screen answers, and why they are read-only |
| [admin-api.md](admin-api.md) | The write surface, its endpoints, and conditional writes |
| [extensibility.md](extensibility.md) | Extending a decision with your own service |
| [admin-tokens.md](admin-tokens.md) | Credentials for the Admin API |

## Migrating in

| | |
|---|---|
| [migrate-from-keycloak.md](migrate-from-keycloak.md) | Importing a realm |
| [migrate-from-authentik.md](migrate-from-authentik.md) | Importing an installation |
