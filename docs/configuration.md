# Every environment variable

One page, because the alternative is what this project had: configuration
described across twenty feature documents, with no place to see it whole — and
four real controls described nowhere at all, including the ones you need to send
an email.

A test enforces this list. `TestEveryEnvVarIsDocumented` fails when the code
reads a `SIGNARI_` variable this page does not mention, so it cannot drift the
way it already had.

## Required

| | |
|---|---|
| `SIGNARI_DSN` | PostgreSQL connection string |
| `SIGNARI_ROOT_KEY` | 32 random bytes, base64. Seals every stored secret. Lose it and sealed data — RADIUS secrets, bind passwords, SCIM tokens, signing keys — cannot be read, and the engine refuses to start rather than run with keys it cannot unwrap |
| `SIGNARI_ISSUER` | The issuer URL. Must match an instance in the database |

`SIGNARI_ROOT_KEY_REF` names an external key reference instead, for a
deployment keeping the root key outside the process environment.

## Listeners

| | |
|---|---|
| `SIGNARI_TLS_CERT`, `SIGNARI_TLS_KEY` | Serve HTTPS. Without them the engine warns: browsers refuse `__Host-` cookies over plaintext on anything but localhost, so sign-in silently fails to persist |
| `SIGNARI_TLS_CLIENT_CA` | Authorities that may issue client certificates for RFC 8705 mutual-TLS. Absent, `tls_client_auth` is refused rather than relaxed |
| `SIGNARI_ADMIN_ADDR` | Listen address for the admin API. Absent, it does not start |
| `SIGNARI_INSECURE_ISSUER` | `1` permits an `http://` issuer. Development only |
| `SIGNARI_PROXY_COOKIE_DOMAIN` | Parent domain for the forward-auth cookie |

## Mail

Without a host and a from-address, recovery links and email codes are **written
to the log instead of sent**, with a warning on every send.

| | |
|---|---|
| `SIGNARI_SMTP_HOST` | Required to send anything |
| `SIGNARI_MAIL_FROM` | Required. The envelope sender |
| `SIGNARI_SMTP_PORT` | Default 587 |
| `SIGNARI_SMTP_USERNAME`, `SIGNARI_SMTP_PASSWORD` | For an authenticated relay |
| `SIGNARI_MAIL_FROM_NAME` | Display name |

The last four were read by the code and documented nowhere, which meant an
authenticated relay — the normal case — could not be configured from the
documentation.

## SMS second factor

See [SMS](sms.md), including why it is the weakest factor offered here.

| | |
|---|---|
| `SIGNARI_SMS_GATEWAY` | `twilio` or `webhook`. A misspelling is **fatal at startup**, not a silent fallback |
| `SIGNARI_SMS_FROM` | Sending number, or a Twilio messaging service SID |
| `SIGNARI_SMS_TWILIO_SID`, `SIGNARI_SMS_TWILIO_TOKEN` | Twilio credentials |
| `SIGNARI_SMS_WEBHOOK_URL`, `SIGNARI_SMS_WEBHOOK_AUTH` | For any other provider. Must be https: the body carries a live code |

## RADIUS and EAP-TLS

See [EAP-TLS](eap-tls.md).

| | |
|---|---|
| `SIGNARI_RADIUS_ADDR` | Listen address. Absent, no RADIUS listener starts |
| `SIGNARI_RADIUS_ORG_ID` | Required when the database holds more than one organisation |
| `SIGNARI_EAP_TLS_CERT`, `SIGNARI_EAP_TLS_KEY` | The certificate supplicants verify |
| `SIGNARI_EAP_CLIENT_CA` | Authorities issuing supplicant certificates. All three or none — a partial configuration is refused |
| `SIGNARI_EAP_IDENTITY_FROM` | `cn`, `email` or `upn`. Use `upn` against Active Directory |

## LDAP (applications binding to this engine)

| | |
|---|---|
| `SIGNARI_LDAP_ADDR` | Listen address |
| `SIGNARI_LDAP_BASE_DN` | Base DN served |
| `SIGNARI_LDAP_ORG_ID` | Required with more than one organisation |
| `SIGNARI_LDAP_USER_ATTR` | Attribute carrying the username |
| `SIGNARI_LDAP_ANONYMOUS_SEARCH` | Permit anonymous search. Off by default |

## Device posture

See [device posture](device-posture.md).

| | |
|---|---|
| `SIGNARI_DEVICE_CA` | Device certificate authority. Strong evidence |
| `SIGNARI_DEVICE_TRUSTED_PROXIES` | CIDRs whose posture headers are believed. **Mandatory** for headers to be read at all; `0.0.0.0/0` is refused |
| `SIGNARI_DEVICE_MANAGED_HEADER` | Header asserting the device is managed |
| `SIGNARI_DEVICE_COMPLIANT_HEADER` | Header asserting it is also healthy |

`SIGNARI_DEVICE_COMPLIANT_HEADER` was undocumented while the policy condition it
feeds, `device_compliant`, was documented — so a rule could be written that
nothing could ever satisfy.

## CAPTCHA

See [CAPTCHA](captcha.md).

| | |
|---|---|
| `SIGNARI_CAPTCHA_MODE` | `off`, `adaptive` or `always` |
| `SIGNARI_CAPTCHA_PROVIDER` | Which service |
| `SIGNARI_CAPTCHA_SITE_KEY`, `SIGNARI_CAPTCHA_SECRET` | Credentials |
| `SIGNARI_CAPTCHA_AFTER_FAILURES` | Failures before adaptive mode challenges |
| `SIGNARI_CAPTCHA_FAIL_CLOSED` | Refuse sign-in when the provider is unreachable. Off by default: a provider outage should not become an authentication outage |

## Risk and trust

| | |
|---|---|
| `SIGNARI_GEOIP_DB` | MaxMind database for impossible-travel checks. Not bundled and not downloaded — an identity provider that fetches a binary blob on startup has added a supply chain to the authentication path |
| `SIGNARI_GEOIP_STATIC` | A fixed mapping, for testing |
| `SIGNARI_CA_BUNDLE` | Roots for outbound calls |
| `SIGNARI_SCIM_CA_BUNDLE` | Roots for SCIM targets specifically |
| `SIGNARI_ADMIN_TOKEN` | Bearer token for the admin API |

## Duo

| | |
|---|---|
| `SIGNARI_DUO_BASE_URL` | Overrides Duo's API host. Testing only |

## Test-only

Read by tests, never by a running engine. Listed so the sweep does not report
them as undocumented and so nobody sets them in production expecting an effect.

| | |
|---|---|
| `SIGNARI_TEST_DSN` | Database for the test suite |
| `SIGNARI_DESTRUCTIVE_TEST_DSN` | A **disposable** database for tests that deliberately break the audit chain. See [the audit chain fork](audit-chain-fork.md) |
| `SIGNARI_DNS_CHECK`, `SIGNARI_DNS_DOMAIN` | Gate the live DNS deliverability test |
| `SIGNARI_SMS_TWILIO_BASE_URL` | Points the Twilio client at a local server |
