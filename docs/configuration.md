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

## Build-time, not runtime

| | |
|---|---|
| `SIGNARI_SCHEMA_FINGERPRINT` | The schema digest a release binary is pinned to, supplied as a **docker build argument** — never as an environment variable at run time. Setting it in the environment of a running engine does nothing. Unpinned, the engine checks the schema *version* at startup and not the schema *shape*, so a hand-patched database is accepted; `signari doctor` reports which of the two a binary does. See [schema-pinning.md](schema-pinning.md) |

Listed here because a control nobody knows exists is a control nobody uses, which
is the same reason every runtime setting below is listed. It is separated because
exporting it into a running process is a reasonable thing to try and would have no
effect at all.

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

## Remote access (RDP, VNC, SSH in the browser)

See [remote-access.md](remote-access.md).

| | |
|---|---|
| `SIGNARI_GUACD_ADDR` | guacd's TCP listener, typically `127.0.0.1:4822`. Absent, remote access answers 503 |

## LDAP (applications binding to this engine)

| | |
|---|---|
| `SIGNARI_LDAP_ADDR` | Listen address |
| `SIGNARI_LDAP_BASE_DN` | Base DN served |
| `SIGNARI_LDAP_ORG_ID` | Required with more than one organisation |
| `SIGNARI_LDAP_USER_ATTR` | Attribute carrying the username |
| `SIGNARI_LDAP_ANONYMOUS_SEARCH` | Permit anonymous search. Off by default |
| `SIGNARI_LDAP_WRITE_GROUP` | Group whose members may Add, Modify, Delete and Modify DN. **Empty means nobody**, and the directory stays read-only. Members can create accounts, set any password, and delete entries — see [ldap.md](ldap.md) |

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
| `SIGNARI_ALLOW_PRIVATE_DELIVERY` | Permit logout and event delivery to private, loopback and link-local addresses. **Off by default.** A `backchannel_logout_uri` is chosen by the *client*, so without the check a registered client can have this server POST a signed logout token into your internal network on every sign-out. Set `1` only if your relying parties genuinely are internal. Trusting an internal CA (`SIGNARI_CA_BUNDLE`) is a different decision and does not imply this one. |
| `SIGNARI_SCIM_CA_BUNDLE` | Roots for SCIM targets specifically |
| `SIGNARI_ADMIN_TOKEN` | Bearer token for the admin API |

## Duo

| | |
|---|---|
| `SIGNARI_DUO_BASE_URL` | Overrides Duo's API host. Testing only |

## Client secrets

A client secret Signari generates is 256 bits from the system random source, so
it is hashed with **SHA-256 and compared in constant time**, not with Argon2.

Argon2 exists to make brute-forcing low-entropy human-chosen passwords
expensive. Against 256 bits there is no dictionary to run and no table to build
— brute force means 2^256 attempts, a number that does not shrink because the
hash is fast. Argon2 there costs a great deal and buys nothing.

Measured, on the `client_credentials` grant:

| | Argon2id | Entropy-appropriate |
|---|---|---|
| p50 | 33.49 ms | **0.84 ms** |
| p99 | 40.25 ms | **1.97 ms** |
| Throughput (16-way) | 174 req/s | **3402 req/s** |

**19.6× the throughput**, for no loss of security — the property protecting the
secret is its entropy, not the cost of hashing it.

A secret whose entropy is *not* established — one imported verbatim from another
provider, which could be `hunter2` — keeps Argon2. Verification dispatches on the
stored format, so existing hashes keep working and are never weakened.

User passwords keep Argon2id, unchanged. They are exactly the low-entropy case
it was designed for.

## Password policy

One gate every new password passes through — sign-up, recovery, admin, CLI. See
[password-policy.md](password-policy.md).

| | |
|---|---|
| `SIGNARI_PASSWORD_MIN_LENGTH` | Floor, counted in characters not bytes (default 8) |
| `SIGNARI_PASSWORD_MIN_SCORE` | Guess-strength floor, 0–4 (default **3**). No network, nothing leaked, so it is on by default — a default that accepts `Password123!` ships weak passwords |
| `SIGNARI_PASSWORD_HISTORY` | Refuse reuse of the last N passwords. 0 (default) disables it |
| `SIGNARI_PASSWORD_BREACH_CHECK` | `1` to consult Have I Been Pwned. Off by default: a binary upgrade must not silently start making outbound calls |
| `SIGNARI_PASSWORD_BREACH_LIST` | Path to a local SHA-1 corpus, for deployments that cannot call out at all |
| `SIGNARI_PASSWORD_BREACH_REQUIRED` | `1` to refuse when the corpus is unreachable. Default lets it through and logs loudly |
| `SIGNARI_PASSWORD_BREACH_RECHECK_DAYS` | Re-consult the corpus at sign-in, at most this often per credential. A password that was clean when chosen and is breached now is flagged for change |

## Chrome Enterprise device trust

A third device posture source, feeding the same `device_managed` and
`device_compliant` a policy already speaks. See
[chrome-device-trust.md](chrome-device-trust.md).

| | |
|---|---|
| `SIGNARI_CHROME_CREDENTIALS` | Google service account JSON with the Verified Access scope. Absent, this source is off |
| `SIGNARI_CHROME_CUSTOMER_ID` | **Required.** Your Workspace customer id. Without it a device managed by *any* customer counts as managed, which means nothing |
| `SIGNARI_CHROME_IMPERSONATE` | Administrator the service account acts as, if delegation requires one |
| `SIGNARI_CHROME_HEADER` | Where the browser puts its signed challenge response (default `X-Verified-Access-Challenge-Response`) |
| `SIGNARI_CHROME_REQUIRE_FIREWALL` | `1` adds Google's `osFirewall` signal to the compliance verdict. Off by default: disk encryption and screen lock are near-universal on managed fleets, the host firewall is not, and requiring it unasked locks out estates that deliberately run without one. An absent signal counts as not satisfied, like every other signal |

## Kerberos (SPNEGO)

See [kerberos.md](kerberos.md). `signari kerberos check` proves a keytab before
a user meets it.

| | |
|---|---|
| `SIGNARI_KERBEROS_KEYTAB` | Service keytab. Absent, `/login/kerberos` is not registered at all |
| `SIGNARI_KERBEROS_REALM` | Realm, upper case by convention. Principals from any other realm are refused |
| `SIGNARI_KERBEROS_SPN` | Service principal, e.g. `HTTP/auth.example.com` |
| `SIGNARI_KERBEROS_STRIP_REALM` | `1` to map `alice@EXAMPLE.COM` to `alice` rather than `alice@example.com` |

## Outposts

Set on the OUTPOST, not the core. See [outposts.md](outposts.md).

| | |
|---|---|
| `SIGNARI_OUTPOST_TOKEN` | Token from `signari outpost create`. An alternative to `-outpost-token`, so it does not appear in the process list |

Outpost kinds: `ldap`, `radius`, `proxy`, and `desktop` — the last for a
credential provider or PAM module, which may verify a second factor as well as a
password. See [desktop-login.md](desktop-login.md).

## FIPS 140-3

No configuration; it is a build and runtime mode. See [fips.md](fips.md) for what
works under it and what cannot.

## Test-only

Read by tests, never by a running engine. Listed so the sweep does not report
them as undocumented and so nobody sets them in production expecting an effect.

| | |
|---|---|
| `SIGNARI_TEST_DSN` | Database for the test suite |
| `SIGNARI_DESTRUCTIVE_TEST_DSN` | A **disposable** database for tests that deliberately break the audit chain. See [the audit chain fork](audit-chain-fork.md) |
| `SIGNARI_DNS_CHECK`, `SIGNARI_DNS_DOMAIN` | Gate the live DNS deliverability test |
| `SIGNARI_SMS_TWILIO_BASE_URL` | Points the Twilio client at a local server |
| `SIGNARI_ALLOW_SKIPPED_DB_TESTS` | Set to `1` to run the suite without a database. Most tests then skip, and the run proves almost nothing — the flag exists so that is a stated choice rather than the accident of an unset `SIGNARI_TEST_DSN`, which once let a mutation harness report eight covered guards as uncovered |
| `SIGNARI_AUTHZEN_INTEROP` | Path to the OpenID AuthZEN interop fixture `decisions-authorization-api-1_0-02.json`. Set to run the working group's 43-scenario decision suite against this engine |
