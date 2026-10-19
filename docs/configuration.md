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

### Rotating the root key

| | |
|---|---|
| `SIGNARI_NEW_ROOT_KEY` | The replacement, read only by `signari keys rewrap-root`. Separate from `SIGNARI_ROOT_KEY` so the command can always tell "the key we are on" from "the key we are moving to"; one overloaded variable would leave it guessing, and guessing wrong produces a database nothing opens |
| `SIGNARI_NEW_ROOT_KEY_REF` | A name for the new key, and it **must differ from the current ref**. Stored rows record which key wrapped them, so two keys sharing a ref are indistinguishable — a later rotation could not tell which rows it had already done, and a failed one could not be diagnosed. The command refuses rather than proceeding |

```sh
export SIGNARI_NEW_ROOT_KEY="$(head -c 32 /dev/urandom | base64)"
export SIGNARI_NEW_ROOT_KEY_REF=v2
signari keys rewrap-root -dry-run   # does the whole job, then rolls back
signari keys rewrap-root
```

The rotation runs in **one transaction**. A partial rotation is not a degraded
state — it is a database where half the rows open with the old key and half with
the new, and no single key opens the deployment.

Afterwards, set `SIGNARI_ROOT_KEY` to the new value on **every** node before any
of them restarts. A node that comes up holding the old key refuses to start,
which is the designed behaviour rather than a fault: the engine compares the
stored `key_ref` against the key it was given and says so, instead of failing
later inside a signature. Keep the old key until every node is running on the new
one and a restore test has passed.

Anything sealed under a *subject's* key — a TOTP secret, for instance — needs no
attention: the subject's DEK is itself root-sealed and is re-wrapped, so
everything under it follows. A test enumerates every encrypted column in the
schema and fails the build if one is not classified, because a root-sealed column
the rotation does not know about becomes ciphertext nobody can ever open, and the
operator is told the rotation succeeded. It covers every `bytea` column, and every
column of any type whose name says it holds a token, a secret, a password or a
key, so a secret kept in a text column in the clear is caught too.

Some sealed values live inside a JSON payload rather than a column of their own:
a CIBA delivery waiting in the outbox holds the client's notification token, the
`auth_req_id` and, for push, the minted tokens, all sealed. The rotation re-seals
those in place, and the command's output lists them after the columns. A second
test finds every place the code seals with the root key and fails unless the
rotation knows that context, so a new sealed value cannot be left out.

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
| `SIGNARI_METRICS_ADDR` | Listen address for `GET /metrics` in the Prometheus text format. Absent, nothing is collected and nothing is served. **Its own listener, like the admin API**: serving metrics from the public listener would publish request rates, error rates and sign-in failure counts to anyone who can reach the sign-in page, which for an identity provider is the internet. No label ever carries an identifier — see below |
| `SIGNARI_SHUTDOWN_DRAIN` | How long to keep serving after SIGTERM before the listener closes, default `5s`. `/readyz` answers 503 for this whole window, so whatever routes traffic here has time to take the node out of rotation before the socket goes. Set it above your readiness probe's interval; `0` disables it, which is right locally and wrong behind a load balancer |
| `SIGNARI_SHUTDOWN_TIMEOUT` | How long in-flight requests may take to finish, default `20s`. Keep it **under** the orchestrator's grace period before SIGKILL — a timeout longer than the one that kills you never runs. Also caps the drain |
| `SIGNARI_OUTPOST_LDAP_INSECURE` | `1` permits an LDAP outpost (`signari outpost run -kind-outpost ldap`) to listen without TLS, as `-ldap-insecure` does. Without it, an LDAP outpost given no `-tls-cert` refuses to start, because every simple bind carries a password. See [outposts](outposts.md#ldaps) |
| `SIGNARI_ADMIN_INSECURE` | `1` permits the admin API to serve plaintext HTTP. Without it, an admin listener configured with no `SIGNARI_TLS_CERT` refuses to start rather than putting a bearer token that can erase a subject on the wire in clear. Only reasonable bound to loopback behind a terminator you control |
| `SIGNARI_INSECURE_ISSUER` | `1` permits an `http://` issuer. Development only |
| `SIGNARI_PROXY_COOKIE_DOMAIN` | Parent domain for the forward-auth cookie |

Every listener (public, admin and metrics) allows 10 seconds for headers, 30
to read a whole request, 60 to answer it and 120 for an idle keep-alive. These
are not settings. Before them a client could send its body a byte a minute and
hold a connection for as long as it liked. The remote-access tunnel is a
WebSocket, and upgrading to one clears these deadlines for that connection, so
a remote desktop is bounded by its session checks instead.

## Behind a reverse proxy

| | |
|---|---|
| `SIGNARI_TRUSTED_PROXIES` | Comma-separated addresses or CIDR prefixes of the proxies in front of the engine: the addresses the ingress controller connects from, not the whole pod network (see below) |
| `SIGNARI_CLIENT_IP_SOURCE` | `socket` (default), `x-forwarded-for` or `forwarded` (the RFC 7239 header) |

Every per-address decision keys on the client address: the sign-in and
client-secret failure budgets, the captcha, and access-policy network rules.
Behind a proxy the socket address belongs to the proxy, so with neither
variable set every client shares one bucket. Twenty wrong passwords from anyone
then lock everyone out for five minutes, and two hundred wrong client secrets
lock out every confidential client.

An IPv6 client is budgeted by its **/64**, not its full address. A host can
use any address in its subnet, and privacy addresses rotate by themselves. A
budget keyed by the /128 was reset by stepping to the next address, so it
limited nothing. Network rules and logs still see the full address. Until
October 2026 every budget and the captcha counter keyed the /128.

When a request arrives from one of the trusted proxies, the client is the
rightmost address in the forwarding chain that is not itself a trusted proxy.
The entries to the left of it were written by the client and are ignored. A
request from any other address is answered by its socket, whatever headers it
carries. A hop that is not an address ends the walk and the proxy's address is
used.

A `Forwarded` header with a quoted string that never closes is not read at all,
and the client address is unknown. Unknown means the shared `unknown` budget,
and it fails every network rule. Such a header could only have come from a
client. A client that sends `for=1.2.3.4;by="` leaves the quote open, so the
hop its proxy appends to the same line ends up inside the quote. Reading the
header anyway would let the client choose its own address. Using the proxy's
address instead would give the client whatever a network rule allows the
proxy's range.

The engine refuses to start on a configuration that protects nothing: a prefix
that covers every address (`0.0.0.0/0`, `::/0`), a header source with no
trusted proxy, or trusted proxies with no header to read. When forwarding
headers arrive from a private or loopback address and no proxy is trusted, it
logs one warning saying so.

```sh
SIGNARI_TRUSTED_PROXIES=10.42.0.17,10.42.1.23 SIGNARI_CLIENT_IP_SOURCE=x-forwarded-for signari serve
```

Name the addresses your proxy connects from and nothing wider. A trusted
address is believed about who the client is. Trusting a whole pod network
(`10.42.0.0/16` on k3s) therefore lets every pod in the cluster set
`X-Forwarded-For`, spend another client's budget and pass a network rule. If
the proxy has no stable address, give it one, or let a NetworkPolicy admit only
the proxy to the engine's port before you trust a range. This page and the Helm
chart's example used to trust the whole pod network.

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

### Every message is translated, and every message is plain text

The seven messages this engine sends — sign-in code, address confirmation,
password-reset request, password changed, passkey added, passkey removed,
recovery codes replaced — are message-catalogue keys under `mail.*` and `sms.*`,
so they translate with everything else and can be overridden per deployment
through the `locales/` directory under `SIGNARI_THEME_DIR`, like any other
string.

**There is no HTML.** That is a decision, not a gap. HTML mail from an identity
provider is a phishing lesson: it teaches people that a message about their
account legitimately contains a styled button they are expected to click, which
is the exact shape of the attack such a message would warn them about. Every
competitor ships HTML templates; shipping them here would close a feature gap by
training users into the failure mode. So the answer stays no, and the reason is
recorded rather than the feature quietly missing.

**Account-security notices are written in the account holder's language, taken
from `core.users.locale` — never from the request.** This is the half that looks
like a detail and is not. Those notices exist to reach the account holder when
somebody *else* triggered the action, and in that case the request carries the
attacker's `Accept-Language`. Rendering "your password was changed" from the
request would deliver the single most important message this system produces in
a language the victim may not read: it would arrive, say the right thing, be
useless, and the deployment would record that they were told.

The address-confirmation mail is the one genuinely interactive message and does
use the request's language — the person at the form is demonstrably the person
who will read it. A sign-in code uses the account holder's, because it is
delivered to the address on the account: if the person at the form is not the
holder, that email is the one telling them somebody has their password.

A user with no recorded preference falls back to the deployment default.

## SMS second factor

See [SMS](sms.md), including why it is the weakest factor offered here.

| | |
|---|---|
| `SIGNARI_SMS_GATEWAY` | `twilio` or `webhook`. A misspelling is **fatal at startup**, not a silent fallback |
| `SIGNARI_SMS_FROM` | Sending number, or a Twilio messaging service SID |
| `SIGNARI_SMS_TWILIO_SID`, `SIGNARI_SMS_TWILIO_TOKEN` | Twilio credentials |
| `SIGNARI_SMS_WEBHOOK_URL`, `SIGNARI_SMS_WEBHOOK_AUTH` | For any other provider. Must be https: the body carries a live code |
| `SIGNARI_SMS_ALLOWED_PREFIXES` | Comma-separated E.164 prefixes of the countries you serve, such as `+1,+44`. A number outside the list cannot be enrolled and is sent nothing. Unset allows every country; `signari doctor` and the startup log both say so |
| `SIGNARI_SMS_NUMBER_DAILY_LIMIT` | Messages one number may be sent per 24 hours, default `10`. Codes and account notices each get this many |
| `SIGNARI_SMS_ORG_DAILY_LIMIT` | Messages one organisation may send per 24 hours, default `1000`. Codes and account notices each get this many. Raise it for a large organisation that uses SMS sign-in daily |

Codes (sign-in and enrolment) and account notices draw on separate allowances.
Anybody can request a password reset for anybody, and each request texts a
notice. When the two shared one allowance, enough requests stopped a person
receiving sign-in codes, and enough across an organisation stopped everyone in
it. Notices are still capped, by their own ceiling, so the most a deployment
can be billed is twice each limit.

Text messages are the one factor where an attacker can spend your money. A
number on a high-cost range earns whoever leases that range a share of every
message sent to it. Enrolling such a number, or challenging it again and again,
bills the deployment; this is known as SMS pumping or toll fraud. Every message
therefore goes through one gate, whatever sends it: enrolment, the sign-in
challenge or an account notice. The gate checks the country list, then the
per-number and per-organisation ceilings. A refused message is not sent and is
recorded as an `sms.refused` audit event. `signari_sms_total` counts messages by
outcome (`sent`, `failed`, `refused_country`, `refused_number_budget`,
`refused_org_budget`). A malformed value in any of these settings stops the
server from starting.

## Second-factor guessing

| | |
|---|---|
| `SIGNARI_MFA_FAILURE_LIMIT` | Consecutive wrong codes before an authenticator app, or an account's set of recovery codes, is **switched off** rather than paused. Default and maximum **100**, the ceiling NIST SP 800-63B §3.2.2 sets; minimum 10. Anything else is **fatal at startup** |

Three limits sit at the code step, and only the last is this setting:

- **A pause.** Five wrong authenticator codes lock it for five minutes, and each
  further failure locks it again.
- **A rate.** Ten wrong codes per account per fifteen minutes, and the sign-in
  form's own per-address budget (twenty per five minutes), answer `429` with
  `Retry-After`. The account limit covers every kind of code, so an account whose
  second factor is not an authenticator app is bounded too.
- **A ceiling.** At the limit the factor is disabled: its codes are refused,
  right or wrong, until the person re-enrols (an authenticator app) or generates
  a new set (recovery codes) after signing in another way, or an operator removes
  it with `DELETE /admin/users/{userID}/factors/totp` or `…/factors/recovery`.
  The account holder is told on every channel they have, and the audit trail
  records `mfa.factor_disabled`. A disabled factor still counts as the account's
  second factor, so switching it off never leaves a password that signs in alone.

A wrong code is counted against the factor it could have been: six digits
against the authenticator app, twenty recovery-code characters against the
recovery codes. Only somebody who already entered the password reaches this
step, so unlike a password counter these cannot be used to lock out a stranger.

## Audit streaming

Forwarding the audit trail to a logically separate system (ASVS V16.4.3). Off
unless a destination is set; see [audit-streaming.md](audit-streaming.md).

| Variable | Meaning |
|---|---|
| `SIGNARI_AUDIT_WEBHOOK_URL` | POST events as NDJSON to a SIEM endpoint. Refused if it resolves into the private network |
| `SIGNARI_AUDIT_WEBHOOK_TOKEN` | Optional bearer token sent as `Authorization` to the webhook |
| `SIGNARI_AUDIT_SYSLOG_ADDR` | `host:port` of a syslog collector (TCP). Ignored if a webhook URL is also set |
| `SIGNARI_AUDIT_SYSLOG_TLS` | `1` to wrap the syslog connection in TLS |
| `SIGNARI_AUDIT_SYSLOG_HOSTNAME` | Hostname stamped into each RFC 5424 line (default `signari`) |

## Authenticator models (FIDO metadata)

Off unless a source is set. When set, the catalogue does two things:

- **Names models.** A passkey's AAGUID resolves to a device model — "YubiKey 5
  NFC" rather than the nickname a user typed — on the passkey-added and
  passkey-removed notices.
- **Anchors attestation.** A registration that conveys a certificate-chain
  attestation for a model the catalogue lists is checked against that model's
  roots, and a model the FIDO Alliance has marked revoked or compromised is
  refused. A model the catalogue does not list is still accepted.

The second is what makes `signari webauthn policy -aaguids` mean anything. An
AAGUID is the authenticator's own claim; only a chain anchored in the catalogue
vouches for it. Packed self-attestation does not, and neither does a chain to
a root the catalogue does not list. **Without a catalogue an approved-model
allow-list cannot verify any registration, so every registration under one is
refused.**

The chain for a listed model must reach one of that model's roots, whatever
names its certificates carry. If it doesn't, the registration is refused. This
covers a self-signed certificate, and also a certificate issued by a made-up CA
that has the same common name. Either one is an authenticator claiming to be a
model it cannot prove it is. Chains are read from the attestation statement's
`x5c`, which covers the packed, TPM, Android key, Apple and U2F formats. A
SafetyNet or compound attestation vouches for nothing here, and is not refused
for that.

The BLOB must be signed by the FIDO production root, wherever it comes from; an
unsigned or wrongly signed one is refused. The startup log says `loaded the FIDO
metadata catalogue` with a count when it worked.

Until October 2026 the official BLOB did not load at all. It is now signed
through a chain with two intermediates, and the WebAuthn library read only the
first of them. The log said `certificate signed by unknown authority`, and every
registration under an allow-list was refused.

| Variable | Meaning |
|---|---|
| `SIGNARI_FIDO_MDS_PATH` | Path to a mounted copy of the FIDO Metadata Service BLOB. Best for air-gapped or pinned deployments. Wins over the URL if both are set |
| `SIGNARI_FIDO_MDS_URL` | Fetch the BLOB from this URL (e.g. an internal mirror) instead of a file |
| `SIGNARI_FIDO_MDS_FETCH` | `1` fetches from the official FIDO endpoint. An explicit opt-in, because otherwise the engine would reach out to fidoalliance.org unasked |

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
| `SIGNARI_LDAP_INSECURE` | `1` permits the LDAP listener to accept binds without TLS. Without it, a listener given no `-tls-cert` **refuses to start**, because every simple bind carries a password. It used to warn and listen anyway, which is exactly what happens behind a TLS-terminating proxy that starts the engine with no certificate. Only reasonable bound to loopback behind a terminator you control. The LDAP outpost has `SIGNARI_OUTPOST_LDAP_INSECURE` for the same decision |
| `SIGNARI_LDAP_ORG_ID` | Required with more than one organisation |
| `SIGNARI_LDAP_USER_ATTR` | Attribute carrying the username |
| `SIGNARI_LDAP_ANONYMOUS_SEARCH` | Permit anonymous search. Off by default |
| `SIGNARI_LDAP_SEARCH_GROUP` | Group whose members may search the whole directory. **Empty means nobody**: everyone else who binds gets back only their own entry. Read by the LDAP listener and by an LDAP outpost. See [ldap.md](ldap.md#other-decisions) |
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
| `SIGNARI_CA_BUNDLE` | A PEM file of certificate authorities **added** to the system roots for every outbound HTTPS call: delivery, transmitter and issuer keys, `jwks_uri`, federation, discovery, directory sync. Read once at startup, and a file that cannot be read or holds no certificate **stops the process**. It used to be read by logout and event delivery alone, so a key set behind an internal authority failed with an unknown-authority error that pointed at nothing. Trusting an authority opens no address: an internal destination is still named in `SIGNARI_OUTBOUND_ALLOW_PRIVATE` |
| `SIGNARI_ALLOW_PRIVATE_DELIVERY` | Permit logout and event delivery to private, loopback and link-local addresses. **Off by default.** A `backchannel_logout_uri` is chosen by the *client*, so without the check a registered client can have this server POST a signed logout token into your internal network on every sign-out. Set `1` only if your relying parties genuinely are internal. Even then no cloud metadata endpoint is reached, in any form that carries one (see [Internal destinations](#internal-destinations)). The switch once replaced the address check with none at all, so a client's logout or CIBA notification URL could read the instance's credentials. Trusting an internal CA (`SIGNARI_CA_BUNDLE`) is a different decision and does not imply this one. |
| `SIGNARI_SCIM_CA_BUNDLE` | Authorities added for SCIM targets specifically, on top of `SIGNARI_CA_BUNDLE`. With that unset it also covers delivery, as it did before the general setting existed |
| `SIGNARI_OUTBOUND_ALLOW_PRIVATE` | Comma-separated addresses or prefixes, such as `10.20.0.0/16,192.168.7.9`, that outbound requests may reach although they are private. **Empty by default.** See [Internal destinations](#internal-destinations) below |
| `SIGNARI_ADMIN_TOKEN` | Bearer token for the admin API |

### Internal destinations

Every request the engine makes to a destination that comes from configuration
goes through one dialler, which checks the **address** at connect time, after
the name has been resolved. That includes webhooks, providers, an upstream
identity provider's token endpoint and keys, a jwt-bearer issuer's keys, an SSF
source's keys, SCIM targets, the old provider behind delegated sign-in, the SMS
gateway, Duo's API host and the FIDO metadata mirror. Private, loopback,
link-local and the special-purpose ranges are refused, and so is a redirect into
them.

When one of those really is inside your network, name it in
`SIGNARI_OUTBOUND_ALLOW_PRIVATE`. That widens what may be reached by exactly
what you list, for every one of the paths above, and the refusal message names
the setting. Two values are refused at startup, because each would switch the
check off under another name:

- a prefix of length zero (`0.0.0.0/0`, `::/0`, `::ffff:0:0/96`);
- anything covering a cloud metadata endpoint, which no destination needs and
  which is the first thing a forged request asks for. The endpoints are
  `169.254.169.254` and its IPv6 twin `fd00:ec2::254`, the container
  credentials range `169.254.170.0/24`, and `100.100.100.200`. So `fd00::/8`,
  `100.64.0.0/10` and `169.254.0.0/16` are refused, and narrower ranges beside
  the endpoints are not. The IPv6 forms that carry an endpoint are refused too:
  `64:ff9b::/96` (NAT64), `2002::/16` (6to4) and the IPv4-compatible form.
  Listing any of them would reopen a metadata service through a translator.
  So are NAT64's local-use prefix `64:ff9b:1::/48` and Teredo `2001::/32`,
  because the IPv4 address behind them cannot be read off the address, and so
  nothing can tell whether it is one of the endpoints.

`signari idp add` (discovery) and `signari idp add-issuer` (the issuer's keys)
apply the same list, so an internal issuer fails when you add it rather than at
the first sign-in.

An SMS webhook on loopback (`SIGNARI_SMS_WEBHOOK_URL=http://127.0.0.1:…`) is
reachable without the list: you wrote that exact address down. The allowance
covers loopback only, and a redirect from it is still checked.

`SIGNARI_ALLOW_PRIVATE_DELIVERY` is the older, wider switch for logout and event
delivery. It opens every private range for those paths. The metadata endpoints
and the two translators above stay refused. If your relying parties are
internal, prefer listing their addresses here.

## Appearance

| | |
|---|---|
| `SIGNARI_THEME_DIR` | A directory of `.html` files replacing the built-in sign-in pages. Read **once, at startup** — a half-written file is a normal state for a directory somebody is editing, and these are the pages people sign in through. A page here that fails validation is refused *individually*: that page falls back to the built-in one and a warning is logged, so a mistyped filename cannot lock every user out of every application. Validate before deploying with `signari theme check`, which exits non-zero. See [theming.md](theming.md) |

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

Every password hash in the process draws on one memory budget of 512 MiB: the
sign-in form, LDAP binds, RADIUS, outposts, signup and the Admin API. Each
evaluation takes what its stored parameters need. Our own Argon2id takes 19 MiB.
An imported Argon2id or scrypt hash takes what it declares, so a few expensive
imports queue behind each other rather than exhausting memory. An imported hash
that needs more than the whole budget cannot be verified, and its owner has to
reset the password. `signari_password_hashes_in_flight` against
`signari_password_hash_slots` shows how close the hasher is to saturation.

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

## Metrics, and the label rule

`SIGNARI_METRICS_ADDR` exposes `GET /metrics` in the Prometheus text format
(version 0.0.4). Six series: HTTP responses by route pattern, method and status
class; request latency; sign-ins by outcome; tokens by grant type; authentication
failures by mechanism.

Sign-ins and authentication failures are counted from the audit trail, so every
sign-in path that records one (the form, LDAP, RADIUS, an outpost, Kerberos, a
passkey) is counted. Tokens are counted where the token endpoint answers 200.
Client-authentication failures are counted where a client's secret,
certificate or assertion is checked. Until October 2026 those three series were
served and nothing incremented them, so they read zero however busy or
attacked the server was. `TestEveryDeclaredMetricIsIncremented` now fails on a
series that nothing outside a test increments.

**No label ever carries an identifier** — not a user id, subject, email,
username, client id, session id, token or IP address. This is enforced
structurally rather than by convention: every labelled metric declares the
complete set of values each label may take, and a value outside that set is
recorded as `other`. A bug that passes a subject id where an outcome was meant
produces `{outcome="other"}` and never the id.

The reason it is enforced this hard is that a metric leaves the boundary this
system controls. It is scraped into a time-series database, retained for months
and copied into dashboards, none of which
`POST /admin/subjects/{id}/erase` can reach. An identifier that reaches a label
is permanent, which makes it the one instrumentation mistake with no remediation.
The second cost lands sooner: one series per user is how a Prometheus server runs
out of memory, and it takes the monitoring down at the moment it is needed.

The HTTP counter is labelled by the **route pattern**, `/admin/users/{userID}`,
never the request path — a path containing a uuid *is* an identifier, and that is
how this mistake is normally made without anybody writing an identifier anywhere.
An unmatched request reports `route="other"` rather than what was probed for, so
a scanner cannot choose the label set.

There is deliberately no per-client, per-user or per-tenant series. This endpoint
answers "is the deployment healthy", never "what is this tenant doing" — the
second question belongs to the audit trail, which is queryable,
access-controlled and erasable.

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
| `SIGNARI_PAGE_PREVIEW_DIR` | Directory to write a rendered copy of every sign-in page into, for looking at. Four variants each — your system setting, light, dark, and one carrying brand colours — plus an `index.html` contact sheet per variant. `SIGNARI_PAGE_PREVIEW_DIR=/tmp/pages go test ./internal/pages/ -run Preview`. Use it when changing a page or writing a theme: validation proves the CSRF token survived, not that the button is still visible |
