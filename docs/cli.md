# `signari` — command reference

Every command the binary dispatches. Kept complete by a test
(`TestEveryCommandIsDocumented`), because the usual failure is not a page that
rots — it is a command that ships and is never written down, which nobody finds,
because the person who added it knows it exists and everybody else cannot know
to look for it.

Most commands need `SIGNARI_DSN`. Anything touching sealed material also needs
`SIGNARI_ROOT_KEY`. See [configuration.md](configuration.md).

A command that edits configuration is cancelled after 60 seconds, so one stuck
behind a lock fails instead of hanging a deploy script. A command whose work
grows with the data has no limit: `serve`, the three `migrate` commands that
apply, `export audit`, `audit checkpoint`, `audit verify`, `audit archive`, both `import` commands, `dir sync`,
`scim sync`, `kerberos sync`, `keys rewrap-root`, `janitor once` and `restore
finalize`. `proxy
check` has five minutes. `-timeout` replaces any of these, and `-timeout 0`
removes the limit. Until October 2026 every command was cancelled at 60 seconds,
which cut off an audit export of a large trail, and a migration building an
index or waiting for another migrate, partway through.

A command that names something by a slug, a name or an address also takes
`-org`. Those are unique within one organisation at most. Without `-org`, the
name must belong to exactly one organisation in the deployment, or the command
refuses and asks which. A single-organisation deployment never needs it. This
covers the SCIM target, directory source and RADIUS client commands,
`user locale` and `duo enroll`. Until October 2026 these acted on every
tenant's row of that name, or on whichever one came back first.

Each command takes its own flags, and `-dsn` and `-timeout`: a flag it does not
read is refused rather than ignored, and so is a word after the flags, where
parsing stops. `signari help <command>` and `signari <command> -h` show what one
command takes. A command exits 0 when it worked, 1 when it failed, 2 when it was
used wrongly (no such command, a flag it does not take, one it needs left out),
and `signari plan` exits 3 when the deployment differs from the file. Until
October 2026 one set of every flag served every command, so a mistyped command's
flags were accepted and did nothing, and every failure exited 1.

`user create`, `group create`, `admin-token create`, `admin-token list`,
`admin-token revoke`, `role list` and `role revoke` also run with no database:
given `-admin-url`, they make their change through the Admin API as the token in
`SIGNARI_ADMIN_TOKEN` or `-token-file`, so it is recorded under that token and
refused what the token may not do, from a machine that holds no database
credentials. `-org` is then required, there being no only organisation to
assume, and `admin-token create -groups`, which names groups, is refused in
favour of `signari api` with their ids. Every other change is one `signari api`
request away.

A listing that takes `-o json` prints its rows as a JSON array of objects, for a
script to read instead of the columns, and `version -o json` one object; its
text is unchanged without it. `signari help <command>` shows whether a command
takes it. A secret is never in either.

## Schema

| | |
|---|---|
| `signari migrate bootstrap` | Apply 0001 — roles, schemas, grants. Needs a **superuser** DSN |
| `signari migrate up` | Apply 0002+ as `signari_engine`. The ordinary upgrade step. Two runs at once take turns: the second waits for the first, then finds nothing to apply. `-lock-timeout` (10s by default; 0 for none) fails a statement that waits longer for a lock, so a migration queued behind a long transaction does not hold every query on the table, and it can be run again; `-statement-timeout` bounds each statement (none by default). A migration whose first line is `-- signari:no-transaction` runs outside a transaction, so it can build an index `CONCURRENTLY` without blocking writes; it may hold only `CREATE INDEX CONCURRENTLY IF NOT EXISTS` and `DROP INDEX CONCURRENTLY IF EXISTS`, and an index a failed build left invalid is dropped so the next run builds it. Against a database ahead of the binary it applies nothing and says so; whether the binary may serve it is `verify`'s answer. See [upgrading.md](upgrading.md) |
| `signari migrate all` | Bootstrap then up, in one invocation, for containers |
| `signari migrate status` | Applied version, pending migrations, live fingerprint, whether it matches what the ledger recorded for the latest migration, and the oldest binary that may serve the database |
| `signari migrate fingerprint` | Print **only** the schema fingerprint, for pinning a release build. See [schema-pinning.md](schema-pinning.md) |
| `signari verify` | Run the startup schema gate and exit: the version, which may be ahead of the binary when every migration since was declared compatible with the one before, then the fingerprint, tenant boundary included, against the build's pin or, unpinned, the ledger. Use in a deploy pipeline. See [schema-pinning.md](schema-pinning.md) and [upgrading.md](upgrading.md) |

The engine refuses to start when the database version and the binary disagree,
naming `migrate up` — a binary running against a schema it was not built for is
a class of failure that shows up as data corruption rather than an error.

## Running it

| | |
|---|---|
| `signari serve` | The engine. `-addr`, `-tls-cert`, `-tls-key` |
| `signari doctor` | Check a deployment's configuration and report what is wrong, including the audit chain, organisation tables without forced row-level security, janitor backlog, the largest tables, the PostgreSQL version and the schema against its ledger. Exits non-zero on a critical finding. `-json` prints the report as JSON for a script: `signari doctor -json \| jq '.findings[] \| select(.severity == "critical")'` |
| `signari version` | The release, commit, Go toolchain, FIPS module, the schema version this binary expects and the fingerprint it is pinned to (`none` when unpinned). Needs no database. `scripts/build-release.sh` reads the `pinned` line before it tags. See [schema-pinning.md](schema-pinning.md) |
| `signari janitor once` | Run one janitor pass by hand — expiry, sweeping, parking |
| `signari plan` / `signari apply` | Declarative configuration from a file. `apply -prune` to delete what the file omits. `plan` exits 3 when the deployment differs from the file, so a pipeline can tell drift from failure |
| `signari help` | Every command, or `signari help <group>` the commands of one group and `signari help <command>` what one does and the flags it takes. Needs no database |
| `signari api` | `signari api <METHOD> <path> [-data JSON\|@file\|-] [-if-match N]`: one request to any Admin API route, as the token in `SIGNARI_ADMIN_TOKEN` or `-token-file` at `-admin-url` or `SIGNARI_ADMIN_URL`, e.g. `signari api GET /admin/me` or `signari api PATCH /admin/organizations/<id>/settings -data '{"session_limit": 5}' -if-match 412`. Prints the answer; a refusal exits 1 with the API's error. Needs no database: the change is the API's, recorded under that token and refused what its scopes and roles do not allow. See [admin-api.md](admin-api.md) |
| `signari completion` | `bash` or `zsh`: a completion script for the commands, each group's verbs and each command's flags, e.g. `source <(signari completion zsh)`. Needs no database |

## Instances, organisations, users

| | |
|---|---|
| `signari instance create` | An issuer and its first signing keys |
| `signari instance add-alias` | `-alias https://old.example.com [-retire-after 2026-12-31]`: a legacy issuer this instance also claims while relying parties move across, for the instance `SIGNARI_ISSUER` names. Accepted by userinfo, introspection and the other token checks from the next request, until its retirement. See [migrating](migrate-from-authentik.md#issuer-aliasing-for-the-applications-you-cannot-reconfigure) |
| `signari instance retire-alias` | `-alias <url> [-retire-after <when>]`: stop accepting an alias, now unless told when. Clients pinned to it get the instance's own issuer from then on |
| `signari instance aliases` | The instance's aliases, their retirement, and how many clients are pinned to each |
| `signari instance session-limit` | How many sessions one person may hold at once, and whether the limit denies the new sign-in or ends the oldest session. `0` is unlimited and is the default |
| `signari instance remember-device` | `-org <id> -days 30`: offer a "remember this device" box after a second factor. A browser that ticked it skips the sign-in flow's `mfa` stage for that many days, 1 to 90, unless the application requires multi-factor (`acr_values=2`, or `client set-acr`); such a session is single-factor. `0`, the default, offers no box and stops every remembered device counting at its next sign-in. People list and forget theirs at `/account/devices`, and signing out everywhere forgets them all. Audited |
| `signari instance org-status` | `-org <id> -status suspended\|active`: suspend an organisation, refused at every entry point from the next request, or reactivate it. Nothing is ended, so a session or grant with time left resumes on reactivation. What is refused is listed under `PATCH /admin/organizations/{orgID}` in [admin-api.md](admin-api.md). Audited `admin.organization_suspended` / `admin.organization_reactivated` |
| `signari instance org-delete` | `-org <id>` says what deleting the organisation would remove and prints a code; `-org <id> -confirm <code>` deletes it, refused unless it was suspended first (`org-status`) and the code was read since nothing changed. Every person is erased as `erase subject` does (key shredded, sessions ended, applications told), then its clients and the organisation go, in one transaction. The audit trail is kept, since it is append-only and names people by id only. Audited `admin.organization_deleted`. Not offered by the Admin API: it is done with the database in front of you |
| `signari instance org-budgets` | `-org <id> [-tokens-per-minute N] [-sign-ins-per-minute N]`: show an organisation's budgets, or set them: tokens its clients may be issued and sign-ins its pages may take, a minute, counted for it alone across every instance. A flag left out keeps that budget, `0` restores the deployment's default (6000 tokens, 1200 sign-ins). The same as `PUT /admin/organizations/{orgID}/budgets` |
| `signari instance new-device-notice` | `-org <id> -notice on\|off`: whether a sign-in from a new device is mailed (and texted, where a number is verified) to the person. A device is a browser on a system, read from the User-Agent without versions, and it is new when none of the person's sessions of the last 90 days came from it. A person's first sign-in in that time, and one on a device they chose to remember, are not told. On by default. Audited `org.new_device_notice_set` |
| `signari instance reauth-window` | `-org <id> -window 10m`: how recently a session must have been signed in for its holder to change the account from `/account` — the password, the sign-in methods, the recovery codes, the sessions and the connected applications. An older session is sent to sign in again and brought back to the page. 1m to 24h, default 10m. An impersonation session changes none of them, whatever its age. Until October 2026 the window was fixed and held the sign-in methods only. Audited |
| `signari instance session-lifetime` | `-org <id> [-lifetime 12h] [-idle 30m] [-offline 720h] [-persistent on\|off]`: `-persistent on` makes the sign-in page offer "stay signed in on this device". A session signed in with it ticked gets a cookie that survives the browser closing, for what the session has left of its lifetime; nothing else about the session changes, so its idle limit and a sign-out end it as before. Off by default. The choice travels with a passkey or a provider's sign-in as well as the password form, and the second-factor page's "remember this device" is a different setting. A sign-in page that cannot tell which organisation it belongs to (a bare `/login` on a deployment with several) does not offer it. how long a session lasts from sign-in (5m to 720h, default 12h), and how long it lasts unused (5m up to the lifetime; `0` for no limit, the default). `-offline` is how long a grant of `offline_access` lasts from when it is given, whether or not the person stays signed in (1h to 8760h, default 720h; `0` ends each with its session, as every one did until October 2026). An offline grant survives a logout or its session expiring, and ends when every session the person has is ended (a password changed or reset, a factor reset, deactivation, "sign out everywhere") or when they remove the application. The person sees until when at `/account/connected`. A grant given in an impersonation is never offline. Using it means the browser presenting its cookie, or an application refreshing a token under it, and the use is written at most once a minute. A session never outlives the lifetime it was signed in with, however much it is used, and the database refuses a deadline past it. A shorter lifetime or an idle limit applies to live sessions at once; a longer lifetime lengthens none already signed in. Either flag left out keeps the current value. Until October 2026 every session lasted twelve hours, used or not. Audited |
| `signari instance password-binds` | `-org <id> -binds refuse_when_mfa` or `allow`. Whether LDAP binds, RADIUS PAP and outposts, which carry **only a password**, may sign in somebody the sign-in flow would ask for a second factor. Organisations created since migration 0128 refuse; older ones allow until changed, and `signari doctor` names each one with a listener or outpost. Audited, and bumps the configuration version. See [LDAP](ldap.md#a-password-alone-and-a-second-factor) |
| `signari instance related-origins` | `-issuer <url> -related-origins https://example.co.uk,https://shop.example`: further origins a passkey made under the instance's RP ID may be used from, such as a country or brand domain, or an application on another host (WebAuthn Level 3 related origin requests). Each is an https origin in lower case, with no path; empty clears them. The engine accepts a ceremony from each, and a browser allows it only when `https://<rp_id>/.well-known/webauthn` lists it. The engine serves that document when the RP ID is its own host; otherwise the command prints it to host there. An application on a related origin can also derive its own keys from the passkey with the WebAuthn PRF extension, at its own origin |
| `signari instance webauthn` | The WebAuthn Relying Party ID passkeys are bound to. **Passkeys are unavailable until this is set.** A credential made under `example.com` works on `login.example.com`; one made under `login.example.com` does not work on `example.com`, and changing the value invalidates every credential already enrolled |
| `signari user create` | A user with a password, in the organisation `-org` names. Subject to the [password policy](password-policy.md). Without `-org` it uses the only organisation there is and refuses when there are several. Until October 2026 it, `client create`, `rac add` and `audit checkpoint` took the oldest organisation whatever `-org` said |
| `signari user locale` | The language this person's security notices are written in, as a BCP 47 tag, and their pages once they next sign in. Empty returns them to the deployment default. The person sets the same thing from their account page |
| `signari user remove-factor` | `-email <address or username> [-org <id>] -factor totp\|email_otp\|sms_otp\|duo\|webauthn\|recovery [-factor-id <id>]`: remove a sign-in method from somebody whose phone or key is lost, as the Admin API's `DELETE /admin/users/{userID}/factors/{kind}` does. Every session they hold ends, and they are told by email and a verified number, delivered by the server's outbox. A passkey is named by its id, since a person may hold several; `recovery` alone removes the whole set. Their next sign-in enrols a new method where a flow requires one. Audited `admin.factor_removed` |
| `signari user passkey-link` | `-email <address or username> [-org <id>] [-link-expires <duration>]`: email somebody a link that registers one passkey with no session, for a new starter with no password or somebody whose only way in is lost. It works once, for a day unless `-link-expires` says otherwise (1m to 168h), and replaces any earlier link they had not used. The token is minted as serve's outbox sends the email and only its hash is kept, so it is never printed: whoever runs this cannot use it. Refused for an account that is not active or has no address. The Admin API's `POST /admin/users/{userID}/passkey-link` does the same. Audited `admin.passkey_link_issued` |
| `signari user approve` | `-email <address or username> [-org <id>]`: let a self-sign-up waiting for approval (`signup enable -require-approval`) sign in, and have the engine tell them so. Refused for an account that is not pending. The Admin API's `PATCH /admin/users/{userID}` with `active: true` does the same. Audited `admin.user_approved` |
| `signari user unlock` | `-email <address or username> [-org <id>]`: clear what wrong guesses charged to this person, the sign-in delay and the per-account and second-factor budgets, for somebody sent to wait who cannot. The next wrong password is charged as before; the per-address budgets are left. The Admin API's `DELETE /admin/users/{userID}/throttle` does the same. Audited |
| `signari instance sms-numbers` | `-org <id> -sms-numbers stored\|hashed`: whether the organisation keeps each person's SMS number, or only a keyed hash of it under the person's own key. Hashed, the person types their number on the code page to be texted a code, and is texted no account notices; a number already stored is replaced by its hash at the person's next sign-in. Back to stored applies to numbers enrolled from then on, since a hash cannot be read back. See [sms](sms.md). Audited |
| `signari instance totp-policy` | `-org <id> [-totp-algorithm SHA1] [-totp-digits 6] [-totp-period 30s]`: what new authenticator apps are enrolled with: SHA1, SHA256 or SHA512; 6 or 8 digits; 30s or 60s. Each run writes all three, and a credential keeps what it was enrolled with, so a change never breaks a phone that already works. Not every app computes SHA256 or SHA512, or shows 8 digits or 60s codes; one that does not shows codes that never match. SHA256 is what lets a deployment under `fips140=only` enrol apps at all ([fips](fips.md)). Audited |
| `signari user assign-otp` | `-email <address or username> [-org <id>] -seed-file <path> -code <now> [-hotp -next-code <after>] [-totp-algorithm] [-totp-digits] [-totp-period]`: make a hardware OATH token the person's authenticator, replacing the one they have, from the seed its vendor shipped. The file holds the seed as base32, or hex after `hex:`, so it never appears in a process list or shell history. `-code` is what the token shows now. A counter-based token (`-hotp`) gives two consecutive codes, found among its first 1000 presses, which also set where its counter stands; at sign-in it accepts the next ten presses. A seed whose codes do not match is refused, rather than stored to refuse the person at their next sign-in. The person is told, by email and a verified number. Audited `mfa.otp_token_assigned` |
| `signari instance login-throttle` | `-org <id> [-free-attempts 3] [-max-delay 15m]`: the sign-in delay. That many wrong passwords for one account are free, then each costs a wait of 1s doubling to the longest, and each failure counts for an hour. 1 to 20 and 1m to 24h; either alone leaves the other. A delay, not a lockout, which would be a button that disables any account somebody can name. Audited |
| `signari group create` / `group list` / `group member` / `group release` | Groups, membership, and which clients may see them |
| `signari group impersonation` | Grant or revoke a group's ability to act as another user. **Deliberately not in the Admin API**: a `groups:write` token is issued for day-to-day administration, and letting one grant this would turn every such token into a way to become anybody. See [impersonation.md](impersonation.md) |
| `signari webauthn policy` / `webauthn show` | Which authenticator models an organisation accepts, and what attestation to ask for. An allow-list admits only a registration whose attestation is a certificate chain anchored in the FIDO catalogue (see `SIGNARI_FIDO_MDS_*` in [configuration](configuration.md)), because any other AAGUID is chosen by the authenticator being filtered. Without a catalogue, every registration under an allow-list is refused. `-refuse-cloned` (on by default) refuses a passkey sign-in whose signature counter did not advance, the sign of a copied authenticator; `-refuse-cloned=false` records it and signs the person in. Synced passkeys report no counter and are unaffected. Until October 2026 the refusal could not be switched on. The ceremony is set here too, and each run writes the whole policy, so a flag left out returns to its default. `-user-verification required` (the default) refuses a passkey sign-in without a PIN or biometric. `preferred` admits it as a single factor, so a flow that asks for a second factor asks for one, and a key touched again is not it. `-resident-key required` (the default), `preferred` or `discouraged`: a credential that is not discoverable signs in only as a second factor. `-attachment platform` or `cross-platform` limits the kind of authenticator the browser offers. That is a request to the browser, and only an allow-list with attestation proves the model. `-algorithms` holds a registration to the listed algorithms, in order of preference, from ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512 and EdDSA. Left out, all ten are offered in that order, as before the setting existed. `-ceremony-timeout` (30s to 5m, default 5m) is how long the browser waits and the challenge is held. `-hints` passes `security-key`, `client-device` or `hybrid` to the browser. The Admin API's `/admin/organizations/{orgID}/webauthn-policy` reads and sets the same policy |
| `signari invite create` / `invite list` | Invitations. `invite create -org <uuid> [-email <addr>] [-groups <list>] [-expires 168h] [-send]` prints the link once, or with `-send` (which needs `-email`) has the engine mail it instead, through the outbox, so it is never printed. The list shows each one's id |
| `signari invite revoke` | `-org <uuid> -invitation <id>`: close an open invitation, so its link stops working at once. Audited. Until October 2026 sign-up refused a revoked invitation and nothing could revoke one, so a link sent to the wrong address stayed good until it expired |
| `signari signup enable` / `signup disable` / `signup show` | Self-service sign-up, and which email domains may use it. `signup enable -org <id> -domains <list> [-groups <list>] [-verify-email=false]`: by default a new account proves its address with a code sent to it before its first sign-in (the sign-in flow's `verify_email` stage), since without that a domain in the rule is only what somebody typed; `-verify-email=false` lets accounts in on an unproved address, and their tokens say `email_verified: false`. `-require-approval` makes each new account wait, `pending` and unable to sign in, until an administrator approves it |
| `signari registration enable` / `registration token` | Dynamic client registration (RFC 7591). `-allow-confidential` lets a registrant asking for a secret get one; the whole policy is written each run, so it is off unless repeated. See [dynamic-registration.md](dynamic-registration.md) |
| `signari registration revoke` | `-org <uuid> -name <n>` or `-token-id <uuid>`: stop a registration token before it is spent or expires. `-name` is refused when two live tokens share it, naming both |
| `signari erase subject` | Erase a person: destroy their data-encryption key so ciphertext, including in backups, is permanently unreadable, and remove their account, which holds their address and names, after ending its sessions. A person with no key is erased too. See [erasure.md](erasure.md) |
| `signari restore finalize` | After restoring a backup and before serving it: end every session and refresh family the restore brought back, queue a back-channel logout and a CAEP session-revoked event for each application, and record `restore.finalized`. `-confirm` repeats the database's name, because it signs everybody out. Running it again ends only what is still live. See [runbook-backup-restore.md](runbook-backup-restore.md) |

There is **no** `signari delete`. This page listed one for months; it has never
existed, and the test that exists to catch exactly that could not see this table
— see the note at the end of this page.

## Clients

| | |
|---|---|
| `signari client create` | Register an OAuth client in the organisation `-org` names (or the only one there is) |
| `signari client set-keys` | Switch to `private_key_jwt` with a public JWKS |
| `signari client set-tls` | mTLS client authentication and certificate-bound tokens |
| `signari client set-dpop` | RFC 9449 §5.2: require a DPoP proof on every token request from this client |
| `signari client set-pkce` | `-client-id <id> [-require-pkce=false]`: whether this client's authorization requests must carry a PKCE challenge. Every client requires one from creation; the opt-out is for an application that cannot send one, and a public client cannot take it, here, at `client create -public` or through the Admin API. The schema refuses one as well (`clients_public_requires_pkce`). Audited, and moves the configuration version |
| `signari client set-logout` | `-client-id <id> -post-logout-redirects a,b -frontchannel-uri https://… [-frontchannel-sid=false] [-backchannel-uri https://… -backchannel-sid=false]`: where RP-initiated logout may return the browser, and the front-channel logout URI. Those three are set together; empty clears. `-backchannel-uri` is where a logout token is posted at sign-out, https with no fragment, and `-backchannel-sid` whether it carries the session's sid; each is left alone unless given, since dynamic registration sets them too. Until October 2026 only dynamic registration could set the back channel, unchecked. See [logout](logout.md#registering-a-clients-sign-out) |
| `signari client set-lifetimes` | `-client-id <id> [-access-ttl 10m] [-refresh-ttl 720h] [-consent-ttl 2160h\|never]`: how long this client's tokens live, and how long a person's consent to it lasts. Access tokens from a minute to an hour, refresh tokens from five minutes to a year; each alone leaves the others. An access token's lifetime is also how long it keeps working after it is revoked, and lowering it does not reach tokens already issued. Default 5m and 720h. A consent from an hour to ten years, or `never` (the default): past it, the next authorization asks the person again, for what is requested then, and nothing of the old consent comes back with their answer. Tokens already issued keep their own lifetimes |
| `signari client set-alg` | `-client-id <id> -alg <alg>`, one of ES256, RS256, PS256 or EdDSA: what signs this client's ID and access tokens. Default ES256; EdDSA is per client only. Refused unless the instance holds an active key of that algorithm (`signari keys rotate -alg <alg>` publishes one) |
| `signari client set-issuer-alias` | `-client-id <id> -alias <url>`: mint this client's ID and access tokens under a legacy issuer the instance claims, so the application moves with a DNS change. Only a live alias of the client's own instance; with no `-alias` the pin is cleared |
| `signari client set-par` | `-client-id <id> [-require-par=false]`: refuse any authorization this client did not push first, RFC 9126's `require_pushed_authorization_requests`; `=false` lifts it. See [par](par.md) |
| `signari client set-admin-api` | `-client-id <id> [-admin-api=false]`: let the client obtain tokens for the Admin API, the audience `<issuer>/admin`, which act with their holder's [roles](admin-api.md#administrative-roles); `=false` refuses its tokens there from the next request. Changing such a client through the Admin API then needs `privileged-users:write` |
| `signari client set-first-party` | `-client-id <id> [-first-party=false]`: skip the consent screen for this client, which is yours; `=false` shows it again. Every other check still applies |
| `signari client set-acr` | `-client-id <id> -minimum-acr 2`: require multi-factor for this client whatever its request asks for; `1` accepts a single factor again; `3` requires a passkey or security key, `4` one bound to its device ([flows](flows.md#above-multi-factor-a-passkey-or-security-key)). A session with one factor is asked for a second at the next authorization, someone with none enrolled is refused with `unmet_authentication_requirements`, and a device or backchannel approval or a refresh from such a session is refused. The Admin API's client PATCH (`minimum_acr`) and `signari apply` set the same. See [flows](flows.md#requiring-multi-factor-for-one-application) |
| `signari client set-exchange` | `-client-id <id> -exchange-audiences a,b`: grant RFC 8693 token exchange to a confidential client, for itself and the audiences named; `-may-exchange=false` withdraws it. The same permission the Admin API's client PATCH (`may_exchange`, `exchange_audiences`) and `signari apply` (`token_exchange`) set. Until October 2026 nothing could set it, while discovery advertised the grant |
| `signari client set-exchange-containment` | RFC 8693: only exchange subject tokens this client holds or is named in the audience of |
| `signari client set-hybrid` | Permit hybrid response types |
| `signari client set-claims-redirects` | UMA 2.0 §3.3.2: where a requesting party may be returned after claims gathering. A separate list from `redirect_uris`, because the specification forbids reusing those. See [uma.md](uma.md) |
| `signari client set-grants` | Which grant types this client may use (RFC 6749 §5.2) |
| `signari client set-ciba` | CIBA delivery mode: `poll`, `ping` or `push`. Dynamic registration may only take `poll` — `ping` and `push` have this issuer POST to a URL the client supplies, so an operator grants those deliberately |

## Verifiable credentials

| | |
|---|---|
| `signari credential define` | Define a credential this issuer mints (SD-JWT VC). `-require-key-attestation` issues it only to a key a trusted attester vouches for, and advertises `key_attestations_required`; left out, a redefinition keeps the setting |
| `signari credential list` | Show the credential configurations published |
| `signari resource add` / `resource list` / `resource remove` | `-org <uuid> -resource <uri> [-name <n>]`: the RFC 8707 resources this organisation's tokens may be audienced to. A `resource` a client asks for that is not registered is refused with `invalid_target`, at authorize, PAR and device authorization and again at minting, so removing one stops refreshes for it too. With none registered, every `resource` is refused. See [resource-indicators.md](resource-indicators.md) |
| `signari credential trust-root` | `-org <id> -name <n> -root-cert <ca.pem>`: trust a CA for OID4VCI key proofs that carry an `x5c` chain. One certificate, a CA, unexpired; a file holding a private key is refused. The same name replaces. With none registered, every `x5c` proof is refused. See [oid4vci.md](oid4vci.md) |
| `signari credential roots` | List the CAs `x5c` key proofs may verify to |
| `signari credential untrust-root` | `-org <id> -name <n>`: withdraw one; chains to it are refused from the next credential request |
| `signari credential offer` | Mint an OID4VCI Credential Offer. See [oid4vci.md](oid4vci.md) |

## Keys and audit

| | |
|---|---|
| `signari keys list` / `keys rotate` / `keys retire` | Signing keys; rotation is next → active → passive → retired. See [key-rotation.md](key-rotation.md) |
| `signari keys rewrap-root` | Rotate `SIGNARI_ROOT_KEY` itself. Re-seals every root-wrapped secret — signing keys, per-subject DEKs, and every integration credential — in **one transaction**: from the current key to `SIGNARI_NEW_ROOT_KEY` with the deployment stopped, or, with it running, from `SIGNARI_ACCEPTED_ROOT_KEY` to `SIGNARI_ROOT_KEY` once every node seals with the latter, which it checks and refuses otherwise, naming the nodes. `-dry-run` performs the whole rotation and rolls back, which is the only way to learn it would succeed without betting the deployment on it |
| `signari audit checkpoint` | Anchor the audit chain. See [audit-chain-fork.md](audit-chain-fork.md) |
| `signari audit verify` | Say whether the audit chain verifies, the whole of it or since the latest checkpoint, as an export judges it; exits non-zero and names the entry when it does not. Needs no Go toolchain. `signari doctor` reports the same. Every signed head in the trail is checked against the entry it covers. `-head <jws>` or `-head @<file>` also checks a head kept outside the database, from the audit stream or an export, which catches a rewrite recomputed after every head in the database was removed. `-file <archive>` checks an archive file instead, with no database |
| `signari audit archive` | `-until YYYY-MM-DD -out <file> -by <name>`: write the entries before that date to a new file that verifies on its own, then remove them from the database, recording in the chain the last archived hash and the file's SHA-256, so the trail left verifies from it. Refused unless the whole chain verifies. See [audit-export.md](audit-export.md#archiving-the-oldest-entries) |
| `signari export audit` | Export the trail |
| `signari export org` | `-org <uuid> [-out <file>]`: write the organisation's configuration (groups, clients, SAML providers, RADIUS clients, protected hosts) as the file `signari plan` and `signari apply` read, sorted so two exports of one configuration are one file. Against the organisation it came from it plans nothing; applied to an empty deployment (`apply -org <new uuid> -f <file>`) it recreates it. Secrets are not in it: a confidential client applied from it has none until one is rotated, and a RADIUS client none until `radius add-client` sets it, so a RADIUS client's `enabled` is left out |
| `signari export subject` | `-subject-id <uuid> [-out <file>]`: write everything kept about one person as JSON, with every credential's value withheld and personal attributes unsealed, so it needs `SIGNARI_ROOT_KEY`. The file is created readable by its owner only, and the export is audited `admin.subject_exported`. See [data-export.md](data-export.md) |
| `signari admin-token create` / `admin-token list` / `admin-token revoke` | Admin API credentials. `create -name <n> -scopes <list> [-org <uuid>] [-expires-in 2160h]`: ninety days unless `-expires-in` is given, and `-expires-in 0` for one that never expires; until October 2026 never was the default. The Admin API mints, rotates and revokes them too, each only for a token no wider than the caller; see [admin-tokens.md](admin-tokens.md) |
| `signari role grant` / `role list` / `role revoke` | Administrative roles. `grant -org <uuid> -role <org-owner\|user-manager\|app-manager\|auditor> (-email <address> \| -client-id <id>) [-group <name>]`: a person or an application holds the role in that organisation, a user manager with `-group` over that group's members only; this is how the first owner is made. `list -org <uuid>` names each binding's id; `revoke -org <uuid> -binding <uuid>` takes one away, refused from the holder's next request. See [admin-api.md](admin-api.md#administrative-roles) |

## Federation in

| | |
|---|---|
| `signari idp add` / `idp list` | An upstream OIDC or OAuth provider. The `-slug` is **unique across the deployment**, not per organisation: it is the sign-in URL (`/login/with/<slug>`), which names no organisation. Two organisations sharing one used to route it at random between them. `-trust-email-verification` is for a generic `oidc` provider and refused on a named one, whose belief in `email_verified` is decided by what that provider is known to do |
| `signari idp disable` / `idp enable` | `-slug <slug>`: take an upstream provider out of service, or put it back. Disabled, its sign-in and link routes, its SAML assertions and its jwt-bearer assertions are refused from the next request, and its button leaves the sign-in page. Settings and every account's link to it are kept, so enabling restores them. Sessions already signed in through it are not ended. Audited, and moves the configuration version. Until October 2026 the switch existed in the schema and was read on every one of those paths, and nothing could turn it off |
| `signari idp assertions` | Allow or refuse RFC 7523 assertions from a provider. See [jwt-bearer.md](jwt-bearer.md) |
| `signari idp link` / `idp unlink` / `idp links` | `-slug <slug> -subject <sub> [-email <person>]`: attach an upstream subject to a person in the provider's organisation, detach it, or list them. The jwt-bearer grant mints for the person an assertion's `sub` is linked to, and a key-publishing issuer is never a sign-in option, so this is the only way its links are made. Until October 2026 nothing made them. A person is one subject at a provider, and a subject acts as one person: linking a subject that already acts as somebody else is refused rather than moved, so unlink it first. See [jwt-bearer.md](jwt-bearer.md) |
| `signari idp add-issuer` | Register a key-publishing issuer (GitHub Actions, Kubernetes) for the jwt-bearer grant |
| `signari client set-assertion-issuers` | Which issuers' assertions a client may exchange. Empty permits none. See [jwt-bearer.md](jwt-bearer.md) |
| `signari idp apple-secret` | Mint the client secret Apple requires (a signed JWT that expires) |
| `signari dir add -kind google` / `-kind entra` | Directory sync from the two most common sources. `google`, `entra` and `ldap` are values of `-kind`, not commands of their own |
| `signari saml add-sp` / `saml list` | SAML service providers |
| `signari saml attribute-release` | Which local user attribute a SAML attribute carries. An explicit map, not a wildcard: a disclosure control that silently releases nothing and one that silently releases everything both look like success |
| `signari saml signing` | `-entity-id <id> [-sign-assertions=false] [-sign-responses] [-assertion-lifetime 300] [-signature-alg rsa-sha256\|ecdsa-sha256]`: what is signed, how long an assertion lives, and with which key. A flag not given keeps its setting. A signed Response is signed after the assertion is signed and encrypted. Signing neither is refused, because the service provider would have nothing to check. `ecdsa-sha256` signs with the active ES256 key and is refused when the provider's instance has none; give the provider `/saml/metadata?sp=<id>` afterwards, which then carries the ES256 certificates |
| `signari saml group-release` | Which groups a service provider is told about, matching `group release` for OIDC clients. Group membership is authorization data, so it is an allow-list |
| `signari scim-source add` / `scim-source list` | Inbound SCIM |
| `signari scim-source disable` / `scim-source enable` | `-org <uuid> -slug <slug>`: take an inbound provisioning source out of service, or put it back. Disabled, its bearer token is refused from the next request. Links, settings and the accounts it provisioned are kept. Audited. The switch existed and was read on every request, and nothing could turn it off |
| `signari kerberos check` / `kerberos principals` / `kerberos sync` | Kerberos/SPNEGO, keytab checking, principal import |
| `signari dir add` / `dir sync` | Directory sync from LDAP, Entra or Google |
| `signari dir list` | `-org <uuid>`: each source's settings and what its last sync did: when it ran, how many people it created, updated and deactivated, and its last error. Every sync recorded these, and no command read them back |
| `signari dir group-map` | Which local group a directory group grants. A sync grants nothing that is not mapped here, so a directory reporting `domain admins` cannot make anybody an administrator of this system by name alone |
| `signari dir set` | Whether a source is enabled, in dry run, what it does with people the directory stops returning, and **the deactivation ceiling** — the share of an organisation one sync may deactivate before the whole plan is refused. A bad fetch looks exactly like "everybody left", and that number is what stops the reconciler acting on it. `-fetch-groups` fetches memberships so mapped groups are reconciled, and `-group-attribute` names the LDAP attribute (memberOf when empty); both also on `dir add`. See [directory-sync.md](directory-sync.md#groups) |
| `signari idp trust-mfa` | `-slug <s> [-upstream-amr a,b] [-upstream-acr x]`: which `amr` or `acr` values in the provider's verified ID token count as multi-factor here, so a federated sign-in satisfies an `mfa` stage. Both lists are replaced; neither given trusts nothing. See [social-login.md](social-login.md) |
| `signari idp verified-email` | `-slug <s> [-trust-email-verification=true\|false] [-require-verified-email=true\|false]`, at least one: whether to believe the provider's `email_verified` claim, and whether a new account through it needs an address it verified and is believed about. A believed address is recorded as verified, so only believe a provider that verifies addresses itself. Belief is set for a generic OIDC provider or a SAML upstream; a named provider's comes from what that provider is known to do. An address never finds or links an account, under either setting |
| `signari idp attribute-map` | Route a claim from an upstream provider into a local user attribute. `-overwrite` decides whether a sign-in may replace a value an administrator set by hand |
| `signari import keycloak` / `import authentik` / `import zitadel` | Migrate a realm, an installation or an organisation in: `-file <export> -org <uuid>`, with `-dry-run` for the first and the third, and for the second a preview unless `-apply`. Every preview is the import rolled back. `-install-id <id>` gives `import authentik` the installation ID its persistent NameIDs and passkey user handles were derived from; without it those are left behind and named. See [migrate-from-keycloak.md](migrate-from-keycloak.md), [migrate-from-authentik.md](migrate-from-authentik.md) and [migrate-from-zitadel.md](migrate-from-zitadel.md) |
| `signari import shadow` | `-org <id> -file shadow [-domain example.com] [-apply]`: an account for each `/etc/shadow` entry that has a password, the name as the username and `name@domain` as the address. A preview unless `-apply`, counting each hash format. SHA-crypt (`$5$`, `$6$`) and MD5-crypt (`$1$`) verify as they are and become Argon2id at the first sign-in; a locked or system entry (`!`, `*`, empty) is skipped, and so is yescrypt (`$y$`), the default on recent distributions, which is not verified here: those people need a password reset or delegated sign-in. Each skipped account is named |
| `signari migration-source add` | `-org <uuid> -kind ldap\|oidc_password -name <n>`, then `-ldap-url`, `-bind-dn-template` and optionally `-ldap-ca` for a directory, or `-token-endpoint`, `-client-id-ext`, `-client-secret` and `-migration-scope` for a provider's password grant. The provider a pending person's password is verified against at their first sign-in. Created disabled; a replaced one keeps its state. See [password-migration.md](password-migration.md) |
| `signari migration-source enable` / `migration-source disable` | `-org <uuid>`: start or stop sending pending people's passwords to the source |
| `signari migration-source show` / `migration-source remove` | `-org <uuid>`: the source and how the cutover is going, or delete it |

## Federation out

| | |
|---|---|
| `signari scim add` / `scim list` / `scim sync` / `scim verify` | Outbound SCIM provisioning |
| `signari scim enable` / `scim disable` | Take a target in or out of service. Disabling keeps the configuration, the links and the remote ids, and the next sync skips it — deleting the target would take the links with it and leave the far-end accounts unreachable rather than merely unmanaged |
| `signari scim scope` | Limit a target to one group's members. Unscoped, a target receives every user in the organisation — right for a company directory, wrong for an application five people use |
| `signari scim provision-group` / `scim deprovision-group` | Create or delete a group at the target and record that we own it. Reconciliation only ever touches groups this link names, so a group the target's own administrators maintain is left alone however similar its name |
| `signari provision add` | Provisioning targets |
| `signari ssf add-stream` / `ssf list` | Shared Signals (CAEP/RISC) streams |
| `signari ssf set-status` | `-org <uuid> -client-id <c> -status enabled\|paused\|disabled [-reason <text>]`: a paused stream holds its events and sends them when enabled again, a disabled one neither sends nor holds. The receiver is sent a `stream-updated` event when the stream leaves or returns to `enabled`. See [ssf-caep.md](ssf-caep.md#pausing-and-disabling-a-stream) |
| `signari ssf add-source` / `ssf received` | Accept Shared Signals from a transmitter, and show what it sent. An issuer and `-source-audience` together belong to **one organisation in the deployment**: the receiver chooses the source by that pair, so a second organisation registering it is refused. See [shared-signals-receiver.md](shared-signals-receiver.md#two-organisations-one-transmitter) |
| `signari events subscribe` / `events list` | Event subscriptions — see [events.md](events.md). A name in `-events` that no recorded event carries is refused, with the nearest one suggested |
| `signari events remove` / `events rotate` / `events enable` / `events test` | `-org <id> -name <n>`: delete a subscription; print a new signing secret, once, the old one stops verifying; switch one back on after ten failures switched it off; queue one signed `signari.test` delivery to it through the outbox |
| — | Transaction Tokens are issued at the token endpoint, not by a command — see [transaction-tokens.md](transaction-tokens.md) |

## Authorization

| | |
|---|---|
| `signari authz set-model` / `authz show-model` | The authorization model. Setting one **runs its own tests** — see [authorization.md](authorization.md) |
| `signari trust-mark issue` / `trust-mark revoke` / `trust-mark list` | Issue, withdraw and inspect OpenID Federation Trust Marks. See [trust-marks.md](trust-marks.md) |
| `signari trust-mark accept` / `trust-mark drop` | Publish, or stop publishing, a Trust Mark somebody granted this entity |
| `signari trust-mark delegate` | Authorise another entity to issue a Trust Mark type this one owns (§7.2) |
| `signari trust-mark issuers` / `trust-mark owners` | The Trust Anchor's two governing claims. Setting either is refused for now: this engine cannot be a Trust Anchor until it serves the `federation_fetch_endpoint` every anchor MUST publish, and every reader ignores them from an entity with a Superior. A file containing `{}` still clears them. See [OpenID Federation](openid-federation.md#enabling-it) |
| `signari federation enable` / `federation show` | Join an OpenID Federation. Generates a **separate** Entity Statement signing key and publishes `/.well-known/openid-federation` — see [openid-federation.md](openid-federation.md). `-trust-anchor-hints`, `-federation-contacts` and `-entity-lifetime` (5m to 168h) are kept when not given |
| `signari authz grant` / `authz revoke` | Relations: `-principal user:alice -relation owner -object document:42` |
| `signari authz check` | Answer a question from the command line, with the reason |
| `signari uma settings` | Offer, or stop offering, resource-owner intervention on refused UMA requests (§3.3.6 `request_submitted`). Off means a refusal is final. See [uma.md](uma.md) |
| `signari uma requests` / `uma approve` / `uma deny` | Requests waiting for a resource owner. Approving **grants a relation** in the authorization model, so the access lives where all other access lives |

## Extension providers

An operator's own service, called to extend a decision this engine makes. See
[extensibility.md](extensibility.md).

| | |
|---|---|
| `signari provider add` | Register one: `-hook authorize -provider-url https://… -mode fail_closed`. **`-mode` is required and has no default** — it says what happens when the service cannot be reached |
| `signari provider list` | What is registered, with its failure mode, and whether any decision point actually consults that hook |
| `signari provider claims` | Which claims a token hook may add. The allow-list is the hook's whole security model: without it a service returning `{"admin": true}` would put that claim in a token this engine signed, and a resource server could not tell it apart from one the engine decided. Protocol claims are refused by the schema |
| `signari provider remove` | Remove it. Decisions are then made locally only |
| `signari provider rotate` | `-org <id> -hook <hook>`: print a new signing secret for the provider's `Signari-Signature`, once; the old one stops verifying at once. `provider add` prints the first. See [extensibility.md](extensibility.md) |

## Outposts and remote access

| | |
|---|---|
| `signari outpost create` / `outpost list` / `outpost run` | `create` registers an LDAP, RADIUS, proxy or desktop outpost and prints its token. `run` runs an LDAP outpost only: a RADIUS one refuses to start, since its per-device shared secrets are not carried by the token, and a proxy or desktop token is presented by your own software rather than run here (this row listed all four as runnable). An LDAP outpost serves LDAPS with `-tls-cert` and `-tls-key` (default `:636`) and refuses to start without them unless `-ldap-insecure` is given. See [outposts](outposts.md#ldaps) |
| `signari outpost disable` / `outpost enable` | `-org <uuid> -name <outpost>`: take an outpost out of service, or put it back. Disabled, the core refuses its token from its next request; its settings are kept |
| `signari outpost search-group` | `-org <uuid> -name <outpost> -search-group <group>`: whose members may search the whole directory through an LDAP outpost; empty clears it, and then each person sees only their own entry. Also settable at `outpost create`. The core enforces it, so a token used without a bind reads nothing. See [outposts](outposts.md#what-an-outpost-token-is-worth) |
| — | LDAP and RADIUS are **listeners inside `signari serve`**, not commands. Set `SIGNARI_LDAP_ADDR` or `SIGNARI_RADIUS_ADDR`; each is off unless its address is. See [ldap.md](ldap.md) and [radius.md](radius.md) |
| `signari radius add-client` / `radius list` / `radius enable-client` / `radius disable-client` | RADIUS clients and their shared secrets |
| `signari radius authorize` | Place a group's members on a VLAN, or name a Filter-Id the device already holds. A VLAN id is 12 bits (RFC 3580 §3.31) and is bounded by the schema. Somebody in several authorised groups gets the highest priority, ties broken by group id so the same person lands on the same VLAN every time |
| `signari proxy check` | Check a forward-auth deployment **from outside** the network — which is why it dispatches before the database is required |
| `signari proxy add-host` / `proxy list` / `proxy disable-host` / `proxy enable-host` / `proxy remove-host` | The applications forward auth protects: `-org <uuid> -host app.example.com` (with `:port` when not 443). Sign-in sends a person back only to a registered host. See [forward auth](forward-auth.md) |
| `signari rac add` / `rac list` | Remote access connections |
| `signari rac add -protocol rdp` / `vnc` / `ssh` | The protocol is a value of `-protocol`, not a command. Sessions are started from `/rac` in a browser |
| `signari rac disable` / `rac enable` | `-slug <s>`: a disabled connection is neither listed nor connectable from the next request; a session already open runs until it closes |
| `signari rac set-parameters` | `-slug <s> -rac-params security=nla,ignore-cert=true`: replace the guacd parameters the protocol takes; empty clears them. The host, port, credentials and recording path are refused here, because the connection's own settings supply them and a credential is sealed, never a parameter. guacd refuses a name it does not take at the next connect |

## Policy, prompts, branding

| | |
|---|---|
| `signari policy show` / `policy apply` / `policy test` / `policy graph` | Access policy. `policy test` answers "would this have been allowed" |
| `signari flow test` / `flow paths` / `flow apply` / `flow show` | Sign-in flows. `flow test` refuses a file whose journeys could issue a session without proving the subject, or that names a stage or condition its journey does not run; `flow paths` lists every journey a flow admits; `flow apply` installs one for an organisation, printing every journey it admits; `flow show` prints the built-in flows as a file to start from. See [flows.md](flows.md) |
| `signari passwords calibrate` | `[-target 250ms]`: time Argon2id on this host at several memory sizes and say which `SIGNARI_ARGON2_MEMORY_MIB` and `SIGNARI_ARGON2_ITERATIONS` make one password hash take about that long, preferring memory, and leaving the 512 MiB budget room for four at once. Needs no database; run it where the engine runs. See [configuration](configuration.md#the-hashs-cost-and-a-pepper) |
| `signari prompt list` / `prompt set` | Interstitial prompts — terms, notices. Editing a prompt's title, body or fields moves its version and asks everybody again at their next sign-in, keeping every earlier answer; `prompt set` says how many people that is, and `prompt list` how many have answered the current version. See [prompts.md](prompts.md) |
| `signari prompt disable` / `prompt enable` | `-org <uuid> -slug <s>`: a disabled prompt is neither asked nor answerable; the answers already given are kept |
| `signari brand set` / `brand show` / `brand check` | Branding. `brand check` verifies contrast |
| `signari theme eject` / `theme check` / `theme list` | Replace the HTML of any sign-in page. `theme eject -theme-dir DIR` writes the built-in pages out to edit; `theme check` validates a directory and **exits non-zero** if a page would be refused — the server would not fail to start, it would serve the built-in and log, so a pipeline is where this is caught; `theme list` prints every page and whether it is built-in or yours. Needs no database. See [theming.md](theming.md) |
| `signari i18n list` / `i18n status` / `i18n keys` | What languages the sign-in pages can be rendered in. `i18n status` names every message a loaded language is missing and **exits non-zero** if any is incomplete — a half-translated language still renders, half in each language, which nothing downstream catches; `i18n keys` prints every message key, to write a catalogue against. Same `-theme-dir` flag, and needs no database. See [i18n.md](i18n.md) |
| `signari duo set` / `duo enroll` / `duo show` | Duo as a second factor |
| `signari attester add` / `attester list` | Trusted Client Attesters for attestation-based client authentication. `attester add --org <id> --name <n> --attester-jwks <file>` registers an attester's **public** keys; a file containing private keys is refused, because this server could then forge the attestations it verifies. `-describe` records who the attester is, shown by `attester list`; re-registering without it keeps the old one. Nothing authenticates with `attest_jwt_client_auth` until at least one attester is registered |

## Testing

| | |
|---|---|
| `signari logout-test` | Prove back-channel logout actually terminates a relying party's session |

## Why this page was wrong

In August 2026 this table listed **eight** commands that do not exist:
`delete`, `google`, `entra`, `ldap`, `radius`, `rdp`, `vnc`, `ssh`. Seven of them
were argument *values* — `dir add -kind google`, `rac add -protocol rdp` — written
up as though they were commands. The eighth was never anything.

Two tests exist to prevent precisely this, and both missed it for the same
reason and a different one:

- `TestEveryDocumentedCommandExists` matched invocations **anchored at the start
  of a line**, so every row of this table — which begins `` | `signari … `` —
  was invisible to it. The page whose entire job is to list every command was the
  one page the check could not read.
- It also treated **every** `case "…"` in `main.go` as a command, including
  switches on unrelated strings. `case "delete":` belongs to an `-on-deactivate`
  flag, and that alone made `signari delete` look real.

Both are fixed. The lesson is the one this repository already had written down
about discovery documents, arriving somewhere new: a check that cannot see the
thing it is checking passes for the same reason a correct one does.
