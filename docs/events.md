# Event subscriptions

Telling other systems what happened here.

```sh
signari events subscribe -org <uuid> -name siem \
  -url https://siem.example/hooks/signari \
  -events login.failed,impersonation.started
```

The signing secret is printed **once**. It is stored sealed with the root key and
never shown again, so a database copy is not a licence to forge events — an
operator who loses it rotates rather than reads.

```sh
signari events list   -org <uuid>
signari events test   -org <uuid> -name siem   # one signed signari.test delivery
signari events rotate -org <uuid> -name siem   # a new secret, shown once; the old one stops verifying
signari events enable -org <uuid> -name siem   # back on after ten failures switched it off
signari events remove -org <uuid> -name siem
```

`-events` names types from the [catalogue](#event-catalogue). A name nothing
records is refused, with the nearest one suggested: `login.failure` is answered
with `login.failed`. Until October 2026 it was stored, and the subscription
received nothing and looked configured. The test delivery's type, `signari.test`,
is not recorded and is in no catalogue: it goes to the subscription named,
whatever its filter.

## Deliveries go through the outbox

Posting from the request path makes every sign-in as slow and as reliable as the
slowest subscriber, and an event whose subscriber was down is simply lost. That
is the failure mode of every "notification webhook" that is really a goroutine
and a hope.

The outbox already had attempts, capped backoff and parking, because
back-channel logout needed them. Events use the same machinery:

- The event and the intent to deliver it **commit in the same transaction**. There
  is no window where the log says something happened and nothing was ever sent.
- One outbox row **per (event, subscriber)**. A slow subscriber cannot hold up a
  fast one, and a permanently failing one can be parked alone.
- After 10 consecutive failures — roughly a day under capped backoff — the
  subscription is **disabled with the reason recorded**, visible in
  `signari events list`. A subscription that stopped working is a fact, not a
  silence.

## Every delivery is signed

```
Signari-Signature: t=1786972759,v1=<hex hmac-sha256>
Signari-Event-Id: ev_9f2a…
Signari-Event-Type: login.failed
```

`v1` is HMAC-SHA256 over **`<t>.<raw body>`** — the timestamp and the body joined
by a full stop, with that subscription's secret.

**The timestamp is inside the MAC.** Signing only the body means a captured
delivery can be replayed forever and a subscriber cannot tell a live event from
last month's. With `t` covered, changing it invalidates the signature, so a
subscriber can refuse anything older than a few minutes and mean it.

**The separator matters.** Without it, `(t=1, body="23")` and `(t=12, body="3")`
produce the same MAC — a signature ambiguous about what it signed is not a
signature.

The scheme is deliberately the one Stripe uses. A subscriber's engineers have
almost certainly implemented it before, and a verification routine somebody
already got right is worth more than an original one.

### Verifying a delivery

```go
func verify(secret, header string, body []byte, tolerance time.Duration) error {
	var ts, sig string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(part, "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			sig = v
		}
	}

	// The timestamp is checked BEFORE the MAC and again after. Before, so a
	// replay costs nothing to reject; the MAC covers `t`, so a replayer cannot
	// move the window without invalidating the signature it is replaying.
	secs, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return errors.New("no timestamp")
	}
	if d := time.Since(time.Unix(secs, 0)); d > tolerance || d < -tolerance {
		return errors.New("outside the tolerance window")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte{'.'})
	mac.Write(body)

	want, err := hex.DecodeString(sig)
	if err != nil {
		return errors.New("malformed signature")
	}
	// Constant time. A byte-by-byte comparison that returns early leaks how
	// much of a guess was right, and a MAC is exactly the value that makes
	// that leak worth harvesting.
	if !hmac.Equal(mac.Sum(nil), want) {
		return errors.New("signature does not match")
	}
	return nil
}
```

Three things this depends on that are easy to get wrong:

- **The RAW body.** Verify the bytes as received, before any JSON decode. Decode
  and re-encode and the key order, spacing and number formatting are your
  library's rather than ours, and a correct delivery fails to verify.
- **Reject before parsing.** An unverified body is attacker-supplied input; a
  handler that decodes first has already acted on it.
- **A tolerance you actually enforce.** A few minutes. Without one the timestamp
  is decoration and a captured delivery replays forever.

Signari's own implementation of this MAC is `Sign` in `internal/outbox`, exported
so a test can call the same function the sender uses. Two implementations of one
MAC is one implementation and one bug.

## The URL is treated as hostile

A webhook URL is a place the identity provider will make a request, to an address
somebody else chose. That is a proxy inside the trust boundary, and the classic
use of one is to reach what the attacker cannot: `169.254.169.254` for cloud
instance credentials, `127.0.0.1` for the admin API, `10.0.0.0/8` for the rest of
the VPC.

So the check is **at dial time, not at save time**. Validating the hostname when
the subscription is saved checks a *name*; the request is made to an *address*,
and the two are joined by DNS, which the name's owner controls. A host that
resolves publicly when checked and to `169.254.169.254` when dialled defeats any
amount of URL parsing — that is DNS rebinding, and it is not exotic.

Refused: loopback, RFC 1918, link-local, multicast, unspecified, unique-local
IPv6, and the same addresses wearing an IPv4-mapped IPv6 shape (`::ffff:127.0.0.1`).
Every redirect hop is dialled through the same check, and a redirect from https
to http is refused outright.

`https` only, enforced by a CHECK constraint as well as at save time.

## The response is not an instruction

Any 2xx is success; everything else is a failure, **including 410 Gone**. A
subscriber that means "stop sending" says so by having its subscription removed
(`signari events remove`).
Treating a status code as an unsubscribe instruction lets anyone who can answer
that URL turn the events off.

The body is drained and discarded. A webhook response is not an instruction, and
reading one is how a subscriber starts driving the identity provider.

## At-least-once

A network that eats the response after we sent it is indistinguishable from one
that ate the request, and retrying is the only safe reading. `Signari-Event-Id`
is stable across retries, so a subscriber can be idempotent without parsing the
body.

## Which events

Every audited event is publishable — the fan-out lives inside `audit.Write`, so
no code path can record an event without it being deliverable. Dozens of places
record events; a fan-out written at each is one missing from some of them, found
by an operator whose alerting never fired for the one type that mattered.

Filtering is per subscription. `-events` empty means every event in the
organisation, which is a choice an operator makes rather than a default they
inherit. Matching is exact: subscribing to `login` does not quietly subscribe you
to `login.failed`.

## Event catalogue

Every type the engine records, and so every type a subscription can name. A
test in `internal/docsync` keeps this list, the one `events subscribe` checks
against, and the types the code writes identical.

| Area | Events |
|---|---|
| Sign-in | `login.succeeded`, `login.failed`, `desktop.login`, `session.logout`, `consent.withdrawn`, `prompt.answered`, `session.user_revoked`, `password.changed`, `password.breached`, `sms.refused` |
| Account | `account.deleted` (a person erased their own account at `/account/delete`, through the unenrolment flow; counts only), `account.exported` (a person downloaded everything kept about them at `/account/export`; a row count), `account.migrated`, `account.password_reset`, `account.recovery_requested`, `account.recovery_cancelled`, `account.recovery_factor_proven` (a second factor proven on a reset link's page, which waives the delay and satisfies a recovery flow's `mfa` stage; the factor and whether the delay was still running), `user.created`, `user.password_removed` (a person with at least two passkeys took their password away at `/account/security`, told on every channel), `user.email_verified` (a self-sign-up's address proved by the code sent to it, at the sign-in flow's `verify_email` stage), `user.attributes_updated` (attributes a person set for themselves at `/account/profile`, at sign-up, or by answering a prompt whose field writes one, `by: prompt` with the prompt: their names, never their values), `user.email_changed` (a person moved their account to a new address at `/account/email`, after a code sent to it came back; the old address and every channel are told) |
| Second factors | `mfa.device_remembered`, `mfa.device_forgotten`, `mfa.totp_enrolled`, `mfa.totp_removed` and `mfa.email_otp_removed` (by the person, from `/account/security`, with `recovery_codes_cleared` when it was their last second factor; `mfa.sms_removed` likewise), `mfa.otp_token_assigned` (a hardware token given to a person with `signari user assign-otp`), `mfa.sms_enrolled`, `mfa.sms_removed`, `mfa.email_otp_enrolled`, `mfa.passkey_registered`, `mfa.passkey_link_used` (a passkey registered from a link `signari user passkey-link` emailed, which spends it), `mfa.passkey_removed`, `mfa.passkey_refused`, `mfa.passkey_counter_regression`, `mfa.passkey_backup_lost`, `mfa.passkey_notice_failed`, `mfa.recovery_codes_regenerated`, `mfa.factor_disabled`, `mfa.duo_succeeded`, `mfa.duo_failed`, `mfa.duo_unavailable`, `mfa.skipped_duo_unavailable` |
| OAuth and OpenID Connect | `oauth.consent_granted`, `oauth.consent_denied`, `oauth.code_reused`, `oauth.refresh_reused`, `oauth.token_revoked`, `oauth.token_exchanged`, `token.vetoed`, `txntoken.issued`, `ciba.requested`, `ciba.approved`, `ciba.denied`, `ciba.step_up_required`, `ciba.unknown_subject`, `uma.submitted`, `uma.claims_gathered`, `uma.granted`, `uma.denied`, `oid4vci.credential_issued` |
| SAML and WS-Federation | `saml.assertion_issued`, `saml.logout_completed`, `saml.logout_propagated`, `wsfed.token_issued` |
| Federation and directories | `federation.user_created`, `federation.account_linked`, `federation.account_unlinked` (a provider removed from the account page; the holder is told, as when one is linked), `federation.refused`, `directory.groups_synced`, `directory.privileged_skipped`, `ssf.received` |
| SCIM | `scim.user_provisioned`, `scim.user_replaced`, `scim.user_patched`, `scim.user_deprovisioned`, `scim.group_provisioned`, `scim.group_replaced`, `scim.group_membership_changed`, `scim.group_deprovisioned`, `scim.privileged_kept`, `scim.privileged_refused` |
| LDAP | `ldap.entry_created`, `ldap.entry_modified`, `ldap.entry_renamed`, `ldap.entry_deleted`, `ldap.password_set`, `ldap.write_refused` (a bound account outside the write group tried to add, modify, delete or rename an entry) |
| Proxy and remote access | `proxy.host_added`, `proxy.host_enabled`, `proxy.host_disabled`, `proxy.host_removed`, `proxy.session_issued`, `rac.session_requested`, `rac.session_ended` |
| Support access | `impersonation.started`, `impersonation.ended`, `impersonation.refused` |
| Administration | `admin.cli_command`, `admin.organization_budgets_set` (an organisation's token and sign-in budgets set by a deployment-wide caller, each from and to, null for the default), `admin.organization_created`, `admin.organization_deleted` (an organisation deleted by `signari instance org-delete`: its slug, how many people were erased, clients and groups removed and sessions ended; the organisation's earlier records are kept), `admin.organization_suspended` and `admin.organization_reactivated` (by the Admin API or `signari instance org-status`, filed under the organisation, with the status it `was`), `admin.user_created`, `admin.user_updated`, `admin.user_deleted`, `admin.user_unlocked`, `admin.user_approved` (a self-sign-up waiting for approval let in by `signari user approve`; the Admin API's approval is `admin.user_updated` with `approved: true`), `admin.subject_erased`, `admin.subject_exported` (everything kept about a person handed to an operator, by the Admin API or `signari export subject`; `via`, who, and a row count), `admin.consent_revoked` (a person's consent to an application withdrawn through the Admin API, with how many refresh grants went with it), `admin.factor_removed`, `admin.token_created`, `admin.token_rotated` (naming the replacement and until when the old secret works), `admin.token_revoked` (admin tokens made, replaced and revoked through the Admin API; never a secret), `admin.passkey_link_issued`, `admin.session_revoked`, `admin.sessions_revoked`, `admin.client_created`, `admin.client_updated`, `admin.client_deleted`, `admin.client_secret_rotated`, `admin.group_created`, `admin.group_updated`, `admin.group_deleted`, `admin.group_member_added`, `admin.group_member_removed`, `admin.group_release_set` and `admin.group_release_removed` (which groups an application is told of in the `groups` claim, named, or that it is told of none), `admin.attribute_declared`, `admin.attributes_set`, `admin.claim_mapper_created`, `admin.claim_mapper_deleted`, `admin.scope_declared`, `admin.scope_deleted`, `admin.signup_rule_set` and `admin.signup_rule_removed` (self-sign-up opened or its rule replaced through the Admin API, with the domains, groups and whether an address must be proved or an administrator approve, or closed), `admin.identity_provider_updated`, `admin.scim_source_updated`, `admin.invitation_created` (an invitation made through the Admin API: whether it is bound to an address, the groups it grants, whether it was mailed; never the link), `admin.invitation_revoked`, `admin.migration_source_set`, `admin.migration_source_removed`, `admin.proxy_host_set`, `admin.proxy_host_removed`, `admin.resource_server_set`, `admin.resource_server_removed`, `admin.role_granted`, `admin.role_revoked` (an administrative role given or taken away through the Admin API, naming the binding, the role, its holder and any group it is narrowed to; `signari role` is recorded as `admin.cli_command`), `admin.webauthn_policy_set`, `admin.privileged_refused`, `org.login_throttle_set`, `org.new_device_notice_set` (whether a sign-in from a new device is mailed to the person, from and to), `org.password_only_binds_set`, `org.reauth_window_set`, `org.session_lifetime_set` (how long sessions last and how long unused, from and to, and how many live sessions it shortened or ended), `org.session_limit_set` (how many sessions one person may hold and what a sign-in past it does, each from and to), `org.remember_device_set`, `org.sms_numbers_set`, `org.totp_policy_set`, `config.applied`, `restore.finalized` (every session and refresh family a restored database brought back was ended; see the backup runbook) |
| The audit trail itself | `audit.archived`, `audit.checkpoint`, `audit.head_signed` |
| The instance | `keys.rotated`: in the audit trail, and delivered to no subscription, since it belongs to no organisation; subscribing to it is refused |

Not recorded, on purpose: each code issued or redeemed, each refresh, each
client-credentials token. Every audit entry takes the chain's lock, and an entry
per token would queue the issuance of every token behind it. A token's record is
its decisions: the sign-in, the consent, a reused code or refresh token, a
revocation.


## Re-review against the Shared Signals Framework, August 2026

Version checked first: **Shared Signals Framework Specification 1.0, published 29
August 2025**. Current, and the version implemented against.

### Two defects, both the same mistake

The receiver was written against **RFC 8417 alone**. The Shared Signals Framework
is a *profile* of RFC 8417, and it is stricter in two places our code did not
know about.

**§4.1.7 — `exp` is forbidden, not merely discouraged.**

> The "exp" claim MUST NOT be used in SETs. The purpose is defense in depth
> against confusion with other JWTs, as described in Sections 4.5 and 4.6 of
> [RFC8417].

RFC 8417 §2.2 on its own only makes `exp` NOT RECOMMENDED, and our code cited
exactly that — then honoured the claim when present, refusing a SET whose expiry
had passed. That was a deliberate earlier fix, and the comment recorded why: a
transmitter that deliberately time-boxed an event had found us acting on it
afterwards.

Reasonable, and aimed at the wrong thing. **`exp` is not there to time-box an
event. It is forbidden so that a SET cannot be shaped like an ID token.** Once
that is the reason, honouring the claim is not enough — a SET with a comfortable
future expiry is exactly as confusable as an expired one, and ours accepted it.

**§4.1.2 — a top-level `sub` is forbidden, and we never checked.**

> The JWT "sub" claim MUST NOT be present in any SET containing an SSF event.

It sits under §4.1.3, *"Distinguishing SETs from other Kinds of JWTs — Of
particular concern is the possibility that SETs are confused for other kinds of
JWTs."* An SSF event names its subject in `sub_id`; a top-level `sub` is the
shape of an ID token.

We check `typ: secevent+jwt`, which is the primary confusion defence and which
would already refuse an actual ID token. The profile adds these two because typ
checking is not universal — defence in depth is its stated purpose, and we had
implemented one layer of it and not the other two.

Both are now refused outright. `Subject` is parsed as a `*string` so that
`"sub": ""` is distinguishable from an absent claim: an empty string is still a
`sub` claim.

| Mutation | Test that caught it |
|---|---|
| Honour `exp` instead of refusing it | `TestASETCarryingExpIsRefused` |
| Allow a top-level `sub` | `TestASETCarryingATopLevelSubIsRefused` |

### The lesson worth keeping

The previous review of this code checked it against RFC 8417 and RFC 8935 and
found five defects. It did not check it against the **profile** that governs it,
and the profile is where both of these live.

An implementation of a profiled specification has two documents to satisfy, and
the profile is the one that adds restrictions the base RFC calls optional. Citing
the base RFC in a comment — as ours did, accurately — is what made the gap look
like diligence.
