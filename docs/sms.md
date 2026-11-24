# SMS codes: the weakest factor here, and it says so

## Introduction

A code sent by text message is the second factor many people already know. It
is also the weakest one Signari offers.

Signari can send a code by Short Message Service (SMS) as a second factor. It
records the factor as SMS everywhere, so that tokens, audit records and access
policies can tell it apart from stronger factors.

You connect a gateway that sends the messages with the `SIGNARI_SMS_`
environment variables on this page. People then enrol their own number.

## Connecting a gateway

Choose one of three gateways. Twilio needs its account details. A webhook covers
anything else, including an in-house relay. A verification service makes, sends
and checks the code itself:

```sh
SIGNARI_SMS_GATEWAY=twilio
SIGNARI_SMS_TWILIO_SID=AC...
SIGNARI_SMS_TWILIO_TOKEN=...
SIGNARI_SMS_FROM=+15550000000        # or a messaging service SID, MG...

# or, for anything else -- including an in-house relay
SIGNARI_SMS_GATEWAY=webhook
SIGNARI_SMS_WEBHOOK_URL=https://sms.internal/send
SIGNARI_SMS_WEBHOOK_AUTH="Bearer ..."

# or a verification service that makes, sends and checks the code itself
SIGNARI_SMS_GATEWAY=verify-webhook
SIGNARI_SMS_VERIFY_URL=https://verify.internal/v1
SIGNARI_SMS_VERIFY_AUTH="Bearer ..."
```

People enrol at `/account/mfa/sms`. They see and remove the number at
`/account/security`, with their other sign-in methods. Removing it there or from
the enrolment page is the same removal. The holder is told, and when it was the
last second factor, the recovery codes go with it.

## A delegated verification service

With `verify-webhook`, the engine never holds a code. The service makes it,
sends it, and says whether the one typed is right. That keeps codes out of
Signari's database and its logs. It also puts delivery where a provider's fraud
and routing controls are.

The engine speaks one contract, version 1, to a service the administrator runs
in front of whichever provider's verification API they use:

```
POST {"version":1,"action":"start","to":"+447700900123"}
     2xx, optionally {"id":"..."}   a code was sent
POST {"version":1,"action":"check","to":"+447700900123","id":"...","code":"123456"}
     2xx {"approved":true}          the code is right; the service spends it
     2xx {"approved":false}         it is not
```

A check carries `to`, `id` or both, as known. An organisation that keeps only
hashes of numbers (below) sends the `id` alone. So a service that gives no `id`
cannot serve it.

Anything else is an error. A check that errors is refused, not charged, so an
outage of the service signs nobody in and disables nobody's factor.

Only a code of 4 to 10 digits is sent to the service. So an authenticator or
recovery code tried first spends none of its checks.

The engine's own rules still apply on top: the countries, the daily allowances,
the five-minute lifetime, five attempts per code and the consecutive-failure
ceiling.

The service sends only codes, so account notices go by email alone, which
`signari doctor` says. The URL must be https, as a check carries a live code.

## Keeping only a hash of the number

By default, a person's number is stored. Then a code can be texted without being
asked for, and account notices reach the phone. But a copy of the database then
holds every person's number. That is where a "SIM swap" begins: somebody
persuades a mobile provider to move the number to a SIM card they hold.

An organisation can instead keep only a keyed hash of each number:

```sh
signari instance sms-numbers -org <id> -sms-numbers hashed
```

The hash is made under the person's own subject key. That key is sealed under
the root key, which is not in the database, so a copy of the database cannot
test guesses. The same number in two accounts hashes differently. A root-key
rotation leaves the hash as it was, and erasing the person destroys it.

What changes for the person: the code page asks for their number, and the code
goes to the number typed when its hash matches. The page says the same whether
it matched or not, because whoever is on that page has the password. Each try
spends the code page's own budget, so nobody can try number after number.

No account notice is texted to a number that is not kept.

A number already stored is replaced by its hash at the person's next sign-in.
That sign-in is still texted to the stored number.

Moving back to `stored` applies to numbers enrolled from then on. A hash cannot
be read back, so it keeps working when typed, until the person enrols again.

## Why it is offered at all

The National Institute of Standards and Technology (NIST) withdrew its
recommendation of SMS for authentication in 2016. The weaknesses behind that
have only got easier to exploit:

- **SIM swap** needs no technical exploit. Somebody persuades a mobile provider
  to move a number. This is how the factor is actually defeated.
- **SS7** access, to the Signalling System No. 7 network that routes texts, is
  purchasable. That signalling network has no authentication worth the name.
- **Forwarding** to an email address is a checkbox in several mobile providers'
  portals.

It is here because the alternative most people choose is not a passkey: it is
nothing. A large share of real people enrol SMS and nothing else. SMS still
defeats credential stuffing, which is by far the most common attack. "Credential
stuffing" is trying passwords leaked from other sites.

The dishonest version of this feature ships the weakness in a docs page, and
then treats the factor as equivalent everywhere in the code. That is worse than
not writing it down, because the documentation buys the confidence and the code
spends it.

## So the weakness is in the data, not only the prose

The `amr` value is **`sms`**, never `otp`. The session and the audit record both
say so:

```
session: acr=2  amr={pwd,sms}
audit:   login.succeeded  {"acr": "2", "amr": ["pwd", "sms"]}
```

RFC 8176 defines both values. Recording a text message as `otp` would make it
indistinguishable from an authenticator app in every token, every audit record
and every policy decision. That would erase the distinction from the one field
machines actually read.

## And the policy language can act on it

`mfa: true` accepts any second factor, including a text message. Two conditions
exist for when that is not enough:

```yaml
policies:
  - name: finance-needs-a-security-key
    when: {client: finance}
    require: {phishing_resistant: true}
    message: Finance requires a passkey or security key.

  - name: admin-no-text-messages
    when: {client: admin}
    require: {factors_any_of: [otp, hwk]}
```

`phishing_resistant` is satisfied **only** by `hwk`, a hardware-backed
credential bound to the origin by the browser.

It is not satisfied by `otp`. A one-time code is typed by a person into whatever
page asked for it, including the attacker's, which is how every real-time
phishing kit works.

Nor is it satisfied by the generic `mfa` value. A provider asserting `mfa` has
said several factors were used, and nothing about which.

This was verified against a running engine, not only in tests. A session proved
with `pwd,sms` got these answers:

```
GET /oauth2/authorize?client_id=thirdparty…   400
   "This application requires a passkey or security key."

GET /oauth2/authorize?client_id=webapp…       303 → code issued
```

The second line is the control. Without it, a policy that denied everything
would look exactly like one that works.

### This was a comment before it was a feature

A comment was written while SMS was being wired in. It said the strong/weak
distinction "lives in the policy language, where a rule can name amr values
directly". Then it was checked. The policy language had a boolean `mfa: true`
and nothing else. So a rule asking for multi-factor authentication (MFA)
silently accepted SMS, which is the exact thing the comment said must not
happen.

`phishing_resistant` and `factors_any_of` exist because that claim had to be
made true or deleted.

## Enrolment is two steps, and the second is not optional

A number is enrolled, a code is sent to it, and the factor counts **only once
that code comes back**. After the person enters the number, the database holds
it unverified:

```
db: +447700900123 | verified=f     ← after entering the number
    counts as a factor: f
```

Enrolling and trusting in one step would mean a typo puts a stranger's phone
between somebody and their own account. They would find out at the worst
possible moment, already locked out.

**Moving to another number works the same way.** The new number is held as
pending. The number that already works stays the factor, and keeps receiving
sign-in codes, until a code sent to the new one comes back. Then the old number
is texted to say codes will no longer come to it.

The send step used to overwrite the working number, and mark the factor
unverified at once. So one request from any signed-in session switched SMS off
for the account. It also aimed SMS at a number of that session's choosing,
without a code being entered.

An enrolment code and a sign-in code are kept apart, and neither is accepted in
place of the other.

## Numbers are E.164 or refused

E.164 is the international form of a phone number: a `+`, then the country
code, then the number. A number in any other form is refused with this message:

```
give the number in international form, starting with a + and the country code
(got "07700900123")
```

A national-format number is **not** guessed at. Assuming a country code is how a
number in one country gets a code for another. The person then never receives a
message, and cannot tell why. The format is enforced in the database as well,
because the engine is not the only thing that writes there.

Numbers are shown redacted, as `••• ••• 23`. The last two digits let somebody
recognise their own number. The whole number would tell anybody who has stolen
a password exactly which number to attack at the mobile provider.

## Operational choices

These are the limits on an SMS code. Sign-ins over the Lightweight Directory
Access Protocol (LDAP) and the Remote Authentication Dial-In User Service
(RADIUS) take none, as the table says:

| | |
|---|---|
| code lifetime | **5 minutes** — shorter than email's ten; a text arrives in seconds and sits on a lock screen |
| resend interval | 60s within one sign-in — every message costs money, and a resend button with no floor spends somebody else's budget. Another sign-in is texted a code of its own at once, within the daily allowances per number and per organisation |
| taken for | the sign-in, or the password reset, it was sent for, and no other: as for [email codes](email-otp.md#one-live-code-never-a-queue-of-them). An LDAP bind, a RADIUS request and the desktop sign-in take none; a bind took one until November 2026 |
| attempts per code | 5 |
| wrong codes in a row, across codes | 100, then the factor is switched off and the holder told, as an authenticator app is. No code is sent or accepted until a number is proved again. A right code resets the count |
| one live code | "send another" replaces, never accumulates |

A misconfigured gateway is **fatal at startup**, not a silent fallback to no
SMS:

```
signari: configuring the SMS gateway: SIGNARI_SMS_GATEWAY must be twilio,
webhook or verify-webhook (got "twilo")
```

A deployment that named a gateway stated an intention. Quietly ignoring a typo
is how a second factor turns out to have been undeliverable for a month.

A plaintext webhook URL is refused for the same reason it matters: the body
carries a live one-time code.

## The MFA gate now tests itself

`HasSecondFactor` is the single gate between a correct password and a session. A
factor missing from it is a factor that silently does not apply. The person
turns on MFA, sees it in their settings, and is waved through on a password
alone.

That bug has appeared twice here. The function was once `HasConfirmedTOTP`. It
checked time-based one-time passwords (TOTP) alone, and claimed in its own
comment to report "a usable second factor". Adding email codes made it a bypass,
and adding SMS created the same opportunity again.

`TestEveryFactorTableIsChecked` now asks the database which tables hold
credentials, and fails when the query does not mention one:

```
core.sms_otp_credentials holds second-factor credentials and HasSecondFactor
does not consult it. A user whose only factor is in that table signs in with a
password alone, while their account settings say MFA is on.
```

A comment saying "remember to update this" is not a mechanism.
