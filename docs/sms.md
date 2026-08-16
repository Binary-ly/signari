# SMS codes: the weakest factor here, and it says so

```sh
SIGNARI_SMS_GATEWAY=twilio
SIGNARI_SMS_TWILIO_SID=AC...
SIGNARI_SMS_TWILIO_TOKEN=...
SIGNARI_SMS_FROM=+15550000000        # or a messaging service SID, MG...

# or, for anything else -- including an in-house relay
SIGNARI_SMS_GATEWAY=webhook
SIGNARI_SMS_WEBHOOK_URL=https://sms.internal/send
SIGNARI_SMS_WEBHOOK_AUTH="Bearer ..."
```

Users enrol at `/account/mfa/sms`.


## Why it is offered at all

NIST withdrew its recommendation of SMS for authentication in 2016, and the
reasons have only got easier:

- **SIM swap** needs no technical exploit — somebody persuades a mobile operator
  to move a number. This is how the factor is actually defeated.
- **SS7** access is purchasable, and the signalling network has no
  authentication worth the name.
- **Forwarding** to an email address is a checkbox in several operators'
  portals.

It is here because the alternative most people choose is not a passkey; it is
nothing. A large share of real users enrol SMS and nothing else, and SMS still
defeats credential stuffing, which is by far the most common attack.

The dishonest version of this feature ships the weakness in a docs page and then
treats the factor as equivalent everywhere in the code. That is worse than not
writing it down, because the documentation buys the confidence and the code
spends it.

## So the weakness is in the data, not just the prose

The `amr` value is **`sms`**, never `otp`:

```
session: acr=2  amr={pwd,sms}
audit:   login.succeeded  {"acr": "2", "amr": ["pwd", "sms"]}
```

RFC 8176 defines both values. Recording a text message as `otp` would make it
indistinguishable from an authenticator app in every token, every audit record
and every policy decision — erasing the distinction from the one field machines
actually read.

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

`phishing_resistant` is satisfied **only** by `hwk` — a hardware-backed
credential bound to the origin by the browser. Not by `otp`: a one-time code is
typed by a person into whatever page asked for it, including the attacker's,
which is how every real-time phishing kit works. And not by the generic `mfa`
value: a provider asserting it has said several factors were used and nothing
about which.

Verified against a running engine, not just in tests. A session proved with
`pwd,sms`:

```
GET /oauth2/authorize?client_id=thirdparty…   400
   "This application requires a passkey or security key."

GET /oauth2/authorize?client_id=webapp…       302 → code issued
```

The second line is the control. Without it, a policy that denied everything
would look exactly like one that works.

### This was a comment before it was a feature

While wiring SMS in, I wrote a comment saying the strong/weak distinction "lives
in the policy language, where a rule can name amr values directly". Then I
checked. The policy language had a boolean `mfa: true` and nothing else — so a
rule asking for MFA silently accepted SMS, which is the exact thing the comment
said must not happen.

`phishing_resistant` and `factors_any_of` exist because that claim had to be
made true or deleted.

## Enrolment is two steps, and the second is not optional

A number is enrolled, a code is sent to it, and the factor counts **only once
that code comes back**:

```
db: +447700900123 | verified=f     ← after entering the number
    counts as a factor: f
```

Enrolling and trusting in one step means a typo puts a stranger's phone between
somebody and their own account — and they find out at the worst possible moment,
already locked out.

## Numbers are E.164 or refused

```
give the number in international form, starting with a + and the country code
(got "07700900123")
```

A national-format number is **not** guessed at. Assuming a country code is how a
number in one country gets a code for another, and the person then never
receives a message and cannot tell why. The format is enforced in the database
as well, because the application is not the only thing that writes there.

Numbers are shown redacted — `••• ••• 23`. The last two digits let somebody
recognise their own number; the whole number tells anybody who has stolen a
password exactly which number to attack at the mobile operator.

## Operational choices

| | |
|---|---|
| code lifetime | **5 minutes** — shorter than email's ten; a text arrives in seconds and sits on a lock screen |
| resend interval | 60s — every message costs money, and a resend button with no floor spends somebody else's budget |
| attempts per code | 5 |
| one live code | "send another" replaces, never accumulates |

A misconfigured gateway is **fatal at startup**, not a silent fallback to no
SMS:

```
signari: configuring the SMS gateway: SIGNARI_SMS_GATEWAY must be twilio or
webhook (got "twilo")
```

A deployment that named a gateway stated an intention. Quietly ignoring a typo
is how a second factor turns out to have been undeliverable for a month.

A plaintext webhook URL is refused for the same reason it matters: the body
carries a live one-time code.

## The MFA gate now tests itself

`HasSecondFactor` is the single gate between a correct password and a session. A
factor missing from it is a factor that silently does not apply — the user turns
on MFA, sees it in their settings, and is waved through on a password alone.

That bug has appeared twice here: the function was once `HasConfirmedTOTP`,
checked TOTP alone, and claimed in its own comment to report "a usable second
factor". Adding email codes made it a bypass; adding SMS created the same
opportunity again.

`TestEveryFactorTableIsChecked` now asks the database which tables hold
credentials and fails when the query does not mention one:

```
core.sms_otp_credentials holds second-factor credentials and HasSecondFactor
does not consult it. A user whose only factor is in that table signs in with a
password alone, while their account settings say MFA is on.
```

A comment saying "remember to update this" is not a mechanism.
