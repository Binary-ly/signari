# Access policy

Access rules as a file you check into version control, review in a pull request,
and test in CI.

```sh
signari policy test  -policy-file access.yaml      # no database needed
signari policy apply -org <uuid> -policy-file access.yaml
signari policy show  -org <uuid>
```

```yaml
version: 1
policies:
  - name: admin-console-requires-mfa
    when:
      client: admin-console
    require:
      groups: [admins]
      mfa: true
    message: The admin console requires an admin account with multi-factor authentication.

tests:
  - name: an admin with MFA reaches the console
    given: {client: admin-console, groups: [admins], mfa: true}
    expect: allow
  - name: an admin without MFA does not
    given: {client: admin-console, groups: [admins], mfa: false}
    expect: deny
```

## A policy that fails its own tests will not load

The tests are not a separate step and not optional. They run when the file is
parsed — by `policy test`, by `policy apply`, and by the engine on every reload.
A file whose stated intent disagrees with its behaviour is **refused**.

```
$ signari policy test -policy-file broken.yaml
signari: this policy does not do what its tests say:
  an admin without MFA does not: expected deny, got allow
$ echo $?
1
```

That inverts the usual failure. Ordinarily an access rule is written, deployed,
and found to be wrong when somebody is locked out — or, far worse, when somebody
who should have been locked out was not. Here the author writes down what they
meant, and the file does not deploy unless the rules agree.

A file with **no** tests is refused too. A policy with no tests is one whose
author has not written down what they meant, and the whole design compares the
two.

`policy test` needs no database, so it runs in CI on a pull request.

## Why not a graph builder

The usual shape is a canvas: drag stages, wire them, save. It demonstrates well
and has three properties that hurt in production — you cannot diff it, you
cannot review it in a pull request, and you cannot test it before it is live. A
file fixes all three for free, and makes the fourth property above possible at
all.

## Decisions

**Rules restrict; they never grant.** Every matching rule must be satisfied. A
rule cannot open access that was not otherwise available, so reading one in
isolation tells you what it does.

**Default-deny is one word at the top of the file**, not a trailing catch-all
rule:

```yaml
version: 1
default: deny
```

That was a correction. The first design expected default-deny to be a rule with
no `when` — but since every matching rule applies, such a rule also matched
requests the earlier rules had just approved, and denied them. Default-deny was
inexpressible. **The file's own tests caught it**, which is the mechanism this
package is about, applied to itself.

**Unknown fields are an error.** `any_groups` is not a field; `any_group` is.
Silently ignoring the typo leaves a rule that appears to restrict and demands
nothing — the most dangerous possible mistake in a file like this.

**A rule that denies cannot also require.** Which was meant would be unclear.

**Every rule must be named**, so a refusal can be traced back to the line that
caused it. The name appears in the log; the message is shown to the person.

**A broken stored policy keeps the previous one in force.** If the document in
the database no longer loads — only possible if it was written there directly,
bypassing `policy apply` — the engine logs loudly and keeps what it had. A
broken policy must never become an *absent* policy, because absent means "allow
everything", and that is the one outcome nobody would choose deliberately.

**Network conditions use the socket address, not `X-Forwarded-For`.** A header
any caller can set is not a location; honouring it would let anybody claim to be
inside the office network by adding a line to their request.

**An address we cannot parse fails the check.** Treating "we do not know where
this came from" as "inside the office" is how a network restriction becomes
decorative behind a proxy that strips the address.

**Group membership and MFA are read at decision time**, not from anything cached
on the session — the same rule the group claims follow.

## Where it is asked

At every way into a relying party or service provider, keyed by its client ID or
SAML entity ID:

| | |
|---|---|
| the authorization endpoint, the portal, remote access | when the person signs in |
| SAML and WS-Federation | in the one function that signs the assertion for both. A SAML refusal goes back to the service provider as `RequestDenied`; WS-Federation answers `403` |
| the device grant and CIBA | when the person presses approve. A refusal is recorded as a denial, so the waiting device or client is told `access_denied` rather than left polling |
| every refresh | before the new tokens are minted. A refusal is `invalid_grant`, and the refresh token is **not** revoked: lifting the rule, or restoring the membership, restores the grant |
| token exchange, the jwt-bearer grant, UMA (once a person is identified) and the OID4VCI pre-authorized code | before the token is minted, and like a refresh: who the person is, not where. The factors are those of the session behind an exchanged token; the other three have none, so **a rule requiring MFA refuses them**. A refusal is `invalid_grant`; a refused pre-authorized code is not spent. The person must also be in the client's organisation |
| forward auth | on every request to a protected application, keyed `proxy:<host>`. Network, device and travel conditions refuse there, because the request comes from the proxy and carries the proxy's address — see [forward auth](forward-auth.md#who-may-reach-which-application) |

Until October 2026 the list stopped at the first row and WS-Federation. A deny
rule for a client blocked its browser sign-ins and still let through its
smart-TV, SAML and CIBA ones, plus every refresh of a token it had already
issued. The four grants in the last row of issuers were found later the same
month, by a test that follows the code from every function that mints a token
or builds an assertion back to its route, and fails where no check is on the
way (`TestEveryIssuingPathAsksTheAccessPolicy`). The authorization code, device
and CIBA redemptions are listed there with the place their check happens. The
client-credentials grant is listed as asking nothing, because it has no person,
and a catch-all rule about people would refuse every machine client.

**A refresh re-checks who the person is, not where they are.** Groups, deny
rules and the factors the session recorded are evaluated again. Someone removed
from the group a rule demands stops receiving tokens at the next refresh. The
network, device and travel conditions are skipped (`refresh: true` in a test
case says the same). They describe the browser at sign-in and were checked
then. A refresh request comes from the application's server, and that server's
address and lack of a device certificate say nothing about the person.

## Verified against the running server

With a rule requiring a `security-cleared` group:

```
alice, not cleared  -> 400, no authorization code issued
                       "You need security clearance to use this application.
                        Ask your administrator."
                       log: rule=grouptest-needs-security-clearance
alice, cleared      -> tokens issued
```

The refusal is rendered to the person, not bounced to the client as
`access_denied`. A policy refusal is about who they are, and the message says
what to do next; an application error page cannot explain that.
