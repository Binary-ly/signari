# Access policy

## Introduction

Acme wants only its payroll team to reach the payroll application, and only from
the office in working hours. Rules like these decide who may use which
application, and a mistake in one either locks people out or lets the wrong
people in.

Signari keeps an organisation's access rules in one file. You check the file
into version control, review it in a pull request, and test it in continuous
integration (CI). The file carries its own tests, and Signari refuses a file
whose rules do not do what its tests say.

You test a policy with `signari policy test`, and install it with
`signari policy apply` or through the Admin API.

> [!NOTE]
> To see a policy as a diagram, read
> [seeing the policy](policy-diagram.md).

## A first policy

These three commands test a policy file, install it for an organisation, and
show the policy that is installed:

```sh
signari policy test  -policy-file access.yaml      # no database needed
signari policy apply -org <uuid> -policy-file access.yaml
signari policy show  -org <uuid>
```

The Admin API reads and applies the same file at
`/admin/organizations/{orgID}/access-policy`. It is parsed and tested the same
way before it is stored. See [the Admin API](admin-api.md).

This policy file has one rule and two tests. The rule requires the `admins`
group and multi-factor authentication ([MFA](glossary.md#mfa)) for the
`admin-console` application:

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

In this example, `when` says which requests the rule applies to, and `require`
says what those requests must meet. The `message` is shown to a person the rule
refuses. Each test gives a request, and the decision it expects.

## A policy that fails its own tests will not load

The tests are not a separate step, and not optional. They run when the file is
parsed: by `policy test`, by `policy apply`, and by the engine on every reload.
A file whose stated intent disagrees with its behaviour is **refused**.

Here, a test expects a request to be denied, and the rules allow it:

```
$ signari policy test -policy-file broken.yaml
signari: this policy does not do what its tests say:
  an admin without MFA does not: expected deny, got allow
$ echo $?
1
```

That inverts the usual failure. Usually, an access rule is written, deployed,
and found to be wrong when somebody is locked out. Far worse, it is found wrong
when somebody who should have been locked out was not. Here, the author writes
down what they meant, and the file does not deploy unless the rules agree.

A file with **no** tests is refused too. A policy with no tests is one whose
author has not written down what they meant, and the whole design compares the
two.

`policy test` needs no database, so it runs in CI on a pull request.

## Why not a graph builder

The usual shape is a canvas: you drag stages onto it, wire them together, and
save. It demonstrates well, but it has three properties that hurt in production.
You cannot diff it, you cannot review it in a pull request, and you cannot test
it before it is live. A file fixes all three for free, and makes the fourth
property above possible at all.

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
no `when`. But every matching rule applies, so such a rule also matched requests
the earlier rules had approved, and denied them. Default-deny could not be
written at all. **The file's own tests caught it**: the mechanism this feature
is built on, applied to itself.

**A rule can ask about a person's attributes**, as the directory holds them when
the decision is made. It can ask for one of some values, or for any value at
all:

```yaml
- name: finance-from-its-own-cost-centres
  when: {client: ledger}
  require:
    user_attributes:
      cost_centre: ["4100", "4200"]   # one of these
      employee_number: []             # any value at all
```

A rule can name only an attribute the organisation has
[declared](admin-api.md#user-attributes), and not one declared as `personal`.
Storing a policy that names any other is refused. An undeclared name is a typo
nobody could meet. A personal value is sealed under its subject's key, and would
be opened for every decision.

A test case gives a person's attributes with `attributes:`. An attribute is about
who somebody is, so it is checked at a refresh too.

**A rule can ask when, and from where.**

These rules hold payroll to office hours in two countries. They also keep out one
country, and an address that has failed too many sign-ins:

```yaml
- name: payroll-in-office-hours
  when: {client: payroll}
  require:
    time: {days: [mon, tue, wed, thu, fri], from: "09:00", to: "17:00", zone: Europe/London}
    from_countries: [GB, IE]
- name: not-from-there
  require:
    not_from_countries: [KP]
- name: not-from-a-bad-address
  require:
    max_recent_failures: 20
```

`time` goes by the clock of the machine Signari runs on, and holds at a refresh
too. So access for office hours stops at the end of them. A test case pins the
moment with `at:`.

The countries need a GeoIP source, which places an IP address in a country:
`SIGNARI_GEOIP_DB` or `SIGNARI_GEOIP_STATIC`. `signari doctor` warns when a
policy asks and there is none.

An address nothing can place does **not** meet `from_countries`, for the same
reason it does not meet `from_networks`. It passes `not_from_countries`, which
is evidence against a request, and an unplaced address has none. Test cases give
`country:`.

`max_recent_failures` refuses an address that has failed more sign-ins than this
in the last five minutes, across every account. The count comes from the budget
the sign-in form keeps. Test cases give `recent_failures:`.

**A rule can ask which network an address is on**, by the "autonomous system"
that announces it. An autonomous system is a network on the internet with its
own number, an autonomous system number (ASN). A rule can ask for the company's
own network, or its cloud provider's, or one that is not a hosting provider's:

```yaml
- name: payroll-from-our-network
  when: {client: payroll}
  require:
    from_asns: [64500, 64501]
- name: not-from-a-hosting-provider
  require:
    not_from_asns: [64666]
```

The networks need an ASN source. That is either `SIGNARI_GEOIP_ASN_DB`, an
IP-to-ASN database in MaxMind's format (GeoLite2-ASN, GeoIP2-ISP, or DB-IP's
IP-to-ASN Lite), or `SIGNARI_GEOIP_ASN_STATIC` for ranges you know.

It is a different file from the GeoIP one. A city database given here is refused
at startup, by its own description, rather than opened to place nobody.

The rule is the countries' rule. An address no source places does not meet
`from_asns`, and passes `not_from_asns`. `signari doctor` warns when a policy
asks and nothing can answer. `0` is refused in either list, because it is what
an unplaced address carries. Test cases give `asn:`.

All of these are about where somebody is. So they are checked at sign-in, not at
a refresh, and are not met on a grant nobody watched.

**Unknown fields are an error.** `any_groups` is not a field, but `any_group` is.
Silently ignoring the typo leaves a rule that appears to restrict and demands
nothing. That is the most dangerous possible mistake in a file like this.

**A rule that denies cannot also require.** Which was meant would be unclear.

**Every rule must be named**, so a refusal can be traced back to the line that
caused it. The name appears in the log, and the message is shown to the person.

**A broken stored policy keeps the previous one in force.** It can break only
if it was written to the database directly, bypassing `policy apply`.
If it does, the engine logs loudly and keeps what it had.

A broken policy must never become an *absent* policy, because absent means "allow
everything". That is the one outcome nobody would choose deliberately.

**Network conditions use the socket address, not `X-Forwarded-For`.** The socket
address is the one the connection really comes from. A header any caller can set
is not a location. Honouring it would let anybody claim to be inside the office
network by adding a line to their request.

**An address we cannot parse fails the check.** Treating "we do not know" as
"inside the office" makes a network restriction decorative. That is what happens
behind a proxy that strips the address.

**Group membership and MFA are read at decision time**, not from anything cached
on the session. That is the same rule the
[group claims](groups.md#membership-is-read-at-issuance-never-cached) follow.

A person is in a group through any group inside it too. So `groups: [engineering]`
admits somebody whose only group is `oncall`, when `oncall` is inside
`engineering` (see [groups inside groups](groups.md#groups-inside-groups)). Test
cases give the groups a person ends up in, nesting included.

## Where it is asked

The policy is asked at every way into an application, keyed by its client ID or
its SAML entity ID. The table names some grants by their abbreviations:
Client-Initiated Backchannel Authentication ([CIBA](ciba.md)), User-Managed
Access ([UMA](uma.md)) and OpenID for Verifiable Credential Issuance
([OID4VCI](oid4vci.md)). An RPT is UMA's requesting party token. The policy is
asked here:

| | |
|---|---|
| the authorization endpoint, the portal, remote access | when the person signs in |
| SAML and WS-Federation | in the one function that signs the assertion for both. A SAML refusal goes back to the service provider as `RequestDenied`; WS-Federation answers `403` |
| the device grant and CIBA | when the person presses approve. A refusal is recorded as a denial, so the waiting device or client is told `access_denied` rather than left polling |
| every refresh | before the new tokens are minted. A refusal is `invalid_grant`, and the refresh token is **not** revoked: lifting the rule, or restoring the membership, restores the grant |
| token exchange, the jwt-bearer grant, UMA (once a person is identified), transaction tokens and the OID4VCI pre-authorized code | before the token is minted. Who the person is is checked as for a refresh; **where they are is not met**, so a network, device or travel condition refuses (`unobserved: true` in a test case). The factors are those of the session behind an exchanged token; the others have none, so **a rule requiring MFA refuses them**. A `scope` rule is matched against the scope the token will carry, not the request's parameter: the client's whole registration when a jwt-bearer request names none or for a pre-authorized code, which has no scope parameter, and the ticket's permissions (`document:42#read`) for an RPT. A refusal is `invalid_grant`; a refused pre-authorized code is not spent. The person must also be in the client's organisation |
| forward auth | on every request to a protected application, keyed `proxy:<host>`. Network, device and travel conditions refuse there, as for the grants above, because the request comes from the proxy and carries the proxy's address and headers — see [forward auth](forward-auth.md#who-may-reach-which-application) |

Until October 2026, the list stopped at the first row and WS-Federation. A deny
rule for an application blocked its browser sign-ins, and still let through its
smart-TV, SAML and CIBA ones. It also let through every refresh of a token
already issued.

The four grants in the last row of issuers were found later the same month. A
test found them by following the code from every function that mints a token or
builds an assertion back to its route. It fails where no check is on the way
(`TestEveryIssuingPathAsksTheAccessPolicy`).

That test lists the authorization code, device and CIBA redemptions with the
place their check happens. It lists the client-credentials grant as asking
nothing, because that grant has no person. A catch-all rule about people would
refuse every machine client.

**A refresh re-checks who the person is, not where they are.** Groups, deny
rules and the factors the session recorded are evaluated again. Someone removed
from the group a rule demands stops receiving tokens at the next refresh.

The network, device and travel conditions are skipped at a refresh
(`refresh: true` in a test case says the same). They describe the browser at
sign-in, and were checked then. A refresh request comes from the application's
server, and that server's address and lack of a device certificate say nothing
about the person.

**A grant nobody watched arrive does not meet a where-from condition.**

The jwt-bearer, pre-authorized code, token exchange, UMA and transaction-token
grants come from a server or a wallet too. But no sign-in to this application
stands behind them, so nothing has ever checked where the person was.

A network, [device](device-posture.md) or [travel](impossible-travel.md)
condition on the application therefore **refuses** them, as it does at forward
authentication. When a person signs in and the travel condition could not be
checked, it is met. That way, somebody signing in for the first time is not
locked out. Here nobody is signing in, so that reason does not apply.

Until October 2026, these grants were decided like a refresh. A rule admitting
an application only from the office network held at its sign-in page. It did
nothing about anybody holding an assertion for it. Forward authentication
refused the network condition, but let the travel condition through as "not
checked". Both now follow the one rule, as this test case shows:

```yaml
tests:
  - name: a grant for the office application
    given: {client: payroll, ip: "10.1.2.3", unobserved: true}
    expect: deny
```

Suppose a server needs such a grant for an application restricted by network.
Put the restriction in a rule for the client the browser uses, and give the
server a client of its own. Here "client" is the protocol's word for an
application's registration.

## Verified against the running server

This is what a person saw under a rule requiring a `security-cleared` group:

```
alice, not cleared  -> 400, no authorization code issued
                       "You need security clearance to use this application.
                        Ask your administrator."
                       log: rule=grouptest-needs-security-clearance
alice, cleared      -> tokens issued
```

The refusal is shown to the person, not bounced to the application as
`access_denied`. A policy refusal is about who they are, and the message says
what to do next. An application's error page cannot explain that.
