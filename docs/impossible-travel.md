# Impossible travel

## Introduction

Somebody signs in from London, and eleven minutes later from São Paulo. Nobody
did that. Either the credential is shared, or one of the two sessions is not who
it claims to be.

Signari can refuse the second sign-in. It compares a person's last sign-in with
this one: where each came from, and when. It refuses a journey no aircraft could
make.

You turn it on with a condition in an [access policy](policy.md). Positions come
from `SIGNARI_GEOIP_STATIC` or `SIGNARI_GEOIP_DB`, described under
[where positions come from](#where-positions-come-from).

## Turn it on

This policy refuses impossible travel for the `bank` application:

```yaml
policies:
  - name: refuse-impossible-travel
    when: {client: bank}
    require: {no_impossible_travel: true}
    message: This sign-in came from an unexpected place. Contact support.
```

## Verified against the running server

These are two sign-ins checked against a running Signari, one refused and one
allowed:

```
previous: London, 11 minutes ago  ->  400
    "This sign-in came from an unexpected place. Contact support."
    detector: 9497 km in 12m0s implies 45642 km/h, which is not travel

previous: London, 13 hours ago    ->  allowed (a real flight)
```

## Most of the design is about not crying wolf

A detector that fires on ordinary behaviour is switched off within a week. A
detector that is switched off catches nothing.

**The threshold is aircraft cruise speed (900 km/h)**, not something lower.
Setting it lower flags every long-haul flight, which is an alert for each
business traveller on each trip. Anything above it is not slow travel. It is two
places at once.

**Sign-ins less than a minute apart are not checked.** Take two authentications
seconds apart, from the same building. A kilometre of coordinate rounding can
compute an absurd speed out of them. Below the floor, the answer is "not
checked", not a confident wrong one.

**The distance is great-circle, not flat.** A flat approximation is wrong by
roughly the cosine of the latitude. That is fine near the equator, and badly
wrong in northern Europe, which is where a great many of these people are.

**"Not checked" is never "fine".** No position, no history, or out-of-order
timestamps each return `Checked: false` with a reason, and the policy condition
is *satisfied*.

A condition that failed whenever it could not be evaluated would lock out every
person signing in for the first time. It would also lock out every deployment
without a location source. That is how a risk signal becomes an outage.

**(0,0) is not a position.** It is a real place in the Atlantic. A nil-handling
bug that leaves coordinates at their zero value will put somebody there. It will
then flag their next sign-in as impossible travel from the Gulf of Guinea.
Positions carry an explicit `Known` flag, rather than relying on the zero value.

## What is stored, and what deliberately is not

**Not the IP address.** This schema has hashed addresses from the beginning. It
did so precisely so that a breach does not hand somebody a movement log for
every person.

What the check needs is a coarse position and a time, so that is what is kept.
It keeps the country, the region, and coordinates **rounded to two decimal
places**, about a kilometre. That is enough to compute a plausible speed over hundreds of
kilometres, and useless for finding where somebody lives.

The rounding happens at the **write**. A precise value rounded only for display
is still a precise value in the database, and the database is what leaks.

## Where positions come from

**`SIGNARI_GEOIP_STATIC`** maps CIDR (Classless Inter-Domain Routing) ranges of
addresses to fixed positions:

```
SIGNARI_GEOIP_STATIC="10.0.0.0/8=GB,51.51,-0.13;198.51.100.0/24=BR,-23.55,-46.63"
```

Many deployments know exactly where their networks are, such as an office range,
a VPN concentrator or a data centre. For those, a licensed database buys
nothing.

Addresses outside every range are **unknown**, not defaulted. Putting
unrecognised addresses at a fixed point would make every one of them look like
impossible travel from the office.

**`SIGNARI_GEOIP_DB`** names a MaxMind-format database. The reader is **not
implemented yet**, and the resolver says so rather than pretending. A lookup
written against a database this repository cannot test with is a lookup nobody
has ever seen return the right answer.

The database is also not bundled and not downloaded. It is licensed, and it
changes weekly. An identity provider that fetches a binary blob from the internet
on startup has added a supply chain to the authentication path.

## A bug worth recording

The refusal worked in testing while **nothing was recording locations at all**.
An edit had silently failed to apply, and the build succeeded. The only row in
the table was one inserted by hand to set up the test.

In a real deployment, the check would have compared against nothing, forever,
and reported "not checked" every time.

It was found by checking what the table contained after a normal sign-in, rather
than by trusting that the refusal proved the whole path worked. It did not: it
proved half of it.
