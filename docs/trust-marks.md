# Trust Marks

A **Trust Mark** is a signed statement by an accreditation authority that some
entity conforms to a set of criteria.

Specification: OpenID Federation 1.0, **Final, 17 February 2026**, §7 and
§8.4–§8.6.

## What it answers that a Trust Chain does not

A Trust Chain proves **provenance**: this entity is who it claims to be, and an
authority above it vouches for its keys. It says nothing about **conformance** —
whether the entity has been assessed against a framework and passed.

So a federation can have a perfectly valid chain to a relying party it must not
admit. A university federation may resolve a chain to every member's software and
still need to know which of them have been assessed against the national privacy
profile. That is what a Trust Mark carries, and it is why the two are separate
mechanisms rather than one.

## The claim name that changed

The type identifier claim is **`trust_mark_type`**.

Drafts of this specification called it `id`. A great deal of deployed code and a
great deal of written-down knowledge still says `id`, and a fair number of
tutorials show a mark carrying both.

Signari writes only `trust_mark_type`, and **refuses** any document carrying
`id` — including one carrying both. A document carrying both means two things at
once, which is worse than one that means the wrong thing: a reader preferring one
member and a reader preferring the other disagree about what was asserted, while
each believes it validated the document.

That is a deliberate compatibility break with draft-era issuers. The alternative
— accepting `id` as a fallback — makes this server the reader that prefers the
wrong member.

## The status endpoint is not what you remember

§8.4 in the Final specification:

- The request is **`POST`** with one parameter, **`trust_mark`** — the whole
  signed JWT. Not a `(sub, id)` pair.
- The response is a **signed JWT**, `typ: trust-mark-status-response+jwt`. Not
  `{"active": true}`.

Both changes point the same way.

Asking by coordinates cannot distinguish a mark from its own superseded
predecessor. Re-issue a mark after a reassessment and the old one still matches
`(sub, type)` — so "active" would be true of a *position* and false of the thing
in the caller's hand. Signari looks the mark up by SHA-256 of its exact
serialisation, so the question asked is the question answered.

Answering in plain JSON leaves the single most security-relevant bit in a
federation — *has this accreditation been withdrawn* — flippable by anything on
the network path.

An unknown mark gets **404**, not a signed `invalid`. Signing `invalid` over
bytes we have never seen would mint a statement about somebody else's document,
which a caller could then present as evidence that we had considered it.

## Issuing

    signari trust-mark issue \
      -trust-mark-type https://federation.example/profile/privacy-v2 \
      -trust-mark-sub  https://rp.example.org \
      -trust-mark-lifetime 8760h

The type identifier must be a URL. §7.1 says it "MUST be collision-resistant
across multiple federations" and *recommends* a URL; Signari **requires** one,
which is stricter than the text. A bare word like `certified` is exactly the
collision §7.1 warns about — two federations both mint it, and a reader that
trusts one now trusts the other's.

Re-issuing supersedes: the previous active mark for that `(type, subject)` is
marked revoked with the reason `superseded by a later issuance`, in the same
transaction, and kept. Reassessment is the ordinary lifecycle of a conformance
mark, and "what did we assert about this entity in March" has an answer only if
the old row survives.

### Issuing without an expiry

`-trust-mark-lifetime 0` issues a mark with no `exp`. §7.1 permits it and says it
means the mark does not expire.

It is a commitment, made by omitting a flag, so the command says so out loud.
§7.3's expiry step becomes vacuous, which means **the only way anybody learns the
mark was withdrawn is to query the status endpoint** — and a reader that caches
and does not re-check will honour it indefinitely.

## Revoking

    signari trust-mark revoke \
      -trust-mark-type https://federation.example/profile/privacy-v2 \
      -trust-mark-sub  https://rp.example.org \
      -trust-mark-reason "failed the 2026 reassessment"

Revocation is local. **Nothing in the protocol tells the subject**, which is
still publishing the mark in its own Entity Configuration and will keep doing so.
Readers learn by querying §8.4. The command prints this, because the gap between
"recorded as revoked" and "no longer honoured anywhere" is where an operator
stops following up.

The guard is in the `WHERE` clause. Two operators revoking at once would
otherwise both read `active`, both write, and the record would keep only the
second reason and the second timestamp — so the first revocation would leave no
trace at all.

## Holding a mark somebody else issued

    signari trust-mark accept -trust-mark-file ./mark.jwt
    signari trust-mark drop   -trust-mark-type ... -trust-mark-issuer ...

`accept` records a mark for republication in the `trust_marks` claim of our own
Entity Configuration.

**The signature is not checked here.** §7.3's validation is the *reader's* job —
a relying party deciding whether to believe our accreditation — and we hold no
key for the issuer. Running the procedure on ourselves would prove nothing we do
not already know.

What *is* checked is everything whose failure damages our own document: a mark
issued to a different entity, one that has already expired, or one whose outer
and inner type identifiers disagree. Each of those makes a conformant reader
reject the mark and, depending on the reader, the whole Entity Configuration — so
one bad row costs us every relying party in the federation.

**Expired held marks are excluded from the published claim, in SQL.** They stay
in the table so `trust-mark list` can show that an accreditation lapsed. A mark
that has expired is one every reader is required to discard, and publishing it
puts a claim in a signed document that the federation throws away while an
operator reading their own configuration sees the accreditation listed.

## Delegation (§7.2)

The owner of a type identifier need not be the party that issues marks of that
type. §7.2's own example is vehicle inspection: the body that mandates the
inspections does not perform them.

    # As the OWNER:
    signari trust-mark delegate \
      -trust-mark-type https://gov.example/inspection \
      -trust-mark-delegate https://inspector.example \
      -trust-mark-lifetime 8760h > delegation.jwt

    # As the DELEGATE:
    signari trust-mark issue \
      -trust-mark-type https://gov.example/inspection \
      -trust-mark-sub https://garage.example \
      -trust-mark-delegation ./delegation.jwt

The direction is the half that gets written backwards: the **owner** is `iss` and
the **delegate** is `sub`. The owner is making a statement about who may issue on
its behalf.

For this to validate, the **Trust Anchor** must publish the owner in its
`trust_mark_owners` claim, *with the owner's federation keys*. §7.2.2 verifies
the delegation against the keys the anchor publishes — never against anything the
delegation itself carries. `trust-mark delegate` prints this reminder, because a
delegation that validates nowhere looks exactly like one that validates.

## The Trust Anchor's two claims

    signari trust-mark issuers -trust-mark-file ./issuers.json
    signari trust-mark owners  -trust-mark-file ./owners.json

Both are refused unless this entity is a Trust Anchor — a schema `CHECK` and a
refusal in `oidfed.Build`, two gates for one rule. §3.1.2 says every reader
**MUST ignore** these claims anywhere else, so publishing them from a subordinate
writes down a federation policy that appears to be in force and is applied
nowhere.

### `trust_mark_issuers` and the empty array

```json
{
  "https://openid.net/certification/op": [],
  "https://refeds.org/sirtfi": ["https://swamid.se"]
}
```

§3.1.2: *"If the array following a Trust Mark type identifier is empty, anyone
MAY issue Trust Marks with that identifier."*

**That is the opposite of how an empty list reads everywhere else in Signari**,
where an empty list permits nothing — the rule the SSF stream `Allows` field
follows, on the grounds that reading an empty list as "everything" is how a
half-made configuration becomes a live grant.

Here the specification says otherwise, so it is implemented as written. What is
*not* collapsed is the three states, which mean three different things:

| state | meaning |
|---|---|
| claim absent | the anchor has not constrained issuers at all |
| type absent from the claim | the anchor enumerated the types it governs, and this is not one |
| type present, empty array | **anyone** may issue this type |

`oidfed.TrustMarkIssuers.IssuerPermitted` returns `(permitted, known)` so the
first two stay distinguishable at every call site. A naive `len(list) == 0 →
deny` turns the specification's "anyone" into "nobody" and every mark in the
federation stops validating; a naive `len(list) == 0 → allow` applied to the
absent-type case turns an unenumerated type into an unguarded one.

`trust-mark issuers` prints `ANYONE may issue this` for each empty array at the
moment it is set, because the file being loaded looks identical either way.

### `trust_mark_owners` and private keys

The owners claim carries a JWK Set, and it goes into a signed document served to
the whole federation. `trust-mark owners` refuses any key carrying a private
member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`) — the same rule
`attester add` applies, for the same reason: a private key pasted in by mistake
would be published, the operator's only signal would have been that nothing
complained, and it is not recoverable.

## Validating a mark (§7.3)

`oidfed.ValidateTrustMark` implements all nine steps. Two of them are worth
calling out.

**Step 4 — the containing entity.** *"The Entity Identifier of the Entity whose
Entity Configuration contains the instance MUST match the value of the Claim sub
in the Trust Mark."*

This is the cheapest forgery in the specification and it needs no keys at all:
copy a genuine, unexpired, correctly signed Trust Mark out of one entity's
configuration and into your own. An implementation that skips step 4 accepts it.
`TrustMarkOptions.ContainingEntity` has no default and validation fails without
it.

**The issuer's keys arrive from a completed chain.** §7.3: *"An Entity MUST
therefore establish trust in the Trust Mark Issuer by following the procedure
defined in Section 10 prior to starting the Trust Mark validation process."* So
`IssuerJWKS` is a parameter, never read from the mark. This is the same shape as
`ValidateChain` taking the anchor's keys out of band, and for the same reason: a
document that supplies the key that verifies it verifies nothing.

**`exp` is optional and the check is not.** §7.1 makes `exp` OPTIONAL; §7.3 says
"the current time MUST be before the time represented by the `exp` Claim". Read
together the check is vacuous when the claim is absent, and §7.3 then adds that
where marks are issued without an expiry "it is RECOMMENDED that a mechanism be
provided to validate them, such as the Trust Mark Status endpoint". Signari
accepts an absent `exp`, and this is precisely the case the status endpoint
exists for.

## Endpoints

| | |
|---|---|
| `POST /federation/trust_mark_status` | §8.4. `trust_mark=<jwt>`. Returns a signed `trust-mark-status-response+jwt`, or **404** for a mark we did not issue |
| `GET /federation/trust_mark_list` | §8.5. `trust_mark_type` required, `sub` optional. Returns a JSON array of Entity Identifiers, `[]` when nobody holds it |
| `GET /federation/trust_mark` | §8.6. `trust_mark_type` and `sub` both required. Returns `application/trust-mark+jwt`, or **404** |

All three are unauthenticated, throttled by their own bucket, and registered only
when this instance has federation keys.

They are **advertised** in `federation_entity` metadata only once this entity has
issued a Trust Mark. The metadata answers "is this a Trust Mark Issuer", and the
honest evidence is whether it has ever issued one — a configuration flag would be
a second copy of the same fact that an operator can set and never act on. It is a
fact that only goes one way: rows are revoked, never deleted, so an issuer that
has withdrawn everything still advertises a status endpoint. Which is right —
"was this withdrawn" is exactly the question that entity will be asked.

§8.6 answers **404** identically for never-issued, revoked and expired. Anyone
actually holding the mark can distinguish those through the status endpoint;
distinguishing them here would let a stranger enumerate which entities we have
ever accredited and then withdrawn.

## Privacy (§19.2)

An unauthenticated status endpoint lets a Trust Mark Issuer observe who is
evaluating whom. §19.2 recommends short-lived marks, or using the listing
endpoint with `trust_mark_type` alone and no `sub`.

That recommendation is addressed to the **caller**, so both forms of the listing
request are answered. What Signari does on its own side is bound the work: these
are unauthenticated database queries, and the bucket is generous enough that a
federation resolving chains legitimately never notices, because a limit tight
enough to matter to an attacker would be tight enough to break the protocol it
protects.
