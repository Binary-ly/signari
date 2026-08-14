# SAML 2.0

Signari is a SAML identity provider. Applications that speak SAML — Grafana,
Jira, Zendesk, Salesforce, most enterprise software — sign in against it.

```sh
signari saml add-sp \
  -org        <org-uuid> \
  -entity-id  https://grafana.example.com/metadata \
  -name       Grafana \
  -acs        https://grafana.example.com/login/saml/acs
```

Then point the application at `https://auth.example.com/saml/metadata`.

| Endpoint | Purpose |
|---|---|
| `GET /saml/metadata` | what the service provider imports |
| `GET /saml/sso` | HTTP-Redirect binding |
| `POST /saml/sso` | HTTP-POST binding |

## What was built against, and why it looks like this

Before writing any of it, the published advisories for the three most-used Go
SAML libraries were read rather than recalled:

| library | advisories |
|---|---|
| `github.com/crewjam/saml` | 4 |
| `github.com/russellhaering/gosaml2` | 5 |
| `github.com/russellhaering/goxmldsig` | 3 |

Almost every one is a **signature-validation or authentication bypass**. Not one
is a cryptographic break. They are parsing and policy decisions — an assertion
accepted because *something* in the document was signed, a LogoutRequest acted
on with no signature at all, a compressed request expanded without a bound.

So the defences are explicit, and the dangerous configuration is the one you
would have to ask for:

**The assertion is signed, not just the response.** If only the response carries
a signature, an attacker holding one valid response can often move the signed
element aside and insert their own assertion; the document still contains a
valid signature over *something*. Signing the assertion means the element
carrying the identity is the element covered.

**XML comments are refused outright.** Go parses
`<Issuer>admin<!---->@evil.test</Issuer>` as `admin@evil.test`. Canonicalisation
drops comments before the digest is computed, and other parsers keep only the
first text node — so the signed bytes, our value, and the peer's value can all
differ. That is CVE-2017-11427 and its relatives. Rather than trying to agree
with every other implementation, documents containing comments are rejected. No
legitimate service provider puts a comment in an AuthnRequest.

**Decompression is bounded during the read**, not measured afterwards. A few
kilobytes of DEFLATE expands to gigabytes; that is how both `crewjam/saml` and
`gosaml2` were taken down.

**ACS URLs are an exact-match allow-list.** This is the SAML equivalent of
`redirect_uri`, and it is where assertions get stolen: whoever can steer the
`AssertionConsumerServiceURL` receives a genuine, correctly signed assertion for
a real user at a server they control. Seventeen evasion techniques are tested —
attacker host, registered host as a prefix, userinfo `@`, subdomain, traversal,
trailing slash, scheme downgrade, explicit `:443`, case, percent-encoding,
appended query and fragment, double slash, backslash, embedded null, newline.

**A request that fails validation is refused to the browser**, never turned into
a SAML error POSTed to the URL the request named. Doing that would make the
endpoint a redirector for any entity id an attacker invents — the ACS URL is
precisely what is in dispute.

**NameIDs are pairwise by default.** Each service provider sees a different
opaque identifier for the same person, so two of them cannot correlate their
users. It also survives an email change, which `emailAddress` NameIDs do not —
the SP treats the NameID as the account key, so a new value means a new, empty
account.

**The authentication context is what actually happened.** A password-only
session asserts `PasswordProtectedTransport`, never
`MultiFactorAuthentication`. Overstating it tells a service provider its
step-up requirement was satisfied when it was not.

## Proof, from tools that are not ours

Verifying our own signature with our own library proves only self-consistency.

- **xmlsec1** (the reference C implementation most SAML software is built on)
  verifies the assertion, and rejects it once the NameID is edited.
- **xmllint against the official OASIS schemas**, vendored into `testdata`,
  confirms the document is schema-valid.
- The parser has taken 3.5M fuzz executions with no crash.

Schema validation earned its place immediately: it caught a document carrying
**two identical `<ds:Signature>` elements**. `goxmldsig` appends the signature
onto etree's child slice without setting its parent, so the reordering code's
`RemoveChild` silently did nothing and the insert left the same element in the
list twice. xmlsec1 reported OK — it found a valid signature — so every
signature-based test passed. A duplicated signature is also exactly the shape a
wrapping attack takes, and strict providers reject it.

## Keys and certificates

SAML needs an X.509 certificate where OIDC needs only a public key, because
service providers **pin** it out of the metadata.

That makes rotation a coordinated change rather than a background one. The
certificate is generated once and stored, never regenerated — a fresh
certificate has a new fingerprint, and every SP pinning it would start rejecting
assertions intermittently depending which node answered.

Metadata publishes **every** current certificate so providers can pick up an
incoming one before it is used. Rotation is then: publish, wait for providers to
refresh, switch.

SAML requires an **RS256** key. ECDSA is specified and refused by a great deal
of real service-provider software, so an EC-signed assertion would be correct
and rejected anyway. Signari says so up front rather than letting you find out:

```
this instance's active key is ECDSA, which most SAML service providers cannot
verify. Rotate in an RS256 key before enabling SAML: `signari keys rotate -alg RS256`
```

## Single logout

Service-provider-initiated logout works on the HTTP-Redirect binding:

```sh
signari saml add-sp ... -slo https://sp.example.com/slo -sp-cert ./sp.crt
```

**A LogoutRequest is acted on only when signed.** gosaml2 GHSA-pcgw-qcv5-h8ch
accepted unsigned ones, which meant anybody who could reach the endpoint could
sign any user out of everything, needing no credential at all — the cheapest
denial of service there is against an identity provider.

So a provider with no certificate on file cannot use single logout, and
registering a logout URL without one is refused at the CLI rather than
producing a configuration that looks complete and rejects every request.

The signature is checked over the **raw query-string octets** in the order the
specification fixes, not over any `<ds:Signature>` the document happens to
carry. On the redirect binding the signature *is* the query parameters; an
embedded element proves nothing about what was actually sent. Rebuilding the
string from a parsed map is the classic mistake — Go's encoder escapes a
different character set, sorts keys, and drops an empty RelayState, so the bytes
verified are not the bytes signed.

Verified live against the running engine:

| | |
|---|---|
| unsigned LogoutRequest | refused, session stays live |
| valid request substituted for the signed one | refused at signature verification |
| correctly signed | `200`, session revoked |
| replay of the same request id | `Requester`, session not touched again |

RSA-SHA1 is refused outright. Chosen-prefix collisions against SHA-1 are
practical, and a warning nobody reads is not a control.

## Logout propagation

Signing out of Signari now signs the user out of the SAML service providers too.

SAML has no usable back-channel — the SOAP binding exists and almost nothing
implements it — so propagation means walking the **browser** through each
provider's logout endpoint in turn. Signari redirects to provider one, it ends
its session and redirects back, then provider two, until the list is empty.

**Our session is terminated before the chain starts, never at the end.** A chain
that ended the local session last would leave the user signed in here whenever a
provider fails to redirect back — and they fail all the time: closed tab, 500,
dropped network. By the time the first redirect is issued, signing out of Signari
has already happened. Everything after is best-effort notification, and what
could not be reached is recorded rather than assumed:

```json
{"status":"signed out",
 "notified":["https://spb.test/md","https://spa.test/md"],
 "failed":[]}
```

Verified end to end against two service providers:

| | |
|---|---|
| requests sent | exactly one per provider |
| NameID | each provider received its **own** pairwise value |
| SessionIndex | the one from that provider's assertion |
| signature | verified by **openssl** against the key in our published metadata |
| local session | revoked before the chain began |

The chain state lives in the database, not a cookie and not the URL. A cookie
would be editable by the user, and it names the endpoints to visit — an attacker
could rewrite it and have a browser carrying our signature visit their own
server. The URL would leak it into every referrer header and access log along
the way. The chain token travels as `RelayState`, which providers return
unmodified, and only its hash is stored.

Chains are bounded at ten providers and expire after five minutes; the janitor
sweeps abandoned ones.

**One deliberate asymmetry:** an inbound LogoutRequest must be signed, but a
LogoutResponse coming back is not required to be. A response ends nothing — the
session is already gone — so the worst a forged one achieves is advancing our own
bookkeeping past a provider we were about to notify, and it costs a valid chain
token the attacker does not have. Requiring a signature would instead strand the
chain at every provider that answers unsigned, which most do.

## Signed AuthnRequests

Off by default, per provider:

```sh
signari saml add-sp -org <uuid> -entity-id https://sp.test/md \
  -acs https://sp.test/acs -sp-cert sp.crt -want-signed-requests
```

The certificate is not optional. Requiring signatures with nothing to verify them
against refuses every login through that provider, so `-want-signed-requests`
without `-sp-cert` is rejected at registration — the same fail-closed rule the
logout URL already had. `signari doctor` reports the same combination as critical
if it is ever created another way.

The signature is checked **before** validation, because everything validation goes
on to decide — which ACS URL, which NameID format, whether to force
re-authentication — is read out of the document.

### The two bindings sign different things

| Binding | What is signed | Verified by |
| --- | --- | --- |
| HTTP-Redirect | the raw query octets, `SigAlg`/`Signature` as separate parameters | `VerifyRedirectSignature` |
| HTTP-POST | an enveloped `<ds:Signature>` inside the document | `VerifyEmbeddedSignature` |

A redirect-binding request may *also* contain a `<ds:Signature>`. Verifying that
one proves nothing — the attacker supplied the whole document — so the binding the
request arrived on decides which check runs, and there is no fallback between them.

### What the POST binding needed on top of goxmldsig

goxmldsig gets the cryptography right and deliberately leaves the policy to its
caller. Three of its behaviours are individually reasonable and collectively a
bypass:

- `findSignature` **traverses the tree**, so a signature anywhere inside the
  document can satisfy it.
- a `Reference URI` of `""` is accepted, meaning "the whole document".
- **RSA-SHA1 is accepted.** The redirect binding here already refuses SHA-1, and a
  signature scheme is only as strong as the weakest binding that accepts it.

So the structure is checked first, and only then is anything verified
cryptographically:

1. exactly one `Signature` element in the whole document,
2. and it is a **direct child of the root**,
3. exactly one `Reference`, whose URI is `#<root ID>`,
4. no duplicate `ID` attributes anywhere,
5. SHA-1 refused on both the signature method and the digest,
6. and afterwards, the element goxmldsig says it verified must still be the
   element we parsed — compared by ID and tag.

Rule 2 is the one that stops classic wrapping, and the test for it uses distinct
IDs deliberately so the duplicate-ID rule cannot be what passes it. Without rule 2
that document has one valid signature, no duplicate IDs, and sails through.

### Surviving the sign-in redirect

A request that arrives before the user is signed in gets parked. On the redirect
binding the signed bytes are *the query as the service provider encoded it*, so
rebuilding that query with `url.Values` changes the escaping and the ordering and
the signature no longer verifies — which would surface **after** the user had
already typed their password, the worst place to discover it.

The original query is therefore carried across verbatim as one opaque `SigQuery`
value. It is attacker-supplied like anything else on a URL, so it earns nothing on
its own: it still has to verify against the registered certificate, and it must
name the same `SAMLRequest` being processed. Both were tested by tampering:

```
drop SigQuery from the resumed URL     -> "no signature on the redirect binding"
swap in a different signed AuthnRequest -> "the preserved signature covers a
                                            different AuthnRequest than the one
                                            being processed"
```

### Metadata

`WantAuthnRequestsSigned` is per provider here, so one global document cannot state
it truthfully for everyone. `/saml/metadata` reports the default (`false`, what a
new registration gets) and `/saml/metadata?sp=<entityID>` reports what is actually
configured for that provider. An unknown entity id gets the default document rather
than an error — failing would make the endpoint a way to enumerate which service
providers are registered.

## Single logout on both bindings

`GET /saml/slo` takes the HTTP-Redirect binding, `POST /saml/slo` the HTTP-POST
binding. Which one a request arrived on decides how it is decoded **and** how its
signature is checked — redirect signs the raw query octets, POST signs the
document — and there is no fallback between them.

Unlike AuthnRequests this is never optional. A LogoutRequest acted on unsigned
lets anybody sign anybody out with no credential at all (gosaml2
GHSA-pcgw-qcv5-h8ch), so a provider with no certificate on file cannot use single
logout.

Tested against the running server with a service provider built separately from
the engine:

| request | result |
| --- | --- |
| correctly signed | accepted, session ended |
| unsigned | refused — "the LogoutRequest carries no signature" |
| subject changed after signing | refused — signature does not verify |
| signature-wrapped | refused — "the Signature is not a direct child of the LogoutRequest" |

The wrapping case used a **different** outer ID, so the duplicate-ID rule was not
what caught it. The placement rule was.

### The response goes back on the binding that was registered

Found by watching the wire rather than reading the code: every `LogoutResponse`
used to leave as an auto-submitting POST form, including to endpoints registered
as `HTTP-Redirect` — which was all of them, since that was the only binding
`saml add-sp` could store. A provider expecting `SAMLResponse`/`SigAlg`/`Signature`
as query parameters got a form POST and had nothing to parse.

The binding is now stored and honoured:

```sh
signari saml add-sp ... -slo https://sp.test/slo -slo-binding HTTP-POST
```

A provider that registered both is answered on whichever binding it used. The
redirect-bound response was checked with **openssl**, against the certificate the
IdP publishes in its own metadata — an entirely separate path from the code that
produced it:

```
openssl dgst -sha256 -verify idp.pub -signature sig.bin signed.bin
Verified OK
```

## Not yet built

- **Encrypted assertions.** Transport is TLS; the assertion itself is not
  encrypted.

Each is absent from the metadata document as well as from this list — the rule
that an endpoint enters discovery only once it works applies here too.
