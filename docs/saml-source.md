# Signing in through a SAML provider

## Introduction

Some organisations already sign their people in with an identity provider that
speaks Security Assertion Markup Language ([SAML](glossary.md#saml)), often
their company directory. You can let those people sign in to Signari through it.

Signari sends the person to that provider, which this page calls the
"upstream". The upstream sends back a signed "assertion", an XML document that
says who signed in. Signari checks every part of it before it believes it, and
then signs the person in.

You add an upstream with `signari idp add -kind saml`, or
[from its metadata](saml-metadata.md).

> [!NOTE]
> This page is the **inbound** half. `/saml/sso` serves applications consuming
> assertions this engine issues, and is covered in [SAML 2.0](saml.md).

## Add a SAML provider

To add an upstream, give its entity ID, its sign-in address and its signing
certificate:

```sh
signari idp add -org <uuid> -kind saml -slug corp \
  -entity-id https://adfs.corp.example/adfs/services/trust \
  -sso-url https://adfs.corp.example/adfs/ls/ \
  -sp-cert /etc/signari/adfs-signing.pem \
  -nameid-format emailAddress
```

In this example, `-entity-id` is the "entity ID", the name the upstream gives
itself in SAML. `-sso-url` is where Signari sends people to sign in, and
`-sp-cert` is the certificate the upstream signs with. `-nameid-format` says
which kind of name the upstream gives the person.

The command prints the addresses the upstream needs. The ACS URL, short for
Assertion Consumer Service, is where the upstream sends its assertions:

```
sign-in URL : /saml/source/corp/start
ACS URL     : <issuer>/saml/source/corp/acs
metadata    : <issuer>/saml/source/corp/metadata
```

Give the upstream the **metadata URL** rather than typing the entity ID and ACS
URL into its console by hand. A mistyped audience produces an assertion that
Signari refuses, correctly and unhelpfully. The same goes the other way: an
upstream that publishes metadata can be [registered from it](saml-metadata.md),
and read again when its key rotates.

## Consuming an assertion is a security boundary

Issuing an assertion is arithmetic. Consuming one is not. The document arrives
from a browser under an attacker's control, and every field is a claim by
whoever sent it until proven otherwise.

Each check below has been the cause of a published vulnerability, a CVE (Common
Vulnerabilities and Exposures entry), in some other implementation. Signari
makes every one of them:

| Check | Why skipping it is a full bypass |
|---|---|
| signature | an unsigned assertion is a claim by anybody |
| `InResponseTo` | otherwise an assertion captured anywhere replays into any browser |
| `Destination` | an assertion minted for another service is not ours |
| `Audience` | same, stated by the issuer rather than the transport |
| `NotBefore` / `NotOnOrAfter` | otherwise it is a permanent credential |
| assertion ID | a valid assertion must work **once** |

An assertion's audience and timing say who it is for, and when. What says it may
be presented to Signari is a bearer `SubjectConfirmation` naming this ACS as its
`Recipient`, with a `NotOnOrAfter` that has not passed.

Every confirmation is tried, since an assertion may carry one for each
recipient, and one that fits is required. An assertion whose only confirmation
names another application's ACS is refused, as is one with no `Recipient` at
all.

## No email matching, at any setting

An external identity is matched on `(provider, subject)`: the upstream it came
from, and the person's identifier there. Never on email.

## Signature wrapping, tested five ways

XML signature wrapping (XSW) attacks work by making the verifier and the
application look at different elements. The defence is structural.
`ConsumeResponse` returns the assertion **inside the element goxmldsig
verified**. Reading a different subtree is then not a discipline somebody has to
remember. Here goxmldsig is the XML signature library the engine uses.

Each of these five forged documents is refused:

```
forged assertion placed before the signed one      refused
forged assertion placed after the signed one       refused
signed assertion hidden inside Extensions          refused
forged assertion nested inside the signed one      refused
duplicate IDs                                      refused
```

The test runs each **twice**: once normally, and once with the outermost guard
switched off. A layered defence claimed in a comment is not a layered defence.

That experiment corrected the claim originally written here. Without the
assertion-count guard, no payload yields the forged subject, but one is
*accepted* while returning the honest one. That is harmless in itself, and a
malformed document accepted is where the next bug starts. The guard stays.

### Where a signature may be

A signature may be on the response, the assertion, or both. Each signature is a
direct child of the element it covers, and names that element's ID.

When both are signed, both must verify: a response the provider signed around an
assertion somebody else signed is refused. Any other signature in the document,
wherever it is, refuses the whole document.

Many providers sign both levels when told to sign the response and the
assertion. Until November 2026, the two were counted together and every such
response was refused. A sign-in through a public test provider found it.

## Unsolicited sign-in is off

An "unsolicited" response is one the upstream sends without being asked, which
SAML calls "IdP-initiated". It has no `InResponseTo`, so it cannot be tied to a
request this browser made. That means a valid assertion captured from a log, a
proxy or a shared machine can be posted into a victim's session.

Some portals only sign people in that way, so `-allow-unsolicited` exists. It
prints a warning that says exactly that.

## Transient NameIDs are refused

A "NameID" is the name the upstream gives the person in its assertion. A
transient NameID is a different value on every sign-in. Linking an account to
one creates a new orphaned account each time somebody signs in.

So a transient NameID is refused at configuration **and** at sign-in, with the
fix in the message.

## Verified against a live engine

This was checked against a running Signari, not only in unit tests. A signed
assertion was posted to the running ACS endpoint. It was signed by an
independent implementation (`lxml` + `cryptography`), with a different
canonicaliser and different cryptography from the engine's `goxmldsig`.

So the claim that Signari works with other software is agreement between two
implementations, rather than one library agreeing with itself. Each case, and
what Signari did:

| | |
|---|---|
| valid assertion | user created, linked, session issued, `amr: ["fed"]` |
| the same assertion again | refused — no sign-in in progress |
| replayed against a fresh request | refused — answers a different request |
| same assertion ID, fresh request, re-signed | refused — **already used** |
| no RelayState (unsolicited) | refused |
| subject tampered, signature untouched | refused — signature |

Each was refused for a *different* reason, which is the point of running them.
The last one is the only proof that the replay table fires at all. The first
three were caught earlier in the chain, by `InResponseTo`.

### The disagreement worth having

The first signature the Python signer produced was **rejected**. The cause was
whitespace: `lxml`'s `remove()` takes the element *and its tail text*, while the
enveloped-signature transform removes only the element. So the signer digested a
document the verifier would never see.

Two independent implementations disagreeing is exactly what this exercise is
for. The bug was in the test harness, but it took a real signature to find out
which side was wrong.

## Email addresses are recorded as verified

A SAML assertion has no `email_verified` field, and there is nowhere to put one.
So the deployment answers the question, and for an enterprise upstream the
honest answer is yes. The organisation's own directory authenticated the person
and stated their address, which is the premise of federating to it at all.

Left off, a newly registered source refuses every sign-in, with a message about a
claim the protocol cannot make. That would be a dead feature, and the first
deployment to hit it would reasonably conclude the software is broken.

This is safe to default on **only because** the address is never used to find or
match an account. It is recorded, displayed and used for notifications. The
attack that makes trusting email dangerous elsewhere is closed one level up, by
[never matching on email](#no-email-matching-at-any-setting).

## This deployment's keys toward an upstream

Signari can sign the requests it sends an upstream. Each upstream gets keys of
its own, kept apart from the keys that sign tokens, so one partner's certificate
is nobody else's.

The keys are made in Signari and sealed under the
[root key](glossary.md#root-key), and only the certificate ever leaves. These
commands make a signing key, and then turn on signed requests:

```sh
signari idp saml-key -slug corp -purpose signing
signari idp saml-use -slug corp -sign-requests=true
```

The certificate is in the upstream's metadata at `/saml/source/corp/metadata`,
with `AuthnRequestsSigned` saying what the upstream can expect. It is also in the
answer to `idp saml-key`.

Give the certificate to the upstream first, and turn signing on second. A
provider that verifies requests refuses any it has no certificate for.

To rotate, make a second key. The newest signs, and the older stays in the
metadata until it is retired with `signari idp saml-key -slug corp -retire <id>`.
A key the upstream is held to cannot be retired while it is the last one.
Neither setting can be turned on with no key to do it with.

A signature is over the HTTP-Redirect query as it is sent, so it verifies however
the upstream's URL was written. The signing is with RSA-SHA256, which is what a
provider that insists on signed requests can be counted on to take.

## Encrypted assertions

An upstream that encrypts its assertions needs a key to encrypt to. These
commands make one, and then refuse an assertion from the upstream that is not
encrypted:

```sh
signari idp saml-key -slug corp -purpose encryption
signari idp saml-use -slug corp -require-encryption=true
```

The certificate is in the metadata with `use="encryption"` and the algorithms
taken here. Any live key opens an assertion, so an upstream can move to a new
certificate in its own time.

Until `-require-encryption` is on, a plain assertion is still taken. That is how
a change of this kind is rolled out without an outage.

`EncryptedAssertion`, `EncryptedID` and `EncryptedAttribute` are all read, the
last as the attribute it holds. When no key is configured, an assertion carrying
an encrypted attribute or NameID is refused, not read without it. An address
dropped quietly would match the person on less than the upstream sent.

The table names two ways of using the AES cipher: GCM (Galois/Counter Mode) and
CBC (cipher block chaining). Signari takes and refuses these algorithms:

| | |
|---|---|
| Key transport | RSA-OAEP, as `rsa-oaep-mgf1p` or `rsa-oaep`, with SHA-1 or SHA-256 |
| Refused outright | RSA PKCS#1 v1.5. It is an oracle on the key itself, and no signature over one document changes what the key does for whoever sends it another |
| Data | AES-128-GCM and AES-256-GCM |
| Only behind a signature | AES-128-CBC and AES-256-CBC |

CBC is what this deployment refuses to send, and takes on one condition. The
attack on it needs a receiver that decrypts what an attacker has altered, and
lets it be seen what became of it. Nothing can alter what a verified signature
covers.

So a signature over the ciphertext, which means on the response, is checked
before a byte is decrypted. CBC with no such signature is refused, and says so.
An encrypted NameID sits inside the assertion, whose signature is checked first
in any case.

Encrypting to a public key says nothing about who wrote the assertion. So one
that is signed by nothing is refused, as a plain one would be.

What decrypts is a document from outside like any other. It gets the same scan
for DTDs (document type definitions) and entities. It must hold one `Assertion`
and nothing else, and gets every check of the assertion after that. A second
assertion, whether inside the ciphertext or beside it, is refused.

## Single Logout with an upstream

SAML's "Single Logout" carries a sign-out between Signari and an upstream, in
either direction. A SAML "binding" is the way a message travels, such as a
browser redirect.

It needs a sign-out address and a signing key. The sign-out address
is read from the upstream's metadata, or set with
`signari idp logout -slug corp -url <its SingleLogoutService>`. With both,
sign-out goes both ways on the HTTP-Redirect binding.

The metadata offers `/saml/source/corp/slo` once both are there, and not before,
because a sign-out request has to be signed.

A sign-out in Signari ends the Signari session first. It then sends the browser
to the upstream with a signed `LogoutRequest`, carrying the NameID and
SessionIndex the upstream's assertion did. Those are kept sealed in the browser,
since a request with anything else ends nothing.

The upstream's answer brings the browser back to where it was going. With no
signing key, the sign-out stops in Signari, and the Signari session has ended
all the same.

A `LogoutRequest` from the upstream has to be signed with the certificate
registered for it, on the HTTP-Redirect or HTTP-POST binding, and is heard once.
It ends every Signari session of the person it names that came through a
provider.

No record is kept that could match its SessionIndex to one of them. The upstream
signed them all in, and it has said they are signed out. A name nobody in
Signari is linked to is answered with success, that being the state it asked
for. The answer is signed and goes back by redirect.

### With no browser

An upstream can end a session on its side by itself, because an administrator
ended it, it expired or the person was deactivated. It can say so over the SOAP
binding, with a signed `LogoutRequest` in a SOAP 1.1 envelope posted to
`/saml/source/corp/slo/soap`. The metadata always offers that address, since it
needs nothing of this deployment's.

It is held to everything the redirect binding's request is: the upstream's
signature, never optional; heard once; and the Destination, when it names one.
It ends the same sessions.

The `LogoutResponse` goes back on the same connection. It is signed when a
signing key is held in Signari, and unsigned when none is, the sign-out having
happened either way. A request refused is answered with a SOAP fault.

## What is not done

A sign-out address that takes only HTTP-POST is left out, with a note, because a
sign-out from Signari reaches an upstream as a redirect.

It is absent from the metadata document as well as from the code. A capability
advertised and not implemented is the failure this project sweeps for.
