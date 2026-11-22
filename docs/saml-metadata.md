# SAML metadata

Registering a SAML partner from what it publishes about itself, in place of
typing its entity ID, endpoints and certificates in by hand. Both roles: a
[service provider](saml.md) this engine signs people in to, and an
[upstream](saml-source.md) this engine signs people in through.

```sh
# A service provider, from a file or an https URL.
signari saml add-sp -org <uuid> -metadata https://sp.example.com/saml/metadata \
  -metadata-signer /etc/signari/federation-signer.pem

# An upstream.
signari idp add -org <uuid> -kind saml -slug corp \
  -metadata /tmp/corp-idp.xml -metadata-unsigned

# One entity out of a federation's aggregate.
signari saml add-sp -org <uuid> -metadata https://mdq.example.org/aggregate.xml \
  -metadata-signer /etc/signari/federation-signer.pem -entity-id https://sp.example.com/saml
```

The same fields go in the Admin API's two registration routes: `metadata` (the
document) or `metadata_url`, with `metadata_signer` or `metadata_unsigned`, and
on the first `metadata_encrypt`.

## A document is a decision

Metadata names where assertions are delivered and which keys are believed, so it
is treated the way a sign-in response is:

1. Comments and `DOCTYPE`s are refused before anything parses it. A file with a
   comment in it has to have the comment taken out, even a harmless one: this is
   the same rule, for the same reason, as every other SAML document here.
2. The signature is checked: one signature, on the root element, by the
   certificate you named, over the element that carries it.
3. Everything after that is read from **the element the verifier returned**, not
   from the document it was given, so a section added beside the signed one
   changes nothing.

**Unsigned metadata is refused.** To take a document anyway, say so by name with
`-metadata-unsigned`: that is you vouching for where it came from, and only you
can. Giving neither is refused, and so is giving both. The signer is a
certificate you hold out of band, because a document must not vouch for its own
signature; a document's own `KeyInfo` proves nothing.

`validUntil` is honoured, on the root, on the entity and on any group between
them. A signature says who wrote a document and not when, so without it an old
signed file naming an old key could be replayed.

**One entity is chosen by its entity ID, never by position.** An aggregate needs
`-entity-id`. A name that appears twice is refused rather than chosen between.
For a single entity, `-entity-id` is a check.

## What is read

| | Service provider | Upstream |
|---|---|---|
| Endpoints | Every https `AssertionConsumerService` on HTTP-POST, the one marked `isDefault` first and otherwise the lowest `index`; a `SingleLogoutService` on SOAP for a logout with no browser, and one on HTTP-Redirect if it has one | The `SingleSignOnService` on HTTP-Redirect, the binding a sign-in here is sent by |
| Keys | Every certificate with `use="signing"` or no `use` | The same, and at least one has to be current |
| Other | `AuthnRequestsSigned`, the first `NameIDFormat` that fits | The first `NameIDFormat` that fits. `transient` is skipped, since an account linked to one is abandoned at once |

What is left out is reported: an endpoint on a binding this engine does not use,
a plain `http` one, an expired certificate.

**A partner in the middle of a rotation publishes two keys, and both are kept.**
A signature verifies against either, on both bindings, so the partner can switch
whenever it likes.

**A key offered for encryption is not used until you say so.** `-metadata-encrypt`
encrypts assertions to it. Encrypted assertions here are AES-256-GCM, and a
provider that cannot read that loses every sign-in, so this stays a decision. A
key with no stated `use` is taken as a signing key: a provider's two keys are kept
apart.

A flag that would answer the same question as the metadata is refused rather than
preferred: `-acs`, `-slo` and `-sp-cert` on `saml add-sp`, `-sso-url` and
`-sp-cert` on `idp add`. `-nameid-format` and `-name` are yours, and win.

## Reading it again

```sh
signari saml refresh-sp -entity-id https://sp.example.com/saml -dry-run
signari saml refresh-sp -entity-id https://sp.example.com/saml
signari idp refresh-saml -slug corp
```

**A refresh is something an operator does. No timer does it.** A partner's
metadata says where assertions go, and that should not change while nobody is
looking, so the engine never reads it on its own. `-dry-run` shows what would
change, certificates by their SHA-256 fingerprint, and changes nothing.

A refresh is held to the terms of the import. It goes back to the same URL and
checks the same signer, and it has to find the same entity ID, so a document for
somebody else at that address is refused. A partner imported under a signature
does not lose it by being asked again: an unsigned document is refused until
`-metadata-unsigned` is given, and that drops the signer for good. A partner
imported from a file needs `-metadata` again each time, since nothing says where
it came from. `-metadata-signer` replaces the signer, for when a federation
rotates its key.

It does not undo a decision of yours. Signed requests you required stay required
when a document stops saying so, assertions you encrypted stay encrypted, a
provider's NameID format stays what it was, because accounts are linked to it.
A document that would leave a provider unable to do what it is set up for, such as
removing the only key its signed requests verify against, is refused whole.

The Admin API has it as `POST .../saml-providers/{providerID}/metadata` and
`POST .../identity-providers/{slug}/metadata`, taking `metadata`, `metadata_url`,
`metadata_signer`, `metadata_unsigned` and `dry_run`, and answering `changes`,
`notes` and `applied`. A dry run moves no configuration version and records
nothing. Each refresh is recorded as `admin.saml_metadata_read`, with the fields
it changed, the URL, and whether it was signed.

The document is read outside any transaction, through the dialer that refuses
private addresses, over https only, and at most 16 MiB of it. A request carrying
the document itself is limited to 2 MiB; give a federation's aggregate by its URL.
