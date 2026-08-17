# WS-Federation

The passive requestor profile, for SharePoint, Windows Identity Foundation
applications, and anything federated to ADFS before SAML 2.0 was the default.

**This is a compatibility shim for an estate being migrated, not a protocol to
choose.** It is here so that moving off ADFS does not have to mean rewriting
every application first.

## Configuration

There is none beyond registering the application as a SAML service provider:

```sh
signari saml add-sp -org <uuid> \
  -entity-id "urn:sharepoint:intranet" \
  -name "Intranet" \
  -acs "https://intranet.example.com/_trust/"
```

The `wtrealm` is the entity id and `wreply` must be one of the registered reply
URLs. One registration serves both protocols, so an application configured for
WS-Federation is released, policy-gated and audited exactly like a SAML one.

## Endpoints

| | |
|---|---|
| `GET /wsfed?wa=wsignin1.0&wtrealm=…` | Sign-in. Answers with a self-posting form carrying the token |
| `GET /wsfed?wa=wsignout1.0` | Sign-out. Handled by the ordinary end-session path |

`wctx` is passed back untouched, which is what the relying party uses to resume
whatever the user was doing.

## wreply is matched exactly

```
wreply is not one of the reply URLs registered for this application. It is
matched exactly, because anything looser would let a link decide where a signed
assertion is delivered
```

Omitting `wreply` is normal and safest: the registered default reply URL is
used. A prefix match would turn this endpoint into a redirector that delivers a
signed assertion wherever a crafted link points, which is how this class of
endpoint is usually broken.

## The token

A `RequestSecurityTokenResponse` containing a **signed SAML 2.0 assertion**,
built by the same code path that builds one for a SAML 2.0 response.

That reuse is deliberate. A second assertion builder would be a second place for
an audience restriction, a subject confirmation or an authentication context to
be forgotten — and everything that makes the SAML side safe is in the code this
reuses. Assertion encryption works here too, without this endpoint containing a
line about encryption.

## SAML 1.1 is not offered

ADFS issues SAML 1.1 tokens for WS-Federation by default, and some very old
relying parties accept nothing else.

This issues SAML 2.0. Windows Identity Foundation accepts it, and so does any
ADFS-era relying party configured for SAML 2.0. **A relying party that requires
1.1 will not work here.** That is a real limitation, stated here rather than
discovered as a signature failure.

## One bug worth recording

The first version declared `xmlns:wsu` on the `<wsu:Created>` element, so its
sibling `<wsu:Expires>` had an unbound prefix. The document was well-formed to
look at and failed to parse at the far end with an error naming a column number.

Namespaces are now declared on the root. It was found by parsing our own output
rather than by reading it, which is the only way this class of thing is found.
