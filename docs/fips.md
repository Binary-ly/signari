# FIPS 140-3

Signari builds and runs against Go's FIPS 140-3 validated cryptographic module.
This page says exactly which features survive that and which cannot, because the
answer is not "all of them" and nobody can tell you which without running it.

## The short version

```sh
GOFIPS140=latest go build ./cmd/signari
GODEBUG=fips140=only ./signari serve
```

**31 of 36 packages pass their tests under `fips140=only`.** (That count is blunter than
the truth: of the five failures, one is only test fixtures and one is only the
non-FIPS default being covered. See below.) Core OIDC — the
authorization code flow, token issue and verification, JWKS, sessions, refresh,
introspection, revocation, DPoP, mTLS, PAR, device flow — is unaffected.

Five packages do not. Four of them cannot be fixed. The fifth, SAML, can be
configured to work and fails its tests only because they also exercise the
interoperable default. The reason is the same
in every case: a protocol or a stored format mandates an algorithm the module
refuses, and no amount of care on our side changes what the specification says
or what another vendor's database already contains.

## The two modes are not the same thing

`GODEBUG=fips140=on` runs approved algorithms through the validated module and
**still allows** everything else. Almost anything passes. It is the mode most
projects mean when they say they support FIPS, and it is close to meaningless as
a claim.

`GODEBUG=fips140=only` makes non-approved algorithms fail — an error where the
API allows one, a panic where it does not. That is the mode this page is about,
and the numbers above are from it. If you are being asked for FIPS compliance,
find out which of these two the requirement means before planning anything.

## What cannot work under `fips140=only`

### TOTP — `internal/mfa`

RFC 6238 specifies HMAC-SHA1, and effectively every authenticator app implements
only that. SHA-1 in HMAC is not a collision-resistance claim and is not broken in
the way SHA-1 signatures are, but the module does not evaluate the argument: it
refuses HMAC with anything outside SHA-2 and SHA-3.

RFC 6238 does define SHA-256 and SHA-512 variants. Google Authenticator, Authy
and Microsoft Authenticator do not implement them, so enabling one enrols users
into codes their phone cannot produce.

**Consequence: no TOTP.** Use WebAuthn instead, which is unaffected — passkeys
are ECDSA P-256 or RSA with SHA-256 and pass cleanly. This is not a bad trade;
it is the direction to move anyway.

### RADIUS — `internal/radius`

RFC 2865 builds the Response Authenticator from MD5, and RFC 2548 derives MPPE
keys with MD5. Both are structural: an implementation that used anything else
would not be RADIUS, and no network access server would talk to it.

**Consequence: no RADIUS, and therefore no EAP-TLS through it.** 802.1X in a
FIPS environment needs a RADIUS server built against a module that carries an MD5
exception for exactly this purpose, which Go's does not.

### Verifying passwords from another IdP — `internal/passwords`


**Consequence: users migrated from those systems can be imported, but cannot
sign in under `fips140=only` until they have set a password here.** The delegated
authentication path is unaffected — it proxies the credential to the old IdP and
stores a local Argon2id hash — so a migration that uses shadow authentication
rather than hash import works.

Note also that Argon2id, bcrypt and scrypt live outside the validated module
entirely. They are not *refused*; they simply are not covered, so a strict
reading gives you no validated password hash at all. PBKDF2 with a long salt and
SHA-256 is the approved option, and it is a considerably worse password hash. If
a FIPS boundary is genuinely required around password storage, that trade needs
stating explicitly to whoever is asking for it.

## What was fixed rather than documented

### SAML assertion encryption — `internal/saml`

Two problems, both now resolved — though note the package still fails its tests
under `fips140=only`, because those tests cover the default configuration as well
as the FIPS one. Encrypted SAML **works** under FIPS; it has to be configured
for it.

**GCM with a caller-supplied IV** is refused, because a nonce reused under one
key destroys GCM completely and the module insists on owning it. Signari now
uses `NewGCMWithRandomNonce`, which produces byte-identical output — XML
Encryption carries the IV as a prefix of the cipher value, and that is precisely
what the library emits.

**RSA-OAEP with SHA-1.** XML Encryption's original `rsa-oaep-mgf1p` fixes SHA-1
as OAEP's hash and mask generation function. `sp_key_transport` now selects
between that and xmlenc11 `rsa-oaep` with SHA-256:

```sh
signari saml add-sp … -sp-encryption-cert sp.pem -sp-key-transport rsa-oaep-sha256
```

The default stays `rsa-oaep-mgf1p`. Every service provider implements it;
xmlenc11 `rsa-oaep` is widely but not universally supported, and choosing it for
one that cannot read it produces assertions that decrypt nowhere. That is a
decision for whoever knows the far end.

When SHA-256 is selected the `EncryptedKey` names both the digest and the mask
generation function explicitly. Naming the MGF is not optional: `rsa-oaep`
defaults to MGF1-SHA1, so declaring SHA-256 and omitting the MGF describes a
combination that was not produced, and the far end fails to unwrap with no
indication of which half disagreed.

## Keeping this page true

`TestFIPSNotesEveryNonApprovedImport` fails if a package starts using a
non-approved primitive without being named here, and if this page names a package
that no longer uses one. The list above is enforced, not maintained by hand.

## What this page does not claim

Signari has not been submitted for validation, and running against a validated
module is not the same as being validated. What is claimed is narrower and
checkable: it builds with `GOFIPS140`, and under `GODEBUG=fips140=only` the
packages listed above fail for the reasons given while the rest pass their tests.
