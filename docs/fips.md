# FIPS 140-3

## Introduction

Federal Information Processing Standard (FIPS) 140-3 is the United States
government's standard for cryptographic modules. Some organisations accept only
software whose cryptography runs through a module validated against it.

Signari builds and runs against Go's FIPS 140-3 cryptographic module. Not every
feature survives that, and nobody can tell you which without running it. This
page says exactly which features survive and which cannot.

Read it if you have been asked for FIPS compliance, or if you review such a
claim. Start with [the two modes](#the-two-modes-are-not-the-same-thing), because
the answer depends on which mode the requirement means.

## The short version

These commands build against the validated snapshot, serve with only approved
algorithms, and build a pinned release with its image:

```sh
GOFIPS140=certified go build ./cmd/signari   # the validated snapshot
GODEBUG=fips140=only ./signari serve
scripts/build-release.sh -fips -image REPO:TAG   # a pinned release and a REPO:TAG-fips image
```

`signari version` says which module a binary was built against
(`fips140  enabled, module v1.0.0-c2097c7c`). `module none` means it was not
built against a snapshot at all, whatever `GODEBUG` says. The release script's
`-fips` refuses a binary or image that does not report the snapshot.

`certified` selects the snapshot Go lists as certified (`v1.0.0-c2097c7c`, in
`$GOROOT/lib/fips140/certified.txt` of the go1.26 toolchains), and the engine
builds against it.

This page used to give `GOFIPS140=latest`, while calling the result a validated
module. `latest` is the module's code as it stands, not a validated snapshot. The
package counts below were measured with `latest` and have not been repeated
against `certified`.

`internal/passwords` and `internal/mfa` were re-run in October 2026 and now pass
under `fips140=only`. Their tests of what is refused in that mode run there, and
the tests whose fixtures need SHA-1 skip. `signari doctor` reports the mode and
what it would refuse.

**Until October 2026 `serve` could not start under `fips140=only` at all**. The
root key and each subject key gave AES-GCM (the Advanced Encryption Standard in
Galois/Counter Mode) a nonce of their own. The module refuses that ("use of GCM
with arbitrary IVs is not allowed"), so the engine died unwrapping its first
signing key. The package tests passed, because none of them unwrapped a real key
in that mode.

Both keys now let the module make the nonce (`NewGCMWithRandomNonce`), in the
same stored layout, so every sealed value opens. A test re-runs itself under
`fips140=only` to seal and open with both. On a copy of a working deployment,
under `fips140=only` with the certified module, `serve` starts and a password
sign-in works. The stored hash moves from Argon2id to PBKDF2 on the first sign-in.

**60 of 67 packages pass their tests under `fips140=only`**, measured in October
2026 against a database, with the certified module. This page once said 31 of
36, counted when there were fewer packages. None of the seven failures is a
request path panicking: each was traced to its frame.

Five fail only in test fixtures that build with an algorithm the module refuses:

- `clientauth` makes RSA keys under 2048 bits to prove they are refused.
- `httpapi` and `store` compute time-based one-time password (TOTP) codes.
- `importer` builds a short-salted PBKDF2 hash.
- `outbox` signs with an HMAC key shorter than the 112 bits the module allows.
  The engine's own webhook and provider secrets are 32 random bytes.

Two fail by design, as described below: `radius`, and `saml`, whose tests cover
the interoperable default as well as the FIPS configuration.

Core OpenID Connect (OIDC) is unaffected: the authorization code flow, token
issue and verification, sessions, refresh, introspection and revocation. So are
the JSON Web Key Set (JWKS), Demonstrating Proof of Possession (DPoP), mutual TLS
(mTLS), Pushed Authorization Requests (PAR) and the device flow.

Where a feature cannot work, the reason is the same every time. A protocol or a
stored format mandates an algorithm the module refuses. No amount of care on our
side changes what the specification says, or what another vendor's database
already contains.

## The two modes are not the same thing

`GODEBUG=fips140=on` runs approved algorithms through the validated module, and
**still allows** everything else. Almost anything passes. It is the mode most
projects mean when they say they support FIPS, and as a claim it is close to
meaningless.

`GODEBUG=fips140=only` makes algorithms that are not approved fail: with an
error where the API allows one, and with a panic where it does not. That is the
mode this page is about, and the numbers above are from it.

If you are being asked for FIPS compliance, find out which of these two the
requirement means before you plan anything.

## What cannot work under `fips140=only`

### SHA-1 one-time codes — `internal/mfa`

One-time codes default to HMAC-SHA1, the variant every authenticator app
computes. HMAC is a hash-based message authentication code. SHA-1 in HMAC is not a
collision-resistance claim, and is not broken in the way SHA-1 signatures are.
But the module does not evaluate the argument. It refuses HMAC with anything
outside SHA-2 and SHA-3, and with a key shorter than 112 bits.

RFC 6238 also defines SHA-256 and SHA-512 variants, and those run inside the
module. An organisation that sets `signari instance totp-policy -totp-algorithm
SHA256` enrols new authenticator apps with SHA-256, and `signari user assign-otp
-totp-algorithm SHA256` assigns a hardware token that computes it.

Not every authenticator app computes SHA-256. One that does not shows codes that
never match, so choose apps or tokens that state it. Each credential keeps the
algorithm it was enrolled with.

**Consequence: no SHA-1 codes.** Use SHA-256 apps or tokens, or WebAuthn, which
is unaffected: passkeys are ECDSA P-256 or RSA with SHA-256, and pass cleanly. A
YubiKey's Yubico OTP (`user assign-otp -yubico`) is unaffected too. Each OTP is
one AES-128 block, decrypted inside the module, and it is checked under
`fips140=only` by test.

`serve` refuses to start under `fips140=only` while anyone has a SHA-1 code
authenticator as a second factor. It says how many, because none of them could
finish signing in. Move them to a SHA-256 authenticator or a passkey, and remove
the factor (`DELETE /admin/users/{id}/factors/totp`) first.

While an organisation still enrols SHA-1 apps, its enrolment page says why it
cannot add one, instead of showing a secret no code could confirm. `signari
doctor` warns as well.

A code checked anyway, or one from a token seed under 112 bits, is refused with an
error rather than a panic. Until October 2026 the check panicked the request, at
the moment the person typed a code.

### A vendor's token file — `internal/importer`

A Portable Symmetric Key Container (PSKC) file carries the secrets of one-time
password tokens from their vendor. RFC 6030 recommends implementing HMAC-SHA1 for
a PSKC file, and it is what the RFC's own example uses, so `signari import pskc`
reads it.

Under `fips140=only` such a file is refused, with a sentence saying so. Read it
once on a build without that setting, or ask the vendor for HMAC-SHA256, which
works in either. AES-CBC and the file's plain secrets are unaffected.

### RADIUS — `internal/radius`

Remote Authentication Dial In User Service (RADIUS) is how network equipment
asks whether someone may connect. RFC 2865 builds the Response Authenticator from
MD5, and RFC 2548 derives MPPE keys with MD5. Both are structural. An
implementation that used anything else would not be RADIUS, and no network access
server would talk to it.

**Consequence: no RADIUS, and therefore no EAP-TLS through it**. EAP-TLS lets a
device join a network with a certificate. In a FIPS environment, 802.1X needs a
RADIUS server built against a module that carries an MD5 exception for exactly
this purpose. Go's module does not carry one. `serve` refuses to start under `fips140=only`
with `SIGNARI_RADIUS_ADDR` set.

### The breached-password check — `internal/passwords`

The corpus is indexed by SHA-1, and the range API takes a SHA-1 prefix, so the
check cannot run under `fips140=only`. `serve` refuses to start with
`SIGNARI_PASSWORD_BREACH_CHECK` or `SIGNARI_PASSWORD_BREACH_LIST` set. A check
reached anyway reports itself unavailable, instead of panicking.

### A certificate's thumbprint in a client assertion — `internal/federation`

`signari idp auth -method private_key_jwt` with a certificate names it in the
assertion's header by `x5t`, which is defined over SHA-1, as well as by
`x5t#S256`. It is a name and protects nothing. But SHA-1 is not available under
`fips140=only`, so there only `x5t#S256` is sent. A provider that looks a key up
by `x5t` alone will not find it.

### Verifying passwords from another IdP — `internal/passwords`


**Consequence: people migrated from those systems can be imported, but cannot
sign in under `fips140=only` until they have set a password here**. The delegated
authentication path is unaffected. It proxies the credential to the old identity
provider (IdP) and stores a local Argon2id hash. So a migration that uses shadow
authentication, instead of hash import, works.

Imported hashes the module refuses fail with an error that says to reset the
password. They are phpass and WordPress (MD5), MD5-crypt and Apache's apr1,
yescrypt, and the LDAP `{SSHA}`, `{SHA}`, `{SMD5}` and `{MD5}` schemes. PBKDF2
imports with SHA-1 or a salt shorter than 128 bits, as many Django salts are,
fail the same way.

Each used to panic the sign-in under `fips140=only`. SHA-crypt (`$5$`, `$6$`) and
the SHA-2 LDAP schemes are SHA-2 throughout, and verify.

### Passwords hashed here

Argon2id, bcrypt, scrypt and yescrypt live outside the validated module. They are
not *refused*; they are not covered. So with FIPS enabled (`on` or `only`), a new
password is hashed with PBKDF2-HMAC-SHA256 through `crypto/pbkdf2`, which is
inside the module.

The hash uses 600,000 iterations, which took 66 ms where this was measured
(Argon2id here took 25 ms), a 128-bit salt and a 256-bit key. It is written
`$pbkdf2-sha256$i=600000$<salt>$<key>`.

An Argon2id password is checked once more at its next sign-in, outside the
module, and rehashed to PBKDF2 in the same transaction. A password nobody signs in
with stays Argon2id, and `signari doctor` reports how many are left. With FIPS off
again, a PBKDF2 password moves back to Argon2id at its next sign-in.

PBKDF2 has no memory hardness, so it is a considerably worse password hash. Its
cost is all CPU, which is what guessing hardware is best at. If a FIPS boundary
around password storage is the requirement, that trade needs stating explicitly
to whoever is asking for it.

### AES-GCM in an encrypted response

[Encrypting a response to a client](response-encryption.md) goes through the
JSON Object Signing and Encryption (JOSE) library. That library chooses GCM's
nonce itself, and the module refuses a nonce the caller chose.

So under `fips140=only` the content encryptions on offer are `A128CBC-HS256` and
`A256CBC-HS512`, in discovery and in the setting alike. `RSA-OAEP-256` and
`ECDH-ES` work with both, and the encryption tests pass in that mode. A client set
to a GCM value before the move answers a 500, rather than send anything in the
clear.

A wallet's [credential request](oid4vci.md#a-credential-only-the-wallet-can-read)
is the same in the other direction. The metadata offers the CBC values, and those
are what open.

A [wallet sign-in](wallet-sign-in.md) set to `direct_post.jwt` cannot work in this
mode. The wallet's answer is encrypted with A128GCM or A256GCM, which the JOSE
library cannot open there, and the wallet offers no other. `direct_post` works.

## What was fixed rather than documented

### Four seals that chose their own nonce

**Until November 2026 four more seals did what the root key did before October**.
Each gave AES-GCM a nonce of its own, so each failed under `fips140=only`. They
were:

- An opaque access token's handle.
- A refresh token's successor, kept for a client with a retry window.
- A wallet presentation waiting for the browser.
- The AES-GCM step of reading an encrypted assertion from an upstream SAML
  provider.

All four were added after the October measurement above, and each was opt-in, so
it did not show. They now let the module make the nonce, in the same stored
layout. Tests re-run themselves under `fips140=only` to seal and open them.

### SAML assertion encryption — `internal/saml`

Security Assertion Markup Language (SAML) assertion encryption had two problems,
and both are now resolved. The package still fails its tests under
`fips140=only`, though, because those tests cover the default configuration as
well as the FIPS one. Encrypted SAML **works** under FIPS; it has to be
configured for it.

**GCM with a caller-supplied IV** is refused, because a nonce reused under one
key destroys GCM completely, and the module insists on owning it. Signari now
uses `NewGCMWithRandomNonce`, which produces byte-identical output. XML
Encryption carries the IV as a prefix of the cipher value, and that is precisely
what the library emits.

**RSA-OAEP with SHA-1.** XML Encryption's original `rsa-oaep-mgf1p` fixes SHA-1
as OAEP's hash and mask generation function. `sp_key_transport` now selects
between that and xmlenc11 `rsa-oaep` with SHA-256. To select SHA-256 for an
application, which SAML calls a "service provider":

```sh
signari saml add-sp … -sp-encryption-cert sp.pem -sp-key-transport rsa-oaep-sha256
```

The default stays `rsa-oaep-mgf1p`, because every SAML application implements it.
xmlenc11 `rsa-oaep` is widely but not universally supported. Choosing it for an
application that cannot read it produces assertions that decrypt nowhere. That is
a decision for whoever knows the far end.

When SHA-256 is selected, the `EncryptedKey` names both the digest and the mask
generation function (MGF) explicitly. Naming the MGF is not optional, because
`rsa-oaep` defaults to MGF1-SHA1. Declaring SHA-256 and omitting the MGF describes
a combination that was not produced. The far end then fails to unwrap, with no
indication of which half disagreed.

## Keeping this page true

`TestFIPSNotesEveryNonApprovedImport` fails if a package starts using a
non-approved primitive without being named here. It also fails if this page names
a package that no longer uses one. The list above is enforced, not maintained by hand.

## What this page does not claim

Signari has not been submitted for validation, and running against a validated
module is not the same as being validated. What is claimed is narrower and
checkable. It builds with `GOFIPS140`, and under `GODEBUG=fips140=only` the
packages listed above fail for the reasons given, while the rest pass their tests.
