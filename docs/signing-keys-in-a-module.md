# Signing keys in a hardware module or a key service

## Introduction

By default, Signari keeps its private signing keys in the database, sealed under
the root key. Some security policies require that a signing key never exists
outside dedicated hardware or a dedicated key service. This page is for the
administrator who has to meet such a policy.

Signari can make its signing keys in a hardware security module (HSM), and keep
them there. These are the keys that sign tokens, Security Assertion Markup
Language (SAML) assertions and the federation's statements. It reaches
the module through PKCS#11, one of the Public-Key Cryptography Standards. It can
use the "transit engine" of Vault or OpenBao instead, a key service that signs
when asked.

Either way, the module makes each key, will not hand out its private half, and
signs with it when asked. The private half is never in this process, in the
database or in a backup of either.

> [!NOTE]
> Every setting on this page is listed in the [configuration
> reference](configuration.md#signing-keys-in-a-hardware-module).

## A PKCS#11 module

A PKCS#11 "module" is a C library, from your HSM's vendor, that the engine loads
when it starts. Loading it takes a build with cgo, Go's way of calling C code, and
the default image is not built that way. To build the `pkcs11` image:

```sh
docker build --target pkcs11 -t signari:pkcs11 engine/
```

You can build a binary instead, with
`CGO_ENABLED=1 go build -tags pkcs11 ./cmd/signari`. Any other build refuses
`SIGNARI_PKCS11_MODULE` and says why. It does not make keys in software beside a
module its administrator configured.

The module is your HSM vendor's, and it is not in the image. Mount it, with
whatever configuration the vendor's module reads. Then name it in these settings:

```sh
SIGNARI_PKCS11_MODULE=/hsm/libvendor-pkcs11.so
SIGNARI_PKCS11_TOKEN=signari             # the token's label
SIGNARI_PKCS11_PIN_FILE=/run/secrets/pin # or SIGNARI_PKCS11_PIN
```

In PKCS#11, a "token" is the store inside the module that holds the keys. It has
nothing to do with the tokens Signari issues.

Each key is made in the token as a token object, sensitive and not extractable.
An RSA key is made unable to decrypt, and an elliptic curve (EC) key unable to
derive, since a signing key does one job. Its `CKA_ID` and `CKA_LABEL` are both
its key ID, or kid, which is what the module's own tools show.

## A transit engine

Vault's transit secrets engine, or OpenBao's, which answers the same API, is the
other place a key can live. Every build speaks it. Name it in these settings:

```sh
SIGNARI_VAULT_ADDR=https://vault.internal:8200
SIGNARI_VAULT_TOKEN_FILE=/vault/agent/token   # or SIGNARI_VAULT_TOKEN
SIGNARI_VAULT_TRANSIT_MOUNT=transit           # the default
```

The Vault token needs to create and read keys on the mount and sign with them,
and nothing else. A token file is read again for every request, so Vault Agent can
renew the token into it. The engine does not renew a token itself.

Each key is made not exportable and with no plaintext backup. It is named
`signari-<kid>-key`, because a transit key's name may not begin or end with a
hyphen, and a kid may.

The engine signs with version 1 of the key, the version it made and published. A
version added inside Vault later is a key no application was given, so it is
never used. Rotation is this deployment's job, and it moves to a new kid.

If a PKCS#11 module is set as well as a transit engine, the process refuses to
start.

## Where new keys are made

With either one configured, every new signing key is made there. That includes
the first keys `signari instance create` makes, each one `keys rotate` publishes,
the successor the unattended rotation makes, and the federation key.

There is no second switch for this. Keys made in software by a node with a module
configured are the mistake a second switch would allow. A test fails if any of
those paths makes a key any other way.

Every node, and every `signari` command that touches keys, needs the same
settings ([configuration](configuration.md#signing-keys-in-a-hardware-module)).
`signari keys list` says where each key is, in its `HELD IN` column: `pkcs11`,
`vault-transit`, or `database` for one sealed under the root key.

## Moving existing keys in

Configure the module, then rotate. Keys made before go on loading from their
sealed rows. They are succeeded by keys made in the module, by `keys rotate` or by
the unattended rotation. The usual day of publication passes before a new key
signs, as [key rotation](key-rotation.md) explains. Once the last old key is
retired, nothing private is left in the database.

A key cannot be moved in. The module would have to import material that had
already existed outside it, which is what the module is there to prevent.

## What the engine checks

- A key's row holds no private material, only `pkcs11:<kid>` or
  `vault-transit:<kid>`.
- When keys are loaded, the public key the module holds under that name must be
  the one this deployment published, or the load fails. Otherwise a second token
  given the same label, or a key replaced by hand, would sign with a key no
  application was given.
- A name already taken is refused rather than adopted. Asked to make a key it
  already holds, a transit engine answers that it did and keeps the old one.
- Two keys under one name in a token are refused, and so is a key the module does
  not have.
- A node that cannot reach its module does not start. A running node keeps the
  keys it has, and tries again at the next refresh.
- `keys rewrap-root` leaves these rows as they are. There is nothing under the
  root key to move.

## Algorithms

Both places make ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384 and
PS512 keys. ES256 is the Elliptic Curve Digital Signature Algorithm on P-256 with
SHA-256, and RS256 is RSA with SHA-256. A transit engine also makes EdDSA keys,
for the Edwards-curve Digital Signature Algorithm.

A PKCS#11 token is not asked for EdDSA, and the rotation refuses it there by
name. RSA keys are the sizes `keys rotate -rsa-bits` takes. RSA-PSS signatures
use a salt as long as the hash, as the engine's own do.

## Not done

- **AWS KMS, Google Cloud KMS and Azure Key Vault**, the cloud providers' key
  management services, are not spoken to. No cloud provider's PKCS#11 module has
  been tried here.
- **The key a wallet encrypts its credential request to** ([credential
  issuance](oid4vci.md)) is made in software. It opens rather than signs, and
  opening in a module is not done.
- **The Admin API** does not say where a key is held; `keys list` does.

## Tested against

SoftHSM 2.7.0, OpenBao 2.4.1 and HashiCorp Vault 2.2.2. The same tests run against
each. They make keys of every algorithm the module makes, and rotate them. They
move a deployment from software keys into the module, and refuse a module key
unlike the published one. They leave the module's keys alone through a root-key
rotation. They sign a token in every algorithm, and verify it against the
published key, with the RSA-PSS salt checked strictly.

The first command runs the tests against a SoftHSM token made for the run, and
the second against a transit engine:

```sh
cd engine
CGO_ENABLED=1 SIGNARI_TEST_DSN=postgres://… go test -tags pkcs11 ./internal/keys/... ./internal/tokens/
SIGNARI_TEST_VAULT_ADDR=http://127.0.0.1:8200 SIGNARI_TEST_VAULT_TOKEN=… \
  SIGNARI_TEST_DSN=postgres://… go test ./internal/keys/ ./internal/tokens/
```

The binary was also run against SoftHSM and OpenBao with a fresh database.
`instance create` and `keys rotate` made their keys in the module, and a person
signed in. OpenSSL then verified the ID token's signature against the JSON Web
Key Set (JWKS) the engine published.

With the token, the SAML metadata it served carried a certificate the token had
signed, which OpenSSL also verified.

Against Vault, `instance create` and `keys rotate` made four keys in its transit
engine, with every row holding only a `vault-transit:` reference. The engine
published those four; signing there is what the tests above verify.

The `pkcs11` image itself, given only Debian's SoftHSM module, made its keys in a
token and loaded them back.
