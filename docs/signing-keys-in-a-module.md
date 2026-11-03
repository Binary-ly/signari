# Signing keys in a hardware module

The keys that sign tokens, SAML assertions and the federation's statements can be
made in a PKCS#11 token, an HSM or anything else with a PKCS#11 module, and kept
there. The token generates each key, marks it sensitive and not extractable, and
signs with it when asked. The private half is never in this process, in the
database or in a backup of either.

## Setting it up

A module is a C library the engine loads when it starts, so this takes a build
with cgo, which the default image is not. Build the `pkcs11` image:

```sh
docker build --target pkcs11 -t signari:pkcs11 engine/
```

or a binary with `CGO_ENABLED=1 go build -tags pkcs11 ./cmd/signari`. Any other
build refuses `SIGNARI_PKCS11_MODULE` and says why, rather than making keys in
software beside a module its operator configured.

The module is your HSM vendor's. It is not in the image: mount it, and whatever
configuration the vendor's module reads, and name it.

```sh
SIGNARI_PKCS11_MODULE=/hsm/libvendor-pkcs11.so
SIGNARI_PKCS11_TOKEN=signari             # the token's label
SIGNARI_PKCS11_PIN_FILE=/run/secrets/pin # or SIGNARI_PKCS11_PIN
```

Every node, and every `signari` command that touches keys, needs the same three.
The settings are in [configuration.md](configuration.md#signing-keys-in-a-hardware-module).

## Where new keys are made

With a module configured, every new signing key is made in it: the first keys
`signari instance create` makes, each one `keys rotate` publishes, the successor
the unattended rotation makes, and the federation key. There is no second switch
for this. Keys made in software by a node with a module configured are the
mistake a second switch would allow, and a test fails if any of those paths
makes a key any other way.

`signari keys list` says where each key is, in its `HELD IN` column: `pkcs11`,
or `database` for one sealed under the root key.

## Moving existing keys in

Configure the module and rotate. Keys made before go on loading from their
sealed rows, and are succeeded by keys made in the token, by `keys rotate` or by
the unattended rotation, with the usual day of publication before a new key
signs. Once the last old key is retired, nothing private is left in the
database.

A key cannot be moved into the token: the token would have to import material
that had already existed outside it, which is what the module is there to
prevent.

## What the engine checks

- A key's row holds no private material, only `pkcs11:<kid>`. The kid is the
  key's `CKA_ID` and `CKA_LABEL` in the token, which is also what the module's
  own tools show.
- When keys are loaded, the token's public key under that name must be the one
  this deployment published, or the load fails. A second token given the same
  label, or an object replaced by hand, would otherwise sign with a key no relying
  party was given.
- Two keys under one name are refused, and so is a key the token does not have.
  A node that cannot reach the token does not start, and a running one keeps the
  keys it has and tries again at the next refresh.
- An RSA key is made unable to decrypt and an EC key unable to derive: a signing
  key does one job.
- `keys rewrap-root` leaves these rows as they are. There is nothing under the
  root key to move.

## Algorithms

ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384 and PS512. RSA keys are
the sizes `keys rotate -rsa-bits` takes. EdDSA is not made in a token; asked for,
the rotation refuses it by name. RSA-PSS signatures from the token use a salt as
long as the hash, as the engine's own do.

## Not done

- **Cloud key services** (AWS KMS, Google Cloud KMS, Azure Key Vault, Vault's
  transit engine) are not spoken to directly, and no cloud provider's PKCS#11
  module has been tried here.
- **The key a wallet encrypts its credential request to** ([credential
  issuance](oid4vci.md)) is made in software. It opens rather than signs, and
  opening in a token is not done.
- **The Admin API** does not say where a key is held; `keys list` does.

## Tested against

SoftHSM 2.7.0. The tests built with `-tags pkcs11` make keys of every algorithm in
a token of their own, rotate them, move a deployment from software keys into the
token, refuse a token key unlike the published one, and sign a token in every
algorithm that is then verified against the published key, RSA-PSS with its salt
checked strictly:

```sh
cd engine
CGO_ENABLED=1 SIGNARI_TEST_DSN=postgres://… go test -tags pkcs11 ./internal/keys/... ./internal/tokens/
```

The binary was also run against a token with a fresh database: `instance create`
and `keys rotate` made their keys in it, a person signed in, and OpenSSL verified
the ID token's signature against the JWKS the server published. The SAML metadata
it served carried a certificate the token had signed, which OpenSSL also verified.
