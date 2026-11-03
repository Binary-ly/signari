# Signing keys in a hardware module or a key service

The keys that sign tokens, SAML assertions and the federation's statements can be
made in a PKCS#11 token, which is how an HSM is reached, or in a Vault or OpenBao
transit engine, and kept there. The module makes each key, will not hand out its
private half, and signs with it when asked. The private half is never in this
process, in the database or in a backup of either.

## A PKCS#11 module

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

Each key is made in the token as a token object, sensitive and not extractable,
an RSA key unable to decrypt and an EC key unable to derive, since a signing key
does one job. Its `CKA_ID` and `CKA_LABEL` are both its kid, which is what the
module's own tools show.

## A transit engine

Vault's transit secrets engine, or OpenBao's, which answers the same API. Every
build speaks it.

```sh
SIGNARI_VAULT_ADDR=https://vault.internal:8200
SIGNARI_VAULT_TOKEN_FILE=/vault/agent/token   # or SIGNARI_VAULT_TOKEN
SIGNARI_VAULT_TRANSIT_MOUNT=transit           # the default
```

The token needs to create and read keys on the mount and sign with them, and
nothing else. A token file is read again for every request, so Vault Agent can
renew the token into it; the engine does not renew a token itself.

Each key is made not exportable and with no plaintext backup, named
`signari-<kid>-key`, because a transit key's name may not begin or end with a
hyphen and a kid may. The engine signs with version 1 of it, the version it made
and published. A version added inside Vault later is a key no relying party was
given, so it is never used: rotation is this deployment's, to a new kid.

Set with a module as well, the process refuses to start.

## Where new keys are made

With either configured, every new signing key is made there: the first keys
`signari instance create` makes, each one `keys rotate` publishes, the successor
the unattended rotation makes, and the federation key. There is no second switch
for this. Keys made in software by a node with a module configured are the
mistake a second switch would allow, and a test fails if any of those paths
makes a key any other way.

Every node, and every `signari` command that touches keys, needs the same
settings ([configuration.md](configuration.md#signing-keys-in-a-hardware-module)).
`signari keys list` says where each key is, in its `HELD IN` column: `pkcs11`,
`vault-transit`, or `database` for one sealed under the root key.

## Moving existing keys in

Configure the module and rotate. Keys made before go on loading from their
sealed rows, and are succeeded by keys made in the module, by `keys rotate` or by
the unattended rotation, with the usual day of publication before a new key
signs. Once the last old key is retired, nothing private is left in the
database.

A key cannot be moved in: the module would have to import material that had
already existed outside it, which is what it is there to prevent.

## What the engine checks

- A key's row holds no private material, only `pkcs11:<kid>` or
  `vault-transit:<kid>`.
- When keys are loaded, the public key the module holds under that name must be
  the one this deployment published, or the load fails. A second token given the
  same label, or a key replaced by hand, would otherwise sign with a key no
  relying party was given.
- A name already taken is refused rather than adopted. Asked to make a key it
  already holds, a transit engine answers that it did and keeps the old one.
- Two keys under one name in a token are refused, and so is a key the module does
  not have. A node that cannot reach its module does not start, and a running one
  keeps the keys it has and tries again at the next refresh.
- `keys rewrap-root` leaves these rows as they are. There is nothing under the
  root key to move.

## Algorithms

ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384 and PS512 in both, and EdDSA
in a transit engine; a PKCS#11 token is not asked for EdDSA, and the rotation
refuses it there by name. RSA keys are the sizes `keys rotate -rsa-bits` takes.
RSA-PSS signatures use a salt as long as the hash, as the engine's own do.

## Not done

- **AWS KMS, Google Cloud KMS and Azure Key Vault** are not spoken to, and no
  cloud provider's PKCS#11 module has been tried here.
- **The key a wallet encrypts its credential request to** ([credential
  issuance](oid4vci.md)) is made in software. It opens rather than signs, and
  opening in a module is not done.
- **The Admin API** does not say where a key is held; `keys list` does.

## Tested against

SoftHSM 2.7.0 and OpenBao 2.4.1. The same tests run against each: they make keys of
every algorithm the module makes, rotate them, move a deployment from software
keys into the module, refuse a module key unlike the published one, leave the
module's keys alone through a root-key rotation, and sign a token in every
algorithm that is then verified against the published key, RSA-PSS with its salt
checked strictly.

```sh
cd engine
CGO_ENABLED=1 SIGNARI_TEST_DSN=postgres://… go test -tags pkcs11 ./internal/keys/... ./internal/tokens/
SIGNARI_TEST_VAULT_ADDR=http://127.0.0.1:8200 SIGNARI_TEST_VAULT_TOKEN=… \
  SIGNARI_TEST_DSN=postgres://… go test ./internal/keys/ ./internal/tokens/
```

The binary was also run against each with a fresh database: `instance create`
and `keys rotate` made their keys in the module, a person signed in, and OpenSSL
verified the ID token's signature against the JWKS the server published. With the
token, the SAML metadata it served carried a certificate the token had signed,
which OpenSSL also verified. The `pkcs11` image itself, given only Debian's SoftHSM
module, made its keys in a token and loaded them back.
