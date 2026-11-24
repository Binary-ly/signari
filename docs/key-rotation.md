# Key rotation, and the reload that made it mean something

## Introduction

Signari signs every token it issues with a private "signing key". It publishes
the matching public keys as a JSON Web Key Set (JWKS), at `/oauth2/jwks`. Each
application checks a token's signature against that set, without asking
Signari. See the [glossary](glossary.md#jwks).

"Key rotation" replaces a signing key with a new one. Signari does it in three
steps. It publishes the new key, signs with it a day later, and removes the old
key once nothing it signed can still be valid. Applications can learn the new
key before any token is signed with it.

This page shows the commands, explains why each step waits, and records a defect
that once made the waiting do nothing. Read it before you rotate a key on a
schedule, or after a key is exposed.

> [!NOTE]
> With a hardware security module (HSM) configured, each of these keys is made in
> it. See [signing-keys-in-a-module.md](signing-keys-in-a-module.md).

## Rotate a signing key

ES256 is the algorithm Signari signs with by default: the Elliptic Curve Digital
Signature Algorithm on the P-256 curve, with SHA-256. Rotating its key takes three
commands, a day apart:

```sh
signari keys rotate -alg ES256     # publishes a `next` key
# …24 hours later…
signari keys rotate -alg ES256     # promotes it to active, demotes the old one
# …24 hours after that…
signari keys retire                # the demoted key leaves the JWKS
```

In this example, the first command publishes a new key, the second starts
signing with it, and the third removes the old one. The next section explains
each step.

## The design

Rotation is staged on purpose, in three steps:

1. **Publish** a new key as `next`. It appears in the JWKS and signs nothing.
2. **Promote** it to `active` a day later. It now signs, and every application
   has had 24 hours to cache it. The outgoing key becomes `passive`.
3. **Retire** the passive key once nothing it signed can still be valid. It
   leaves the JWKS, and its row stays in the database.

Publishing before signing is the whole point. Some applications cache the JWKS,
and do not fetch it again when they meet an unknown key ID, or `kid`. Such an
application rejects tokens signed with a key it has never seen. That is an
outage, and it looks like a bug in the token.

## The design did nothing

Signari used to read its key set **once at startup**, and never again. This is
what the database held, and what each of two running nodes published, after a
rotation:

```
database          b7B5aS8Y active   fonp6m7E active   0Lt3Doa3 next
instance :9999    b7B5aS8Y          fonp6m7E
instance :9998    b7B5aS8Y          fonp6m7E
```

The new key, `0Lt3Doa3`, was in the database and in neither node's JWKS. So:

- The `next` key never reached a single application.
- The day-long wait protected nothing.
- After a restart, nodes would begin signing with a key nobody had cached.

Every part of the rotation ran correctly, and none of it had any effect. An
administrator rotating a compromised key would have believed the job done.

The defect was found by rotating against two running nodes and reading their
JWKS. Reading the code did not find it, because there "load the keys" looks like
exactly what you want.

## The fix

Each node now reads its keys again every minute, and replaces the set it serves:

```
t+10s  A=0  B=0
…
t+70s  A=1  B=1   ← both publish the new key
```

The swap happens behind a lock, instead of by handing out a new pointer. Call
sites hold the `*Set` itself, and asking each of them to re-read an indirection
is a rule that gets broken exactly once.

The replacement is **validated before it is applied**. A reload that produced two
active keys for one algorithm, or a duplicate `kid`, must not replace a working
set with a broken one. The keys already loaded are the ones known to work.

If the database is briefly unreachable, the node keeps its current set in force
and logs the failure. It does not take itself out of service for a transient
fault.

The reload was tested under `-race`: eight readers called `JWKS`, `Keys` and
`Active` while 200 replacements landed underneath them.

One subtlety is worth naming. Two of the read methods took the snapshot **twice**
in a single operation: once to size a slice, and once to fill it. A replacement
landing between the two would size from one set and copy from another. Each
operation now takes one snapshot.

## What this does not change

- Promotion is still manual, and still waits 24 hours. Automatic promotion on a
  timer would mean a key could start signing while a node was down and unable to
  publish it.
- An application that caches the JWKS forever and never fetches it again is
  still broken. No amount of advance publication fixes that. The 24 hours is what
  makes a rotation survivable for the applications that fetch it on a schedule.

## A new algorithm, or a smaller key

An instance starts with ES256 and RS256, which is RSA with SHA-256. Any other
algorithm gets its first key the same way, published and then promoted. An
application needs the same day to see that key before it signs. For ES384:

```sh
signari keys rotate -alg ES384     # publishes a `next` key
# …24 hours later…
signari keys rotate -alg ES384     # promotes it; there is nothing to demote
signari client set-alg -client-id web-app -alg ES384
```

In this example, the last command makes Signari sign the `web-app` application's
tokens with ES384.

ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512 and EdDSA, the
Edwards-curve Digital Signature Algorithm, are the choices. Each ES algorithm is
held to its own curve, P-256, P-384 and P-521, and a key on another curve is
refused when it loads. The discovery document lists only what has an active key.

Until November 2026, `signari keys rotate` refused any algorithm that had no key
already.
So although EdDSA and PS256 could be chosen for a client, nothing could publish a
key for them.

RSA keys are 3072 bits. If an application's library stops at 2048, you can give
it that size by name, on one algorithm:

```sh
signari keys rotate -alg RS256 -rsa-bits 2048
```

Rotation keeps the size of the key it replaces, by hand and unattended. A key made
small for a reason does not grow behind that reason's back. `signari doctor`
reports one for as long as it signs, and `-rsa-bits 3072` goes back. 2048 is the
floor: a smaller key is refused when it loads.

## Retirement

For a long time, the rotation stopped at `passive`. The state diagram said
`next → active → passive → removed`, and `MinPassiveBeforeRetire` had been
declared since the beginning, but nothing read it. Passive keys stayed in the
JWKS forever, so the published set grew with every rotation and no key ever left.

`signari keys retire` is the missing step. It removes only keys that nothing can
still be verifying against, and `-dry-run` shows what it would do. It prints how
long passive keys must stay published, then each key it retires:

```
Passive keys must stay published for 24h0m0s (the 24h0m0s floor for token lifetimes).
0Lt3Doa3 (ES256): retired. It leaves the JWKS at the next restart or config reload.
```

### The dwell is not always 24 hours

A passive key's "dwell" is how long it stays published after it stops signing.
24 hours is a **floor**, derived from token lifetimes. Access and ID tokens live
five minutes. "Logout tokens", which tell an application a session has ended, and
security event tokens live less. Refresh tokens are opaque: they are looked up by
hash, never signed.

OpenID for Verifiable Credential Issuance (OID4VCI) broke that reasoning. A
verifiable credential is signed with the same `oidc` key. Its lifetime is an
interval the administrator configures, with no ceiling.

Take a credential issued for ninety days, signed by a key retired twenty-four
hours after demotion. It would stop verifying with eighty-nine days left to run.
It would fail at a verifier this deployment does not run, weeks after anyone
could connect it to a rotation.

So the dwell is the longest lifetime anything signed by that key can still have,
and the command says which configuration set it:

```
Passive keys must stay published for 2160h0m0s
(credential configuration "employee-badge" issues credentials valid for 2160h0m0s).
```

A deployment that issues long-lived credentials therefore keeps passive keys for
months. That is the correct outcome, not a limitation. It is printed instead of
inferred, so nobody has to guess why a key will not retire.

### There is no `-now`

`keys rotate -now` exists because signing with a compromised key is worse than
some applications failing verification for a few hours. The administrator also
sees that failure immediately.

Early retirement inverts both halves. It does not stop a compromised key being
used, because demotion already did that. Its damage lands on tokens already
issued, and fails at verifiers this deployment does not run, long after the cause
is forgotten. There is no emergency that early retirement solves. The flag would
only ever be a way to cause the problem the dwell exists to prevent.

### Retired, not deleted

A retired key's row survives, with `state = 'retired'` and the `retire_after`
deadline that was computed at the time. Deleting it would destroy the only record
that the `kid` ever existed. That record is exactly what you want when an
application appears months later, reporting an unknown key. A retirement date is
an answer; a missing row is a mystery.

The key is no longer loaded, so nothing can sign or verify with it. `keys list`
does not show it either, because that command shows what applications can see.
