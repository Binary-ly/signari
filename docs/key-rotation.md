# Key rotation, and the reload that made it mean something

```sh
signari keys rotate -alg ES256     # publishes a `next` key
# …24 hours later…
signari keys rotate -alg ES256     # promotes it to active, demotes the old one
# …24 hours after that…
signari keys retire                # the demoted key leaves the JWKS
```

## The design

Rotation is deliberately staged:

1. **Publish** a new key as `next`. It appears in JWKS and signs nothing.
2. **Promote** it to `active` a day later. It now signs, and every relying
   party has had 24 hours to cache it. The outgoing key becomes `passive`.
3. **Retire** the passive key once nothing it signed can still be valid. It
   leaves the JWKS; the row stays.

Publishing before signing is the whole point. A relying party that caches JWKS
and does not re-fetch on an unknown `kid` will reject tokens signed with a key
it has never seen — which is an outage that looks like a token bug.

## The design did nothing

The key set was read **once at startup** and never again.

```
database          b7B5aS8Y active   fonp6m7E active   0Lt3Doa3 next
instance :9999    b7B5aS8Y          fonp6m7E
instance :9998    b7B5aS8Y          fonp6m7E
```

The new key was in the database and in neither instance's JWKS. So:

- the `next` key never reached a single relying party
- the day-long wait protected nothing
- after a restart, instances would begin signing with a key nobody had cached

Every part of the rotation ceremony ran correctly and none of it had any effect.
An operator rotating a compromised key would have believed it done.

Found by rotating against two running instances and reading their JWKS — not by
reading the code, where "load the keys" looks like exactly what you want.

## The fix

Instances re-read their keys every minute and replace the live set:

```
t+10s  A=0  B=0
…
t+70s  A=1  B=1   ← both publish the new key
```

The swap is behind a lock rather than by handing out a new pointer, because call
sites hold the `*Set` itself and asking each of them to re-read an indirection
is a rule that gets broken exactly once.

The replacement is **validated before it is applied**. A reload that produced two
active keys for one algorithm, or a duplicate `kid`, must not replace a working
set with a broken one — the keys currently loaded are the ones known to work. A
database that is briefly unreachable leaves the current set in force and logs
the failure, rather than taking an instance out of service for a transient
fault.

Tested under `-race`: eight readers calling `JWKS`, `Keys` and `Active` while
200 replacements land underneath them.

One subtlety worth naming: two of the read methods took the snapshot **twice** in
a single operation — once to size a slice and once to fill it. A replacement
landing between the two would size from one set and copy from another. One
snapshot per operation.

## What this does not change

- Promotion is still manual and still waits 24 hours. Automatic promotion on a
  timer would mean a key could start signing while an instance was down and
  unable to publish it.
- A relying party that caches JWKS forever and never refetches is still broken,
  and no amount of advance publication fixes that. The 24 hours is what makes it
  survivable for the ones that refetch on a schedule.

## Retirement

For a long time the machine stopped at `passive`. The state diagram said
`next → active → passive → removed` and `MinPassiveBeforeRetire` had been
declared since the beginning, but nothing read it: passive keys stayed in the
JWKS forever, so the published set grew with every rotation and no key ever left.

`signari keys retire` is the missing step. It removes only keys that nothing can
still be verifying against, and `-dry-run` shows what it would do.

```
Passive keys must stay published for 24h0m0s (the 24h0m0s floor for token lifetimes).
0Lt3Doa3 (ES256): retired. It leaves the JWKS at the next restart or config reload.
```

### The dwell is not always 24 hours

24 hours is a **floor**, derived from token lifetimes: access and ID tokens live
five minutes, logout and security event tokens less, and refresh tokens are opaque
— looked up by hash, never signed.

OID4VCI broke that reasoning. A verifiable credential is signed with the same
`oidc` key, and its lifetime is an operator-configured interval with no ceiling. A
credential issued for ninety days, signed by a key retired twenty-four hours after
demotion, would stop verifying with eighty-nine days left to run — and it would
fail at a verifier this deployment does not run, weeks after anyone could connect
it to a rotation.

So the dwell is the longest lifetime anything signed by that key can still have,
and the command says which configuration set it:

```
Passive keys must stay published for 2160h0m0s
(credential configuration "employee-badge" issues credentials valid for 2160h0m0s).
```

A deployment issuing long-lived credentials therefore keeps passive keys for
months. That is the correct outcome rather than a limitation, and it is printed
rather than inferred so nobody has to guess why a key will not retire.

### There is no `-now`

`keys rotate -now` exists because signing with a compromised key is worse than
some relying parties failing verification for a few hours, and the operator sees
that failure immediately.

Early retirement inverts both halves. It does not stop a compromised key being
used — demotion already did that — and the damage lands on tokens already issued,
failing at verifiers this deployment does not run, long after the cause is
forgettable. There is no emergency that early retirement solves, so the flag would
only ever be a way to cause the problem the dwell exists to prevent.

### Retired, not deleted

The row survives with `state = 'retired'` and the `retire_after` deadline that was
computed at the time. Deleting it would destroy the only record that the `kid`
ever existed, which is exactly what is wanted when a relying party appears months
later reporting an unknown key. A retirement date is an answer; a missing row is a
mystery.

The key is no longer loaded, so nothing can sign or verify with it. `keys list`
does not show it either — that command shows what relying parties can see.
