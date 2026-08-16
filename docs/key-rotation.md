# Key rotation, and the reload that made it mean something

```sh
signari keys rotate -alg ES256     # publishes a `next` key
# …24 hours later…
signari keys rotate -alg ES256     # promotes it to active
```

## The design

Rotation is deliberately two steps:

1. **Publish** a new key as `next`. It appears in JWKS and signs nothing.
2. **Promote** it to `active` a day later. It now signs, and every relying
   party has had 24 hours to cache it.

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
