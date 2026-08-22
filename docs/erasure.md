# Erasing a subject

```sh
signari erase subject -subject-id <uuid> -confirm <uuid> -deactivate
```

Signari erases a person by destroying the key their data is encrypted with, not by
deleting rows. Everything sealed with that key becomes permanently unreadable —
including in every backup taken before the erasure, which is the part row deletion
cannot give you.

**It cannot be undone by anyone**, including us. An erased subject can never hold a
key again: `LoadOrCreateSubjectKey` refuses to mint a replacement, deliberately,
because minting one would make new data readable under the same subject identifier
and quietly undo an erasure somebody is entitled to rely on.

## The confirmation is the subject id, not a `-yes`

You repeat the uuid. That is on purpose: a `-force` or `-yes` flag is satisfied by
muscle memory and by copy-paste from a runbook, and *which subject* is the only
mistake this command can make that nobody can reverse.

The account's email address is printed before anything is destroyed, so the
confirmation can be checked against a person rather than against a uuid.

## Why an active account is refused

An erased subject can never hold a key again. So an account left active after
erasure does not work with less data — it fails, permanently, on every path that
needs the key, in ways that look like bugs rather than like the erasure somebody
requested.

The command therefore refuses an active account unless you say what should happen
to it:

```sh
# either: erase and deactivate in one transaction
signari erase subject -subject-id <uuid> -confirm <uuid> -deactivate

# or: deactivate first, then erase — the same thing in two deliberate steps
```

This is a guard, not a policy. What erasure should *mean* is the operator's
decision, and there are three defensible answers — immediate, delay-and-notify
like account recovery, or two-person. The engine implements immediate and makes
you state the account's fate; it does not choose the rest for you.

## What survives, and why

The `core.subject_keys` row stays, with `erased_at` set and `wrapped_dek` NULL. A
database constraint enforces that pairing, so a half-erasure cannot commit.

That row is the evidence the erasure happened and when. A deleted row proves
nothing, and *"we did erase them, we just cannot show you"* is not a position to be
in during an audit.

The audit chain also survives, because it hashes **ciphertext** rather than
plaintext — so the chain stays verifiable across a shred instead of being broken
by it.

## Erasing a subject with no account

Supported, and the reason erasure is keyed on the subject rather than on the user:
a subject key outlives the account it was made for. If the account is gone and the
key is not, the ciphertext it protects is still readable and still worth
destroying.

## Over the admin API

```
POST /admin/subjects/{subjectID}/erase
Authorization: Bearer <token with subjects:erase>
Content-Type: application/json

{"confirm_subject_id": "<the same uuid>", "deactivate": true}
```

The confirmation works the same way and for the same reason: the body must repeat
the identifier in the path, so a request replayed against a different path erases
nothing.

`subjects:erase` is its own scope. It is not folded into `users:write`, because a
token that may rename a user should not thereby be able to destroy one
irreversibly — and most tokens that need the former do not need the latter.
