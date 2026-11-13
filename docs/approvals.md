# A second person for the highest-value changes

Some changes through the Admin API cannot be taken back, or hand over everything
at once. An organisation can have those wait until somebody else approves them
(ASVS 5.0.0 V2.3.5, multi-user approval for high-value flows):

| Kind | The change |
|---|---|
| `subject_erasure` | `POST /admin/subjects/{id}/erase`: a person erased, their key destroyed. It cannot be undone |
| `owner_grant` | `POST /admin/organizations/{id}/role-bindings` with `"role": "org-owner"`: every other permission at once |

```sh
signari api PATCH /admin/organizations/<org>/settings -data '{"approvals_required": ["subject_erasure", "owner_grant"]}'
```

## What happens

Such a request answers `202` with an `approval_id`, and nothing changes yet. It
waits a day.

```sh
signari api GET  /admin/organizations/<org>/approvals            # what is waiting
signari api POST /admin/approvals/<id>/approve                    # as somebody else
signari api POST /admin/approvals/<id>/reject                     # or turn it down
```

**The approver makes the change, as themselves.** Approving replays the request
through the API as the approver. Their token, scopes and organisation apply, and
so do the checks on privileged people, as if they had sent it. The change's own
audit record names the approver, and `admin.approval_granted` names who asked. So
an approval can never reach further than its approver could alone. An approver
without the scope gets the change's own refusal, and the request stays waiting
for somebody who has it.

**The one who asked cannot approve it.** A person signed in to the console is
the person, whichever role binding they hold. A token is itself, so somebody who
holds two tokens is two askers. Give each person their own credential.

**Turning one down** takes the scope the change needs, or a token with no right
to erase anybody could stop every erasure. The one who asked may always
withdraw it.

**Relaxing the rule waits too.** A request that takes a kind out of
`approvals_required` answers `202` and waits for a second person, with the rest
of the request waiting with it. Otherwise one token could turn the rule off and
then act alone. Adding a kind takes effect at once.

A request's body is kept only while it waits (an erasure's is the person's id),
and is cleared when it is decided or expires. Decided requests stay listed for
thirty days.

## What it does not cover

The `signari` command on the host works on the database directly, where an
operator can already do anything, so the rule is not applied there. Organisation
deletion is one of those commands and already takes two steps.

## Measured

November 2026, through `signari api` against a running engine, with an organisation
that has erasure wait and three tokens:

| | Answer |
|---|---|
| The asker erases a person | `202`, an approval id; the person still active |
| The asker approves it | `403 approval_by_requester` |
| A `config:read` token approves it | its replay refused `insufficient_scope`; still pending |
| A second `subjects:erase` token approves it | `200 approved`; the person gone |
| Taking `subject_erasure` away, even with the break-glass token | `202`, waiting |

The trail read `admin.approval_requested`, `admin.approval_failed`,
`admin.subject_erased` (by the approver) and `admin.approval_granted`.
