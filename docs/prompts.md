# Prompts during sign-in

Terms acceptance, a field the directory did not supply, a notice somebody must
see. This is the part of a flow builder people actually use.

```yaml
# terms.yaml
slug: terms
title: Terms of service
body: We have updated our terms. Please read and accept them to continue.
once: true
fields:
  - type: notice
    label: "By continuing you agree to the acceptable use policy dated 2026-08-01."
  - name: accept
    type: checkbox
    label: I accept the terms of service
    required: true
  - name: department
    type: select
    label: Which team are you in?
    options: [engineering, finance, support]
    required: true
```

```sh
signari prompt set -org <uuid> -prompt-file terms.yaml
signari prompt list -org <uuid>
```

A YAML block rather than a graph: it diffs in a pull request, and it cannot be
edited by accident in a console at two in the morning.

## It cannot be walked past

The prompt is shown **between authentication and the session**. Answer it and
you are signed in; do not, and you are not.

```
correct password → Terms of service
                   session cookies: 0
                   GET /account → 303
```

Establishing the session first and prompting afterwards would make it advisory —
a signed-in person can simply navigate elsewhere — and a terms notice that can be
navigated past is not a terms notice.

## No sign-in route can forget it

The check lives inside the single function every route funnels through:
password, passkey, MFA, Duo, Kerberos and every federated provider. Eight call
sites, one check.

A prompt that covered five routes out of six would be a notice nobody agreed to
on the sixth, and that is discovered by a lawyer rather than a test.

## An unticked box is not agreement

Browsers do not send unchecked checkboxes. A validator that asks "is the field
present and non-empty" cannot tell *"I did not agree"* from *"this field was not
in the form"* — and the obvious fix for the second silently accepts the first.

```
please complete: I accept the terms of service
```

`""`, `"0"`, `"false"` and absence are all refused for a required checkbox. An
unticked *optional* box is recorded as `false` rather than omitted, because "they
declined" and "they were never asked" are different facts.

A select value that was not offered is refused too — that submission did not come
from the rendered form.

## Answers are kept

```json
{"accept": "true", "department": "engineering"}
```

Not reduced to a boolean. *"When did they accept the terms, and to what?"* is
asked months later by somebody who needs the date and the content, and a boolean
cannot answer it. The answer is also written to the audit trail, for whoever has
the export and not the database.

## `once`

`once: true` asks until answered, then never again — terms acceptance.
`once: false` asks on every sign-in — a notice.

Getting it backwards is either an annoyance or a compliance failure, so it is an
explicit field rather than a default anybody has to infer.

A prompt containing **only** notices is refused at definition time: it collects
nothing, so it can never be answered, so it would be shown on every sign-in
forever.

## One bug worth recording

The first version read outstanding prompts through the connection **pool** while
the answer had just been written inside an uncommitted **transaction**. The pool
could not see it, so the prompt came back, was answered again, and came back
again — an infinite loop that locked out every user, and one that appears only
once a deployment defines a prompt.

The check now reads through the transaction. There is a test that answers a
prompt inside a transaction and asserts the same transaction sees nothing
outstanding, and I confirmed it fails when the pool is used instead.
