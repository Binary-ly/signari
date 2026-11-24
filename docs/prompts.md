# Prompts during sign-in

## Introduction

Sometimes a person must do something on the way in. They may need to accept new
terms, fill in a field the directory did not supply, or see a notice. A "prompt" is a page that
asks for it during sign-in.

Signari shows a prompt after the person has proved who they are, and before it
gives them a session. Every answer is kept, with the version of the prompt it
answered. This is the part of a [sign-in flow](flows.md) builder that people
actually use.

You write a prompt as a YAML file, and install it with `signari prompt set`.

## Define a prompt

This prompt asks the person to accept new terms of service, and to say which
team they are in:

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

Install it in an organisation, then list the organisation's prompts:

```sh
signari prompt set -org <uuid> -prompt-file terms.yaml
signari prompt list -org <uuid>
```

A prompt is a YAML block, not a graph. It diffs in a pull request, and it cannot
be edited by accident in a console at two in the morning.

## It cannot be walked past

The prompt is shown **between authentication and the session**. Answer it and
you are signed in. Do not, and you are not.

This is the state after a correct password, while the prompt waits for an
answer:

```
correct password → Terms of service
                   session cookies: 0
                   GET /account → 303
```

Establishing the session first and prompting afterwards would make the prompt
advisory, because a signed-in person can navigate elsewhere. A terms notice that
can be navigated past is not a terms notice.

## No sign-in route can forget it

The check lives inside the single function every route funnels through:
password, passkey, multi-factor authentication (MFA), Duo, Kerberos and every
federated provider. There are eight call sites, and one check.

A prompt that covered five routes out of six would be a notice nobody agreed to
on the sixth. A lawyer would discover that, not a test.

## An unticked box is not agreement

Browsers do not send unchecked checkboxes. A validator that asks "is the field
present and non-empty" cannot tell *"I did not agree"* from *"this field was not
in the form"*. And the obvious fix for the second silently accepts the first.

A required box left unticked is refused with this error:

```
please complete: I accept the terms of service
```

`""`, `"0"`, `"false"` and absence are all refused for a required checkbox. An
unticked *optional* box is recorded as `false`, not omitted, because "they
declined" and "they were never asked" are different facts.

A select value that was not offered is refused too, because that submission did
not come from the rendered form.

## Answers are kept

An answer is not reduced to a yes or a no. The stored answer keeps every field,
like this answer to the terms prompt:

```json
{"accept": "true", "department": "engineering"}
```

Each answer is its own row. It records when it was given, and the **version** of
the prompt it answered. It also keeps a hash of the title, body and fields
exactly as they stood. So *"to what did they agree, and when?"* is answered by the record, not by
memory.

A response is never changed in place: the database refuses an update to one. The
answer is also written to the audit trail with its version, for whoever has the
export and not the database.

## Editing a prompt asks again

The version moves when the title, the body or the fields change, and only then.
Reordering a prompt, or switching it on or off, leaves the version as it is.

A `once` prompt is outstanding until its **current** version is answered. So new
terms are put to everybody at their next sign-in, and their answers to the old
ones are kept. Setting a changed prompt says how many people will be asked
again:

```
signari prompt set -org <uuid> -prompt-file terms.yaml
prompt terms, version 2
  412 person(s) who answered an earlier version will be asked again; their
  earlier answers are kept
```

The version is decided by the database, on every write, so no writer can change
the terms without moving it. The page carries the version it showed. Terms
edited while somebody was reading them are shown again, not accepted on their
behalf. `prompt list` counts the people who have answered the current version.

Until October 2026, an answer replaced the one before it. Editing a prompt kept
the answers given to the old text, and asked nobody again. Answers from before
then are version 1, and what they answered was not kept.

## An answer can be an attribute

A field with `attribute:` writes its answer to that attribute of the person, in
the same transaction as the answer. A [claim mapper](admin-api.md#claim-mappers)
then releases it to applications from the next token on:

```yaml
fields:
  - name: team
    type: select
    label: Which team are you in?
    options: [engineering, finance, support]
    required: true
    attribute: department
```

`prompt set` refuses the field unless the organisation has declared the
attribute. It also refuses the field unless every answer it can give fits the
attribute's type. A checkbox into a boolean is fine, but a select offering `yes`
and `no` into a boolean is not. That is refused when the prompt is defined, not
at somebody's sign-in.

A personal attribute is sealed under the person's key, as any other write is. A
field left blank leaves the attribute as it was. A notice collects nothing, so
it cannot name an attribute. Neither can two fields name the same one.

The prompt writes whether or not the attribute is `user_writable`. That setting
governs the person's own profile page. Mapping a field is the administrator
deciding to collect the value. Each write is recorded as
`user.attributes_updated` with `by: prompt`, naming the attributes and never
their values.

## Required attributes nobody has given

Sign-up refuses an account without a `required` attribute the person may write.
But some accounts were made before the attribute was required, and never met
that check. They were made by an administrator, by an import or by a directory.
So
the prompt stage asks for those attributes too, after the administrator's own
prompts and before any session.

It is a page of its own, in the reader's language. It has one field for each
required, `user_writable` attribute the person holds no value for. A yes-or-no
attribute is a box, and unticked means no. A blank field is refused, naming it.

The answer is written as the person's profile writes it, so nothing they could
not set there can be set here. It is recorded as `user.attributes_updated` with
`by: sign-in`. Once given, it is not asked again.

A required attribute the person may not write is an administrator's to fill, and
is never asked. The page's slug, `signari.required-attributes`, is reserved: no
prompt of the administrator's may take it.

## `once`

`once: true` asks until answered, then never again — terms acceptance.
`once: false` asks on every sign-in — a notice.

Getting it backwards is either an annoyance or a compliance failure. So it is an
explicit field, not a default anybody has to infer.

A prompt containing **only** notices is refused when it is defined. It collects
nothing, so it can never be answered, so it would be shown on every sign-in
forever.

## One bug worth recording

The first version read outstanding prompts through the connection **pool**, the
shared set of database connections. But the answer had been written a moment
before, inside an uncommitted **transaction**, and the pool could not see it. So the prompt came
back, was answered again, and came back again. That infinite loop locked out
every person, and it appears only once a deployment defines a prompt.

The check now reads through the transaction. A test answers a prompt inside a
transaction, and asserts that the same transaction sees nothing outstanding. The
test was confirmed to fail when the pool is used instead.
