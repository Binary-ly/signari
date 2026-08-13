# Licensing

Signari is licensed under the **GNU Affero General Public License v3.0 only**
(`AGPL-3.0-only`). The full text is in [LICENSE](LICENSE).

## What AGPL means here, in plain terms

AGPL is the GPL plus one clause that matters for server software: if you run a
modified version and let other people use it **over a network**, you must offer
them the source of your modifications. Ordinary GPL does not require that,
because it is triggered by *distribution*, and nobody distributes a hosted
service.

For an identity provider that is the correct choice for two reasons:

* **Auditability.** Nobody should have to trust an authentication server they
  cannot read. AGPL guarantees that anyone relying on a deployment can see what
  it actually does.
* **It keeps the hosted option open.** A cloud provider cannot take this, run it
  as a service, and keep their changes private. Apache-2.0 or MIT would allow
  exactly that.

**Using Signari does not make your applications AGPL.** Talking to it over OIDC
is use, not derivation — the same way running PostgreSQL does not license your
schema. The obligation applies to modifying *Signari itself* and offering that
modified version to others over a network.

## `-only`, not `-or-later`

`AGPL-3.0-only` pins the terms to version 3. `-or-later` would pre-commit this
project to the terms of a licence that does not exist yet and that nobody has
read. Since the copyright is held in one place, moving to a future version stays
possible — it just becomes a decision rather than an automatic consequence.

## Commercial licensing

The copyright holder can grant terms other than AGPL to anyone who needs them,
which is the standard open-core arrangement. That option only survives while the
copyright stays consolidated: **outside contributions need a CLA or copyright
assignment before they are merged**, or dual licensing quietly becomes impossible.

## Dependencies

Signari depends on MIT- and BSD-licensed libraries (Laravel, pgx, go-jose,
go-webauthn, and others). Those licences are compatible with AGPL — permissive
code may be used in a copyleft project. Their notices remain in
`vendor/` and `go.sum` respectively.
