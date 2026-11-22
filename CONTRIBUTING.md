# Contributing to Signari

Thank you for wanting to help. This page says how a change gets in: what to open,
what a pull request needs, and the one agreement a first contribution asks for.

## Reporting

- **A bug or an idea:** open an issue at
  <https://github.com/Binary-ly/signari/issues>. Say what you did, what you expected
  and what happened instead, with the version or commit and the relevant log lines.
- **A vulnerability:** never in a public issue. Follow [SECURITY.md](SECURITY.md),
  which reports it privately.

## Before you start

For anything larger than a small fix, open an issue first and say what you intend to
change. An identity provider has decisions that cannot be reversed lightly (the
database schema, the key layer, the session model), and agreeing on the approach
before the code saves both of us a rewrite.

## A pull request

Open it against `main`, one focused change per pull request. It is ready when:

- **It builds and is formatted.** From `engine/`:

  ```sh
  go build ./... && go vet ./... && test -z "$(gofmt -l .)"
  ```

- **It comes with tests of what it adds or fixes**, and the suite passes. The engine's
  tests need a PostgreSQL database and refuse to pass without one, because a suite that
  quietly skips its database tests proves little:

  ```sh
  createdb signari_test
  SIGNARI_DSN=postgres://$USER@localhost/signari_test go run ./cmd/signari migrate bootstrap   # as a superuser
  SIGNARI_DSN=postgres://signari_engine@localhost/signari_test go run ./cmd/signari migrate up
  SIGNARI_TEST_DSN=postgres://$USER@localhost:5432/signari_test go test -count=1 ./...
  ```

  The console's suite runs from `admin/` with `composer test`, also against PostgreSQL.
  A fix comes with a test that fails without it.

- **The documentation moves with the code.** A new or changed command, setting or Admin
  API route belongs on [docs/cli.md](docs/cli.md),
  [docs/configuration.md](docs/configuration.md) or
  [docs/admin-api.md](docs/admin-api.md) in the same change; tests in
  `engine/internal/docsync` fail the build when code and these pages disagree.

- **It adds no new static-analysis finding.** CI runs govulncheck, gosec against
  [engine/gosec-baseline.txt](engine/gosec-baseline.txt) and CodeQL. A finding that is
  not a defect is explained where it is, as
  [docs/security-scanning.md](docs/security-scanning.md) does for the ones there now.

- **Its commit messages say what changed and why it matters**, in a sentence.

CI runs all of this on every pull request, and a maintainer reviews it before it is
merged.

## The Contributor License Agreement

Signari is released under [AGPL-3.0-only](LICENSE), and its copyright holder also
offers it under other terms, which [NOTICE.md](NOTICE.md) explains. That is only
possible while the copyright stays in one place, so **a first contribution asks you to
sign the [Contributor License Agreement](CLA.md)** before it is merged. The CLA
Assistant bot comments on your first pull request with a link to it, and you sign by
replying with exactly:

    I have read the CLA Document and I hereby sign the CLA

The agreement says what it grants, so read it before you sign. It covers your later pull
requests too.

## Conduct

Be direct about the code and kind to the people. Disagreement about a change belongs
in its pull request or issue, argued from what the change does.
