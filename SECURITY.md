# Security policy

Signari is an identity provider: a vulnerability in it is usually a way to sign
in as somebody else. Please report one privately, never in a public issue,
discussion or pull request.

## How to report

Use GitHub's private vulnerability reporting:
<https://github.com/binary-ly/signari/security/advisories/new>.

Include what you can of:

- the version (`signari version` prints it, with the commit and the schema),
- the configuration that matters: which protocol, flow or setting,
- the steps that reproduce it, against a deployment you own or a local one,
- what an attacker gains: whose account, which data, which control bypassed.

Test only against a deployment you own or are authorised to test. Do not access
other people's data or degrade a service while doing so.

## What happens next

The report is acknowledged in the advisory, the finding is reproduced, and a fix
is developed in a private fork of the advisory. A disclosure date is agreed with
you before anything is published. The advisory, published with the fixed
release, credits you unless you ask otherwise.

## Supported versions

Fixes are made to the latest release. A deployment on an older release upgrades
to receive them; [docs/upgrading.md](docs/upgrading.md) describes how, including
which releases may run side by side during the upgrade.

## Verifying a release

`signari version` names the commit a binary was built from, the schema
fingerprint it is pinned to, and, for a FIPS build, the validated module. A
release is built by `scripts/build-release.sh`, which refuses to build on a
reachable vulnerability (`govulncheck`) or a static-analysis finding above the
reviewed baseline (`scripts/gosec-check.sh`). It also builds the binary twice and
refuses unless the two are byte-identical, so anyone with the same toolchain can
rebuild a release from its tag and compare.

Each binary gets a CycloneDX SBOM beside it, `signari.cdx.json`, and the image
gets one of its own, `signari.image.cdx.json`, because the binary inside it is
built for another platform. Both are read from the build information the binary
carries, so they list what was linked: every module with its hash, and the Go
standard library with its version. The script refuses an SBOM that leaves out a
module the binary names. Neither has a serial number or a timestamp, so the same
binary always gives the same SBOM. Every base image is pinned by digest
([deployment artefacts](docs/deployment-artefacts.md#base-images-are-pinned-by-digest)).

Signed releases and SLSA provenance are not produced yet. Both need an identity
to sign with, which a release built on a workstation does not have.
