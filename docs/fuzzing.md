# Fuzzing

## Introduction

"Fuzzing" is testing a program with a stream of generated inputs, most of them
malformed, to find one that crashes it or never returns. Go has it built in: a
"fuzz target" is a test function that the fuzzer feeds with inputs.

Every parser that reads what a stranger sends, before anything about the sender is
known, has a native Go fuzz target. A panic in any of them would be an
unauthenticated crash of a listener.

This page lists the targets, shows how to run one, and records what fuzzing has
found. It also gives the files that will run the targets continuously, once the
repository is public. It is for a contributor adding a parser, and for a reviewer
checking how hostile input is tested.

## The targets

Among the protocols the targets read are the Lightweight Directory Access Protocol
(LDAP), Remote Authentication Dial-In User Service (RADIUS) and System for
Cross-domain Identity Management (SCIM). Others read Proof Key for Code Exchange
(PKCE) verifiers and Demonstrating Proof of Possession (DPoP) proofs.

Each target ends in an answer for any input and, where there is one, holds a
property as well:

| Package | What it reads | Targets |
|---|---|---|
| `internal/ldapd` | an LDAP search filter, from anybody who reaches the port | `FuzzDecodeFilter`, decoding and then evaluating against an entry |
| `internal/radius` | a RADIUS datagram, and the EAP and EAP-TLS framing inside it | `FuzzDecode` (every attribute read is bytes of the packet), `FuzzDecodeEAP` |
| `internal/proxyproto` | a PROXY v2 header, the first bytes on the listener | `FuzzRead`: never reads past the header it reports |
| `internal/clientip` | `X-Forwarded-For` and `Forwarded` | `FuzzClientIP`: answers an address, or nothing for unknown, never text a client wrote |
| `internal/jsonstrict` | every JSON body, first | `FuzzNoDuplicateKeys`: a member named twice is always seen |
| `internal/oauth` | an authorization request, a PKCE verifier | `FuzzValidateAuthz`, `FuzzVerifyPKCE` |
| `internal/tokens` | a bearer token presented to a resource | `FuzzVerifyAccessToken` |
| `internal/dpop` | a DPoP proof | `FuzzVerify` |
| `internal/rar` | `authorization_details` | `FuzzParse`, then validation |
| `internal/saml` | an AuthnRequest's or a response's XML | `FuzzUnmarshal` |
| `internal/scim` | a SCIM list filter and PATCH path | `FuzzParseListFilter`, `FuzzParsePath` |
| `internal/oid4vp` | a wallet's answer | `FuzzVerifyMdoc` (no bytes nobody signed are believed), `FuzzReadDCAPIAnswer`, `FuzzParsePath` |
| `internal/sdjwt` | a wallet's disclosures | `FuzzParse` |
| `internal/oidfed` | an entity statement | `FuzzParseStatement` |
| `internal/uma` | resource registrations, permission requests, scopes, claim tokens | `FuzzParseResourceDescription`, `FuzzParseScope` |
| `internal/authzen` | an access evaluation | `FuzzDecode` |

## Running one

To fuzz one target for a minute, name it and its package:

```sh
cd engine
go test -run='^$' -fuzz='^FuzzDecodeFilter$' -fuzztime=1m ./internal/ldapd/
```

A failing input is written to the package's `testdata/fuzz/<target>/`. From then
on, `go test` runs it as an ordinary case, so a fix stays fixed. Without `-fuzz`,
`go test` runs every target's seeds, which is how the suite and continuous
integration (CI) exercise them.

For a short run, add `-fuzzminimizetime=5s`. Go minimises each new input that
reaches new code before it reports progress again, for up to a minute by default.
So the progress line can sit still for many seconds while the worker is busy.

A run that ends in the middle of that can be reported as failed, with no failing
input. Twice here a 20-second run did so. With minimisation limited, the same
targets ran half a million inputs without stopping.

## What it found

On its first run, the fuzzer found a loop in `internal/jsonstrict`. Every JSON
body that is checked for duplicate members passes through it: `authorization_details`,
an AuthZEN evaluation, a Security Event Token, and a User-Managed Access (UMA)
resource registration.

Malformed JSON inside an array or an object, such as `{"evaluations":[{}R}`, never
returned. Each level answered the token it could not read by returning, and the
loop around it asked again at the same byte. A body of twenty bytes kept a core
busy for good. `authorization_details` reaches it in an authorization request
nobody has to authenticate.

The fuzzer found it three ways: through AuthZEN, through `jsonstrict` itself, and
through `authorization_details`. Those inputs are kept under `testdata/fuzz/`, and
`TestMalformedJSONEndsTheWalk` holds the fix with a time limit.

## Continuous fuzzing

`engine/fuzz/oss-fuzz-build.sh` builds every target with
`compile_native_go_fuzzer`, the helper OSS-Fuzz's and ClusterFuzzLite's Go build
image provides.

`TestEveryFuzzTargetIsBuiltForOSSFuzz` (`internal/docsync`) fails when a target is
missing from the script, or when the script names one that no longer exists. It
also fails when a package in the table above loses its last target.

OSS-Fuzz takes open-source projects, so the project is submitted once the
repository is public. Its `projects/signari/` directory holds three files. The
homepage, the repository address and the contact are left for whoever submits it.
The first file, `project.yaml`, describes the project:

```yaml
# project.yaml
homepage: "<the project's homepage>"
language: go
primary_contact: "<security contact>"
main_repo: "<the repository's public address>"
fuzzing_engines:
  - libfuzzer
sanitizers:
  - address
```

The `Dockerfile` clones the repository and copies the build script in:

```dockerfile
# Dockerfile
FROM gcr.io/oss-fuzz-base/base-builder-go
RUN git clone --depth 1 <the repository's public address> signari
WORKDIR $SRC/signari
COPY build.sh $SRC/
```

The `build.sh` runs the repository's own build script:

```sh
# build.sh
#!/bin/bash -eu
exec "$SRC/signari/engine/fuzz/oss-fuzz-build.sh"
```

Until then, the same script runs under ClusterFuzzLite, which fuzzes a private
repository from its own CI. That would spend the repository's CI minutes on every
run, so it is not switched on here.
