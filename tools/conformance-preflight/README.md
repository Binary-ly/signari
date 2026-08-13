# Conformance preflight

**This is not certification.** Certification means running the OpenID
Foundation's suite against a publicly reachable deployment and submitting the
results at <https://certification.openid.net>, which needs a human with an
account there.

What this does is find the failures first, so that session is spent submitting
rather than debugging.

```sh
node preflight.mjs <issuer> <client_id> <redirect_uri> <username> <password>
```

Exit 0 when everything the Basic OP profile checks holds.

## Why the assertions are written against the spec, not the code

Each check names the section it comes from (`Core 3.1.3.7`, `RFC 9207`, …). A
test that only agrees with the implementation under test proves nothing — the
same reason the password verifiers were tested against hashes produced by PHP
rather than by us.

## Getting to actual certification

1. Expose the deployment publicly. A Cloudflare quick tunnel is enough and needs
   no account — see `docs/runbook-public-conformance.md`. **The issuer must equal
   the public URL byte for byte.**
2. Run this preflight against that public URL. Fix anything it reports.
3. Sign in at <https://certification.openid.net>, create a plan for
   **Basic OP**, point it at the discovery URL, run it.
4. Submit the results.

Steps 1 and 2 are automatable. Steps 3 and 4 are not: they need your login.

## Known local-suite limitation

The self-hosted suite hardcodes `HtmlUnitDriver`, which throws
`org.htmlunit.ScriptException` parsing **its own** Bootstrap bundle from
jsdelivr — an upstream bug in the suite's browser, not in the provider under
test. Use the hosted suite instead.
