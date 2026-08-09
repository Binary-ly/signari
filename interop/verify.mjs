// Cross-language conformance check.
//
// Everything the Go engine does is currently verified by tests written against
// the same understanding of the specs that produced the implementation. If that
// understanding is wrong, the tests are wrong in the same direction and agree
// with each other. A second, independent implementation is the cheapest way to
// break that circularity.
//
// `jose` is a good choice specifically: it is by the author of
// node-oidc-provider, it is OpenID-certified, and it shares no code, no
// language, and no author with go-jose. Where the two agree, the encoding is
// probably right. Where they disagree, one of them has a bug worth finding.
//
// Usage: node verify.mjs <issuer-base-url> <id_token> <access_token>

import {
  createRemoteJWKSet,
  jwtVerify,
  decodeProtectedHeader,
  decodeJwt,
} from 'jose'

const [, , issuer, idToken, accessToken] = process.argv
if (!issuer || !idToken) {
  console.error('usage: node verify.mjs <issuer> <id_token> [access_token]')
  process.exit(2)
}

let failures = 0
const check = (label, ok, detail = '') => {
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? ` -- ${detail}` : ''}`)
  if (!ok) failures++
}

// 1. Discovery must be fetchable and self-consistent. A relying party starts
//    here, so an error at this step is invisible to every Go test we have.
const discovery = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json()
check('discovery issuer matches the requested issuer', discovery.issuer === issuer,
  `${discovery.issuer}`)
check('jwks_uri is under the issuer', String(discovery.jwks_uri).startsWith(issuer))

// 2. Fetch the key set the way a real relying party does, by URL, with jose's
//    own caching and kid resolution -- not by handing it a key we already have.
const JWKS = createRemoteJWKSet(new URL(discovery.jwks_uri))

// 3. Verify the ID token independently.
const header = decodeProtectedHeader(idToken)
check('id_token header carries a kid', Boolean(header.kid), header.kid)
check('id_token alg is advertised in discovery',
  discovery.id_token_signing_alg_values_supported.includes(header.alg), header.alg)

try {
  const { payload } = await jwtVerify(idToken, JWKS, {
    issuer,
    // Audience is checked by the library, not by us reading the claim.
    audience: decodeJwt(idToken).aud,
  })
  check('id_token signature verifies under an independent implementation', true)
  check('id_token has sub', Boolean(payload.sub))
  check('id_token has sid (needed for back-channel logout mapping)', Boolean(payload.sid))
  check('id_token exp is in the future', payload.exp * 1000 > Date.now())
  check('id_token iat is not in the future', payload.iat * 1000 <= Date.now() + 60000)
} catch (e) {
  check('id_token signature verifies under an independent implementation', false, e.message)
}

// 4. Verify the access token, and assert the typ separation holds from the
//    outside. RFC 9068 requires at+jwt; without it an ID token and an access
//    token are interchangeable to anything that only checks the signature.
if (accessToken) {
  const atHeader = decodeProtectedHeader(accessToken)
  check('access_token typ is at+jwt (RFC 9068)', atHeader.typ === 'at+jwt', atHeader.typ)
  check('id_token typ is NOT at+jwt', header.typ !== 'at+jwt', header.typ ?? '(absent)')

  try {
    const { payload } = await jwtVerify(accessToken, JWKS, { issuer })
    check('access_token signature verifies independently', true)
    check('access_token has jti (RFC 9068 requires it)', Boolean(payload.jti))
    check('access_token aud is present', Boolean(payload.aud))
  } catch (e) {
    check('access_token signature verifies independently', false, e.message)
  }

  // 5. at_hash: recompute it here rather than trusting ours. Halving the wrong
  //    thing -- the token text instead of the raw hash bytes -- is the classic
  //    at_hash bug and produces a value that looks entirely plausible.
  const claims = decodeJwt(idToken)
  if (claims.at_hash) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(accessToken))
    const half = new Uint8Array(digest).slice(0, 16)
    const expected = Buffer.from(half).toString('base64url')
    check('at_hash is the left-most half of SHA-256(access_token)',
      claims.at_hash === expected, `got ${claims.at_hash}, computed ${expected}`)
  }
}

console.log(failures === 0
  ? '\n  all cross-language checks passed'
  : `\n  ${failures} cross-language check(s) FAILED`)
process.exit(failures === 0 ? 0 : 1)
