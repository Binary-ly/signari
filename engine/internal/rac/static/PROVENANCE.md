# guacamole-common.js

The browser half of the Guacamole protocol, from the Apache Guacamole project —
the same project as `guacd`, which this engine already connects to.

| | |
|---|---|
| Package | `guacamole-common-js` (npm) |
| Version | 1.5.0 |
| Build | `dist/esm/guacamole-common.js` — the readable one, not the minified one |
| License | Apache 2.0 (`guacamole-common.LICENSE`) |
| Tarball SHA-256 | `b68f2ddc6643ceb199c4bbba94d837fc897c3f866bf6510858ff789592f07cc7` |
| File SHA-256 | `038360093fe5939e58cc3a6c84bd70337abcb792f2ed0f6a025f4508b1e28fca` |

## Why this is vendored rather than written

Signari's own rule for browser code is that the sign-in page carries no
dependency: WebAuthn there is a hand-written file, because anything larger is
somebody else's supply chain running where the session cookie lives.

This is a deliberate exception, on three grounds.

It is not the sign-in page. It is a page a signed-in user opens to reach a
machine they are already authorised for.

Rewriting it would not reduce the trust placed in this project — the same
project's daemon already receives the credentials for every host in the estate.
Declining its client while trusting its server would be a distinction with no
security content.

And the client is not a thin wrapper. It is a layered canvas compositor with
image streams, cursor handling and input translation, versioned against guacd.
A reimplementation would drift from the daemon it has to agree with, and the
failures would be rendering corruption rather than clean errors.

## Updating

Download the tarball, check the SHA-256 above changes as expected, replace the
file, and update this note. There is no build step and nothing is bundled.
