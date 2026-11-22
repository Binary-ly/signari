-- 0299_vp_cross_device.sql
--
-- A wallet sign-in may offer the wallet on another device, by a code to scan, when its
-- operator turns that on (vp_verifiers.cross_device, off by default). The verifier cannot
-- tell that answer from one an attacker relayed to somebody else's phone
-- (specs/oid4vp.txt:2032-2037), so it signs nobody in until a code emailed to the linked
-- account's own address is typed where the sign-in began. A cross-device request is marked
-- on its pending sign-in, its answer is kept there sealed under the root key, and the
-- code that confirms it is named there too. Compatible with the previous release, which
-- reads none of it and offers the same device alone.
-- signari:compatible-with-previous

ALTER TABLE core.vp_verifiers ADD COLUMN cross_device boolean NOT NULL DEFAULT false;

ALTER TABLE core.federated_logins ADD COLUMN vp_cross_device boolean NOT NULL DEFAULT false;

ALTER TABLE core.federated_logins ADD COLUMN vp_cross_presented bytea;

ALTER TABLE core.federated_logins ADD COLUMN vp_confirm_attempt uuid;

COMMENT ON COLUMN core.vp_verifiers.cross_device IS
    'the wallet may be on another device, by a code to scan, confirmed by a code emailed to the account';

COMMENT ON COLUMN core.federated_logins.vp_cross_presented IS
    'a cross-device answer, root-sealed; no response code is handed out for one';

COMMENT ON COLUMN core.federated_logins.vp_confirm_attempt IS
    'the email_sign_in_codes row whose code confirms this cross-device sign-in';
