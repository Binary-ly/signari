-- 0143_webauthn_refuse_cloned.sql
--
-- Whether a passkey whose signature counter did not advance is refused, per
-- organisation, on by default.
--
-- # The defect
--
-- The engine has always detected the regression (WebAuthn §7.2, the counter
-- step) and recorded it. Refusing the sign-in hung on a configuration field
-- that nothing assigned, so it could not be switched on: a copied
-- authenticator signed in, and the only trace was an audit event.
--
-- # Why on
--
-- A counter that went backwards is the one signal that a credential has been
-- copied. The cost of refusing is the race the specification names, two
-- assertions from one authenticator finishing out of order, and the person can
-- sign in again. Synced passkeys report a counter of zero, and the check does
-- not apply to them at all, so the default reaches only authenticators that
-- keep a counter. An organisation that prefers to record and admit can turn it
-- off.

SET search_path = core, public;

ALTER TABLE webauthn_policy ADD COLUMN refuse_cloned boolean NOT NULL DEFAULT true;
