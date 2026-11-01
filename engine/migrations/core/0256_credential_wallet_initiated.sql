-- signari:compatible-with-previous
-- 0256_credential_wallet_initiated.sql
--
-- A wallet can ask for a credential at the authorization endpoint (12.06). Until now issuance
-- began with an operator's offer, so who could have what was decided before anybody asked. A
-- request an authorization server receives is the wallet's own idea, so a configuration says
-- whether anybody signed in here may ask for it, and it is off: the claims come from the person's
-- record, but whether they hold this credential at all is the issuer's to say. An offer for the
-- authorization code grant keeps its issuer_state on core.preauthorized_codes, under a hash no
-- pre-authorized code can match, so a state is never a bearer code. An older binary reads neither.

ALTER TABLE core.credential_configurations ADD COLUMN wallet_initiated boolean NOT NULL DEFAULT false;
