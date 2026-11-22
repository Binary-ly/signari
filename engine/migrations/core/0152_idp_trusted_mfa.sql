-- 0152_idp_trusted_mfa.sql
--
-- Which upstream authentication claims an identity provider is trusted to
-- assert multi-factor with.
--
-- A federated sign-in records amr `fed` and nothing else, so a flow with an
-- unconditional `mfa` stage refused everybody who signs in through a provider
-- and has no factor enrolled here, however strongly that provider had
-- authenticated them. These lists say which `amr` values, or which `acr`, in a
-- provider's verified ID token count as multi-factor. Empty, the default,
-- trusts nothing, and the sign-in is `fed` alone as before.

SET search_path = core, public;

ALTER TABLE identity_providers
    ADD COLUMN mfa_amr text[] NOT NULL DEFAULT '{}',
    ADD COLUMN mfa_acr text[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN core.identity_providers.mfa_amr IS
    'Upstream ID token amr values that count as multi-factor here (signari idp trust-mfa).';
COMMENT ON COLUMN core.identity_providers.mfa_acr IS
    'Upstream ID token acr values that count as multi-factor here (signari idp trust-mfa).';
