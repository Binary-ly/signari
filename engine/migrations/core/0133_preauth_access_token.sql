-- 0133_preauth_access_token.sql
--
-- A redeemed credential offer records the access token it minted, so the
-- credential endpoint can tell an issuance token from any other.
--
-- # The defect
--
-- The credential endpoint accepted any access token audienced to this issuer
-- and issued whichever configuration the request named, for the token's
-- subject, bound to whatever key the caller proved. A login token from an
-- unrelated client minted verifiable credentials, and a token redeemed from an
-- offer for one credential minted every other. OID4VCI 1.0 section 5.1.2
-- (specs/oid4vci.txt:1332) has the issuer interpret what a token authorizes as
-- "a request to access the Credential Endpoint ... for the issuance of a
-- Credential type identified by that scope value"; section 8.3.1.1 answers a
-- token that does not enable issuance of the requested credential with an
-- authorization error.
--
-- # Why a column rather than a claim
--
-- The standard claim for this is authorization_details of type
-- openid_credential, and returning it obliges the wallet to use the
-- credential_identifiers that come with it (section 6.2), a request form this
-- issuer does not accept yet. The offer already names its configurations, so
-- the token is tied to the offer instead, and the endpoint reads the offer.

ALTER TABLE core.preauthorized_codes ADD COLUMN access_token_jti text;

CREATE UNIQUE INDEX preauthorized_codes_access_token_jti_key
    ON core.preauthorized_codes (access_token_jti)
    WHERE access_token_jti IS NOT NULL;
