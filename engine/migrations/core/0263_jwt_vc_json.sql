-- 0263_jwt_vc_json.sql
--
-- A second credential format (12.05): a W3C Verifiable Credential signed as a JWT, which OID4VCI
-- Appendix A.1.1 names `jwt_vc_json`. Nothing else in the row changes, and `vct` holds the credential's
-- type, the second entry of `credential_definition.type`. The check that admitted one format is
-- replaced, so this is not additive: a release before this one reading a `jwt_vc_json` row refuses to
-- issue it and says the format is not implemented.

ALTER TABLE core.credential_configurations DROP CONSTRAINT credential_configurations_format_check;
ALTER TABLE core.credential_configurations ADD CONSTRAINT credential_configurations_format_check
    CHECK (format IN ('dc+sd-jwt', 'jwt_vc_json'));
