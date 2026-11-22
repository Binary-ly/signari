-- signari:no-transaction
-- signari:compatible-with-previous
--
-- 0222_user_foreign_key_indexes.sql
--
-- An index for every foreign key into core.users (0.50). Each one with none made a delete
-- of a person scan that table to find their rows, so a person cost 10.7 ms, an organisation
-- of a hundred thousand took eighteen minutes in one transaction, and `instance org-delete`,
-- `-on-deactivate delete` and erasure all paid it. Full and not partial, because the check a
-- cascade runs has no predicate to match one.
--
-- Built concurrently, outside a transaction, as 0196's were, so people go on signing in
-- while these build.

CREATE INDEX CONCURRENTLY IF NOT EXISTS authorization_codes_user ON core.authorization_codes (user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS authorization_models_updated_by ON core.authorization_models (updated_by);
CREATE INDEX CONCURRENTLY IF NOT EXISTS device_authorizations_user ON core.device_authorizations (user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS duo_challenges_user ON core.duo_challenges (user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS federated_logins_link_user ON core.federated_logins (link_user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS group_members_added_by ON core.group_members (added_by);
CREATE INDEX CONCURRENTLY IF NOT EXISTS impersonations_actor ON core.impersonations (actor_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS invitations_created_by ON core.invitations (created_by);
CREATE INDEX CONCURRENTLY IF NOT EXISTS invitations_used_by ON core.invitations (used_by);
CREATE INDEX CONCURRENTLY IF NOT EXISTS preauthorized_codes_user ON core.preauthorized_codes (user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS recovery_codes_user ON core.recovery_codes (user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS recovery_requests_user ON core.recovery_requests (user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS refresh_token_families_user ON core.refresh_token_families (user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS relations_granted_by ON core.relations (granted_by);
CREATE INDEX CONCURRENTLY IF NOT EXISTS saml_logout_progress_user ON core.saml_logout_progress (user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS saml_name_ids_user ON core.saml_name_ids (user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS scim_source_links_by_user ON core.scim_source_links (user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS sessions_impersonator ON core.sessions (impersonator_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS sessions_user ON core.sessions (user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ssf_received_user ON core.ssf_received (user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS uma_claims_interactions_requesting_party ON core.uma_claims_interactions (requesting_party);
CREATE INDEX CONCURRENTLY IF NOT EXISTS uma_pending_requests_decided_by ON core.uma_pending_requests (decided_by);
CREATE INDEX CONCURRENTLY IF NOT EXISTS uma_pending_requests_requesting_party ON core.uma_pending_requests (requesting_party);
CREATE INDEX CONCURRENTLY IF NOT EXISTS uma_permission_tickets_requesting_party ON core.uma_permission_tickets (requesting_party);
