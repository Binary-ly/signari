-- Let the engine read the tables it has to read before anyone has signed in.
--
-- 0057 gave core.invitations and core.signup_rules the row-level security
-- policy that predates 0018:
--
--     USING (org_id = core.current_org_id())
--
-- Since 0018 every tenant table carries `core.is_engine() OR ...` instead,
-- because the engine sets no org context on its connection. Without the escape
-- hatch the policy evaluates against NULL, the engine sees zero rows, and the
-- feature fails in a way that looks like a missing invitation rather than a
-- permissions problem.
--
-- It was invisible in development, and that is the part worth recording: a
-- development DSN usually names a superuser, superusers bypass row-level
-- security entirely, and so every policy looks like it works. This deployment
-- would have failed on the first correctly-configured install -- which is
-- exactly the failure 0018 was written to fix the last time.
--
-- Signup and invitation acceptance both happen before there is a session, so
-- there is no org context to compare against and no way to add one.
DROP POLICY IF EXISTS invitations_org_isolation ON core.invitations;
CREATE POLICY invitations_org_isolation ON core.invitations
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

DROP POLICY IF EXISTS signup_rules_org_isolation ON core.signup_rules;
CREATE POLICY signup_rules_org_isolation ON core.signup_rules
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());
