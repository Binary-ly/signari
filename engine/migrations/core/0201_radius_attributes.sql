-- 0201_radius_attributes.sql
--
-- What else a group's members can be given at Access-Accept (7.06), beside a
-- VLAN and a Filter-Id: a Session-Timeout in seconds, a Class the device echoes
-- in accounting, and vendor-specific attributes. Those are named by number, the
-- vendor's enterprise number and its own attribute type, because a device's
-- documentation gives them that way and a dictionary here would be one more
-- thing to go stale.
--
-- A row saying only one of these says something, so the check that a row
-- authorises something widens to them.

SET search_path = core, public;

ALTER TABLE core.radius_group_authorization
    ADD COLUMN session_timeout integer CHECK (session_timeout IS NULL OR session_timeout BETWEEN 1 AND 2147483647),
    ADD COLUMN class text CHECK (class IS NULL OR length(class) BETWEEN 1 AND 253),
    ADD COLUMN vendor_attributes jsonb NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE core.radius_group_authorization
    DROP CONSTRAINT radius_authorization_says_something,
    ADD CONSTRAINT radius_authorization_says_something
        CHECK (vlan_id IS NOT NULL OR filter_id IS NOT NULL OR session_timeout IS NOT NULL
               OR class IS NOT NULL OR vendor_attributes <> '[]'::jsonb);
