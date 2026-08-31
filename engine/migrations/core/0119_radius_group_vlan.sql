-- Network authorisation a RADIUS Access-Accept may carry.
--
-- # Why only these, and not user attributes generally
--
-- `RADIUSAuthenticator.Authenticate` discarded the identity on purpose, with a
-- stated reason: an Access-Accept "is not a place to start leaking a directory".
-- That reasoning is right and is preserved here.
--
-- What changes is that VLAN assignment is not leakage — it is the thing the
-- switch asked the question for. RFC 3580 §3.31 defines it as the answer to
-- "which network does this person go on", and a deployment that authenticates
-- somebody and then cannot say which VLAN has done half the job.
--
-- So the reply carries authorisation and never identity: a VLAN id and a filter
-- name, both chosen by the operator per group. No email, no display name, no
-- user attributes. A network device gets a decision, not a directory.
--
-- # Keyed on GROUP, because that is where access decisions already live
--
-- `core.groups` decides which applications a member reaches; extending it to
-- decide which network segment they reach keeps one place to look. A per-user
-- VLAN would be a second membership model that has to be kept in step with the
-- first, and the two would disagree.

CREATE TABLE core.radius_group_authorization (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    group_id    uuid        NOT NULL REFERENCES core.groups(id) ON DELETE CASCADE,

    -- The VLAN this group's members are placed on.
    --
    -- RFC 3580 §3.31: "the VLANID is 12-bits, taking a value between 1 and 4094,
    -- inclusive." Bounded here so an out-of-range value is refused at
    -- configuration time rather than encoded into a reply a switch will reject
    -- or, worse, misread.
    vlan_id     integer     CHECK (vlan_id IS NULL OR vlan_id BETWEEN 1 AND 4094),

    -- RADIUS Filter-Id (attribute 11): the name of a filter list already
    -- configured on the device. Naming one this deployment does not control is
    -- the point -- the switch owns the filter, we say which.
    filter_id   text        CHECK (filter_id IS NULL OR length(filter_id) BETWEEN 1 AND 253),

    -- Priority when somebody is in several authorised groups. Highest wins, and
    -- ties are broken by group id so the answer is stable rather than dependent
    -- on row order.
    --
    -- A deterministic rule matters more than which rule: a person in two groups
    -- must land on the same VLAN every time they connect, or they get an
    -- intermittent network that nobody can reproduce.
    priority    integer     NOT NULL DEFAULT 0,

    created_at  timestamptz NOT NULL DEFAULT now(),

    UNIQUE (org_id, group_id),

    -- A row that authorises nothing is a configuration somebody believes is
    -- doing something.
    CONSTRAINT radius_authorization_says_something
        CHECK (vlan_id IS NOT NULL OR filter_id IS NOT NULL)
);

CREATE INDEX radius_group_authorization_by_org ON core.radius_group_authorization (org_id);

ALTER TABLE core.radius_group_authorization ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.radius_group_authorization FORCE ROW LEVEL SECURITY;
CREATE POLICY radius_group_authorization_org_isolation ON core.radius_group_authorization
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());
