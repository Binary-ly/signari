-- signari:compatible-with-previous
--
-- 0187_new_device_notice.sql
--
-- Whether a sign-in from a device the person has not used is told to them
-- (5.21).
--
-- Nothing said so. A password used from somewhere new is the moment a person
-- can still act on, and the session list showed it only to somebody who went
-- looking. On by default: a mail on each new browser is the cost, and an
-- organisation whose people sign in from many shared machines turns it off
-- with `signari instance new-device-notice -notice off`.
--
-- Compatible with the release before: a column with a default, which it never
-- reads.

ALTER TABLE core.organizations ADD COLUMN new_device_notice boolean NOT NULL DEFAULT true;

COMMENT ON COLUMN core.organizations.new_device_notice IS
    'Whether a sign-in from a browser and system none of the person''s sessions of the last 90 days used is mailed to them. `signari instance new-device-notice`.';
