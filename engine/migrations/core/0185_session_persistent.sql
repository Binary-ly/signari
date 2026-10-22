-- signari:compatible-with-previous
--
-- 0185_session_persistent.sql
--
-- Whether a session was signed in with "stay signed in on this device" ticked
-- (5.17).
--
-- The choice lived only in the cookie's lifetime. With more than one account
-- in a browser, a session moves between the cookie in use and the ones that
-- hold the others, and each move rewrites its cookie: without the choice on the
-- row, switching away from an account and back turned "stay signed in" into a
-- cookie that ends with the browser, or the other way round. Set when the
-- session is made, from the person's choice and the organisation's offer.
--
-- Compatible with the release before: a column with a default, which it never
-- reads.

ALTER TABLE core.sessions ADD COLUMN persistent boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN core.sessions.persistent IS
    'Signed in with "stay signed in on this device", where the organisation offered it: its cookie outlasts the browser wherever this browser keeps it.';
