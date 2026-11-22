-- signari:compatible-with-previous
--
-- 0207_directory_sync_schedule.sql
--
-- A directory source that syncs itself (7.15). A sync ran when somebody ran it, so a
-- departed employee kept their account until the next cron job an operator had to
-- write and watch. next_sync_at is claimed by the statement that moves it, so of
-- several nodes one takes a source and the rest see it not yet due, and a sync that
-- fails or dies waits for its next turn rather than being asked for every minute.

ALTER TABLE core.directory_sources
    ADD COLUMN sync_interval_seconds integer CHECK (sync_interval_seconds BETWEEN 300 AND 604800);

ALTER TABLE core.directory_sources
    ADD COLUMN next_sync_at timestamptz CHECK ((sync_interval_seconds IS NULL) = (next_sync_at IS NULL));
