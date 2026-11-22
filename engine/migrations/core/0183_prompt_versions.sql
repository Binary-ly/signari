-- 0183_prompt_versions.sql
--
-- A prompt that is edited is asked again, and every answer is kept with the
-- version it answered (5.13).
--
-- # The defect
--
-- Editing a prompt's text -- new terms -- changed nothing for anybody who had
-- accepted the old ones: a `once` prompt was satisfied by any answer ever
-- given. And an answer was stored by upsert on (prompt, person), so answering
-- again overwrote the last answer and its date. "Which terms did they accept,
-- and when" could be answered with neither the terms nor the history.
--
-- # How
--
-- prompts.version starts at 1 and moves when the title, body or fields change
-- (content_hash, a SHA-256 of the three); position, once and enabled leave it.
-- A trigger computes both, on every insert and update, so no writer -- the
-- CLI today, an API or `apply` later -- can change the terms without moving
-- the version, or move it without changing them. A `once` prompt is pending
-- until the current version is answered. Each answer is a new row naming the
-- version and the content hash it answered, and an UPDATE of one is refused by
-- trigger: a record is answered again, not changed. Deleting still works, as an
-- account's deletion and erasure need.
--
-- Answers from before this migration are version 1 with no content hash: what
-- they answered was not kept.
--
-- Not compatible with the release before: its answer upserts on the primary
-- key this replaces.

ALTER TABLE core.prompts ADD COLUMN version integer NOT NULL DEFAULT 1 CHECK (version >= 1);
ALTER TABLE core.prompts ADD COLUMN content_hash bytea;
-- The hash of each part's hash, so no title, body or fields can be written to
-- collide with another split of the same characters.
CREATE FUNCTION core.prompt_content_hash(title text, body text, fields jsonb) RETURNS bytea
    LANGUAGE sql IMMUTABLE AS $$
    SELECT sha256(sha256(convert_to(title, 'UTF8')) || sha256(convert_to(coalesce(body, ''), 'UTF8'))
                  || sha256(convert_to(fields::text, 'UTF8')))
$$;

UPDATE core.prompts SET content_hash = core.prompt_content_hash(title, body, fields);
ALTER TABLE core.prompts ALTER COLUMN content_hash SET NOT NULL;

CREATE FUNCTION core.prompt_versioned() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    NEW.content_hash := core.prompt_content_hash(NEW.title, NEW.body, NEW.fields);
    IF TG_OP = 'UPDATE' THEN
        NEW.version := CASE WHEN NEW.content_hash = OLD.content_hash THEN OLD.version
                            ELSE OLD.version + 1 END;
    ELSE
        NEW.version := 1;
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER prompts_versioned BEFORE INSERT OR UPDATE ON core.prompts
    FOR EACH ROW EXECUTE FUNCTION core.prompt_versioned();

COMMENT ON COLUMN core.prompts.version IS
    'Moves when the title, body or fields change; a `once` prompt is asked again at each.';

ALTER TABLE core.prompt_responses ADD COLUMN prompt_version integer NOT NULL DEFAULT 1;
ALTER TABLE core.prompt_responses ADD COLUMN content_hash bytea;
ALTER TABLE core.prompt_responses DROP CONSTRAINT prompt_responses_pkey;
ALTER TABLE core.prompt_responses ADD COLUMN id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY;
CREATE INDEX prompt_responses_by_version ON core.prompt_responses (prompt_id, user_id, prompt_version);

COMMENT ON COLUMN core.prompt_responses.content_hash IS
    'The content hash of the prompt as it was answered: the evidence of exactly what was agreed. NULL before 0183.';

CREATE FUNCTION core.prompt_responses_are_a_record() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'a prompt response is a record: answer again rather than change one';
END $$;

CREATE TRIGGER prompt_responses_append_only BEFORE UPDATE ON core.prompt_responses
    FOR EACH ROW EXECUTE FUNCTION core.prompt_responses_are_a_record();
