-- signari:compatible-with-previous
-- 0251_session_risk.sql
--
-- What was known about a sign-in, kept with the session it made (11.07). The authorization model
-- has always had words for device posture and a risk score, and no decision could read either: a
-- PDP call arrives from a relying party with no browser behind it, so what the browser showed has
-- to be written down when it is there. An older binary writes the defaults: no risk and no device
-- shown, so a model asking for a device refuses and a model capping risk passes, as it did.

ALTER TABLE core.sessions ADD COLUMN risk smallint NOT NULL DEFAULT 0 CHECK (risk BETWEEN 0 AND 100);
ALTER TABLE core.sessions ADD COLUMN device_managed boolean NOT NULL DEFAULT false;
ALTER TABLE core.sessions ADD COLUMN device_compliant boolean NOT NULL DEFAULT false;
