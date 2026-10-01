-- 0036: per-org-unique actor handles for @-mentions (item 31).
--
-- `actors` (created by 0008) had only a free-text `display_name`. Mentions
-- need a stable, unique-per-org identifier to resolve `@handle` against
-- the org roster.
--
-- Normalization rules (recorded, not ad hoc):
--   * lowercase (Unicode-aware via lower(); non-ASCII letters are not in
--     the allowed set and become separators)
--   * allowed characters: a-z 0-9 . _ -
--   * any other character acts as a separator; separator runs collapse to
--     a single '-'
--   * leading/trailing '-' and '.' are stripped
--   * truncated to 64 characters (a truncation-exposed trailing separator
--     is stripped too)
--   * an empty result becomes 'actor'
-- The Rust twin of this function is `tinker_core::handles::normalize_handle`
-- — keep the two in sync.
--
-- Collision policy: deterministic suffix, GitHub-style. The first actor
-- (by created_at) in an org keeps the bare handle; later claimants get
-- handle-2, handle-3, ... Fail-closed was rejected for the backfill: it
-- would abort the migration on real duplicate display names, and the
-- UNIQUE(organization_id, handle) constraint enforces the invariant
-- regardless. New inserts resolve collisions in application code with the
-- same suffix rule (see tinker-auth ApiKeyIssuer::issue).

CREATE OR REPLACE FUNCTION normalize_actor_handle(raw TEXT)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    s TEXT := lower(COALESCE(raw, ''));
    i INT;
    ch TEXT;
    out TEXT := '';
    need_sep BOOLEAN := FALSE;
BEGIN
    FOR i IN 1..char_length(s) LOOP
        ch := substring(s FROM i FOR 1);
        IF ch ~ '^[a-z0-9._-]$' THEN
            IF need_sep AND out <> '' THEN
                out := out || '-';
            END IF;
            need_sep := FALSE;
            out := out || ch;
        ELSE
            need_sep := TRUE;
        END IF;
    END LOOP;
    out := regexp_replace(out, '^[-.]+', '');
    out := regexp_replace(out, '[-.]+$', '');
    out := left(out, 64);
    out := regexp_replace(out, '[-.]+$', '');
    IF out = '' THEN
        out := 'actor';
    END IF;
    RETURN out;
END;
$$;

ALTER TABLE actors ADD COLUMN IF NOT EXISTS handle TEXT;

-- Backfill from display_name with the deterministic-suffix collision
-- policy, oldest actor per org first.
DO $$
DECLARE
    r RECORD;
    base TEXT;
    cand TEXT;
    n INT;
BEGIN
    FOR r IN
        SELECT id, organization_id, display_name
        FROM actors
        ORDER BY organization_id, created_at, id
    LOOP
        base := normalize_actor_handle(r.display_name);
        cand := base;
        n := 1;
        WHILE EXISTS (
            SELECT 1 FROM actors a
            WHERE a.organization_id = r.organization_id
              AND a.handle = cand
              AND a.id <> r.id
        ) LOOP
            n := n + 1;
            cand := base || '-' || n::text;
        END LOOP;
        UPDATE actors SET handle = cand WHERE id = r.id;
    END LOOP;
END;
$$;

ALTER TABLE actors ALTER COLUMN handle SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'uq_actors_org_handle'
    ) THEN
        ALTER TABLE actors
            ADD CONSTRAINT uq_actors_org_handle UNIQUE (organization_id, handle);
    END IF;
END;
$$;
