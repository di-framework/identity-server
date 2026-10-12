-- Pins name resolution in the column encryption trigger functions (identity-server#57 review S1).
--
-- V18 created both functions without a search_path, and identity_reject_plaintext() read the latch
-- table unqualified. pg_temp is searched first for relations, and PUBLIC may create temp tables by
-- default, so a session holding only the service credentials could create
-- pg_temp.identity_column_encryption claiming "disabled" and write plaintext past the trigger.
--
-- The fix is applied in the schema V18 created the functions in (and the latch table with them),
-- found through pg_proc, so it holds whichever schema the owner migrated into:
--   * identity_reject_plaintext() is replaced with a body that names the latch table by schema,
--     so the lookup no longer depends on any search_path;
--   * both functions get SET search_path = pg_catalog, pg_temp. Built-ins resolve from pg_catalog
--     first, and pg_temp is listed last so it is never searched before them. The caller's own
--     search_path no longer reaches either function.
-- CREATE OR REPLACE keeps the function's OID, owner and grants, so the triggers V18 attached
-- (and the service role's EXECUTE) are unchanged. V18 and V19 are not edited: deployed databases
-- have already recorded their checksums.
DO $migration$
DECLARE
  home text;
BEGIN
  SELECT n.nspname INTO STRICT home
  FROM pg_catalog.pg_proc p
  JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
  WHERE p.oid = 'identity_reject_plaintext()'::regprocedure;

  EXECUTE format($function$
CREATE OR REPLACE FUNCTION %I.identity_reject_plaintext() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $body$
DECLARE
  written jsonb := to_jsonb(NEW);
  previous jsonb := CASE WHEN TG_OP = 'UPDATE' THEN to_jsonb(OLD) ELSE '{}'::jsonb END;
  column_name text;
BEGIN
  -- Recorded key checks count as enabled too, so clearing only `enabled` downgrades nothing.
  IF NOT EXISTS (
    SELECT 1 FROM %I.identity_column_encryption
    WHERE enabled OR column_key_check IS NOT NULL OR bidx_key_check IS NOT NULL
  ) THEN
    RETURN NEW;
  END IF;
  FOREACH column_name IN ARRAY TG_ARGV LOOP
    IF jsonb_typeof(written -> column_name) <> 'null'
       AND (written -> column_name) IS DISTINCT FROM (previous -> column_name) THEN
      RAISE EXCEPTION 'column encryption is enabled; %%.%% must not be written in plaintext',
        TG_TABLE_NAME, column_name USING ERRCODE = 'IDC01';
    END IF;
  END LOOP;
  RETURN NEW;
END
$body$
$function$, home, home);

  -- The latch guard reads only OLD and NEW, so nothing in it can be shadowed today. Pin it anyway
  -- so a later change to its body cannot reintroduce caller-controlled name resolution.
  EXECUTE format(
    'ALTER FUNCTION %I.identity_column_encryption_guard() SET search_path = pg_catalog, pg_temp',
    home
  );
END
$migration$;
