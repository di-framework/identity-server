-- Earlier writers bound JSON text straight to `::jsonb`, which stored a JSON string scalar
-- (for example "{\"role\":\"owner\"}") instead of an object. Unwrap those values in place.
UPDATE auth_audit_records
SET before_metadata = (before_metadata #>> '{}')::jsonb
WHERE jsonb_typeof(before_metadata) = 'string' AND (before_metadata #>> '{}') LIKE '{%';

UPDATE auth_audit_records
SET after_metadata = (after_metadata #>> '{}')::jsonb
WHERE jsonb_typeof(after_metadata) = 'string' AND (after_metadata #>> '{}') LIKE '{%';

UPDATE browser_sessions
SET attributes = (attributes #>> '{}')::jsonb
WHERE jsonb_typeof(attributes) = 'string' AND (attributes #>> '{}') LIKE '{%';
