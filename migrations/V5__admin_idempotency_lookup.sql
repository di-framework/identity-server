CREATE INDEX auth_audit_records_idempotency_idx
  ON auth_audit_records (action, correlation_id, created_at)
  WHERE correlation_id IS NOT NULL;
