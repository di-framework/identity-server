CREATE TABLE identity_security_notifications (
    id UUID PRIMARY KEY,
    event_key CHAR(64) NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action VARCHAR(64) NOT NULL,
    recipient_email VARCHAR(320),
    provider_name VARCHAR(128) NOT NULL,
    issuer VARCHAR(512) NOT NULL,
    identity_hint VARCHAR(32) NOT NULL,
    correlation_id VARCHAR(128),
    status VARCHAR(32) NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    sent_at TIMESTAMP WITH TIME ZONE,
    last_error VARCHAR(128)
);

CREATE INDEX idx_identity_security_notifications_due
    ON identity_security_notifications(status, next_attempt_at, created_at);
