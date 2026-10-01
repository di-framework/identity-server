CREATE TABLE identity_links (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issuer VARCHAR(512) NOT NULL,
    subject VARCHAR(512) NOT NULL,
    provider_name VARCHAR(128) NOT NULL,
    provider_email VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_identity_links_issuer_subject UNIQUE (issuer, subject)
);

CREATE INDEX idx_identity_links_user_id ON identity_links(user_id);
