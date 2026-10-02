CREATE TABLE users (
  id uuid PRIMARY KEY,
  login varchar(128) NOT NULL UNIQUE,
  normalized_login varchar(128) NOT NULL UNIQUE,
  email varchar(254) UNIQUE,
  normalized_email varchar(254) UNIQUE,
  password_hash varchar(255),
  display_name varchar(255) NOT NULL,
  avatar_url text,
  email_verified boolean NOT NULL DEFAULT false,
  status varchar(16) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','archived')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE organizations (
  id uuid PRIMARY KEY,
  slug varchar(128) NOT NULL UNIQUE,
  name varchar(255) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE organization_memberships (
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  role varchar(16) NOT NULL CHECK (role IN ('member','owner')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,user_id)
);
CREATE TABLE email_challenges (
  id uuid PRIMARY KEY,
  user_id uuid REFERENCES users(id) ON DELETE CASCADE,
  email varchar(254) NOT NULL,
  token_hash char(64) NOT NULL UNIQUE,
  purpose varchar(32) NOT NULL CHECK (purpose IN ('sign_in','activation','invite')),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  request_ip_hash char(64),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX email_challenges_rate_limit_idx ON email_challenges (email, purpose, created_at DESC);
CREATE TABLE auth_audit_records (
  id uuid PRIMARY KEY,
  action varchar(128) NOT NULL,
  actor_client_id varchar(255),
  target varchar(255),
  correlation_id varchar(512),
  before_metadata jsonb NOT NULL DEFAULT '{}',
  after_metadata jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);
