-- PostgreSQL schema (Supabase in production, PGlite locally).
-- Everything lives in the "dpp" schema, which Supabase does NOT expose through
-- its auto-generated REST API (only "public" is exposed by default). RLS is
-- also enabled without policies, so even if the schema were exposed by mistake
-- the anon/authenticated roles could read nothing. The server connects as the
-- table owner and is unaffected.
--
-- Timestamps are ISO-8601 text and passport data is text (not jsonb) on
-- purpose: values round-trip byte for byte, which keeps hashes, exports and the
-- client's field order stable across database drivers.

CREATE SCHEMA IF NOT EXISTS dpp;

CREATE TABLE IF NOT EXISTS dpp.tenants (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  vat_id     TEXT,
  status     TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dpp.api_keys (
  id         TEXT PRIMARY KEY,
  tenant_id  TEXT NOT NULL REFERENCES dpp.tenants(id),
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

-- rev increases on every change (new version, document added/removed) and is
-- the cache key for rendered public pages.
CREATE TABLE IF NOT EXISTS dpp.passports (
  id                 TEXT PRIMARY KEY,
  tenant_id          TEXT NOT NULL REFERENCES dpp.tenants(id),
  product_identifier TEXT NOT NULL,
  category           TEXT NOT NULL,
  current_version    INTEGER NOT NULL,
  rev                INTEGER NOT NULL DEFAULT 1,
  created_at         TEXT NOT NULL,
  updated_at         TEXT NOT NULL,
  UNIQUE (tenant_id, product_identifier)
);
CREATE INDEX IF NOT EXISTS passports_tenant ON dpp.passports (tenant_id, created_at, id);

CREATE TABLE IF NOT EXISTS dpp.passport_versions (
  passport_id TEXT NOT NULL REFERENCES dpp.passports(id),
  version     INTEGER NOT NULL,
  data        TEXT NOT NULL,
  data_hash   TEXT NOT NULL,
  note        TEXT,
  created_at  TEXT NOT NULL,
  created_by  TEXT NOT NULL,
  PRIMARY KEY (passport_id, version)
);

CREATE TABLE IF NOT EXISTS dpp.documents (
  id           TEXT PRIMARY KEY,
  passport_id  TEXT NOT NULL REFERENCES dpp.passports(id),
  name         TEXT NOT NULL,
  content_type TEXT NOT NULL,
  size         INTEGER NOT NULL,
  sha256       TEXT NOT NULL,
  access       TEXT NOT NULL CHECK (access IN ('public', 'legitimate_interest', 'authority')),
  created_at   TEXT NOT NULL,
  removed_at   TEXT
);
CREATE INDEX IF NOT EXISTS documents_passport ON dpp.documents (passport_id);

CREATE TABLE IF NOT EXISTS dpp.accessors (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  role       TEXT NOT NULL CHECK (role IN ('legitimate_interest', 'authority')),
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS dpp.sessions (
  id_hash     TEXT PRIMARY KEY,
  accessor_id TEXT NOT NULL REFERENCES dpp.accessors(id),
  expires_at  BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS dpp.audit_log (
  seq       INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ts        TEXT NOT NULL,
  actor     TEXT NOT NULL,
  action    TEXT NOT NULL,
  target    TEXT,
  details   TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash      TEXT NOT NULL
);

CREATE OR REPLACE FUNCTION dpp.reject_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '%', TG_ARGV[0];
END
$$;

DROP TRIGGER IF EXISTS audit_immutable ON dpp.audit_log;
CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE ON dpp.audit_log
  FOR EACH ROW EXECUTE FUNCTION dpp.reject_change('audit_log is append-only');
DROP TRIGGER IF EXISTS audit_no_truncate ON dpp.audit_log;
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON dpp.audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION dpp.reject_change('audit_log is append-only');

DROP TRIGGER IF EXISTS versions_immutable ON dpp.passport_versions;
CREATE TRIGGER versions_immutable BEFORE UPDATE OR DELETE ON dpp.passport_versions
  FOR EACH ROW EXECUTE FUNCTION dpp.reject_change('passport versions are immutable');
DROP TRIGGER IF EXISTS versions_no_truncate ON dpp.passport_versions;
CREATE TRIGGER versions_no_truncate BEFORE TRUNCATE ON dpp.passport_versions
  FOR EACH STATEMENT EXECUTE FUNCTION dpp.reject_change('passport versions are immutable');

ALTER TABLE dpp.tenants           ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpp.api_keys          ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpp.passports         ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpp.passport_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpp.documents         ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpp.accessors         ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpp.sessions          ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpp.audit_log         ENABLE ROW LEVEL SECURITY;
