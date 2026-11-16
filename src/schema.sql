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

-- Battery models: data shared by every battery of a model (most of Annex XIII)
-- is stored once here. A passport's effective data = model data overlaid with
-- the battery's own (item-level) data.
CREATE TABLE IF NOT EXISTS dpp.models (
  id              TEXT PRIMARY KEY,
  tenant_id       TEXT NOT NULL REFERENCES dpp.tenants(id),
  name            TEXT NOT NULL,
  category        TEXT NOT NULL,
  current_version INTEGER NOT NULL,
  rev             INTEGER NOT NULL DEFAULT 1,
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL,
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS dpp.model_versions (
  model_id   TEXT NOT NULL REFERENCES dpp.models(id),
  version    INTEGER NOT NULL,
  data       TEXT NOT NULL,
  data_hash  TEXT NOT NULL,
  note       TEXT,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  PRIMARY KEY (model_id, version)
);

ALTER TABLE dpp.passports ADD COLUMN IF NOT EXISTS model_id TEXT REFERENCES dpp.models(id);
CREATE INDEX IF NOT EXISTS passports_model ON dpp.passports (model_id, created_at, id);

-- A document belongs either to one passport or to a model (then it is shown on
-- every passport of that model and stored only once).
ALTER TABLE dpp.documents ADD COLUMN IF NOT EXISTS model_id TEXT REFERENCES dpp.models(id);
ALTER TABLE dpp.documents ALTER COLUMN passport_id DROP NOT NULL;
CREATE INDEX IF NOT EXISTS documents_model ON dpp.documents (model_id);
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'documents_owner') THEN
    ALTER TABLE dpp.documents ADD CONSTRAINT documents_owner CHECK ((passport_id IS NULL) <> (model_id IS NULL));
  END IF;
END
$$;

-- Client portal users (people working for a tenant).
CREATE TABLE IF NOT EXISTS dpp.users (
  id               TEXT PRIMARY KEY,
  tenant_id        TEXT NOT NULL REFERENCES dpp.tenants(id),
  email            TEXT NOT NULL UNIQUE,
  password_hash    TEXT,
  setup_token_hash TEXT UNIQUE,
  setup_expires_at BIGINT,
  created_at       TEXT NOT NULL,
  disabled_at      TEXT
);

CREATE TABLE IF NOT EXISTS dpp.portal_sessions (
  id_hash    TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES dpp.users(id),
  expires_at BIGINT NOT NULL
);

-- Externally hosted passports (e.g. by a non-EU manufacturer). The QR code
-- points to this platform (a domain the importer controls); visitors are
-- redirected to the external host while it works, and served the archived EU
-- mirror copy when it does not.
ALTER TABLE dpp.passports ADD COLUMN IF NOT EXISTS external_url TEXT;
ALTER TABLE dpp.passports ADD COLUMN IF NOT EXISTS mirror_status TEXT;         -- NULL (never checked) | 'ok' | 'down'
ALTER TABLE dpp.passports ADD COLUMN IF NOT EXISTS mirror_checked_at TEXT;
ALTER TABLE dpp.passports ADD COLUMN IF NOT EXISTS mirror_sha256 TEXT;         -- last good copy (blob)
ALTER TABLE dpp.passports ADD COLUMN IF NOT EXISTS mirror_content_type TEXT;
ALTER TABLE dpp.passports ADD COLUMN IF NOT EXISTS mirror_fetched_at TEXT;     -- when the last good copy was taken
ALTER TABLE dpp.passports ADD COLUMN IF NOT EXISTS mirror_error TEXT;
CREATE INDEX IF NOT EXISTS passports_mirror_due ON dpp.passports (mirror_checked_at) WHERE external_url IS NOT NULL;

-- Log of mirror events: only status changes and content changes are recorded.
CREATE TABLE IF NOT EXISTS dpp.mirror_events (
  id           TEXT PRIMARY KEY,
  passport_id  TEXT NOT NULL REFERENCES dpp.passports(id),
  at           TEXT NOT NULL,
  status       TEXT NOT NULL,
  http_status  INTEGER,
  sha256       TEXT,
  content_type TEXT,
  size         INTEGER,
  error        TEXT
);
CREATE INDEX IF NOT EXISTS mirror_events_passport ON dpp.mirror_events (passport_id, at DESC);

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

DROP TRIGGER IF EXISTS model_versions_immutable ON dpp.model_versions;
CREATE TRIGGER model_versions_immutable BEFORE UPDATE OR DELETE ON dpp.model_versions
  FOR EACH ROW EXECUTE FUNCTION dpp.reject_change('model versions are immutable');

ALTER TABLE dpp.mirror_events     ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpp.models            ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpp.model_versions    ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpp.users             ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpp.portal_sessions   ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpp.tenants           ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpp.api_keys          ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpp.passports         ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpp.passport_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpp.documents         ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpp.accessors         ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpp.sessions          ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpp.audit_log         ENABLE ROW LEVEL SECURITY;
