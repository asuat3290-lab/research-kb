PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
    project_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    objective TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active', 'archived')),
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS documents (
    document_id TEXT PRIMARY KEY,
    content_hash TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    creator TEXT,
    source_type TEXT NOT NULL,
    language TEXT NOT NULL DEFAULT 'unknown',
    source_date TEXT,
    source_version TEXT,
    source_name TEXT NOT NULL,
    source_uri TEXT NOT NULL,
    reliability_status TEXT NOT NULL CHECK(reliability_status IN
        ('unknown', 'unverified', 'reviewed', 'authoritative')),
    verification_status TEXT NOT NULL CHECK(verification_status IN
        ('unverified', 'partially_verified', 'verified')),
    ingestion_method TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS passages (
    passage_id TEXT PRIMARY KEY,
    document_id TEXT NOT NULL REFERENCES documents(document_id),
    ordinal INTEGER NOT NULL,
    location_json TEXT NOT NULL,
    text TEXT NOT NULL,
    text_hash TEXT NOT NULL,
    char_start INTEGER NOT NULL,
    char_end INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(document_id, ordinal)
);

CREATE VIRTUAL TABLE IF NOT EXISTS passages_fts USING fts5(
    passage_id UNINDEXED,
    title,
    body,
    tokenize='unicode61 remove_diacritics 2'
);

CREATE TRIGGER IF NOT EXISTS passages_fts_insert
AFTER INSERT ON passages BEGIN
    INSERT INTO passages_fts(passage_id, title, body)
    SELECT NEW.passage_id, d.title, NEW.text
    FROM documents d WHERE d.document_id = NEW.document_id;
END;

CREATE TABLE IF NOT EXISTS project_sources (
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    document_id TEXT NOT NULL REFERENCES documents(document_id),
    added_at TEXT NOT NULL,
    PRIMARY KEY(project_id, document_id)
);

CREATE TABLE IF NOT EXISTS research_items (
    item_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    kind TEXT NOT NULL CHECK(kind IN ('note', 'hypothesis', 'objection', 'report')),
    status TEXT NOT NULL CHECK(status IN
        ('draft', 'candidate', 'under_review', 'accepted', 'rejected', 'archived')),
    created_by TEXT NOT NULL,
    supersedes_item_id TEXT REFERENCES research_items(item_id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS research_item_versions (
    version_id TEXT PRIMARY KEY,
    item_id TEXT NOT NULL REFERENCES research_items(item_id),
    version_no INTEGER NOT NULL,
    payload_json TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(item_id, version_no)
);

CREATE TABLE IF NOT EXISTS verification_tokens (
    token_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    passage_id TEXT NOT NULL REFERENCES passages(passage_id),
    document_hash TEXT NOT NULL,
    quote_text TEXT NOT NULL,
    quote_hash TEXT NOT NULL,
    issued_to TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS verified_evidence (
    verified_evidence_id TEXT PRIMARY KEY,
    passage_id TEXT NOT NULL REFERENCES passages(passage_id),
    document_id TEXT NOT NULL REFERENCES documents(document_id),
    document_hash TEXT NOT NULL,
    quote_text TEXT NOT NULL,
    quote_hash TEXT NOT NULL,
    location_json TEXT NOT NULL,
    verified_by TEXT NOT NULL,
    verified_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_links (
    link_id TEXT PRIMARY KEY,
    version_id TEXT NOT NULL REFERENCES research_item_versions(version_id),
    relation TEXT NOT NULL CHECK(relation IN ('supports', 'counters', 'context')),
    passage_id TEXT REFERENCES passages(passage_id),
    verified_evidence_id TEXT REFERENCES verified_evidence(verified_evidence_id),
    created_at TEXT NOT NULL,
    CHECK((passage_id IS NOT NULL) <> (verified_evidence_id IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS approval_requests (
    request_id TEXT PRIMARY KEY,
    item_id TEXT NOT NULL REFERENCES research_items(item_id),
    requested_by TEXT NOT NULL,
    requested_status TEXT NOT NULL CHECK(requested_status = 'accepted'),
    status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected')),
    rationale TEXT,
    decided_by TEXT,
    decision_note TEXT,
    created_at TEXT NOT NULL,
    decided_at TEXT
);

CREATE TABLE IF NOT EXISTS agent_sessions (
    session_id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL,
    framework TEXT NOT NULL,
    model TEXT,
    project_id TEXT REFERENCES projects(project_id),
    started_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS search_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    query_text TEXT NOT NULL,
    query_hash TEXT NOT NULL,
    parameters_json TEXT NOT NULL,
    result_ids_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    session_id TEXT NOT NULL,
    project_id TEXT,
    operation TEXT NOT NULL,
    parameters_json TEXT NOT NULL,
    result_json TEXT NOT NULL,
    success INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_passages_document ON passages(document_id, ordinal);
CREATE INDEX IF NOT EXISTS idx_project_sources_document ON project_sources(document_id);
CREATE INDEX IF NOT EXISTS idx_items_project_status ON research_items(project_id, status, kind);
CREATE INDEX IF NOT EXISTS idx_versions_item ON research_item_versions(item_id, version_no DESC);
CREATE INDEX IF NOT EXISTS idx_search_session ON search_events(session_id, event_id DESC);
CREATE INDEX IF NOT EXISTS idx_approval_status ON approval_requests(status, created_at);

CREATE TRIGGER IF NOT EXISTS documents_identity_immutable
BEFORE UPDATE ON documents
WHEN NEW.document_id <> OLD.document_id
  OR NEW.content_hash <> OLD.content_hash
  OR NEW.source_uri <> OLD.source_uri
  OR NEW.ingestion_method <> OLD.ingestion_method
  OR NEW.created_at <> OLD.created_at
BEGIN SELECT RAISE(ABORT, 'document identity and source content are immutable'); END;
CREATE TRIGGER IF NOT EXISTS documents_no_delete
BEFORE DELETE ON documents BEGIN SELECT RAISE(ABORT, 'documents are immutable'); END;
CREATE TRIGGER IF NOT EXISTS passages_no_update
BEFORE UPDATE ON passages BEGIN SELECT RAISE(ABORT, 'passages are immutable'); END;
CREATE TRIGGER IF NOT EXISTS passages_no_delete
BEFORE DELETE ON passages BEGIN SELECT RAISE(ABORT, 'passages are immutable'); END;
CREATE TRIGGER IF NOT EXISTS item_versions_no_update
BEFORE UPDATE ON research_item_versions BEGIN SELECT RAISE(ABORT, 'item versions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS item_versions_no_delete
BEFORE DELETE ON research_item_versions BEGIN SELECT RAISE(ABORT, 'item versions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS evidence_links_no_update
BEFORE UPDATE ON evidence_links BEGIN SELECT RAISE(ABORT, 'evidence links are append-only'); END;
CREATE TRIGGER IF NOT EXISTS evidence_links_no_delete
BEFORE DELETE ON evidence_links BEGIN SELECT RAISE(ABORT, 'evidence links are append-only'); END;
CREATE TRIGGER IF NOT EXISTS verified_evidence_no_update
BEFORE UPDATE ON verified_evidence BEGIN SELECT RAISE(ABORT, 'verified evidence is immutable'); END;
CREATE TRIGGER IF NOT EXISTS verified_evidence_no_delete
BEFORE DELETE ON verified_evidence BEGIN SELECT RAISE(ABORT, 'verified evidence is immutable'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_update
BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete
BEFORE DELETE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS accepted_item_no_update
BEFORE UPDATE ON research_items WHEN OLD.status = 'accepted'
BEGIN SELECT RAISE(ABORT, 'accepted items are immutable; create a superseding item'); END;
CREATE TRIGGER IF NOT EXISTS items_no_delete
BEFORE DELETE ON research_items BEGIN SELECT RAISE(ABORT, 'research items cannot be deleted'); END;

