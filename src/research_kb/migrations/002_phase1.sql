-- Phase 1 schema additions. 001_initial.sql is intentionally preserved.

ALTER TABLE verification_tokens ADD COLUMN project_id TEXT REFERENCES projects(project_id);
ALTER TABLE verification_tokens ADD COLUMN source_version TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE verified_evidence ADD COLUMN source_version TEXT NOT NULL DEFAULT 'unknown';

CREATE INDEX IF NOT EXISTS idx_verification_tokens_project
    ON verification_tokens(project_id, token_hash);

CREATE TRIGGER IF NOT EXISTS verification_token_binding_immutable
BEFORE UPDATE ON verification_tokens
WHEN NEW.token_id <> OLD.token_id
  OR NEW.token_hash <> OLD.token_hash
  OR NEW.passage_id <> OLD.passage_id
  OR NEW.document_hash <> OLD.document_hash
  OR NEW.quote_text <> OLD.quote_text
  OR NEW.quote_hash <> OLD.quote_hash
  OR NEW.issued_to <> OLD.issued_to
  OR NEW.expires_at <> OLD.expires_at
  OR COALESCE(NEW.project_id, '') <> COALESCE(OLD.project_id, '')
  OR COALESCE(NEW.source_version, '') <> COALESCE(OLD.source_version, '')
  OR NEW.created_at <> OLD.created_at
  OR OLD.consumed_at IS NOT NULL
  OR NEW.consumed_at IS NULL
BEGIN SELECT RAISE(ABORT, 'verification token binding is immutable'); END;

CREATE TRIGGER IF NOT EXISTS verification_token_no_delete
BEFORE DELETE ON verification_tokens
BEGIN SELECT RAISE(ABORT, 'verification tokens cannot be deleted'); END;

CREATE TABLE IF NOT EXISTS evidence_status_history (
    status_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    verified_evidence_id TEXT NOT NULL REFERENCES verified_evidence(verified_evidence_id),
    status TEXT NOT NULL CHECK(status IN ('candidate', 'accepted', 'rejected')),
    reason TEXT NOT NULL DEFAULT '',
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_status_latest
    ON evidence_status_history(verified_evidence_id, status_event_id DESC);

CREATE TABLE IF NOT EXISTS source_metadata_audit (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id TEXT NOT NULL REFERENCES documents(document_id),
    old_values_json TEXT NOT NULL,
    new_values_json TEXT NOT NULL,
    reason TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_source_metadata_audit_document
    ON source_metadata_audit(document_id, audit_id DESC);

CREATE TABLE IF NOT EXISTS approval_requests_v2 (
    request_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    target_type TEXT NOT NULL CHECK(target_type IN ('research_item', 'evidence')),
    item_id TEXT REFERENCES research_items(item_id),
    verified_evidence_id TEXT REFERENCES verified_evidence(verified_evidence_id),
    requested_by TEXT NOT NULL,
    requested_status TEXT NOT NULL CHECK(requested_status = 'accepted'),
    status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected')),
    rationale TEXT NOT NULL DEFAULT '',
    decided_by TEXT,
    decision_note TEXT,
    created_at TEXT NOT NULL,
    decided_at TEXT,
    CHECK(
        (target_type = 'research_item' AND item_id IS NOT NULL AND verified_evidence_id IS NULL)
        OR
        (target_type = 'evidence' AND item_id IS NULL AND verified_evidence_id IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_approval_v2_project_status
    ON approval_requests_v2(project_id, status, created_at);

CREATE INDEX IF NOT EXISTS idx_approval_v2_target
    ON approval_requests_v2(target_type, item_id, verified_evidence_id);

CREATE VIRTUAL TABLE IF NOT EXISTS passages_search_fts USING fts5(
    passage_id UNINDEXED,
    title,
    body,
    tokenize='unicode61 remove_diacritics 2'
);

CREATE TRIGGER IF NOT EXISTS evidence_status_no_update
BEFORE UPDATE ON evidence_status_history
BEGIN SELECT RAISE(ABORT, 'evidence status history is append-only'); END;

CREATE TRIGGER IF NOT EXISTS evidence_status_no_delete
BEFORE DELETE ON evidence_status_history
BEGIN SELECT RAISE(ABORT, 'evidence status history is append-only'); END;

CREATE TRIGGER IF NOT EXISTS evidence_status_transition
BEFORE INSERT ON evidence_status_history
WHEN EXISTS (
    SELECT 1 FROM evidence_status_history prior
    WHERE prior.verified_evidence_id = NEW.verified_evidence_id
      AND prior.status_event_id = (
          SELECT MAX(latest.status_event_id)
          FROM evidence_status_history latest
          WHERE latest.verified_evidence_id = NEW.verified_evidence_id
      )
      AND prior.status <> 'candidate'
)
BEGIN SELECT RAISE(ABORT, 'accepted or rejected evidence is immutable'); END;

CREATE TRIGGER IF NOT EXISTS source_metadata_audit_no_update
BEFORE UPDATE ON source_metadata_audit
BEGIN SELECT RAISE(ABORT, 'source metadata audit is append-only'); END;

CREATE TRIGGER IF NOT EXISTS source_metadata_audit_no_delete
BEFORE DELETE ON source_metadata_audit
BEGIN SELECT RAISE(ABORT, 'source metadata audit is append-only'); END;

CREATE TRIGGER IF NOT EXISTS approval_v2_target_exists
BEFORE INSERT ON approval_requests_v2
WHEN NOT (
    (NEW.target_type = 'research_item' AND EXISTS (
        SELECT 1 FROM research_items
        WHERE item_id = NEW.item_id AND project_id = NEW.project_id
    ))
    OR
    (NEW.target_type = 'evidence' AND EXISTS (
        SELECT 1
        FROM verified_evidence ve
        JOIN project_sources ps ON ps.document_id = ve.document_id
        WHERE ve.verified_evidence_id = NEW.verified_evidence_id
          AND ps.project_id = NEW.project_id
    ))
)
BEGIN SELECT RAISE(ABORT, 'approval target is missing or outside project'); END;

CREATE TRIGGER IF NOT EXISTS approval_v2_target_immutable
BEFORE UPDATE ON approval_requests_v2
WHEN OLD.target_type <> NEW.target_type
  OR OLD.project_id <> NEW.project_id
  OR COALESCE(OLD.item_id, '') <> COALESCE(NEW.item_id, '')
  OR COALESCE(OLD.verified_evidence_id, '') <> COALESCE(NEW.verified_evidence_id, '')
BEGIN SELECT RAISE(ABORT, 'approval target is immutable'); END;

CREATE TRIGGER IF NOT EXISTS approval_v2_status_transition
BEFORE UPDATE OF status ON approval_requests_v2
WHEN OLD.status <> 'pending'
  OR NEW.status NOT IN ('approved', 'rejected')
BEGIN SELECT RAISE(ABORT, 'approval status transition is invalid'); END;

CREATE TRIGGER IF NOT EXISTS approval_v2_no_delete
BEFORE DELETE ON approval_requests_v2
BEGIN SELECT RAISE(ABORT, 'approval requests are append-only'); END;

INSERT INTO evidence_status_history(
    verified_evidence_id, status, reason, actor_id, actor_kind, created_at
)
SELECT ve.verified_evidence_id, 'candidate', 'migration bootstrap', 'migration', 'system', datetime('now')
FROM verified_evidence ve
WHERE NOT EXISTS (
    SELECT 1 FROM evidence_status_history esh
    WHERE esh.verified_evidence_id = ve.verified_evidence_id
);

INSERT INTO approval_requests_v2(
    request_id, project_id, target_type, item_id, verified_evidence_id,
    requested_by, requested_status, status, rationale, decided_by,
    decision_note, created_at, decided_at
)
SELECT ar.request_id, ri.project_id, 'research_item', ar.item_id, NULL,
       ar.requested_by, ar.requested_status, ar.status, COALESCE(ar.rationale, ''),
       ar.decided_by, ar.decision_note, ar.created_at, ar.decided_at
FROM approval_requests ar
JOIN research_items ri ON ri.item_id = ar.item_id
WHERE NOT EXISTS (
    SELECT 1 FROM approval_requests_v2 v2 WHERE v2.request_id = ar.request_id
);