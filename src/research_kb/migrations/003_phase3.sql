-- Phase 3 state-machine invariants. 001_initial.sql and 002_phase1.sql remain unchanged.

ALTER TABLE verification_tokens ADD COLUMN issued_session_id TEXT NOT NULL DEFAULT 'legacy';
CREATE INDEX IF NOT EXISTS idx_verification_tokens_session
    ON verification_tokens(issued_session_id, token_hash);

-- Tokens created before session binding cannot be safely resumed after migration.
UPDATE verification_tokens
SET consumed_at = COALESCE(consumed_at, expires_at)
WHERE issued_session_id = 'legacy' AND consumed_at IS NULL;

CREATE TRIGGER IF NOT EXISTS research_item_status_transition
BEFORE UPDATE OF status ON research_items
WHEN NOT (
    (OLD.status = NEW.status)
    OR (OLD.status = 'draft' AND NEW.status = 'candidate')
    OR (OLD.status = 'candidate' AND NEW.status = 'under_review')
    OR (OLD.status = 'under_review' AND NEW.status IN ('accepted', 'rejected'))
)
BEGIN SELECT RAISE(ABORT, 'research item status transition is invalid'); END;

CREATE TRIGGER IF NOT EXISTS evidence_status_transition_strict
BEFORE INSERT ON evidence_status_history
WHEN EXISTS (
    SELECT 1 FROM evidence_status_history prior
    WHERE prior.verified_evidence_id = NEW.verified_evidence_id
)
AND NEW.status = 'candidate'
BEGIN SELECT RAISE(ABORT, 'evidence candidate status is already recorded'); END;


CREATE TRIGGER IF NOT EXISTS verification_token_session_immutable
BEFORE UPDATE ON verification_tokens
WHEN NEW.issued_session_id <> OLD.issued_session_id
BEGIN SELECT RAISE(ABORT, 'verification token session binding is immutable'); END;
