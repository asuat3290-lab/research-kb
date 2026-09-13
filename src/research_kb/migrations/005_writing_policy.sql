-- Phase 5 writing policy and delivery metadata. 001_initial.sql through 004_phase0.sql remain unchanged.
-- All new columns are additive and nullable so legacy manifest rows keep their meaning.

ALTER TABLE report_manifest ADD COLUMN deliverable_layer TEXT;
ALTER TABLE report_manifest ADD COLUMN artifact_profile TEXT;
ALTER TABLE report_manifest ADD COLUMN writing_policy_id TEXT;
ALTER TABLE report_manifest ADD COLUMN writing_policy_version TEXT;
ALTER TABLE report_manifest ADD COLUMN writing_policy_snapshot_json TEXT;
ALTER TABLE report_manifest ADD COLUMN compression_review_status TEXT;
ALTER TABLE report_manifest ADD COLUMN writing_audit_summary_json TEXT;
