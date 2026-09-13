-- Phase 0 report manifest base design. 001_initial.sql through 003_phase3.sql remain unchanged.

CREATE TABLE IF NOT EXISTS report_manifest (
    report_manifest_id TEXT PRIMARY KEY,
    report_version_id TEXT NOT NULL REFERENCES research_item_versions(version_id),
    protocol_project_id TEXT NOT NULL REFERENCES projects(project_id),
    claim_revision_ids_json TEXT NOT NULL,
    evidence_revision_ids_json TEXT NOT NULL,
    passage_revision_ids_json TEXT NOT NULL,
    verification_event_ids_json TEXT NOT NULL,
    approval_event_ids_json TEXT NOT NULL,
    source_snapshot_ids_json TEXT NOT NULL,
    constraint_revision_id TEXT,
    research_project_id TEXT,
    project_export_ids_json TEXT NOT NULL,
    cross_project_link_ids_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_report_manifest_version
    ON report_manifest(report_version_id);

CREATE TRIGGER IF NOT EXISTS report_manifest_no_update
BEFORE UPDATE ON report_manifest
BEGIN SELECT RAISE(ABORT, 'report manifest is append-only'); END;

CREATE TRIGGER IF NOT EXISTS report_manifest_no_delete
BEFORE DELETE ON report_manifest
BEGIN SELECT RAISE(ABORT, 'report manifest is append-only'); END;

CREATE TRIGGER IF NOT EXISTS report_manifest_target_exists
BEFORE INSERT ON report_manifest
WHEN NOT EXISTS (
    SELECT 1
    FROM research_item_versions riv
    JOIN research_items ri ON ri.item_id = riv.item_id
    WHERE riv.version_id = NEW.report_version_id
      AND ri.kind = 'report'
      AND ri.project_id = NEW.protocol_project_id
)
BEGIN SELECT RAISE(ABORT, 'report manifest target is missing or outside project'); END;
