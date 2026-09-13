from __future__ import annotations

import argparse
import copy
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .writing_policy import policy_fingerprint


SUPPORTED_LAYERS = ("A", "B", "C")
PROFILE_BY_LAYER = {
    "A": "academic_paper",
    "B": "method_appendix",
    "C": "technical_report",
}
BUCKETS = ("errors", "warnings", "review_items", "approval_blockers")
MANIFEST_VERSION = "2.0"
SUPPORTED_PACKAGE_STATES = ("REVIEW", "PENDING", "APPROVED", "ARCHIVED")

MANIFEST_SPEC_ANCHORS = {
    "manifest-delivery-package-v2": "docs/manifest-format.md",
    "manifest-v2-field-created_at": "docs/manifest-format.md",
    "manifest-v2-field-artifact_audit": "docs/manifest-format.md",
}


def compute_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _clean_counts(value: Any, label: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{label} must be an object"]
    allowed = {"errors", "warnings", "review_items", "approval_blockers"}
    problems: list[str] = []
    unknown = set(value) - allowed
    if unknown:
        problems.append(f"{label} contains unknown keys: {', '.join(sorted(unknown))}")
    for key in ("errors", "warnings", "review_items", "approval_blockers"):
        raw = value.get(key, 0)
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
            problems.append(f"{label}.{key} must be a non-negative integer")
    return problems


def manifest_info(manifest: dict[str, Any]) -> dict[str, Any]:
    version = manifest.get("manifest_version")
    legacy = version is None or str(version) != MANIFEST_VERSION
    return {
        "manifest_version": version if isinstance(version, str) and version else None,
        "legacy": legacy,
        "migration_recommended": legacy,
    }


def upgrade_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be a JSON object")
    upgraded = json.loads(json.dumps(manifest))
    upgraded.setdefault("manifest_version", MANIFEST_VERSION)
    upgraded.setdefault("package_state", "REVIEW")
    if not isinstance(upgraded.get("writing_policy_audit"), dict):
        counts = {
            "errors": 0,
            "warnings": 0,
            "review_items": 0,
            "approval_blockers": 0,
        }
        legacy_counts = upgraded.get("writing_audit_summary")
        if isinstance(legacy_counts, dict):
            for key in counts:
                value = legacy_counts.get(key, 0)
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    counts[key] = value
        upgraded["writing_policy_audit"] = counts
    upgraded.setdefault("artifact_audit", copy.deepcopy(upgraded["writing_policy_audit"]))
    upgraded.setdefault("created_at", "")
    upgraded.setdefault("research_approval", None)
    upgraded.setdefault("final_approval", "pending")
    upgraded.setdefault("supporting_artifacts", [])
    upgraded.setdefault("policy_snapshot_sha256", "")
    return upgraded


def _problems_for_artifact(
    artifact: dict[str, Any],
    base_dir: Path,
    manifest: dict[str, Any],
    audit_summary: dict[str, Any] | None = None,
    summary_label: str = "writing_audit_summary",
) -> tuple[bool, list[str]]:
    problems: list[str] = []
    name = artifact.get("file")
    if not isinstance(name, str) or not name:
        return False, ["artifact requires a non-empty file name"]
    for key in ("deliverable_layer", "artifact_profile", "audit_report", "sha256", "audit_sha256"):
        if not isinstance(artifact.get(key), str) or not artifact[key]:
            return False, [f"artifact {name!r} requires {key}"]
    layer = artifact["deliverable_layer"]
    profile = artifact["artifact_profile"]
    if layer not in SUPPORTED_LAYERS:
        return False, [f"artifact {name!r} has unsupported deliverable_layer {layer!r}"]
    if PROFILE_BY_LAYER[layer] != profile:
        return False, [f"artifact {name!r} profile {profile!r} does not match layer {layer!r}"]

    file_path = base_dir / name
    if not file_path.is_file():
        return False, [f"artifact file is missing: {name}"]
    actual = compute_sha256(file_path)
    if actual != artifact["sha256"]:
        problems.append(f"artifact sha256 mismatch for {name}: manifest {artifact['sha256']} != computed {actual}")

    audit_path = base_dir / artifact["audit_report"]
    if not audit_path.is_file():
        return False, problems + [f"audit report is missing: {artifact['audit_report']}"]
    actual_audit = compute_sha256(audit_path)
    if actual_audit != artifact["audit_sha256"]:
        problems.append(
            f"audit sha256 mismatch for {artifact['audit_report']}: manifest {artifact['audit_sha256']} != computed {actual_audit}"
        )
    try:
        audit = json.loads(audit_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return False, problems + [f"audit report is not valid JSON: {artifact['audit_report']}"]
    if not isinstance(audit, dict):
        return False, problems + [f"audit report must be a JSON object: {artifact['audit_report']}"]
    if audit.get("profile") != profile:
        problems.append(
            f"audit profile {audit.get('profile')!r} does not match artifact profile {profile!r}"
        )
    if audit.get("policy_version") != manifest.get("policy_version"):
        problems.append(
            f"audit policy_version {audit.get('policy_version')!r} does not match manifest policy_version {manifest.get('policy_version')!r}"
        )
    for bucket in BUCKETS:
        items = audit.get(bucket)
        if not isinstance(items, list):
            problems.append(f"audit {bucket} must be a list")
            continue
        for finding in items:
            if not isinstance(finding, dict) or not isinstance(finding.get("rule_id"), str):
                problems.append(f"audit {bucket} contains a finding without rule_id")
                break
    source_path = audit.get("source_path")
    if source_path and Path(str(source_path)).name != Path(name).name:
        problems.append(
            f"audit source_path {source_path!r} does not match artifact file {name!r}"
        )
    snapshot = audit.get("policy_snapshot")
    if isinstance(snapshot, dict):
        if snapshot.get("profile") != profile:
            problems.append("audit policy_snapshot profile does not match artifact profile")
        if snapshot.get("policy_version") != manifest.get("policy_version"):
            problems.append("audit policy_snapshot version does not match manifest policy_version")
        fingerprint = audit.get("policy_fingerprint")
        if fingerprint and fingerprint != policy_fingerprint(snapshot):
            problems.append("audit policy_fingerprint does not match policy_snapshot")
    summary = audit_summary if isinstance(audit_summary, dict) else manifest.get("writing_audit_summary")
    if layer != "A":
        summary = None
    if isinstance(summary, dict):
        for bucket in BUCKETS:
            expected = summary.get(bucket)
            if expected is None:
                continue
            if not isinstance(expected, int) or isinstance(expected, bool) or expected < 0:
                problems.append(f"{summary_label}.{bucket} must be a non-negative integer")
                continue
            if expected != len(audit.get(bucket) or []):
                problems.append(
                    f"{summary_label}.{bucket} {expected} != audit count {len(audit.get(bucket) or [])}"
                )
    return (not problems), problems


def validate_delivery_manifest(
    manifest: dict[str, Any], base_dir: str | Path | None = None
) -> dict[str, Any]:
    problems: list[str] = []
    if not isinstance(manifest, dict):
        return {
            "valid": False,
            "problems": ["manifest must be a JSON object"],
            "artifacts": [],
            "manifest_version": None,
            "legacy": True,
            "migration_recommended": True,
        }
    info = manifest_info(manifest)
    if info["manifest_version"] is not None and info["manifest_version"] != MANIFEST_VERSION:
        problems.append(
            f"unsupported manifest_version {info['manifest_version']!r}; expected {MANIFEST_VERSION}"
        )
    created_at = manifest.get("created_at")
    if info["manifest_version"] == MANIFEST_VERSION:
        if not isinstance(created_at, str) or not created_at.strip():
            problems.append("v2 manifest requires created_at")
        else:
            try:
                datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            except ValueError:
                problems.append("created_at must be an ISO-8601 timestamp")
    for key in ("delivery_package_id", "policy_id", "policy_version"):
        if not isinstance(manifest.get(key), str) or not manifest[key]:
            problems.append(f"manifest requires {key}")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        problems.append("manifest requires a non-empty artifacts list")
    base = Path(base_dir) if base_dir is not None else Path.cwd()
    audit_summary = manifest.get("artifact_audit")
    if audit_summary is not None:
        problems.extend(_clean_counts(audit_summary, "artifact_audit"))
        summary_label = "artifact_audit"
    else:
        audit_summary = manifest.get("writing_policy_audit")
        if audit_summary is not None:
            problems.extend(_clean_counts(audit_summary, "writing_policy_audit"))
            summary_label = "writing_policy_audit"
        else:
            audit_summary = manifest.get("writing_audit_summary")
            summary_label = "writing_audit_summary"
    package_state = manifest.get("package_state")
    if package_state is not None:
        if not isinstance(package_state, str) or not package_state.strip():
            problems.append("package_state must be a non-empty string")
        elif (
            info["manifest_version"] == MANIFEST_VERSION
            and package_state not in SUPPORTED_PACKAGE_STATES
        ):
            problems.append(f"unsupported package_state {package_state!r}")
    research = manifest.get("research_approval")
    if research is not None:
        if not isinstance(research, dict):
            problems.append("research_approval must be an object")
        else:
            for key in ("review_items", "approval_blockers"):
                value = research.get(key, 0)
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    problems.append(
                        f"research_approval.{key} must be a non-negative integer"
                    )
    final_approval = manifest.get("final_approval")
    if final_approval is not None and (
        not isinstance(final_approval, str) or not final_approval.strip()
    ):
        problems.append("final_approval must be a non-empty string")
    supporting = manifest.get("supporting_artifacts")
    if supporting is not None:
        if not isinstance(supporting, list):
            problems.append("supporting_artifacts must be a list")
        elif not supporting and info["manifest_version"] == MANIFEST_VERSION:
            problems.append("v2 manifest requires supporting_artifacts")
        else:
            for item in supporting:
                if not isinstance(item, dict):
                    problems.append("supporting_artifacts entries must be objects")
                    continue
                for key in ("file", "type", "sha256"):
                    if not isinstance(item.get(key), str) or not item[key]:
                        problems.append(f"supporting_artifacts entry requires {key}")
                file_name = item.get("file")
                if isinstance(file_name, str) and file_name:
                    path = base / file_name
                    if not path.is_file():
                        problems.append(f"supporting artifact file is missing: {file_name}")
                    else:
                        actual = compute_sha256(path)
                        if actual != item.get("sha256"):
                            problems.append(
                                f"supporting artifact sha256 mismatch for {file_name}"
                            )
    fingerprint = manifest.get("policy_snapshot_sha256")
    if fingerprint:
        if not isinstance(fingerprint, str) or not fingerprint.startswith("sha256:"):
            problems.append("policy_snapshot_sha256 must be a sha256: prefixed string")
        else:
            a_audit = next(
                (
                    artifact
                    for artifact in artifacts
                    if isinstance(artifact, dict)
                    and artifact.get("deliverable_layer") == "A"
                ),
                None,
            )
            if a_audit:
                audit_name = a_audit.get("audit_report")
                if isinstance(audit_name, str) and audit_name:
                    try:
                        audit = json.loads(
                            (base / audit_name).read_text(encoding="utf-8")
                        )
                        audit_fingerprint = (
                            audit.get("policy_fingerprint")
                            if isinstance(audit, dict)
                            else None
                        )
                        if audit_fingerprint and audit_fingerprint != fingerprint:
                            problems.append(
                                "policy_snapshot_sha256 does not match the A-layer audit policy_fingerprint"
                            )
                    except (OSError, UnicodeError, json.JSONDecodeError):
                        pass
    artifact_results: list[dict[str, Any]] = []
    for artifact in artifacts if isinstance(artifacts, list) else []:
        if not isinstance(artifact, dict):
            artifact_results.append(
                {
                    "file": None,
                    "valid": False,
                    "problems": ["artifact must be an object"],
                }
            )
            continue
        valid, artifact_problems = _problems_for_artifact(
            artifact, base, manifest, audit_summary, summary_label
        )
        artifact_results.append(
            {"file": artifact.get("file"), "valid": valid, "problems": artifact_problems}
        )
        problems.extend(artifact_results[-1]["problems"])
    valid = not problems and all(item["valid"] for item in artifact_results)
    return {
        "valid": valid,
        "problems": problems,
        "artifacts": artifact_results,
        **info,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a research-kb delivery package manifest")
    parser.add_argument("manifest", help="path to manifest.json")
    parser.add_argument("--base-dir", default=None, help="directory containing artifacts (defaults to manifest directory)")
    args = parser.parse_args(argv)
    manifest_path = Path(args.manifest)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(json.dumps({"valid": False, "problems": [f"cannot read manifest: {exc}"], "artifacts": []}, ensure_ascii=False, indent=2))
        return 1
    base_dir = Path(args.base_dir) if args.base_dir else manifest_path.parent
    result = validate_delivery_manifest(manifest, base_dir=base_dir)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
