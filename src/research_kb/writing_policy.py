from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .policy import PolicyError
from ._resources import PackagedResourceError, read_json_resource


DEFAULT_POLICY_RESOURCE = "writing_policy.json"
DEFAULT_POLICY_SCHEMA_RESOURCE = "writing_policy.schema.json"

SUPPORTED_LAYERS = ("A", "B", "C")
KNOWN_PROFILES = (
    "academic_paper",
    "method_appendix",
    "technical_report",
    "research_memo",
)
COMPRESSION_REVIEW_STATUSES = ("not_required", "pending", "passed", "returned")
LINE_ENDINGS = ("lf", "crlf")
LINE_ENDING_SEVERITIES = ("error", "warning", "off")

_PROFILE_BY_LAYER = {
    "A": "academic_paper",
    "B": "method_appendix",
    "C": "technical_report",
}

_RULE_KINDS = {
    "forbidden_term",
    "regex",
    "budget",
    "section_numbering",
    "argument_gain",
    "required_section",
    "required_section_content",
    "footnote_integrity",
    "bibliography",
    "citation_surface",
    "compression_duplicate",
    "compression_limit_echo",
    "bibliography_completeness",
}
_SEVERITIES = {"error", "warning", "review"}
_ENFORCEMENTS = {"system", "agent_local"}
_IGNORE_NAMES = {
    "code_blocks",
    "inline_code",
    "html_comments",
    "front_matter",
    "references",
    "footnotes",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_writing_policy(path: str | Path | None = None) -> dict[str, Any]:
    if path is None:
        try:
            raw = read_json_resource(DEFAULT_POLICY_RESOURCE)
        except PackagedResourceError as exc:
            raise PolicyError("writing policy resource is unavailable") from exc
    else:
        selected = Path(path)
        try:
            raw = json.loads(selected.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PolicyError("writing policy file is invalid") from exc
    if not isinstance(raw, dict):
        raise PolicyError("writing policy must be a JSON object")
    validate_policy(raw)
    return raw


def load_policy_schema(path: str | Path | None = None) -> dict[str, Any]:
    if path is None:
        try:
            raw = read_json_resource(DEFAULT_POLICY_SCHEMA_RESOURCE)
        except PackagedResourceError as exc:
            raise PolicyError("writing policy schema resource is unavailable") from exc
    else:
        selected = Path(path)
        try:
            raw = json.loads(selected.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PolicyError("writing policy schema is invalid") from exc
    if not isinstance(raw, dict):
        raise PolicyError("writing policy schema must be a JSON object")
    return raw


def profile_by_layer(layer: str | None) -> str | None:
    return _PROFILE_BY_LAYER.get(layer)


def validate_policy(policy: dict[str, Any]) -> None:
    if not isinstance(policy, dict):
        raise PolicyError("writing policy must be a JSON object")
    policy_id = policy.get("policy_id")
    policy_version = policy.get("policy_version")
    if not isinstance(policy_id, str) or not policy_id.strip():
        raise PolicyError("writing policy requires a policy_id")
    if not isinstance(policy_version, str) or not policy_version.strip():
        raise PolicyError("writing policy requires a policy_version")
    if policy.get("schema_version") != "1":
        raise PolicyError("writing policy schema_version must be 1")
    default_profile = policy.get("default_profile")
    profiles = policy.get("profiles")
    if not isinstance(default_profile, str) or not isinstance(profiles, dict) or not profiles:
        raise PolicyError("writing policy requires a default_profile and profiles")
    if default_profile not in profiles:
        raise PolicyError(f"default_profile {default_profile!r} is not defined")
    for name, profile in profiles.items():
        if not isinstance(profile, dict):
            raise PolicyError(f"profile {name} must be an object")
        layer = profile.get("deliverable_layer")
        if layer not in SUPPORTED_LAYERS + (None,):
            raise PolicyError(f"profile {name} has invalid deliverable_layer")
        budget = profile.get("budget") or {}
        if not isinstance(budget, dict):
            raise PolicyError(f"profile {name} budget must be an object")
        for key in ("min_chars", "max_chars"):
            value = budget.get(key, 0)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise PolicyError(f"profile {name} budget.{key} must be a non-negative integer")
        if budget.get("max_chars") and budget.get("min_chars", 0) > budget["max_chars"]:
            raise PolicyError(f"profile {name} budget min exceeds max")
    rules = policy.get("rules")
    if not isinstance(rules, list):
        raise PolicyError("writing policy rules must be a list")
    seen_ids: set[str] = set()
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise PolicyError(f"rule {index} must be an object")
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            raise PolicyError(f"rule {index} requires an id")
        if rule_id in seen_ids:
            raise PolicyError(f"duplicate rule id {rule_id!r}")
        seen_ids.add(rule_id)
        if rule.get("enforcement") not in _ENFORCEMENTS:
            raise PolicyError(f"rule {rule_id} has invalid enforcement")
        if rule.get("kind") not in _RULE_KINDS:
            raise PolicyError(f"rule {rule_id} has invalid kind")
        if rule.get("severity") not in _SEVERITIES:
            raise PolicyError(f"rule {rule_id} has invalid severity")
        rule_profiles = rule.get("profiles")
        if not isinstance(rule_profiles, list) or not rule_profiles:
            raise PolicyError(f"rule {rule_id} requires profiles")
        if any(name not in profiles for name in rule_profiles):
            raise PolicyError(f"rule {rule_id} references an unknown profile")
        blockers = rule.get("blocker_profiles", [])
        if not isinstance(blockers, list) or any(name not in profiles for name in blockers):
            raise PolicyError(f"rule {rule_id} has invalid blocker_profiles")
        ignore = rule.get("ignore", [])
        if not isinstance(ignore, list) or any(name not in _IGNORE_NAMES for name in ignore):
            raise PolicyError(f"rule {rule_id} has invalid ignore names")
        if rule.get("kind") == "forbidden_term" and not isinstance(rule.get("terms"), list):
            raise PolicyError(f"forbidden_term rule {rule_id} requires terms")
        if rule.get("kind") == "regex" and not isinstance(rule.get("pattern"), str):
            raise PolicyError(f"regex rule {rule_id} requires a pattern")
    compression = policy.get("compression_review")
    if not isinstance(compression, dict) or not isinstance(compression.get("statuses"), list):
        raise PolicyError("writing policy requires compression_review.statuses")
    if any(status not in COMPRESSION_REVIEW_STATUSES for status in compression["statuses"]):
        raise PolicyError("compression_review contains an invalid status")
    gains = policy.get("argument_gain", {}).get("allowed")
    if not isinstance(gains, list) or not gains:
        raise PolicyError("writing policy requires argument_gain.allowed")
    line_endings = policy.get("line_endings")
    if not isinstance(line_endings, dict):
        raise PolicyError("writing policy requires line_endings")
    for key in ("default", "mixed_severity", "mismatch_severity"):
        if key not in line_endings:
            raise PolicyError(f"writing policy line_endings requires {key}")
    if line_endings["default"] not in LINE_ENDINGS:
        raise PolicyError("line_endings.default must be lf or crlf")
    for key in ("mixed_severity", "mismatch_severity"):
        if line_endings[key] not in LINE_ENDING_SEVERITIES:
            raise PolicyError(f"line_endings.{key} must be error, warning, or off")


def validate_resolved_policy(snapshot: dict[str, Any]) -> None:
    if not isinstance(snapshot, dict):
        raise PolicyError("resolved writing policy must be an object")
    for key in ("policy_id", "policy_version", "schema_version", "profile"):
        if not isinstance(snapshot.get(key), str) or not snapshot[key]:
            raise PolicyError(f"resolved writing policy requires {key}")
    profile = snapshot["profile"]
    if profile not in KNOWN_PROFILES:
        raise PolicyError(f"resolved writing policy has unknown profile {profile!r}")
    layer = snapshot.get("deliverable_layer")
    if layer not in SUPPORTED_LAYERS + (None,):
        raise PolicyError("resolved writing policy has invalid deliverable_layer")
    budget = snapshot.get("budget") or {}
    for key in ("min_chars", "max_chars"):
        value = budget.get(key, 0)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise PolicyError(f"resolved policy budget.{key} must be a non-negative integer")
    if not isinstance(snapshot.get("rules"), list):
        raise PolicyError("resolved writing policy requires rules")
    if not isinstance(snapshot.get("extra_forbidden_terms", []), list):
        raise PolicyError("extra_forbidden_terms must be a list")
    line_endings = snapshot.get("line_endings")
    if not isinstance(line_endings, dict):
        raise PolicyError("resolved writing policy requires line_endings")
    for key in ("default", "mixed_severity", "mismatch_severity"):
        if line_endings.get(key) not in (LINE_ENDINGS if key == "default" else LINE_ENDING_SEVERITIES):
            raise PolicyError(f"resolved policy line_endings.{key} is invalid")


def policy_fingerprint(snapshot: dict[str, Any]) -> str:
    """Canonical SHA-256 of a resolved policy snapshot, excluding volatile meta."""
    if not isinstance(snapshot, dict):
        raise PolicyError("policy snapshot must be an object")
    if not isinstance(snapshot.get("policy_id"), str) or not snapshot["policy_id"]:
        raise PolicyError("policy snapshot requires policy_id")
    if not isinstance(snapshot.get("policy_version"), str) or not snapshot["policy_version"]:
        raise PolicyError("policy snapshot requires policy_version")
    if not isinstance(snapshot.get("profile"), str) or not snapshot["profile"]:
        raise PolicyError("policy snapshot requires profile")
    stable = {key: value for key, value in snapshot.items() if key != "_meta"}

    def _sorted(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: _sorted(value[key]) for key in sorted(value)}
        if isinstance(value, list):
            return [_sorted(item) for item in value]
        return value

    canonical = json.dumps(
        _sorted(stable), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _apply_overrides(
    result: dict[str, Any],
    overrides: dict[str, Any],
    policy: dict[str, Any],
    *,
    source: str,
) -> None:
    if not isinstance(overrides, dict):
        raise PolicyError(f"{source} writing policy overrides must be an object")
    locked_fields = set(policy.get("locked", {}).get("fields", []))
    overridable = set(policy.get("overridable_fields", []))
    merge_mode = policy.get("array_merge", {})
    for key, value in overrides.items():
        if key in locked_fields:
            raise PolicyError(f"{source} cannot override locked writing policy field {key!r}")
        if key not in overridable:
            raise PolicyError(f"{source} cannot override writing policy field {key!r}")
        if key == "budget":
            if not isinstance(value, dict):
                raise PolicyError(f"{source} budget override must be an object")
            for field in ("min_chars", "max_chars"):
                if field in value and (
                    isinstance(value[field], bool)
                    or not isinstance(value[field], int)
                    or value[field] < 0
                ):
                    raise PolicyError(f"{source} budget.{field} must be a non-negative integer")
            result["budget"] = {**(result.get("budget") or {}), **value}
            continue
        if key in {"extra_forbidden_terms", "allowed_sections"}:
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                raise PolicyError(f"{source} {key} must be a list of strings")
            if merge_mode.get(key, "append") == "append":
                result.setdefault(key, [])
                result[key].extend(value)
            else:
                result[key] = list(value)
            continue
        if key == "compression_review_options":
            if not isinstance(value, dict):
                raise PolicyError(f"{source} compression_review_options must be an object")
            result.setdefault("compression_review_options", {})
            result["compression_review_options"].update(value)
            continue
        raise PolicyError(f"{source} cannot override writing policy field {key!r}")


def resolve_writing_policy(
    policy: dict[str, Any] | None = None,
    *,
    profile: str | None = None,
    project_config: dict[str, Any] | None = None,
    manifest_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    base = policy if policy is not None else load_writing_policy()
    validate_policy(base)
    profile_name = profile or base["default_profile"]
    if profile_name not in base["profiles"]:
        raise PolicyError(f"unknown writing policy profile {profile_name!r}")
    result = copy.deepcopy(base["profiles"][profile_name])
    result["policy_id"] = base["policy_id"]
    result["policy_version"] = base["policy_version"]
    result["schema_version"] = base["schema_version"]
    result["profile"] = profile_name
    result["rules"] = [
        rule for rule in base["rules"] if profile_name in rule.get("profiles", [])
    ]
    result["compression_review"] = copy.deepcopy(base.get("compression_review", {}))
    result["argument_gain"] = copy.deepcopy(base.get("argument_gain", {}))
    result["locked"] = copy.deepcopy(base.get("locked", {}))
    result["overridable_fields"] = list(base.get("overridable_fields", []))
    result["array_merge"] = dict(base.get("array_merge", {}))
    result["line_endings"] = copy.deepcopy(base.get("line_endings", {}))
    result.setdefault("extra_forbidden_terms", [])

    project_policy: dict[str, Any] = {}
    if isinstance(project_config, dict):
        candidate = project_config.get("writing_policy")
        if candidate is not None:
            if not isinstance(candidate, dict):
                raise PolicyError("project writing_policy must be an object")
            project_policy = candidate
    manifest_policy: dict[str, Any] = {}
    if manifest_overrides is not None:
        manifest_policy = manifest_overrides
    _apply_overrides(result, project_policy, base, source="project_config")
    _apply_overrides(result, manifest_policy, base, source="report_manifest_config")

    result["_meta"] = {
        "inheritance": list(base.get("inheritance", [])),
        "sources": {
            "system_default": True,
            "artifact_profile": True,
            "project_config": bool(project_policy),
            "report_manifest_config": bool(manifest_policy),
        },
        "resolved_at": _now_iso(),
        "profile": profile_name,
        "policy_fingerprint": policy_fingerprint(result),
    }
    validate_resolved_policy(result)
    return result


def resolve_submission_policy(
    *,
    deliverable_layer: str | None = None,
    artifact_profile: str | None = None,
    writing_policy_id: str | None = None,
    writing_policy_version: str | None = None,
    writing_policy_snapshot: dict[str, Any] | None = None,
    writing_policy_overrides: dict[str, Any] | None = None,
    project_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    base = load_writing_policy()
    if deliverable_layer is not None and deliverable_layer not in SUPPORTED_LAYERS:
        raise PolicyError("deliverable_layer must be A, B, or C")
    if artifact_profile is not None and artifact_profile not in KNOWN_PROFILES:
        raise PolicyError(f"artifact_profile must be one of {', '.join(KNOWN_PROFILES)}")
    if writing_policy_id is not None and writing_policy_id != base["policy_id"]:
        raise PolicyError(f"unsupported writing_policy_id {writing_policy_id!r}")

    profile = artifact_profile or profile_by_layer(deliverable_layer) or base["default_profile"]
    layer = deliverable_layer or base["profiles"][profile].get("deliverable_layer")
    if (
        deliverable_layer is not None
        and base["profiles"][profile].get("deliverable_layer") not in (None, deliverable_layer)
    ):
        raise PolicyError("deliverable_layer does not match artifact_profile")

    snapshot: dict[str, Any]
    if writing_policy_snapshot is not None:
        validate_resolved_policy(writing_policy_snapshot)
        if writing_policy_snapshot.get("profile") != profile:
            raise PolicyError("writing_policy_snapshot profile does not match artifact_profile")
        snapshot_layer = writing_policy_snapshot.get("deliverable_layer")
        if layer is not None and snapshot_layer not in (None, layer):
            raise PolicyError("writing_policy_snapshot layer does not match deliverable_layer")
        snapshot = writing_policy_snapshot
        if writing_policy_id is not None and snapshot.get("policy_id") != writing_policy_id:
            raise PolicyError("writing_policy_id does not match writing_policy_snapshot")
        if (
            writing_policy_version is not None
            and snapshot.get("policy_version") != writing_policy_version
        ):
            raise PolicyError("writing_policy_version does not match writing_policy_snapshot")
    else:
        snapshot = resolve_writing_policy(
            base,
            profile=profile,
            project_config=project_config,
            manifest_overrides=writing_policy_overrides,
        )
        if writing_policy_id is not None and snapshot.get("policy_id") != writing_policy_id:
            raise PolicyError("unsupported writing_policy_id")
        if (
            writing_policy_version is not None
            and writing_policy_version != snapshot.get("policy_version")
        ):
            raise PolicyError(
                "writing_policy_version requires a matching writing_policy_snapshot "
                "when it differs from the bundled policy version"
            )

    return {
        "profile": profile,
        "deliverable_layer": layer,
        "policy_id": snapshot.get("policy_id"),
        "policy_version": snapshot.get("policy_version"),
        "snapshot": snapshot,
    }


def validate_writing_audit_summary(summary: Any) -> dict[str, int]:
    """Validate the compact audit summary stored on report manifests.

    The full audit report remains a file/artifact; the manifest only stores
    the four non-negative bucket counts plus any caller-provided context.
    """
    if not isinstance(summary, dict):
        raise PolicyError("writing_audit_summary must be an object")
    allowed = {"errors", "warnings", "review_items", "approval_blockers"}
    unknown = set(summary) - allowed
    if unknown:
        raise PolicyError(
            "writing_audit_summary contains unknown keys: " + ", ".join(sorted(unknown))
        )
    clean: dict[str, int] = {}
    for key in ("errors", "warnings", "review_items", "approval_blockers"):
        value = summary.get(key, 0)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise PolicyError(f"writing_audit_summary.{key} must be a non-negative integer")
        if value > 1_000_000:
            raise PolicyError(f"writing_audit_summary.{key} exceeds the allowed range")
        clean[key] = value
    return clean
