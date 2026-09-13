from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ._resources import PackagedResourceError, read_json_resource


POLICY_VERSION = "1.1.0"
SCHEMA_VERSION = "1.1"
DEFAULT_SCHEMA_RESOURCE = "research_risk.schema.json"

POLICY_LEVELS = ("none", "interpretive", "comparative", "genealogical", "causal")
EVIDENCE_ROLES = (
    "discovery",
    "design_evidence",
    "holdout",
    "negative_control",
    "validation",
    "background",
)
HYPOTHESIS_KINDS = (
    "shared_source",
    "template_too_broad",
    "retrospective_reconstruction",
    "alternative_mechanism",
    "other",
)
CONTRIBUTION_TYPES = (
    "textual_discovery",
    "source_discovery",
    "genealogical_explanation",
    "causal_explanation",
    "conceptual_reconstruction",
    "dispute_adjudication",
    "methodological_framework",
    "negative_result",
)
CONTROL_RESULTS = ("pending", "passes", "fails", "indeterminate")
DESIGN_STATUSES = ("draft", "locked")
REVIEW_STATUSES = ("pending", "completed")
BRIDGE_STRENGTHS = ("high", "medium", "low", "unresolved", "unproven")
CONNECTION_TYPES = (
    "self_citation",
    "explicit_redefinition",
    "intermediate_recurrence",
    "source_transmission",
    "problem_reactivation",
    "chronology_only",
)
HYPOTHESIS_STATUSES = (
    "supported",
    "partially_supported",
    "not_falsified",
    "unresolved",
    "weakened",
    "falsified",
    "unadjudicated",
)
RESULT_KEYS = (
    "hypothesis_statuses",
    "positive_discriminating_evidence",
    "observations",
)
ADJUDICATION_KEYS = ("adjudication_version", "verdicts")

_BUCKETS = ("errors", "warnings", "review_items", "approval_blockers")
_CONTROL_REQUIRING_LEVELS = ("comparative", "genealogical", "causal")


def load_research_risk_schema() -> dict[str, Any]:
    """Load the installed research-risk schema without relying on a checkout path."""

    try:
        return read_json_resource(DEFAULT_SCHEMA_RESOURCE)
    except PackagedResourceError as exc:
        raise RuntimeError("research-risk schema resource is unavailable") from exc


def _s(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _effective_policy(doc: dict[str, Any]) -> tuple[bool, str]:
    """Return the effective (enabled, policy_level) pair.

    The ``research_risk_policy`` wrapper takes precedence over the top-level
    fields when both are present.
    """
    wrapper = doc.get("research_risk_policy")
    if isinstance(wrapper, dict):
        enabled = wrapper.get("enabled", doc.get("enabled", True))
        level = wrapper.get("level", doc.get("policy_level", "none"))
    else:
        enabled = doc.get("enabled", True)
        level = doc.get("policy_level", "none")
    return bool(enabled), level


@dataclass(frozen=True)
class RiskFinding:
    rule_id: str
    bucket: str
    message: str
    path: str | None = None
    snippet: str | None = None

    @property
    def severity(self) -> str:
        if self.bucket in ("errors", "approval_blockers"):
            return "error"
        if self.bucket == "warnings":
            return "warning"
        return "review"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "bucket": self.bucket,
            "message": self.message,
            "path": self.path,
            "snippet": self.snippet,
        }


@dataclass(frozen=True)
class RiskAuditResult:
    document: dict[str, Any]
    findings: tuple[RiskFinding, ...]
    input_sha256: str
    source_path: str | None = None
    design_sha256: str | None = None
    design_hash_status: str | None = None

    def _bucket(self, name: str) -> list[dict[str, Any]]:
        return [finding.to_dict() for finding in self.findings if finding.bucket == name]

    def as_dict(self) -> dict[str, Any]:
        buckets = {name: self._bucket(name) for name in _BUCKETS}
        enabled, level = _effective_policy(self.document)
        data = {
            "schema_version": str(self.document.get("schema_version") or SCHEMA_VERSION),
            "policy_version": POLICY_VERSION,
            "enabled": enabled,
            "policy_level": level,
            "design_version": self.document.get("design_version") or 1,
            "design_status": self.document.get("design_status") or "draft",
            "errors": buckets["errors"],
            "warnings": buckets["warnings"],
            "review_items": buckets["review_items"],
            "approval_blockers": buckets["approval_blockers"],
            "summary": {name: len(buckets[name]) for name in _BUCKETS},
            "input_sha256": self.input_sha256,
            "source_path": self.source_path,
        }
        if self.design_sha256 is not None:
            data["design_sha256"] = self.design_sha256
            data["design_hash_status"] = self.design_hash_status
        return data


def _check_predictions(
    problems: list[tuple[str, str]], hypothesis: dict[str, Any], path: str
) -> None:
    predictions = hypothesis.get("predictions")
    if not isinstance(predictions, list):
        problems.append((f"{path}.predictions", "predictions must be a list"))
        return
    for index, prediction in enumerate(predictions):
        pred_path = f"{path}.predictions[{index}]"
        if not isinstance(prediction, dict):
            problems.append((pred_path, "prediction must be an object"))
            continue
        if not _s(prediction.get("evidence_class")):
            problems.append((f"{pred_path}.evidence_class", "evidence_class is required"))
        if not _s(prediction.get("expected_observation")):
            problems.append(
                (f"{pred_path}.expected_observation", "expected_observation is required")
            )
        counterfactual = prediction.get("counterfactual")
        if counterfactual is not None and not isinstance(counterfactual, bool):
            problems.append((f"{pred_path}.counterfactual", "counterfactual must be a boolean"))


def _validate_structure(doc: Any) -> list[tuple[str, str]]:
    problems: list[tuple[str, str]] = []
    if not isinstance(doc, dict):
        return [("$", "document must be a JSON object")]

    if doc.get("schema_version") != SCHEMA_VERSION:
        problems.append(("schema_version", f"schema_version must be {SCHEMA_VERSION!r}"))
    if not isinstance(doc.get("enabled", True), bool):
        problems.append(("enabled", "enabled must be a boolean"))
    if doc.get("policy_level") not in POLICY_LEVELS:
        problems.append(("policy_level", f"policy_level must be one of {POLICY_LEVELS}"))
    design_version = doc.get("design_version", 1)
    if (
        isinstance(design_version, bool)
        or not isinstance(design_version, int)
        or design_version < 1
    ):
        problems.append(("design_version", "design_version must be a positive integer"))
    if doc.get("design_status") not in DESIGN_STATUSES:
        problems.append(("design_status", f"design_status must be one of {DESIGN_STATUSES}"))

    wrapper = doc.get("research_risk_policy")
    if wrapper is not None:
        if not isinstance(wrapper, dict):
            problems.append(("research_risk_policy", "research_risk_policy must be an object"))
        else:
            if not isinstance(wrapper.get("enabled", True), bool):
                problems.append(
                    ("research_risk_policy.enabled", "enabled must be a boolean")
                )
            if wrapper.get("level") not in POLICY_LEVELS:
                problems.append(
                    (
                        "research_risk_policy.level",
                        f"level must be one of {POLICY_LEVELS}",
                    )
                )

    enabled, level = _effective_policy(doc)
    if not enabled or level == "none":
        return problems

    if not _s(doc.get("research_question")):
        problems.append(("research_question", "research_question must be a non-empty string"))

    primary = doc.get("primary_hypothesis")
    if not isinstance(primary, dict):
        problems.append(("$.primary_hypothesis", "primary_hypothesis must be an object"))
    else:
        if not _s(primary.get("id")):
            problems.append(("$.primary_hypothesis.id", "id is required"))
        if not _s(primary.get("statement")):
            problems.append(("$.primary_hypothesis.statement", "statement is required"))
        if not isinstance(primary.get("risk_bearing"), bool):
            problems.append(
                ("$.primary_hypothesis.risk_bearing", "risk_bearing must be a boolean")
            )
        _check_predictions(problems, primary, "$.primary_hypothesis")

    rivals = doc.get("rival_hypotheses")
    if not isinstance(rivals, list):
        problems.append(("rival_hypotheses", "rival_hypotheses must be a list"))
    else:
        for index, rival in enumerate(rivals):
            path = f"$.rival_hypotheses[{index}]"
            if not isinstance(rival, dict):
                problems.append((path, "rival hypothesis must be an object"))
                continue
            if not _s(rival.get("id")):
                problems.append((f"{path}.id", "id is required"))
            if not _s(rival.get("statement")):
                problems.append((f"{path}.statement", "statement is required"))
            kind = rival.get("hypothesis_kind")
            if kind is not None and kind not in HYPOTHESIS_KINDS:
                problems.append(
                    (f"{path}.hypothesis_kind", f"hypothesis_kind must be one of {HYPOTHESIS_KINDS}")
                )
            simplicity = rival.get("simplicity_note")
            if simplicity is not None and not isinstance(simplicity, str):
                problems.append((f"{path}.simplicity_note", "simplicity_note must be a string"))
            _check_predictions(problems, rival, path)

    falsifications = doc.get("falsification_conditions")
    if not isinstance(falsifications, list):
        problems.append(("falsification_conditions", "falsification_conditions must be a list"))
    else:
        for index, item in enumerate(falsifications):
            path = f"$.falsification_conditions[{index}]"
            if not isinstance(item, dict) or not _s(item.get("id")) or not _s(item.get("statement")):
                problems.append((path, "each falsification condition requires id and statement"))
                continue
            status_at_lock = item.get("status_at_lock")
            if status_at_lock is not None and status_at_lock not in (
                "known_before_lock",
                "genuinely_open",
            ):
                problems.append(
                    (f"{path}.status_at_lock", "status_at_lock must be known_before_lock or genuinely_open")
                )

    criteria = doc.get("operational_criteria")
    if not isinstance(criteria, list):
        problems.append(("operational_criteria", "operational_criteria must be a list"))
    else:
        for index, item in enumerate(criteria):
            path = f"$.operational_criteria[{index}]"
            if not isinstance(item, dict):
                problems.append((path, "criterion must be an object"))
                continue
            if not _s(item.get("id")) or not _s(item.get("statement")):
                problems.append((path, "each criterion requires id and statement"))
            for key in ("inclusion_test", "exclusion_test"):
                value = item.get(key)
                if value is not None and not isinstance(value, str):
                    problems.append((f"{path}.{key}", f"{key} must be a string"))

    for key in ("diachronic_connection_evidence", "mechanism_chain", "mechanism_failure_conditions"):
        value = doc.get(key)
        if not isinstance(value, list):
            problems.append((key, f"{key} must be a list"))
    for index, item in enumerate(doc.get("diachronic_connection_evidence") or []):
        path = f"$.diachronic_connection_evidence[{index}]"
        if not isinstance(item, dict):
            problems.append((path, "diachronic evidence must be an object"))
            continue
        connection_type = item.get("connection_type")
        if connection_type is not None and connection_type not in CONNECTION_TYPES:
            problems.append(
                (f"{path}.connection_type", f"connection_type must be one of {CONNECTION_TYPES}")
            )

    materials = doc.get("materials")
    if not isinstance(materials, list):
        problems.append(("materials", "materials must be a list"))
    else:
        for index, item in enumerate(materials):
            path = f"$.materials[{index}]"
            if not isinstance(item, dict):
                problems.append((path, "material must be an object"))
                continue
            if not _s(item.get("id")) or not _s(item.get("source_ref")):
                problems.append((path, "each material requires id and source_ref"))
            if item.get("evidence_role") not in EVIDENCE_ROLES:
                problems.append(
                    (f"{path}.evidence_role", f"evidence_role must be one of {EVIDENCE_ROLES}")
                )
            if not isinstance(item.get("seen_before_lock", False), bool):
                problems.append((f"{path}.seen_before_lock", "seen_before_lock must be a boolean"))
            if item.get("design_impacted") is not None and not isinstance(
                item.get("design_impacted"), bool
            ):
                problems.append((f"{path}.design_impacted", "design_impacted must be a boolean"))

    holdout_sources = doc.get("holdout_sources")
    if not isinstance(holdout_sources, list):
        problems.append(("holdout_sources", "holdout_sources must be a list"))
    else:
        for index, item in enumerate(holdout_sources):
            path = f"$.holdout_sources[{index}]"
            if not isinstance(item, dict):
                problems.append((path, "holdout source must be an object"))
                continue
            if not _s(item.get("id")) or not _s(item.get("source_ref")):
                problems.append((path, "each holdout source requires id and source_ref"))
            if not isinstance(item.get("seen_before_lock", False), bool):
                problems.append((f"{path}.seen_before_lock", "seen_before_lock must be a boolean"))

    controls = doc.get("negative_controls")
    if not isinstance(controls, list):
        problems.append(("negative_controls", "negative_controls must be a list"))
    else:
        for index, item in enumerate(controls):
            path = f"$.negative_controls[{index}]"
            if not isinstance(item, dict):
                problems.append((path, "negative control must be an object"))
                continue
            for key in ("id", "source_ref", "reason_for_control", "expected_result"):
                if not _s(item.get(key)):
                    problems.append((f"{path}.{key}", f"{key} is required"))
            if not isinstance(item.get("same_standard_as_primary", True), bool):
                problems.append(
                    (f"{path}.same_standard_as_primary", "same_standard_as_primary must be a boolean")
                )
            actual = item.get("actual_result")
            if actual is not None and actual not in CONTROL_RESULTS:
                problems.append(
                    (f"{path}.actual_result", f"actual_result must be one of {CONTROL_RESULTS} or null")
                )
            tests = item.get("tests_hypotheses")
            if tests is not None:
                if not isinstance(tests, list) or any(not _s(value) for value in tests):
                    problems.append(
                        (f"{path}.tests_hypotheses", "tests_hypotheses must be a list of hypothesis ids")
                    )

    branches = doc.get("outcome_branches")
    if not isinstance(branches, dict):
        problems.append(("outcome_branches", "outcome_branches must be an object"))
    else:
        for name, branch in branches.items():
            path = f"$.outcome_branches.{name}"
            if not isinstance(branch, dict):
                problems.append((path, "outcome branch must be an object"))
                continue
            if not _s(branch.get("conclusion_effect")):
                problems.append((f"{path}.conclusion_effect", "conclusion_effect is required"))
            for key in ("retracts_primary", "changes_contribution", "changes_center_conclusion"):
                value = branch.get(key)
                if value is not None and not isinstance(value, bool):
                    problems.append((f"{path}.{key}", f"{key} must be a boolean"))

    contribution = doc.get("contribution_type")
    if not isinstance(contribution, dict):
        problems.append(("contribution_type", "contribution_type must be an object"))
    else:
        if contribution.get("primary") not in CONTRIBUTION_TYPES:
            problems.append(
                ("contribution_type.primary", f"primary must be one of {CONTRIBUTION_TYPES}")
            )
        secondary = contribution.get("secondary")
        if not isinstance(secondary, list) or any(
            value not in CONTRIBUTION_TYPES for value in secondary
        ):
            problems.append(
                ("contribution_type.secondary", "secondary must be a list of contribution types")
            )

    bridges = doc.get("bridge_assessments")
    if not isinstance(bridges, list):
        problems.append(("bridge_assessments", "bridge_assessments must be a list"))
    else:
        for index, item in enumerate(bridges):
            path = f"$.bridge_assessments[{index}]"
            if not isinstance(item, dict) or not _s(item.get("bridge_id")):
                problems.append((path, "each bridge assessment requires bridge_id"))
                continue
            strength = item.get("overall_strength")
            if strength is not None and strength not in BRIDGE_STRENGTHS:
                problems.append(
                    (f"{path}.overall_strength", f"overall_strength must be one of {BRIDGE_STRENGTHS}")
                )
            if item.get("dimensions") is not None and not isinstance(item.get("dimensions"), dict):
                problems.append((f"{path}.dimensions", "dimensions must be an object"))

    adversarial = doc.get("adversarial_review")
    if not isinstance(adversarial, dict):
        problems.append(("adversarial_review", "adversarial_review must be an object"))
    else:
        if adversarial.get("status") not in REVIEW_STATUSES:
            problems.append(("adversarial_review.status", "status must be pending or completed"))

    validation_status = doc.get("validation_status")
    if not isinstance(validation_status, dict):
        problems.append(("validation_status", "validation_status must be an object"))
    else:
        if not isinstance(validation_status.get("required", False), bool):
            problems.append(("validation_status.required", "required must be a boolean"))
        if not isinstance(validation_status.get("completed", False), bool):
            problems.append(("validation_status.completed", "completed must be a boolean"))

    history = doc.get("design_history")
    if not isinstance(history, list):
        problems.append(("design_history", "design_history must be a list"))
    else:
        for index, item in enumerate(history):
            path = f"$.design_history[{index}]"
            if not isinstance(item, dict):
                problems.append((path, "design history entry must be an object"))
                continue
            for key in ("from_version", "to_version"):
                value = item.get(key)
                if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                    problems.append((f"{path}.{key}", f"{key} must be a positive integer"))
            if not isinstance(item.get("reason", ""), str):
                problems.append((f"{path}.reason", "reason must be a string"))
            for key in ("evidence_seen_before_change", "changed_fields"):
                if not isinstance(item.get(key, []), list):
                    problems.append((f"{path}.{key}", f"{key} must be a list"))
            makes_easier = item.get("makes_primary_easier")
            if makes_easier is not None and not isinstance(makes_easier, bool):
                problems.append(
                    (f"{path}.makes_primary_easier", "makes_primary_easier must be a boolean or null")
                )
            old_result = item.get("old_design_result")
            if old_result is not None and not isinstance(old_result, str):
                problems.append((f"{path}.old_design_result", "old_design_result must be a string"))

    return problems


def _effective_materials(doc: dict[str, Any]) -> list[dict[str, Any]]:
    materials = list(doc.get("materials") or [])
    for item in doc.get("holdout_sources") or []:
        if isinstance(item, dict):
            materials.append(
                {
                    "id": item.get("id"),
                    "source_ref": item.get("source_ref"),
                    "evidence_role": "holdout",
                    "seen_before_lock": item.get("seen_before_lock", False),
                }
            )
    return materials


def _hypothesis_predictions(hypothesis: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        prediction
        for prediction in hypothesis.get("predictions") or []
        if isinstance(prediction, dict) and _s(prediction.get("evidence_class"))
    ]


def _pair_discriminates(first: dict[str, Any], second: dict[str, Any]) -> bool:
    def observations(hypothesis: dict[str, Any]) -> dict[str, set[str]]:
        result: dict[str, set[str]] = {}
        for prediction in _hypothesis_predictions(hypothesis):
            evidence_class = prediction["evidence_class"].strip()
            observation = str(prediction.get("expected_observation") or "").strip().lower()
            result.setdefault(evidence_class, set()).add(observation)
        return result

    first_observations = observations(first)
    second_observations = observations(second)
    for evidence_class, values in first_observations.items():
        other_values = second_observations.get(evidence_class)
        if other_values is not None and values != other_values:
            return True
    return False


def _nondiscrimination_findings(
    primary: dict[str, Any] | None, rivals: list[dict[str, Any]]
) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    hypotheses: list[dict[str, Any]] = []
    if isinstance(primary, dict):
        hypotheses.append(primary)
    hypotheses.extend(rivals)
    seen_pairs: set[tuple[str, str]] = set()
    for index, first in enumerate(hypotheses):
        for second in hypotheses[index + 1 :]:
            first_id = str(first.get("id") or index)
            second_id = str(second.get("id") or index + 1)
            pair = tuple(sorted((first_id, second_id)))
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            if not _pair_discriminates(first, second):
                findings.append(
                    RiskFinding(
                        "RIVAL_HYPOTHESIS_NOT_DISCRIMINATING",
                        "warnings",
                        f"hypotheses {first_id} and {second_id} share no discriminating evidence",
                        f"$.rival_hypotheses",
                    )
                )
    return findings



def _canonical_design_hash(doc: dict[str, Any]) -> str:
    payload = json.dumps(doc, sort_keys=True, ensure_ascii=False).encode("utf-8")
    payload = payload.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(payload).hexdigest()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _is_positive_discriminating_evidence(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    if item.get("observed_after_lock") is not True:
        return False
    if item.get("outcome_unknown_at_lock") is not True:
        return False
    if item.get("supports_primary_prediction") is not True:
        return False
    discriminated = item.get("discriminates_against")
    return isinstance(discriminated, list) and any(_s(value) for value in discriminated)


def _validate_sidecar_structure(doc: Any, kind: str) -> list[tuple[str, str]]:
    problems: list[tuple[str, str]] = []
    if not isinstance(doc, dict):
        return [("$", f"{kind} must be a JSON object")]
    if doc.get("schema_version") != SCHEMA_VERSION:
        problems.append(("schema_version", f"schema_version must be {SCHEMA_VERSION!r}"))
    design_version = doc.get("design_version", 1)
    if isinstance(design_version, bool) or not isinstance(design_version, int) or design_version < 1:
        problems.append(("design_version", "design_version must be a positive integer"))
    if not _is_sha256(doc.get("design_sha256")):
        problems.append(("design_sha256", "design_sha256 must be a 64-character hex digest"))

    if kind == "results":
        for key in ("hypothesis_statuses", "positive_discriminating_evidence", "observations"):
            if not isinstance(doc.get(key), list):
                problems.append((key, f"{key} must be a list"))
        for index, status in enumerate(doc.get("hypothesis_statuses") or []):
            path = f"$.hypothesis_statuses[{index}]"
            if not isinstance(status, dict) or not _s(status.get("hypothesis_id")) or status.get("status") not in HYPOTHESIS_STATUSES:
                problems.append((path, "hypothesis status requires hypothesis_id and a valid status"))
        for index, item in enumerate(doc.get("positive_discriminating_evidence") or []):
            path = f"$.positive_discriminating_evidence[{index}]"
            if not isinstance(item, dict) or not _s(item.get("id")) or not _s(item.get("evidence_class")):
                problems.append((path, "positive discriminating evidence requires id and evidence_class"))
                continue
            for key in ("observed_after_lock", "outcome_unknown_at_lock", "supports_primary_prediction"):
                if not isinstance(item.get(key), bool):
                    problems.append((f"{path}.{key}", f"{key} must be a boolean"))
            discriminated = item.get("discriminates_against")
            if not isinstance(discriminated, list) or not any(_s(value) for value in discriminated):
                problems.append((f"{path}.discriminates_against", "at least one rival hypothesis id is required"))
        for index, observation in enumerate(doc.get("observations") or []):
            path = f"$.observations[{index}]"
            if not isinstance(observation, dict) or not _s(observation.get("id")):
                problems.append((path, "observation requires id"))
                continue
            for key in ("evidence_class", "outcome", "observed_at"):
                if not _s(observation.get(key)):
                    problems.append((f"{path}.{key}", f"{key} is required"))
            if not isinstance(observation.get("known_before_lock"), bool):
                problems.append((f"{path}.known_before_lock", "known_before_lock must be a boolean"))
    else:
        adjudication_version = doc.get("adjudication_version", 1)
        if isinstance(adjudication_version, bool) or not isinstance(adjudication_version, int) or adjudication_version < 1:
            problems.append(("adjudication_version", "adjudication_version must be a positive integer"))
        verdicts = doc.get("verdicts")
        if not isinstance(verdicts, list):
            problems.append(("verdicts", "verdicts must be a list"))
        else:
            for index, verdict in enumerate(verdicts):
                path = f"$.verdicts[{index}]"
                if not isinstance(verdict, dict) or not _s(verdict.get("hypothesis_id")) or verdict.get("status") not in HYPOTHESIS_STATUSES or not _s(verdict.get("reasoning")):
                    problems.append((path, "verdict requires hypothesis_id, a valid status, and reasoning"))
    return problems


def _semantic_rules_1_1(
    *,
    doc: dict[str, Any],
    level: str,
    locked: bool,
    materials: list[dict[str, Any]],
    controls: list[dict[str, Any]],
    branches: dict[str, Any],
    primary: dict[str, Any] | None,
    rivals: list[dict[str, Any]],
    results_doc: dict[str, Any] | None,
    adjudication_doc: dict[str, Any] | None,
    design_sha256: str | None,
) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    results = results_doc or {}
    statuses = {
        status.get("hypothesis_id"): status.get("status")
        for status in results.get("hypothesis_statuses") or []
        if isinstance(status, dict)
    }
    pde_items = results.get("positive_discriminating_evidence") or []
    observations = results.get("observations") or []
    validation_status = doc.get("validation_status") or {}
    contribution = doc.get("contribution_type") or {}
    claimed = [contribution.get("primary")] + list(contribution.get("secondary") or [])

    def append(rule_id, buckets, message, path=None):
        for bucket in buckets:
            findings.append(RiskFinding(rule_id, bucket, message, path))

    if (
        locked
        and level in ("genealogical", "causal")
        and validation_status.get("completed") is True
    ):
        known_pre_lock = [
            item
            for item in observations
            if isinstance(item, dict) and item.get("known_before_lock") is True
        ]
        if known_pre_lock:
            append(
                "VALIDATION_EVIDENCE_CONTAMINATED",
                ("errors", "approval_blockers"),
                "completed validation includes observations that were known before lock",
                "$.observations",
            )

    if locked:
        if not any(
            isinstance(item, dict) and item.get("status_at_lock") == "genuinely_open"
            for item in doc.get("falsification_conditions") or []
        ):
            append(
                "NO_OPEN_FALSIFICATION_CONDITION",
                ("errors", "approval_blockers"),
                "locked design has no genuinely-open falsification condition",
                "$.falsification_conditions",
            )

    if primary is not None:
        primary_status = statuses.get(primary.get("id"))
        if primary_status in ("supported", "partially_supported") and not any(
            _is_positive_discriminating_evidence(item) for item in pde_items
        ):
            append(
                "PRIMARY_SUPPORTED_BY_RIVAL_FAILURE_ONLY",
                ("errors", "approval_blockers"),
                "supported/partially_supported requires positive discriminating evidence",
                "$.positive_discriminating_evidence",
            )

    if (
        locked
        and level in ("genealogical", "causal")
        and validation_status.get("required") is True
        and validation_status.get("completed") is True
    ):
        post_lock_observations = [
            item
            for item in observations
            if isinstance(item, dict)
            and item.get("known_before_lock") is False
            and _s(item.get("observed_at"))
        ]
        if not post_lock_observations:
            append(
                "POST_LOCK_VALIDATION_MISSING",
                ("errors", "approval_blockers"),
                "completed validation has no post-lock observation",
                "$.observations",
            )

    evidence = doc.get("diachronic_connection_evidence") or []
    if (
        level in ("genealogical", "causal")
        and evidence
        and all(
            isinstance(item, dict) and item.get("connection_type") == "chronology_only"
            for item in evidence
        )
        and any(item in ("genealogical_explanation", "causal_explanation") for item in claimed)
    ):
        append(
            "CHRONOLOGY_USED_AS_CONNECTION_EVIDENCE",
            ("errors", "approval_blockers"),
            "chronology-only evidence cannot support a genealogical/causal contribution",
            "$.diachronic_connection_evidence",
        )

    bridge_dimensions: dict[str, Any] = {}
    for bridge in doc.get("bridge_assessments") or []:
        if isinstance(bridge, dict) and isinstance(bridge.get("dimensions"), dict):
            bridge_dimensions.update(bridge["dimensions"])
    weak_bridge_statuses = ("unproven", "low", "unresolved")
    if "genealogical_explanation" in claimed and bridge_dimensions.get("genealogical_continuity") in weak_bridge_statuses:
        append(
            "CONTRIBUTION_EXCEEDS_BRIDGE_STATUS",
            ("errors",),
            "genealogical_explanation exceeds bridge genealogical_continuity status",
            "$.contribution_type",
        )
    if "causal_explanation" in claimed and bridge_dimensions.get("mechanism_continuity") in weak_bridge_statuses:
        append(
            "CONTRIBUTION_EXCEEDS_BRIDGE_STATUS",
            ("errors",),
            "causal_explanation exceeds bridge mechanism_continuity status",
            "$.contribution_type",
        )

    for index, control in enumerate(controls):
        tests = control.get("tests_hypotheses")
        if not isinstance(tests, list) or not tests or any(not _s(value) for value in tests):
            buckets = ("errors", "approval_blockers") if locked else ("errors",)
            append(
                "NEGATIVE_CONTROL_OVERGENERALIZED",
                buckets,
                "negative control must declare the hypotheses it tests",
                f"$.negative_controls[{index}].tests_hypotheses",
            )

    if any(key in doc for key in RESULT_KEYS) or any(key in doc for key in ADJUDICATION_KEYS):
        append(
            "DESIGN_RESULT_MIXED",
            ("errors",),
            "results and adjudication data must be stored in separate files",
            "$",
        )

    for index, item in enumerate(materials):
        if item.get("design_impacted") is True and item.get("evidence_role") != "design_evidence":
            append(
                "EVIDENCE_ROLE_STALE",
                ("errors",),
                "design-impacted material must be registered as design_evidence",
                f"$.materials[{index}]",
            )
        if item.get("evidence_role") == "design_evidence" and item.get("design_impacted") is not True:
            append(
                "EVIDENCE_ROLE_STALE",
                ("errors",),
                "design_evidence material must declare design_impacted=true",
                f"$.materials[{index}]",
            )

    if locked and (results_doc is not None or adjudication_doc is not None):
        for sidecar, label in ((results_doc, "results"), (adjudication_doc, "adjudication")):
            if sidecar is not None and sidecar.get("design_sha256") != design_sha256:
                append(
                    "LOCKED_DESIGN_HASH_MISMATCH",
                    ("errors", "approval_blockers"),
                    f"{label} design_sha256 does not match the current design",
                    f"$.{label}.design_sha256",
                )
    return findings


def _run_rules(
    doc: dict[str, Any],
    level: str,
    results_doc: dict[str, Any] | None = None,
    adjudication_doc: dict[str, Any] | None = None,
    design_sha256: str | None = None,
) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    primary = doc.get("primary_hypothesis")
    rivals = list(doc.get("rival_hypotheses") or [])
    materials = _effective_materials(doc)
    controls = list(doc.get("negative_controls") or [])
    branches = doc.get("outcome_branches") or {}
    locked = doc.get("design_status") == "locked"
    required_rivals = 2 if level == "genealogical" else 1

    def append(
        rule_id: str,
        buckets: tuple[str, ...],
        message: str,
        path: str | None = None,
    ) -> None:
        for bucket in buckets:
            findings.append(RiskFinding(rule_id, bucket, message, path))

    if primary is None or not isinstance(primary, dict):
        findings.append(
            RiskFinding(
                "PRIMARY_HYPOTHESIS_MISSING",
                "errors",
                "primary_hypothesis is required",
                "$.primary_hypothesis",
            )
        )
    else:
        if primary.get("risk_bearing") is not True:
            append(
                "RISK_BEARING_MISSING",
                ("errors", "approval_blockers"),
                "primary hypothesis must declare risk_bearing=true",
                "$.primary_hypothesis.risk_bearing",
            )
        if not _s(primary.get("failure_effect")):
            findings.append(
                RiskFinding(
                    "FAILURE_EFFECT_MISSING",
                    "errors",
                    "primary hypothesis must declare a failure_effect",
                    "$.primary_hypothesis.failure_effect",
                )
            )

    if len(rivals) < required_rivals:
        append(
            "RIVAL_HYPOTHESIS_MISSING",
            ("errors", "approval_blockers"),
            f"at least {required_rivals} rival hypothesis(es) are required",
            "$.rival_hypotheses",
        )
    if not doc.get("falsification_conditions"):
        findings.append(
            RiskFinding(
                "FALSIFICATION_CONDITIONS_MISSING",
                "errors",
                "falsification_conditions must be declared",
                "$.falsification_conditions",
            )
        )

    hypotheses: list[dict[str, Any]] = (
        [primary] if isinstance(primary, dict) else []
    ) + rivals
    for hypothesis in hypotheses:
        if not _hypothesis_predictions(hypothesis):
            findings.append(
                RiskFinding(
                    "HYPOTHESIS_PREDICTIONS_MISSING",
                    "warnings",
                    f"hypothesis {hypothesis.get('id') or '?'} has no usable predictions",
                    "$.primary_hypothesis.predictions",
                )
            )

    if level in _CONTROL_REQUIRING_LEVELS:
        findings.extend(_nondiscrimination_findings(primary, rivals))

    if not isinstance(branches, dict) or not branches:
        append(
            "OUTCOME_BRANCHES_MISSING",
            ("errors", "approval_blockers"),
            "outcome_branches must declare at least one branch",
            "$.outcome_branches",
        )
    else:
        has_failure_branch = any(
            isinstance(branch, dict)
            and (
                branch.get("retracts_primary")
                or branch.get("changes_contribution")
                or branch.get("changes_center_conclusion")
            )
            for branch in branches.values()
        )
        if not has_failure_branch:
            append(
                "ALL_OUTCOMES_PRESERVE_PRIMARY_HYPOTHESIS",
                ("errors", "approval_blockers"),
                "every outcome branch preserves the primary hypothesis",
                "$.outcome_branches",
            )

    if level in _CONTROL_REQUIRING_LEVELS:
        if not controls:
            buckets = ("errors", "approval_blockers") if locked else ("errors",)
            append(
                "NEGATIVE_CONTROL_MISSING",
                buckets,
                "negative_controls are required at this policy level",
                "$.negative_controls",
            )
        for index, control in enumerate(controls):
            path = f"$.negative_controls[{index}]"
            if not _s(control.get("reason_for_control")) or not _s(control.get("expected_result")):
                findings.append(
                    RiskFinding(
                        "NEGATIVE_CONTROL_NOT_COMPARABLE",
                        "warnings",
                        "negative control must state its rationale and expected result",
                        path,
                    )
                )
            if control.get("same_standard_as_primary") is not True:
                findings.append(
                    RiskFinding(
                        "NEGATIVE_CONTROL_NOT_COMPARABLE",
                        "warnings",
                        "negative control must use the same standard as primary materials",
                        f"{path}.same_standard_as_primary",
                    )
                )
            actual = control.get("actual_result")
            if actual is None:
                buckets = ("warnings", "approval_blockers") if locked else ("warnings",)
                append(
                    "NEGATIVE_CONTROL_NOT_COMPLETED",
                    buckets,
                    "negative control has not reported an actual_result",
                    f"{path}.actual_result",
                )
            elif actual == "passes":
                findings.append(
                    RiskFinding(
                        "NEGATIVE_CONTROL_PASSES_PRIMARY_CRITERIA",
                        "errors",
                        "negative control satisfies the primary criteria",
                        f"{path}.actual_result",
                    )
                )

    if level == "genealogical":
        if not materials:
            findings.append(
                RiskFinding(
                    "MATERIALS_MISSING",
                    "errors",
                    "materials must be registered for genealogical policy",
                    "$.materials",
                )
            )
        else:
            has_validation = any(
                item.get("evidence_role") in ("validation", "holdout") for item in materials
            )
            if not has_validation:
                append(
                    "VALIDATION_OR_HOLDOUT_MISSING",
                    ("errors", "approval_blockers"),
                    "at least one validation or holdout material is required",
                    "$.materials",
                )
            for item in materials:
                if item.get("evidence_role") == "holdout" and item.get("seen_before_lock"):
                    append(
                        "HOLDOUT_CONTAMINATED",
                        ("errors", "approval_blockers"),
                        "holdout material was already seen before the design lock",
                        "$.materials",
                    )
        if not any(
            isinstance(rival, dict) and rival.get("hypothesis_kind") == "shared_source"
            for rival in rivals
        ):
            findings.append(
                RiskFinding(
                    "SHARED_SOURCE_RIVAL_MISSING",
                    "errors",
                    "genealogical policy requires a shared-source rival hypothesis",
                    "$.rival_hypotheses",
                )
            )
        if not doc.get("diachronic_connection_evidence"):
            findings.append(
                RiskFinding(
                    "DIACHRONIC_EVIDENCE_MISSING",
                    "errors",
                    "genealogical policy requires diachronic_connection_evidence",
                    "$.diachronic_connection_evidence",
                )
            )
        if locked:
            validation_status = doc.get("validation_status") or {}
            if validation_status.get("required") and not validation_status.get("completed"):
                findings.append(
                    RiskFinding(
                        "VALIDATION_INCOMPLETE",
                        "approval_blockers",
                        "post-lock validation is not completed",
                        "$.validation_status",
                    )
                )
            adversarial = doc.get("adversarial_review") or {}
            if adversarial.get("status") != "completed":
                findings.append(
                    RiskFinding(
                        "ADVERSARIAL_REVIEW_INCOMPLETE",
                        "approval_blockers",
                        "adversarial review is not completed",
                        "$.adversarial_review",
                    )
                )

    if level == "causal":
        if not doc.get("mechanism_chain"):
            findings.append(
                RiskFinding(
                    "MECHANISM_CHAIN_MISSING",
                    "errors",
                    "causal policy requires a mechanism_chain",
                    "$.mechanism_chain",
                )
            )
        if not any(
            isinstance(rival, dict)
            and rival.get("hypothesis_kind") == "alternative_mechanism"
            for rival in rivals
        ):
            findings.append(
                RiskFinding(
                    "ALTERNATIVE_MECHANISM_MISSING",
                    "errors",
                    "causal policy requires an alternative-mechanism rival",
                    "$.rival_hypotheses",
                )
            )
        if not doc.get("mechanism_failure_conditions"):
            findings.append(
                RiskFinding(
                    "MECHANISM_FAILURE_CONDITIONS_MISSING",
                    "errors",
                    "causal policy requires mechanism_failure_conditions",
                    "$.mechanism_failure_conditions",
                )
            )
        has_counterfactual = any(
            isinstance(prediction, dict) and prediction.get("counterfactual") is True
            for hypothesis in hypotheses
            for prediction in hypothesis.get("predictions") or []
        )
        if not has_counterfactual:
            findings.append(
                RiskFinding(
                    "COUNTERFACTUAL_EVIDENCE_MISSING",
                    "warnings",
                    "causal policy expects counterfactual or discriminating evidence",
                    "$.primary_hypothesis.predictions",
                )
            )

    design_version = doc.get("design_version", 1)
    if locked:
        if not _s(doc.get("locked_at")):
            findings.append(
                RiskFinding(
                    "LOCKED_AT_MISSING",
                    "errors",
                    "locked designs require locked_at",
                    "$.locked_at",
                )
            )
        history = list(doc.get("design_history") or [])
        if design_version > 1 and not any(
            isinstance(entry, dict) and entry.get("to_version") == design_version
            for entry in history
        ):
            append(
                "DESIGN_DRIFT_UNDISCLOSED",
                ("errors", "approval_blockers"),
                "design version changed without a matching design_history entry",
                "$.design_history",
            )
        for entry in history:
            if not isinstance(entry, dict):
                continue
            if entry.get("evidence_seen_before_change") and (
                entry.get("makes_primary_easier") is None
                or not _s(entry.get("old_design_result"))
            ):
                findings.append(
                    RiskFinding(
                        "POST_HOC_CRITERIA_RELAXATION",
                        "warnings",
                        "criteria changed after evidence was seen without a full record",
                        "$.design_history",
                    )
                )
            if not _s(entry.get("old_design_result")):
                findings.append(
                    RiskFinding(
                        "DESIGN_CHANGE_REVIEW",
                        "review_items",
                        "design change does not record the result under the old design",
                        "$.design_history",
                    )
                )
    else:
        for entry in doc.get("design_history") or []:
            if isinstance(entry, dict) and not _s(entry.get("old_design_result")):
                findings.append(
                    RiskFinding(
                        "DESIGN_CHANGE_REVIEW",
                        "review_items",
                        "design change does not record the result under the old design",
                        "$.design_history",
                    )
                )

    contribution = doc.get("contribution_type") or {}
    primary_contribution = contribution.get("primary")
    if primary_contribution == "negative_result" and not any(
        isinstance(branch, dict) and branch.get("retracts_primary")
        for branch in branches.values()
    ):
        append(
            "CONTRIBUTION_TYPE_MISMATCH",
            ("errors",),
            "negative_result contribution requires a retracting outcome branch",
            "$.contribution_type.primary",
        )
    if primary_contribution == "genealogical_explanation" and (
        not doc.get("diachronic_connection_evidence")
        or not any(
            item.get("evidence_role") in ("validation", "holdout") for item in materials
        )
    ):
        append(
            "CONTRIBUTION_TYPE_MISMATCH",
            ("errors",),
            "genealogical_explanation requires diachronic evidence and validation material",
            "$.contribution_type.primary",
        )
    if primary_contribution in ("textual_discovery", "source_discovery") and not any(
        item.get("evidence_role") in ("discovery", "validation") for item in materials
    ):
        append(
            "CONTRIBUTION_TYPE_MISMATCH",
            ("errors",),
            "discovery contributions require discovery or validation materials",
            "$.contribution_type.primary",
        )
    if primary_contribution == "dispute_adjudication" and len(rivals) < 2:
        append(
            "CONTRIBUTION_TYPE_MISMATCH",
            ("errors",),
            "dispute_adjudication expects at least two rival hypotheses",
            "$.contribution_type.primary",
        )

    for index, bridge in enumerate(doc.get("bridge_assessments") or []):
        if (
            isinstance(bridge, dict)
            and bridge.get("overall_strength") in ("high", "medium")
            and not bridge.get("dimensions")
        ):
            findings.append(
                RiskFinding(
                    "BRIDGE_STRENGTH_AGGREGATED",
                    "warnings",
                    "bridge strength is aggregated without a dimension breakdown",
                    f"$.bridge_assessments[{index}]",
                )
            )

    for index, criterion in enumerate(doc.get("operational_criteria") or []):
        if isinstance(criterion, dict) and not _s(criterion.get("exclusion_test")):
            findings.append(
                RiskFinding(
                    "CRITERIA_EXCLUSION_MISSING",
                    "review_items",
                    "operational criterion lacks an exclusion_test",
                    f"$.operational_criteria[{index}]",
                )
            )
    for index, rival in enumerate(rivals):
        if isinstance(rival, dict) and not _s(rival.get("simplicity_note")):
            findings.append(
                RiskFinding(
                    "RIVAL_SIMPLICITY_REVIEW",
                    "review_items",
                    "rival hypothesis lacks a simplicity_note",
                    f"$.rival_hypotheses[{index}].simplicity_note",
                )
            )

    findings.extend(
        _semantic_rules_1_1(
            doc=doc,
            level=level,
            locked=locked,
            materials=materials,
            controls=controls,
            branches=branches,
            primary=primary,
            rivals=rivals,
            results_doc=results_doc,
            adjudication_doc=adjudication_doc,
            design_sha256=design_sha256,
        )
    )
    return findings


def audit_research_risk(
    doc: dict[str, Any],
    *,
    source_path: str | None = None,
    input_bytes: bytes | None = None,
    results_doc: dict[str, Any] | None = None,
    adjudication_doc: dict[str, Any] | None = None,
) -> RiskAuditResult:
    if input_bytes is None:
        input_bytes = json.dumps(doc, sort_keys=True, ensure_ascii=False).encode("utf-8")
    digest = hashlib.sha256(input_bytes).hexdigest()
    canonical_design_sha256 = _canonical_design_hash(doc)
    problems = _validate_structure(doc)
    if results_doc is not None:
        problems.extend(_validate_sidecar_structure(results_doc, "results"))
    if adjudication_doc is not None:
        problems.extend(_validate_sidecar_structure(adjudication_doc, "adjudication"))
    findings: list[RiskFinding] = []
    if problems:
        for path, message in problems:
            findings.append(RiskFinding("SCHEMA_INVALID", "errors", message, path))
    else:
        enabled, level = _effective_policy(doc)
        if enabled and level != "none":
            findings.extend(
                _run_rules(
                    doc,
                    level,
                    results_doc=results_doc,
                    adjudication_doc=adjudication_doc,
                    design_sha256=canonical_design_sha256,
                )
            )
    hash_status = None
    if doc.get("design_status") == "locked" and (results_doc is not None or adjudication_doc is not None):
        mismatched = False
        for sidecar in (results_doc, adjudication_doc):
            if sidecar is not None and sidecar.get("design_sha256") != canonical_design_sha256:
                mismatched = True
        hash_status = "mismatch" if mismatched else "matched"
    return RiskAuditResult(
        document=doc,
        findings=tuple(findings),
        input_sha256=digest,
        source_path=source_path,
        design_sha256=canonical_design_sha256,
        design_hash_status=hash_status,
    )


def render_markdown(data: dict[str, Any]) -> str:
    lines = [
        "# research-risk-audit",
        "",
        f"- policy_version: {data['policy_version']}",
        f"- schema_version: {data['schema_version']}",
        f"- policy_level: {data['policy_level']}",
        f"- enabled: {data['enabled']}",
        f"- design_status: {data['design_status']}",
        f"- design_version: {data['design_version']}",
        f"- input_sha256: {data['input_sha256']}",
    ]
    if data.get("design_sha256") is not None:
        lines.append(f"- design_sha256: {data['design_sha256']}")
    if data.get("design_hash_status") is not None:
        lines.append(f"- design_hash_status: {data['design_hash_status']}")
    lines.append("")
    lines.append("## 摘要")
    lines.append("")
    summary = data["summary"]
    for bucket in _BUCKETS:
        lines.append(f"- {bucket}: {summary[bucket]}")
    lines.append("")
    for bucket in _BUCKETS:
        lines.append(f"## {bucket}")
        lines.append("")
        findings = data[bucket]
        if not findings:
            lines.append("无")
            lines.append("")
            continue
        for finding in findings:
            path = finding.get("path") or ""
            lines.append(f"- `{finding['rule_id']}` {finding['message']} ({path})")
            lines.append("")
    return "\n".join(lines).strip() + "\n"


def _cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit a research-risk.json study design sidecar"
    )
    parser.add_argument("input", help="research-risk.json file")
    parser.add_argument(
        "--results",
        default=None,
        metavar="RESULTS",
        help="research-risk-results.json sidecar",
    )
    parser.add_argument(
        "--adjudication",
        default=None,
        metavar="ADJUDICATION",
        help="research-risk-adjudication.json sidecar",
    )
    parser.add_argument(
        "--manifest",
        default=None,
        metavar="OUT",
        help="write the audit JSON result to OUT",
    )
    parser.add_argument(
        "--markdown",
        default=None,
        metavar="OUT",
        help="write a human-readable audit report to OUT",
    )
    parser.add_argument("--check", action="store_true", help="emit the audit result as JSON")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit with status 1 when errors or approval blockers are present",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _cli_parser().parse_args(argv)
    path = Path(args.input)
    try:
        raw = path.read_bytes()
        doc = json.loads(raw.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - report unreadable input as a schema error
        doc = {
            "schema_version": SCHEMA_VERSION,
            "enabled": True,
            "policy_level": "none",
            "design_version": 1,
            "design_status": "draft",
        }
        result = RiskAuditResult(
            document=doc,
            findings=(
                RiskFinding(
                    "SCHEMA_INVALID",
                    "errors",
                    f"cannot read input: {exc}",
                    "$",
                ),
            ),
            input_sha256=hashlib.sha256(b"").hexdigest(),
            source_path=str(path),
        )
    else:
        results_doc = None
        adjudication_doc = None
        if args.results:
            results_doc = json.loads(Path(args.results).read_bytes().decode("utf-8"))
        if args.adjudication:
            adjudication_doc = json.loads(
                Path(args.adjudication).read_bytes().decode("utf-8")
            )
        result = audit_research_risk(
            doc,
            source_path=str(path),
            input_bytes=raw,
            results_doc=results_doc,
            adjudication_doc=adjudication_doc,
        )
    data = result.as_dict()
    if args.manifest:
        Path(args.manifest).write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    if args.markdown:
        Path(args.markdown).write_text(render_markdown(data), encoding="utf-8")
    if args.check or (not args.manifest and not args.markdown):
        print(json.dumps(data, ensure_ascii=False, indent=2))
    if args.strict and (data["errors"] or data["approval_blockers"]):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
