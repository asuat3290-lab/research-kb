"""Pure deterministic bounded-iteration planning for MR-2A."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from ..contract import RolePacket, canonical_sha256, make_event_id
from ..contract.models import RehydrationPolicy
from .contracts import DeliberationCallSpec, RunnerPlan, RunnerProfile


_ROUND_TYPES = {"exploration", "adjudication", "attack", "rehydration", "acquisition_review", "cold_review"}
_CYCLE = {
    "": ("exploration", "socratic_exploration", "initial bounded exploration", "socratic"),
    "exploration": ("acquisition_review", "targeted_retrieval", "expand the current question with a new strategy", "source_auditor"),
    "acquisition_review": ("adjudication", "habermasian_adjudication", "compare independent positions", "adjudicator"),
    "adjudication": ("attack", "adversarial_attack", "attack the leading explanation", "rival"),
    "attack": ("acquisition_review", "targeted_retrieval", "retrieve against the adversarial gap", "source_auditor"),
    "rehydration": ("exploration", "socratic_exploration", "resume the bounded cognitive cycle", "socratic"),
    "cold_review": ("exploration", "socratic_exploration", "resume after a bounded review", "socratic"),
}


def _last_round(history: Sequence[Mapping[str, Any]]) -> str:
    if not history:
        return ""
    ordered = sorted(history, key=lambda item: (int(item.get("sequence_no", item.get("sequence", 0)) or 0), str(item.get("iteration_id", ""))))
    for item in reversed(ordered):
        if item.get("status") == "completed":
            return str(item.get("round_type", item.get("kind", "")))
    return ""


def _canonical_ids(state: Mapping[str, Any]) -> tuple[str, ...]:
    latest = state.get("latest_by_id", {})
    if isinstance(latest, Mapping):
        return tuple(sorted(str(item) for item in latest))
    objects = state.get("objects", ())
    return tuple(sorted(str(item.get("stable_id")) for item in objects if isinstance(item, Mapping) and item.get("stable_id")))


def build_plan(
    *,
    project_id: str,
    run_id: str,
    sequence: int,
    state: Mapping[str, Any],
    history: Sequence[Mapping[str, Any]] = (),
    profile: RunnerProfile,
    rehydration_policy: RehydrationPolicy | Mapping[str, Any] | None = None,
    recovery_required: bool = False,
    policy_triggers: Sequence[str] = (),
    budget_snapshot: Mapping[str, Any] | None = None,
    forced_round_type: str | None = None,
) -> RunnerPlan:
    """Return the same plan for the same immutable inputs.

    This function reads only supplied values.  It never consults a clock,
    creates a random nonce, opens a database, or calls an adapter.
    """

    if isinstance(rehydration_policy, Mapping):
        policy = RehydrationPolicy.from_mapping(rehydration_policy)
    else:
        policy = rehydration_policy or RehydrationPolicy()
    state_hash = str(state.get("state_hash", ""))
    if not state_hash:
        raise ValueError("planner requires an input Research State hash")
    last = _last_round(history)
    trigger_values = tuple(sorted(set(str(item) for item in policy_triggers)))
    interval_due = policy.interval_iterations > 0 and sequence > 1 and sequence % policy.interval_iterations == 0
    if forced_round_type is not None:
        forced = str(forced_round_type)
        forced_values = {
            "exploration": ("exploration", "socratic_exploration", "server bounded exploration", "socratic"),
            "socratic": ("exploration", "socratic_exploration", "server bounded Socratic exploration", "socratic"),
            "source_retrieval": ("acquisition_review", "targeted_retrieval", "server bounded source retrieval", "source_auditor"),
            "evidence_comparison": ("acquisition_review", "targeted_retrieval", "server bounded evidence comparison", "source_auditor"),
            "habermasian": ("adjudication", "habermasian_adjudication", "server bounded Habermasian adjudication", "adjudicator"),
            "adjudication": ("adjudication", "habermasian_adjudication", "server bounded adjudication", "adjudicator"),
            "attack": ("attack", "adversarial_attack", "server bounded adversarial attack", "rival"),
            "rehydration": ("rehydration", "rehydration_review", "server canonical rehydration boundary", "rehydrator"),
        }
        if forced not in forced_values:
            raise ValueError("server planner selected an unsupported long-run round")
        round_type, cognitive_kind, reason, primary_role = forced_values[forced]
    elif recovery_required or interval_due or any(item in policy.triggers for item in trigger_values):
        round_type, cognitive_kind, reason, primary_role = "rehydration", "rehydration_review", "canonical recovery/review boundary", "rehydrator"
    else:
        round_type, cognitive_kind, reason, primary_role = _CYCLE.get(last, _CYCLE[""])
    if round_type not in _ROUND_TYPES:
        raise ValueError("planner selected an unsupported persistence round type")
    ids = _canonical_ids(state)
    target_id = str(state.get("active_leading_hypothesis_id") or (ids[0] if ids else "research-question-placeholder"))
    basis = {"project_id": project_id, "run_id": run_id, "sequence": sequence, "state_hash": state_hash, "last_round": last, "round_type": round_type, "cognitive_kind": cognitive_kind, "reason": reason, "profile_hash": profile.profile_hash, "model_identity": profile.model_identity, "history": [dict(item) for item in history], "triggers": trigger_values, "budget": dict(budget_snapshot or {})}
    iteration_id = make_event_id("iteration", project_id, {"run_id": run_id, "sequence": sequence, "plan_basis": canonical_sha256(basis)})
    roles = (primary_role,)
    specs: tuple[DeliberationCallSpec, ...]
    if round_type == "adjudication":
        # Five independent logical calls are part of the frozen plan.  Only
        # the first two receive the canonical packet alone; later calls see
        # bounded, normalized public artifacts from the named predecessors.
        specs = (
            DeliberationCallSpec("lead_position", "lead_position", "lead", (), "canonical_packet", "position"),
            DeliberationCallSpec("rival_position", "rival_position", "rival", (), "canonical_packet", "position"),
            DeliberationCallSpec("rival_cross_examination", "rival_cross_examination", "rival", ("lead_position", "rival_position"), "public_positions", "cross_examination"),
            DeliberationCallSpec("lead_cross_examination_response", "lead_cross_examination_response", "lead", ("lead_position", "rival_position", "rival_cross_examination"), "public_positions_and_question", "correction"),
            DeliberationCallSpec("adjudicator", "adjudicator", "adjudicator", ("lead_position", "rival_position", "rival_cross_examination", "lead_cross_examination_response"), "canonical_and_public_packet", "adjudication"),
        )
        roles = tuple(spec.role for spec in specs)
    else:
        specs = (DeliberationCallSpec(f"{round_type}:primary", round_type, primary_role, (), "canonical_packet", round_type),)
    packets: list[RolePacket] = []
    for index, role in enumerate(roles):
        packet = RolePacket(project_id=project_id, run_id=run_id, state_hash=state_hash, target_id=target_id, role=role, allowed_canonical_ids=ids, model_identity=profile.model_identity, inference_profile_hash=profile.inference_profile.inference_profile_hash, forbidden_output_ids=(), sees_other_role_outputs=bool(specs[index].upstream_call_ids))
        packets.append(packet)
    metadata = {"planner_version": "mr-2a/v1", "history_count": len(history), "trigger_names": list(trigger_values), "budget_snapshot_hash": canonical_sha256(budget_snapshot or {})}
    if round_type == "rehydration":
        metadata.update({"cold_context": True, "excluded_sections": ["working_summary", "recent_summaries", "working_interpretation", "search_history", "search_history_narrative", "role_discussion_history"]})
    return RunnerPlan(project_id, run_id, sequence, state_hash, round_type, cognitive_kind, reason, profile.model_identity, profile.inference_profile.inference_profile_hash, iteration_id, tuple(packets), metadata, "", "", specs)


__all__ = ["build_plan"]
