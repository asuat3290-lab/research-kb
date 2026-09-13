from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import uuid
from pathlib import Path

from .admin import AdminService
from .catalog import run_catalog_scan
from .config import Settings
from .db import SCHEMA_VERSION
from .doctor import format_doctor_text, run_doctor
from .storage_check import run_storage_check
from .thesis_review import audit_review_dir, scaffold_review_dir
from .policy import Actor, PolicyError
from .max_research.admin import MaxAdminService
from .max_research.persistence import MaxControlError, MaxControlRepository
from .max_research.live_canary import LiveCanaryAuthorityStore
from .max_research.production_bridge import LiveCanaryExecutor
from .max_research.provider.store import ProviderStore
from .max_research.service import MaxAcquisitionService, MaxCanaryService, MaxProviderService, MaxRunnerService, MaxSchedulerService, MaxWorkerService, NativeLiveCanaryService, NativePreparationService, resolve_control_database
from .max_research.convergence import LiveExecutionCapsuleStore
from .max_research.portability import (
    AgentHostProfile,
    ExecutionBackendProfile,
    MaxPortabilityService,
    NormalizedAgentResult,
)
from .max_research.external_agent import ExternalAgentService
from .max_research.runner import FixtureResearchGateway, FixtureUsageAuthority, RunnerProfile, ScriptedFakeAdapter
from .max_research.provider import HermeticTransport, ProviderProfile, TransportResponse
from .max_research.scheduler import SchedulerPolicy


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="research-kb",
        description="Human-admin entry point for the research-kb framework.",
    )
    parser.add_argument("--config", default="config.toml", help="Path to config.toml")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("init", help="Create directories and apply database migrations")
    subcommands.add_parser("status", help="Run a read-only status and integrity check")
    doctor = subcommands.add_parser("doctor", help="Run a read-only system governance diagnosis")
    doctor.add_argument("--json", action="store_true", help="Emit deterministic machine-readable JSON")
    doctor.add_argument("--manifest", default=None, help="Optional system manifest TOML")
    doctor.add_argument("--strict", action="store_true", help="Return exit code 2 for warnings")
    doctor.add_argument("--deep", action="store_true", help="Run bounded declared-skill inventory checks")
    doctor.add_argument("--show-paths", action="store_true", help="Show local paths in administrator output")

    project = subcommands.add_parser("project", help="Manage research projects")
    project_commands = project.add_subparsers(dest="project_command", required=True)
    create = project_commands.add_parser("create")
    create.add_argument("--project-id", required=True)
    create.add_argument("--title", required=True)
    create.add_argument("--objective", required=True)
    project_commands.add_parser("list")
    archive = project_commands.add_parser("archive")
    archive.add_argument("--project-id", required=True)

    ingest = subcommands.add_parser("ingest", help="Ingest files from an explicit JSON manifest")
    ingest.add_argument("--project", required=True, dest="project_id")
    ingest.add_argument("--manifest", required=True)
    ingest.add_argument("--dry-run", action="store_true")

    metadata = subcommands.add_parser("metadata", help="Show or correct source metadata")
    metadata_commands = metadata.add_subparsers(dest="metadata_command", required=True)
    metadata_show = metadata_commands.add_parser("show")
    metadata_show.add_argument("--project", required=True, dest="project_id")
    metadata_show.add_argument("--document", required=True, dest="document_id")
    metadata_update = metadata_commands.add_parser("update")
    metadata_update.add_argument("--project", required=True, dest="project_id")
    metadata_update.add_argument("--document", required=True, dest="document_id")
    metadata_update.add_argument("--reason", required=True)
    metadata_update.add_argument(
        "--set",
        action="append",
        required=True,
        metavar="FIELD=VALUE",
        help="Repeat for each allowed metadata field",
    )

    approval = subcommands.add_parser("approval", help="List or decide human approvals")
    approval_commands = approval.add_subparsers(dest="approval_command", required=True)
    approval_list = approval_commands.add_parser("list")
    approval_list.add_argument("--project", dest="project_id")
    approval_list.add_argument("--status", choices=["pending", "approved", "rejected"])
    approval_decide = approval_commands.add_parser("decide")
    approval_decide.add_argument("--request-id", required=True)
    decision = approval_decide.add_mutually_exclusive_group(required=True)
    decision.add_argument("--approve", action="store_true")
    decision.add_argument("--reject", action="store_true")
    approval_decide.add_argument("--note", default="")

    backup = subcommands.add_parser("backup", help="Create and verify a SQLite backup")
    backup.add_argument("--output")
    restore = subcommands.add_parser("restore", help="Restore a backup to a separate database path")
    restore.add_argument("--input", required=True, dest="backup_path")
    restore.add_argument("--output", required=True)
    token = subcommands.add_parser("token", help="Manage expired verification tokens")
    token_commands = token.add_subparsers(dest="token_command", required=True)
    token_commands.add_parser("cleanup", help="Mark expired unconsumed tokens as terminal")
    subcommands.add_parser("reindex", help="Rebuild the derived lexical search index")

    max_control = subcommands.add_parser("max", help="Manage the independent Max Research control plane")
    max_control.add_argument("--database", dest="max_database", default=None, help="Explicit Max control database path")
    max_commands = max_control.add_subparsers(dest="max_command", required=True)
    max_init = max_commands.add_parser("init", help="Explicitly create/apply the Max control database")
    max_init.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_init.add_argument("--fixture", action="store_true", help="mark this newly created temporary database for simulate-next")
    max_propose = max_commands.add_parser("propose", help="Create an awaiting-approval Max Run")
    max_propose.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_propose.add_argument("--project", required=True, dest="project_id")
    charter_group = max_propose.add_mutually_exclusive_group(required=True)
    charter_group.add_argument("--charter", help="Path to canonical Charter JSON")
    charter_group.add_argument("--charter-json", help="Canonical Charter JSON text")
    max_approve = max_commands.add_parser("approve", help="Create and consume a human StartApproval")
    max_approve.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_approve.add_argument("--run-id", required=True)
    max_approve.add_argument("--charter-hash", required=True)
    max_approve.add_argument("--reason", required=True)
    max_approve.add_argument("--ttl-seconds", type=int, default=3600)
    max_start = max_commands.add_parser("start", help="Start an approved run and acquire its first lease")
    max_start.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_start.add_argument("--run-id", required=True)
    max_start.add_argument("--lease-ttl", type=int, default=60)
    max_pause = max_commands.add_parser("pause", help="Pause a running run")
    max_pause.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_pause.add_argument("--run-id", required=True)
    max_pause.add_argument("--fencing-token", required=True, type=int)
    max_resume = max_commands.add_parser("resume", help="Resume a paused run")
    max_resume.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_resume.add_argument("--run-id", required=True)
    max_resume.add_argument("--fencing-token", required=False, type=int, default=None, help="optional legacy token; paused resume is checked against explicit expectations")
    max_resume.add_argument("--expected-state-version", type=int, default=None)
    max_resume.add_argument("--expected-checkpoint-id", default=None)
    max_resume.add_argument("--expected-state-hash", default=None)
    max_resume.add_argument("--lease-ttl", type=int, default=60)
    max_cancel = max_commands.add_parser("cancel", help="Cancel a run")
    max_cancel.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_cancel.add_argument("--run-id", required=True)
    max_cancel.add_argument("--fencing-token", type=int, default=None)
    max_status = max_commands.add_parser("status", help="Read a redacted Max Run status")
    max_status.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_status.add_argument("--run-id", required=True)
    max_events = max_commands.add_parser("events", help="Read redacted cursor-paginated events")
    max_events.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_events.add_argument("--run-id", required=True)
    max_events.add_argument("--cursor", type=int, default=0)
    max_events.add_argument("--limit", type=int, default=50)
    max_verify = max_commands.add_parser("verify", help="Verify chain, graph, checkpoints and budget")
    max_verify.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_verify.add_argument("--run-id", required=True)
    max_register = max_commands.add_parser("register-profile", help="Register an immutable bounded runner profile")
    max_register.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    profile_group = max_register.add_mutually_exclusive_group(required=True)
    profile_group.add_argument("--profile", dest="profile_file")
    profile_group.add_argument("--profile-json", dest="profile_json")
    max_handoff = max_commands.add_parser("handoff", help="Explicitly hand an approved Run to a non-admin runner")
    max_handoff.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_handoff.add_argument("--run-id", required=True)
    max_handoff.add_argument("--runner-id", required=True)
    max_handoff.add_argument("--runner-session", required=True)
    max_handoff.add_argument("--runner-kind", choices=["runner", "agent", "worker"], default="runner")
    max_handoff.add_argument("--admin-fencing-token", type=int, default=None)
    max_handoff.add_argument("--lease-ttl", type=int, default=60)
    handoff_profile_group = max_handoff.add_mutually_exclusive_group(required=True)
    handoff_profile_group.add_argument("--profile", dest="profile_file")
    handoff_profile_group.add_argument("--profile-json", dest="profile_json")
    max_run_next = max_commands.add_parser("run-next", help="Advance exactly one bounded runner iteration")
    max_run_next.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_run_next.add_argument("--run-id", required=True)
    max_run_next.add_argument("--runner-id", required=True)
    max_run_next.add_argument("--runner-session", required=True)
    max_run_next.add_argument("--runner-kind", choices=["runner", "agent", "worker"], default="runner")
    max_run_next.add_argument("--lease-ttl", type=int, default=60)
    run_profile_group = max_run_next.add_mutually_exclusive_group(required=True)
    run_profile_group.add_argument("--profile", dest="profile_file")
    run_profile_group.add_argument("--profile-json", dest="profile_json")
    max_simulate_next = max_commands.add_parser("simulate-next", help="Advance one explicitly marked temporary fixture iteration")
    max_simulate_next.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_simulate_next.add_argument("--run-id", required=True)
    max_simulate_next.add_argument("--runner-id", required=True)
    max_simulate_next.add_argument("--runner-session", required=True)
    max_simulate_next.add_argument("--runner-kind", choices=["runner", "agent", "worker"], default="runner")
    max_simulate_next.add_argument("--lease-ttl", type=int, default=60)
    max_simulate_next.add_argument("--fixture", action="store_true", required=True)
    simulate_profile_group = max_simulate_next.add_mutually_exclusive_group(required=True)
    simulate_profile_group.add_argument("--profile", dest="profile_file")
    simulate_profile_group.add_argument("--profile-json", dest="profile_json")
    max_runner_status = max_commands.add_parser("runner-status", help="Read bounded runner recovery status")
    max_runner_status.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_runner_status.add_argument("--run-id", required=True)
    max_ambiguous = max_commands.add_parser("ambiguous-decision", help="Record an explicit admin decision for an ambiguous call")
    max_ambiguous.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_ambiguous.add_argument("--run-id", required=True)
    max_ambiguous.add_argument("--logical-call-id", required=True)
    max_ambiguous.add_argument("--decision", choices=["retry", "abort", "accept"], required=True)

    max_provider_validate = max_commands.add_parser("provider-validate", help="Strictly validate an MR-2B0 provider profile without persisting it")
    max_provider_validate.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    provider_validate_group = max_provider_validate.add_mutually_exclusive_group(required=True)
    provider_validate_group.add_argument("--profile", dest="provider_profile_file")
    provider_validate_group.add_argument("--profile-json", dest="provider_profile_json")
    max_provider_register = max_commands.add_parser("provider-register", help="Register an immutable provider profile and pricing snapshot")
    max_provider_register.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    provider_register_group = max_provider_register.add_mutually_exclusive_group(required=True)
    provider_register_group.add_argument("--profile", dest="provider_profile_file")
    provider_register_group.add_argument("--profile-json", dest="provider_profile_json")
    max_provider_show = max_commands.add_parser("provider-show", help="Show a redacted provider profile")
    max_provider_show.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_provider_show.add_argument("--profile-hash", default=None)
    max_provider_show.add_argument("--profile-id", default=None)
    max_provider_show.add_argument("--profile-version", default=None)
    max_provider_bind = max_commands.add_parser("provider-bind", help="Bind one immutable provider profile to a Max Run")
    max_provider_bind.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_provider_bind.add_argument("--run-id", required=True)
    max_provider_bind.add_argument("--profile-hash", required=True)
    max_grant = max_commands.add_parser("grant-live", help="Issue a one-time hermetic execution grant")
    max_grant.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_grant.add_argument("--run-id", required=True)
    max_grant.add_argument("--profile-hash", required=True)
    max_grant.add_argument("--caps-json", required=True)
    max_grant.add_argument("--reason", required=True)
    max_grant.add_argument("--ttl-seconds", type=int, default=3600)
    max_grant_status = max_commands.add_parser("grant-status", help="Read redacted execution grant status")
    max_grant_status.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_grant_status.add_argument("--run-id", required=True)
    max_consume_grant = max_commands.add_parser("consume-live-grant", help="Consume an admin-issued live grant before creating network authorities")
    max_consume_grant.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_consume_grant.add_argument("--run-id", required=True)
    max_consume_grant.add_argument("--grant-id", required=True)
    max_authorize_live = max_commands.add_parser("authorize-live", help="Issue one bounded live-network authority without connecting")
    max_authorize_live.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_authorize_live.add_argument("--run-id", required=True)
    max_authorize_live.add_argument("--grant-id", required=True)
    max_authorize_live.add_argument("--profile-hash", default=None)
    max_authorize_live.add_argument("--caps-json", required=True)
    max_authorize_live.add_argument("--network-policy-json", required=True)
    max_authorize_live.add_argument("--reason", required=True)
    max_authorize_live.add_argument("--ttl-seconds", type=int, default=900)
    max_live_preflight = max_commands.add_parser("provider-live-preflight", help="Read-only static live-provider authorization preflight; never resolves or probes")
    max_live_preflight.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_live_preflight.add_argument("--run-id", required=True)
    max_live_preflight.add_argument("--authorization-id", default=None)
    max_live_preflight.add_argument("--grant-id", default=None)
    max_network_policy = max_commands.add_parser("provider-network-policy-show", help="Show a stored redacted live network policy")
    max_network_policy.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_network_policy.add_argument("--network-policy-hash", required=True)
    max_network_policy_register = max_commands.add_parser("provider-network-policy-register", help="Register one immutable reviewed live network policy")
    max_network_policy_register.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_network_policy_register.add_argument("--network-policy-json", required=True)
    max_live_auth_status = max_commands.add_parser("live-authorization-status", help="Read redacted live-network authorization status")
    max_live_auth_status.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_live_auth_status.add_argument("--run-id", required=True)
    max_live_auth_status.add_argument("--authorization-id", default=None)
    max_revoke_live = max_commands.add_parser("revoke-live-authorization", help="Revoke an active live-network authorization")
    max_revoke_live.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_revoke_live.add_argument("--authorization-id", required=True)
    max_revoke_live.add_argument("--reason", required=True)
    max_expire_live = max_commands.add_parser("expire-live-authorization", help="Expire an already expired live-network authorization")
    max_expire_live.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_expire_live.add_argument("--authorization-id", required=True)
    max_expire_live.add_argument("--reason", default="expired by admin")
    max_bundle_create = max_commands.add_parser("live-bundle-create", help="Create an ordered immutable live-authorization bundle")
    max_bundle_create.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_bundle_create.add_argument("--run-id", required=True)
    max_bundle_create.add_argument("--grant-id", required=True)
    max_bundle_create.add_argument("--authorization-id", action="append", required=True)
    max_bundle_status = max_commands.add_parser("live-bundle-status", help="Read redacted live bundle status")
    max_bundle_status.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_bundle_status.add_argument("--run-id", required=True)
    max_bundle_status.add_argument("--bundle-id", default=None)
    max_bundle_revoke = max_commands.add_parser("revoke-live-bundle", help="Revoke an unexhausted live bundle")
    max_bundle_revoke.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_bundle_revoke.add_argument("--bundle-id", required=True)
    max_bundle_revoke.add_argument("--reason", required=True)
    max_iteration_approve = max_commands.add_parser("live-iteration-approve", help="Approve exactly the next bounded live iteration")
    max_iteration_approve.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_iteration_approve.add_argument("--run-id", required=True)
    max_iteration_approve.add_argument("--grant-id", required=True)
    max_iteration_approve.add_argument("--bundle-id", required=True)
    max_iteration_approve.add_argument("--provider-profile-hash", required=True)
    max_iteration_approve.add_argument("--runner-profile-hash", required=True)
    max_iteration_approve.add_argument("--reason", required=True)
    max_iteration_approve.add_argument("--ttl-seconds", type=int, default=900)
    max_iteration_approval_status = max_commands.add_parser("live-iteration-approval-status", help="Read one-iteration approval status")
    max_iteration_approval_status.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_iteration_approval_status.add_argument("--run-id", required=True)
    max_live_smoke = max_commands.add_parser("provider-live-smoke", help="Prepare a fixed offline live-provider smoke request")
    max_live_smoke.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_live_smoke.add_argument("--run-id", required=True)
    max_live_smoke.add_argument("--authorization-id", required=True)
    max_live_smoke.add_argument("--authorization-hash", required=True)
    max_live_smoke.add_argument("--profile-hash", required=True)
    max_live_smoke.add_argument("--execute", action="store_true", help="Explicit execution flag; production network execution remains disabled in MR-2B1A")
    max_scheduler_tick = max_commands.add_parser("scheduler-tick", help="Execute exactly one hermetic bounded runner tick")
    max_scheduler_tick.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_scheduler_tick.add_argument("--run-id", required=True)
    max_scheduler_tick.add_argument("--grant-id", required=True)
    max_scheduler_tick.add_argument("--worker-id", required=True)
    max_scheduler_tick.add_argument("--worker-session", required=True)
    max_scheduler_tick.add_argument("--response-json", required=True, help="Injected hermetic provider response JSON")
    max_scheduler_tick.add_argument("--policy-json", default=None)
    max_scheduler_tick.add_argument("--profile", dest="provider_profile_file", required=False)
    max_scheduler_tick.add_argument("--profile-json", dest="provider_profile_json", required=False)
    max_scheduler_tick.add_argument("--lease-ttl", type=int, default=300)
    max_scheduler_run = max_commands.add_parser("scheduler-run-bounded", help="Execute a frozen finite number of hermetic scheduler ticks")
    max_scheduler_run.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_scheduler_run.add_argument("--run-id", required=True)
    max_scheduler_run.add_argument("--grant-id", required=True)
    max_scheduler_run.add_argument("--worker-id", required=True)
    max_scheduler_run.add_argument("--worker-session", required=True)
    max_scheduler_run.add_argument("--response-json", required=True)
    max_scheduler_run.add_argument("--max-ticks", required=True, type=int)
    max_scheduler_run.add_argument("--policy-json", default=None)
    max_scheduler_run.add_argument("--profile", dest="provider_profile_file", required=False)
    max_scheduler_run.add_argument("--profile-json", dest="provider_profile_json", required=False)
    max_scheduler_run.add_argument("--lease-ttl", type=int, default=300)
    max_scheduler_status = max_commands.add_parser("scheduler-status", help="Read scheduler ticks and current pointer")
    max_scheduler_status.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_scheduler_status.add_argument("--run-id", required=True)
    max_scheduler_verify = max_commands.add_parser("scheduler-verify", help="Verify scheduler policy, tick and pointer hashes")
    max_scheduler_verify.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_scheduler_verify.add_argument("--run-id", required=True)
    max_worker_command = max_commands.add_parser("worker-command", help="Issue a durable pause, drain, or stop command")
    max_worker_command.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_worker_command.add_argument("--run-id", required=True)
    max_worker_command.add_argument("--action", choices=["pause", "drain", "stop"], required=True)
    max_worker_command.add_argument("--reason", required=True)
    max_worker_status = max_commands.add_parser("worker-status", help="Read durable foreground-worker status")
    max_worker_status.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_worker_status.add_argument("--run-id", required=True)
    max_worker_verify = max_commands.add_parser("worker-verify", help="Verify worker commands, heartbeats, and projection")
    max_worker_verify.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_worker_verify.add_argument("--run-id", default=None)
    max_acquisition_propose = max_commands.add_parser("acquisition-propose", help="Persist a typed acquisition request; never downloads")
    max_acquisition_propose.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    acquisition_input = max_acquisition_propose.add_mutually_exclusive_group(required=True)
    acquisition_input.add_argument("--request", dest="acquisition_request_file")
    acquisition_input.add_argument("--request-json", dest="acquisition_request_json")
    max_acquisition_decide = max_commands.add_parser("acquisition-decision", help="Approve, reject, cancel, or accept a validated acquisition")
    max_acquisition_decide.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_acquisition_decide.add_argument("--request-id", required=True)
    max_acquisition_decide.add_argument("--decision", choices=["approve", "reject", "cancel", "accept"], required=True)
    max_acquisition_decide.add_argument("--reason", required=True)
    max_acquisition_decide.add_argument("--validation-hash", default=None)
    max_acquisition_decide.add_argument("--dry-run-manifest-hash", default=None)
    max_acquisition_authorize = max_commands.add_parser("acquisition-authorize-worker", help="Issue one bounded acquisition-worker grant")
    max_acquisition_authorize.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_acquisition_authorize.add_argument("--request-id", required=True)
    max_acquisition_authorize.add_argument("--worker-id", required=True)
    max_acquisition_authorize.add_argument("--worker-session", required=True)
    max_acquisition_authorize.add_argument("--max-candidates", type=int, required=True)
    max_acquisition_authorize.add_argument("--max-bytes", type=int, required=True)
    max_acquisition_authorize.add_argument("--ttl-seconds", type=int, default=3600)
    max_acquisition_authorize.add_argument("--reason", required=True)
    max_acquisition_claim = max_commands.add_parser("acquisition-claim", help="Consume an exact acquisition-worker grant")
    max_acquisition_claim.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_acquisition_claim.add_argument("--request-id", required=True)
    max_acquisition_claim.add_argument("--worker-grant-id", required=True)
    max_acquisition_claim.add_argument("--worker-id", required=True)
    max_acquisition_claim.add_argument("--worker-session", required=True)
    max_acquisition_validate = max_commands.add_parser("acquisition-validate-stage", help="Independently validate an isolated staging directory; never ingests")
    max_acquisition_validate.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_acquisition_validate.add_argument("--request-id", required=True)
    max_acquisition_validate.add_argument("--claim-id", required=True)
    max_acquisition_validate.add_argument("--staging-run", required=True)
    max_acquisition_validate.add_argument("--existing-content-hash", action="append", default=[])
    max_acquisition_status = max_commands.add_parser("acquisition-status", help="Read redacted acquisition states")
    max_acquisition_status.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_acquisition_status.add_argument("--run-id", required=True)
    max_acquisition_status.add_argument("--request-id", default=None)
    max_acquisition_verify = max_commands.add_parser("acquisition-verify", help="Verify acquisition authority and receipt chains")
    max_acquisition_verify.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_acquisition_verify.add_argument("--run-id", default=None)

    # Versioned control-plane discovery for already-running external Agents.
    # This is intentionally a CLI control surface, not a new researcher MCP
    # tool and not a provider/model dispatcher.
    max_external_agent_discover = max_commands.add_parser(
        "external-agent-discover",
        help="Describe the governed external-Agent work protocol",
    )
    max_external_agent_discover.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)

    # MR-4B1A one-shot Canary administration.  Transport remains disabled by
    # default; execute requires a separate explicit flag and all server-side
    # bindings.  This round's offline commands never pass that flag.
    max_canary_preview = max_commands.add_parser("live-canary-preview", help="Read-only deterministic live-Canary preview")
    max_canary_preview.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_canary_preview.add_argument("--value-json", required=False, help="Explicit hash-only preview binding JSON (fixture/legacy seam)")
    max_canary_preview.add_argument("--authority-id", default=None, help="Rebuild Preview from a server-owned MR-4B1A authority binding")
    max_canary_preview.add_argument("--fixture", action="store_true", help="Allow only an explicitly marked fixture database")
    max_canary_prepare = max_commands.add_parser("live-canary-prepare-intent", help="Prepare one server-owned unfinished model intent without execution")
    max_canary_prepare.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_canary_prepare.add_argument("--run-id", required=True)
    max_canary_prepare.add_argument("--provider-profile-hash", required=True)
    max_canary_prepare.add_argument("--source-egress-policy-hash", required=True)
    max_canary_prepare.add_argument("--candidate-wheel-sha256", required=True)
    max_canary_prepare.add_argument("--source-manifest-sha256", required=True)
    max_canary_prepare.add_argument("--source-tree-sha256", required=True)
    max_canary_prepare.add_argument("--engine-version", required=True)
    max_canary_prepare.add_argument("--caps-json", required=True)
    max_canary_snapshot = max_commands.add_parser("live-canary-snapshot-create", help="Create a durable non-executable MR-4B1B-v11R1 preparation Snapshot")
    max_canary_snapshot.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_canary_snapshot.add_argument("--run-id", required=True)
    max_canary_snapshot.add_argument("--source-binding-json", required=True)
    max_canary_snapshot.add_argument("--preparation-json", required=True)
    max_canary_snapshot.add_argument("--caps-json", required=True)
    max_canary_snapshot.add_argument("--release-identity-json", required=True)
    max_canary_snapshot.add_argument("--review-ttl-seconds", type=int, default=7 * 24 * 3600)
    max_canary_snapshot_status = max_commands.add_parser("live-canary-snapshot-status", help="Read a redacted v11R1 preparation Snapshot status")
    max_canary_snapshot_status.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_canary_snapshot_status.add_argument("--snapshot-id", required=True)
    max_canary_snapshot_status.add_argument("--release-identity-json", default=None)
    max_canary_preview_snapshot = max_commands.add_parser("live-canary-preview-from-snapshot", help="Create a human-review Preview from a durable Snapshot")
    max_canary_preview_snapshot.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_canary_preview_snapshot.add_argument("--snapshot-id", required=True)
    max_canary_preview_snapshot.add_argument("--dns-policy-json", required=True)
    max_canary_preview_snapshot.add_argument("--review-ttl-seconds", type=int, default=7 * 24 * 3600)
    max_canary_dns_request = max_commands.add_parser("live-canary-dns-request", help="Create a DNS-only request; never performs DNS")
    max_canary_dns_request.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_canary_dns_request.add_argument("--preview-id", required=True)
    max_canary_dns_request.add_argument("--ttl-seconds", type=int, default=24 * 3600)
    max_preparation_handoff = max_commands.add_parser("preparation-handoff", help="Atomically hand preparation authority to a durable human-wait state")
    max_preparation_handoff.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_preparation_handoff.add_argument("--run-id", required=True)
    max_preparation_handoff.add_argument("--snapshot-id", required=True)
    max_preparation_handoff.add_argument("--preview-id", required=True)
    max_preparation_handoff.add_argument("--dns-authority-id", required=True)
    max_preparation_handoff.add_argument("--dns-request-id", required=True)
    max_preparation_handoff.add_argument("--preparation-claim-id", required=True)
    max_preparation_handoff.add_argument("--fencing-token", required=True, type=int)
    max_preparation_handoff.add_argument("--worker-id", required=True)
    max_preparation_handoff.add_argument("--worker-session", required=True)
    max_preparation_handoff.add_argument("--worker-kind", choices=["worker", "runner", "agent"], default="worker")
    max_preparation_handoff.add_argument("--reservation-id", default=None)
    max_preparation_close = max_commands.add_parser("preparation-handoff-close", help="Close a waiting preparation handoff without execution authority")
    max_preparation_close.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_preparation_close.add_argument("--run-id", required=True)
    max_preparation_close.add_argument("--handoff-id", default=None)
    max_preparation_close.add_argument("--state", choices=["CANCELLED", "EXPIRED", "CLOSED"], required=True)
    max_preparation_close.add_argument("--reason", required=True)
    # MR-CONVERGENCE-DEV18 compact, server-owned capsule surface.  The
    # caller selects only the preparation Preview or capsule hash; all
    # internal DNS/approval/JIT records are created and consumed by the
    # package-owned control flow.
    max_capsule_preflight = max_commands.add_parser("canary-preflight", help="Create one bounded Live Execution Capsule Preview")
    max_capsule_preflight.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_capsule_preflight.add_argument("--preview-id", required=True, dest="capsule_preparation_preview_id")
    max_capsule_preflight.add_argument("--ttl-seconds", type=int, default=86_400)
    max_capsule_execute = max_commands.add_parser("canary-execute", help="Consume and execute one bounded Live Execution Capsule")
    max_capsule_execute.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_capsule_execute.add_argument("--capsule-hash", required=True)
    max_capsule_execute.add_argument("--confirmation", "--confirmation-phrase", required=True, dest="capsule_confirmation")
    # MR-4B1B-v12R1 native Preparation -> JIT bridge.  These commands are
    # deliberately separate from the legacy live-canary authority lifecycle.
    max_native_dns_receipt = max_commands.add_parser("live-canary-snapshot-dns-receipt", help="Persist one bounded DNS result; never performs DNS")
    max_native_dns_receipt.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_native_dns_receipt.add_argument("--preview-id", required=True)
    max_native_dns_receipt.add_argument("--request-id", default=None)
    max_native_dns_receipt.add_argument("--bounded-result-json", required=True)
    max_dns_execute = max_commands.add_parser("live-canary-snapshot-dns-execute", help="Execute one server-owned DNS attempt; requires explicit --execute")
    max_dns_execute.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_dns_execute.add_argument("--preview-id", required=True)
    max_dns_execute.add_argument("--request-id", required=True)
    max_dns_execute.add_argument("--confirmation-phrase", required=True)
    max_dns_execute.add_argument("--execute", action="store_true", help="Required explicit resolver boundary")
    max_dns_recover = max_commands.add_parser("live-canary-snapshot-dns-recover", help="Close an interrupted DNS attempt as unknown without retry")
    max_dns_recover.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_dns_recover.add_argument("--attempt-id", required=True)
    max_dns_recover.add_argument("--reason", default="recovery_after_resolver_start")
    max_dns_status = max_commands.add_parser("live-canary-snapshot-dns-status", help="Read redacted v14R3 DNS attempt status")
    max_dns_status.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_dns_status.add_argument("--attempt-id", default=None)
    max_dns_status.add_argument("--request-id", default=None)
    max_dns_verify = max_commands.add_parser("live-canary-snapshot-dns-verify", help="Verify one v14R3 DNS attempt chain")
    max_dns_verify.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_dns_verify.add_argument("--attempt-id", required=True)
    max_approval_preview = max_commands.add_parser("live-canary-snapshot-approval-preview", help="Create one server-owned Live Canary Approval Preview without creating Approval")
    max_approval_preview.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_approval_preview.add_argument("--preview-id", required=True, help="Server-owned Preparation Preview selector")
    max_approval_preview.add_argument("--preview-ttl-seconds", type=int, default=3600)
    max_approval_preview.add_argument("--approval-ttl-seconds", type=int, default=3600)
    max_native_authorize = max_commands.add_parser("live-canary-snapshot-authorize", help="Create one Native Approval from a server-owned Live Approval Preview")
    max_native_authorize.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_native_authorize.add_argument("--approval-preview-id", default=None)
    max_native_authorize.add_argument("--preview-id", default=None, help="Deprecated Preparation Preview selector; always rejected")
    max_native_authorize.add_argument("--confirmation-phrase", required=True)
    max_native_authorize.add_argument("--expires-at", default=None, help="Deprecated client expiry; always rejected")
    max_native_execute = max_commands.add_parser("live-canary-snapshot-execute", help="Consume native approval, create JIT, and execute only an injected hermetic transport")
    max_native_execute.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_native_execute.add_argument("--authority-id", required=False)
    max_native_execute.add_argument("--preview-id", required=False)
    max_native_execute.add_argument("--execute", action="store_true", help="Required explicit execution flag")
    max_native_execute.add_argument("--response-json", default=None, help="Optional local hermetic fixture response; never enables network transport")
    max_native_status = max_commands.add_parser("live-canary-snapshot-native-status", help="Read redacted native Preparation/JIT status")
    max_native_status.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_native_status.add_argument("--preview-id", default=None)
    max_native_status.add_argument("--run-id", default=None)
    max_native_status.add_argument("--authority-id", default=None)
    max_live_preview = max_commands.add_parser("live-canary-snapshot-execution-preview", aliases=["live-canary-snapshot-live-preview"], help="Create one server-owned execution authorization Preview after Human Live Approval")
    max_live_preview.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_live_preview.add_argument("--approval-id", required=True, help="Server-owned v2 Human Live Approval selector")
    max_live_preview.add_argument("--ttl-seconds", type=int, default=900)
    max_live_authorize = max_commands.add_parser("live-canary-snapshot-execution-authorize", aliases=["live-canary-snapshot-live-authorize"], help="Create one server-owned execution authorization from an exact execution phrase")
    max_live_authorize.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_live_authorize.add_argument("--execution-preview-id", required=True)
    max_live_authorize.add_argument("--confirmation-phrase", required=True)
    max_live_execute = max_commands.add_parser("live-canary-snapshot-execution", aliases=["live-canary-snapshot-live-execute"], help="Execute exactly one explicitly authorized production live iteration")
    max_live_execute.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_live_execute.add_argument("--execution-authorization-id", required=True)
    max_live_execute.add_argument("--execution-authorization-hash", required=True)
    max_live_execute.add_argument("--execute", action="store_true", help="Required explicit production send boundary")
    max_live_status = max_commands.add_parser("live-canary-snapshot-execution-status", aliases=["live-canary-snapshot-live-status"], help="Read redacted Native live execution status")
    max_live_status.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_live_status.add_argument("--execution-preview-id", default=None)
    max_live_status.add_argument("--execution-authorization-id", default=None)
    max_live_status.add_argument("--run-id", default=None)
    max_live_verify = max_commands.add_parser("live-canary-snapshot-execution-verify", aliases=["live-canary-snapshot-live-verify"], help="Verify Native live execution bridge chains")
    max_live_verify.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_live_verify.add_argument("--run-id", default=None)
    max_canary_preflight = max_commands.add_parser("live-canary-preflight", help="Read-only live-Canary authority preflight")
    max_canary_preflight.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_canary_preflight.add_argument("--authority-id", default=None)
    max_canary_preflight.add_argument("--preview-id", default=None)
    max_canary_preflight.add_argument("--run-id", default=None)
    max_canary_authorize = max_commands.add_parser("live-canary-authorize", help="Consume one explicit human approval for a fresh MR-4B1 Preview")
    max_canary_authorize.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_canary_authorize.add_argument("--preview-id", required=True)
    max_canary_authorize.add_argument("--preview-hash", required=True)
    max_canary_authorize.add_argument("--confirmation-phrase", required=True)
    max_canary_authorize.add_argument("--expires-at", required=True)
    max_canary_authorize.add_argument("--reason", required=True)
    max_canary_authorize.add_argument("--fixture", action="store_true", help="Allow only an explicitly marked fixture database")
    max_canary_status = max_commands.add_parser("live-canary-status", help="Read redacted live-Canary status")
    max_canary_status.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_canary_status.add_argument("--authority-id", default=None)
    max_canary_status.add_argument("--preview-id", default=None)
    max_canary_status.add_argument("--run-id", default=None)
    max_canary_revoke = max_commands.add_parser("live-canary-revoke", help="Revoke an active MR-4B1 Canary approval before transport")
    max_canary_revoke.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_canary_revoke.add_argument("--approval-id", required=True)
    max_canary_revoke.add_argument("--reason", required=True)
    max_canary_revoke.add_argument("--fixture", action="store_true", help="Allow only an explicitly marked fixture database")
    max_canary_execute = max_commands.add_parser("live-canary-execute", help="Execute one explicitly authorized physical Canary call; transport is disabled by default")
    max_canary_execute.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_canary_execute.add_argument("--authority-id", required=True)
    max_canary_execute.add_argument("--approval-id", required=True)
    max_canary_execute.add_argument("--execute", action="store_true", help="Required explicit execution flag; production transport still needs separate release enablement")
    max_canary_reconcile = max_commands.add_parser("live-canary-reconcile", help="Human-gated read-only reconciliation of an unknown Canary outcome")
    max_canary_reconcile.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_canary_reconcile.add_argument("--permit-id", required=True)
    max_canary_reconcile.add_argument("--confirmation-phrase", required=True)
    max_canary_reconcile.add_argument("--reconcile", action="store_true", help="Explicit human reconciliation permission")

    # MR-4A offline control-plane commands.  These are admin/read-only CLI
    # surfaces only; no MCP tool or live provider execution path is added.
    max_lr_preview = max_commands.add_parser("long-run-preview", help="Read-only preview of a bounded long-run window")
    max_lr_preview.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_lr_preview.add_argument("--run-id", required=True)
    max_lr_preview.add_argument("--source-egress-policy-hash", required=True)
    max_lr_preview.add_argument("--caps-json", required=True)
    max_lr_preview.add_argument("--not-before", required=True)
    max_lr_preview.add_argument("--expires-at", required=True)
    max_lr_authorize = max_commands.add_parser("long-run-authorize", help="Authorize one bounded long-run window after exact confirmation")
    max_lr_authorize.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_lr_authorize.add_argument("--run-id", required=True)
    max_lr_authorize.add_argument("--source-egress-policy-hash", required=True)
    max_lr_authorize.add_argument("--caps-json", required=True)
    max_lr_authorize.add_argument("--not-before", required=True)
    max_lr_authorize.add_argument("--expires-at", required=True)
    max_lr_authorize.add_argument("--confirmation-hash", required=True)
    max_lr_status = max_commands.add_parser("long-run-status", help="Read redacted long-run window status")
    max_lr_status.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_lr_status.add_argument("--run-id", default=None)
    max_lr_status.add_argument("--window-id", default=None)
    max_lr_renew = max_commands.add_parser("long-run-renew", help="Issue an explicit append-only long-run successor")
    max_lr_renew.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_lr_renew.add_argument("--window-id", required=True)
    max_lr_renew.add_argument("--caps-json", required=True)
    max_lr_renew.add_argument("--not-before", required=True)
    max_lr_renew.add_argument("--expires-at", required=True)
    max_lr_renew.add_argument("--confirmation-hash", required=True)
    max_lr_renew.add_argument("--reason", required=True)
    max_lr_renew.add_argument("--source-egress-policy-hash", default=None)
    max_lr_renew_preview = max_commands.add_parser("long-run-renew-preview", help="Read-only preview of an append-only long-run successor")
    max_lr_renew_preview.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_lr_renew_preview.add_argument("--window-id", required=True)
    max_lr_renew_preview.add_argument("--caps-json", required=True)
    max_lr_renew_preview.add_argument("--not-before", required=True)
    max_lr_renew_preview.add_argument("--expires-at", required=True)
    max_lr_renew_preview.add_argument("--reason", required=True)
    max_lr_renew_preview.add_argument("--source-egress-policy-hash", default=None)
    max_lr_control = max_commands.add_parser("long-run-control", help="Pause, drain, stop, revoke or resume a long-run window")
    max_lr_control.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_lr_control.add_argument("--window-id", required=True)
    max_lr_control.add_argument("--action", choices=["pause", "resume", "drain", "stop", "revoke", "expire"], required=True)
    max_lr_control.add_argument("--reason", required=True)
    max_lr_verify = max_commands.add_parser("long-run-verify", help="Verify long-run permit and event chains")
    max_lr_verify.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_lr_verify.add_argument("--run-id", default=None)
    max_egress_policy = max_commands.add_parser("source-egress-policy", help="Persist one explicit canonical source-egress policy")
    max_egress_policy.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_egress_policy.add_argument("--run-id", required=True)
    max_egress_policy.add_argument("--policy-json", required=True)
    max_egress_preflight = max_commands.add_parser("source-egress-preflight", help="Read-only source-egress boundary preflight")
    max_egress_preflight.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_egress_preflight.add_argument("--policy-id", required=True)
    max_egress_preflight.add_argument("--purpose", required=True)
    max_egress_preflight.add_argument("--passage-id", required=True)
    max_egress_preflight.add_argument("--source-role", required=True)
    max_egress_preflight.add_argument("--evidential-function", required=True)
    max_egress_status = max_commands.add_parser("source-egress-status", help="Read redacted source-egress policy status")
    max_egress_status.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_egress_status.add_argument("--run-id", default=None)
    max_egress_status.add_argument("--policy-id", default=None)
    max_packet_status = max_commands.add_parser("source-packet-status", help="Read redacted canonical source packet receipt status")
    max_packet_status.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_packet_status.add_argument("--receipt-id", required=True)
    max_egress_verify = max_commands.add_parser("source-egress-verify", help="Verify canonical packet/receipt/event chains")
    max_egress_verify.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_egress_verify.add_argument("--run-id", default=None)

    # MR-PORTABILITY-0: one stable, redacted administrator JSON surface for
    # host discovery, backend registration, explicit Run binding and the
    # human-gated handoff.  These commands never expose a SQLite handle to an
    # agent and never select a backend from a host/process name.
    max_host_list = max_commands.add_parser("host-list", help="List supported and registered Agent Host profiles")
    max_host_list.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_host_describe = max_commands.add_parser("host-describe", help="Describe a registered or built-in Agent Host profile")
    max_host_describe.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_host_describe.add_argument("--host-profile-id", default=None)
    max_host_describe.add_argument("--host-kind", choices=["codex", "luna", "qoder", "hermes", "generic_cli_agent"], default=None)
    max_host_register = max_commands.add_parser("host-register", help="Register an immutable server-owned Agent Host profile")
    max_host_register.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    host_profile_input = max_host_register.add_mutually_exclusive_group(required=True)
    host_profile_input.add_argument("--profile-json", default=None)
    host_profile_input.add_argument("--profile-file", default=None)
    max_host_install = max_commands.add_parser("host-installation-register", help="Attest a server-owned host installation without exposing paths")
    max_host_install.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_host_install.add_argument("--host-profile-id", required=True)
    max_host_install.add_argument("--package-identity-hash", required=True)
    max_host_install.add_argument("--canonical-skill-hash", required=True)
    max_host_install.add_argument("--adapter-hash", required=True)
    max_host_install.add_argument("--capability-artifact-hash", required=True)
    max_host_install.add_argument("--attestation-id", required=True)
    max_host_install.add_argument("--not-registered", action="store_true")
    max_host_install.add_argument("--not-attested", action="store_true")
    max_host_install.add_argument("--not-bindable", action="store_true")
    max_host_install_status = max_commands.add_parser("host-installation-status", help="Read redacted host installation attestations")
    max_host_install_status.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_host_install_status.add_argument("--host-profile-id", required=True)
    max_backend_list = max_commands.add_parser("backend-list", help="List supported and registered Execution Backend profiles")
    max_backend_list.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_backend_describe = max_commands.add_parser("backend-describe", help="Describe a registered or built-in Execution Backend profile")
    max_backend_describe.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_backend_describe.add_argument("--backend-profile-id", default=None)
    max_backend_describe.add_argument("--backend-kind", choices=["openai_compatible_http", "openai_responses_http", "local_agent_cli", "hermetic_fixture"], default=None)
    max_backend_describe.add_argument("--provider-name", default=None)
    max_backend_describe.add_argument("--model-identity", default=None)
    max_backend_register = max_commands.add_parser("backend-register", help="Register an immutable server-owned Execution Backend profile")
    max_backend_register.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    backend_profile_input = max_backend_register.add_mutually_exclusive_group(required=True)
    backend_profile_input.add_argument("--profile-json", default=None)
    backend_profile_input.add_argument("--profile-file", default=None)
    max_portability_status = max_commands.add_parser("portability-status", help="Read the portable host/backend registry status")
    max_portability_status.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_portability_status.add_argument("--run-id", default=None)
    max_portability_quiescent = max_commands.add_parser("portability-quiescent", help="Check the read-only quiescence gate for a Run")
    max_portability_quiescent.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_portability_quiescent.add_argument("--run-id", required=True)
    max_profile_disable = max_commands.add_parser("profile-disable", help="Append a disabled profile status event")
    max_profile_disable.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_profile_disable.add_argument("--profile-kind", choices=["host", "backend"], required=True)
    max_profile_disable.add_argument("--profile-id", required=True)
    max_profile_disable.add_argument("--reason", required=True)
    max_profile_revoke = max_commands.add_parser("profile-revoke", help="Append a revoked profile status event")
    max_profile_revoke.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_profile_revoke.add_argument("--profile-kind", choices=["host", "backend"], required=True)
    max_profile_revoke.add_argument("--profile-id", required=True)
    max_profile_revoke.add_argument("--reason", required=True)
    max_bind_backend = max_commands.add_parser("bind-backend", help="Bind an explicit host/backend profile to a Run")
    max_bind_backend.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_bind_backend.add_argument("--run-id", required=True)
    max_bind_backend.add_argument("--host-profile-id", required=True)
    max_bind_backend.add_argument("--backend-profile-id", required=True)
    max_bind_backend.add_argument("--source-policy-hash", required=True)
    max_bind_backend.add_argument("--budget-hash", required=True)
    max_bind_backend.add_argument("--capability-manifest-hash", default=None)
    max_handoff_preview = max_commands.add_parser("preview-backend-handoff", help="Create a server-owned human-gated backend handoff Preview")
    max_handoff_preview.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_handoff_preview.add_argument("--run-id", required=True)
    max_handoff_preview.add_argument("--new-backend-profile-id", required=True)
    max_handoff_preview.add_argument("--new-host-profile-id", default=None)
    max_handoff_preview.add_argument("--reason", required=True)
    max_handoff_preview.add_argument("--ttl-seconds", type=int, default=3600)
    max_handoff_approve = max_commands.add_parser("approve-backend-handoff", help="Consume one exact human backend handoff approval")
    max_handoff_approve.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_handoff_approve.add_argument("--handoff-approval-id", required=True)
    max_handoff_approve.add_argument("--confirmation-phrase", required=True)
    max_portability_verify = max_commands.add_parser("verify-portability", help="Verify portable host/backend bindings and event chains")
    max_portability_verify.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_portability_verify.add_argument("--run-id", default=None)
    max_packet_status = max_commands.add_parser("rehydration-packet-status", help="Read a redacted rehydration packet status")
    max_packet_status.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_packet_status.add_argument("--packet-id", required=True)
    max_packet_read = max_commands.add_parser("rehydration-packet-read", help="Read a segmented rehydration packet metadata view")
    max_packet_read.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_packet_read.add_argument("--packet-id", required=True)
    max_packet_read.add_argument("--page-size", type=int, default=64)
    max_packet_read.add_argument("--cursor", default=None)
    max_packet_ack = max_commands.add_parser("acknowledge-rehydration", help="Acknowledge one server-owned rehydration packet")
    max_packet_ack.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_packet_ack.add_argument("--packet-id", required=True)
    max_packet_ack.add_argument("--packet-hash", required=True)
    max_packet_ack.add_argument("--handoff-id", default=None)
    max_packet_ack.add_argument("--new-binding-id", default=None)
    max_packet_ack.add_argument("--target-host-profile-id", default=None)
    max_packet_ack.add_argument("--target-installation-id", default=None)
    max_packet_ack.add_argument("--target-installation-hash", default=None)
    max_packet_ack.add_argument("--adapter-capability-hash", default=None)
    max_packet_ack.add_argument("--target-session", default=None)
    max_packet_ack.add_argument("--observed-checkpoint-hash", default=None)
    max_packet_ack.add_argument("--observed-state-hash", default=None)
    max_packet_ack.add_argument("--rehydrated-state-hash", default=None)
    max_packet_ack.add_argument("--manifest-root", default=None)
    max_packet_ack.add_argument("--manifest-count", type=int, default=None)
    max_packet_ack.add_argument("--read-complete", action="store_true")
    max_result_record = max_commands.add_parser("normalized-result-record", help="Record one bounded, invocation-attributed agent result")
    max_result_record.add_argument("--database", dest="max_database", default=argparse.SUPPRESS)
    max_result_record.add_argument("--run-id", required=True)
    max_result_record.add_argument("--binding-id", required=True)
    result_input = max_result_record.add_mutually_exclusive_group(required=True)
    result_input.add_argument("--result-json", default=None)
    result_input.add_argument("--result-file", default=None)
    max_result_record.add_argument("--project-id", default=None)
    max_result_record.add_argument("--iteration-id", default=None)
    max_result_record.add_argument("--invocation-id", default=None)
    max_result_record.add_argument("--intent-id", default=None)
    max_result_record.add_argument("--input-state-hash", default=None)
    max_result_record.add_argument("--checkpoint-id", default=None)
    max_result_record.add_argument("--invocation-hash", default=None)

    catalog = subcommands.add_parser("catalog", help="Build a read-only full-material catalog and dry-run candidate manifest")
    catalog_commands = catalog.add_subparsers(dest="catalog_command", required=True)
    catalog_scan = catalog_commands.add_parser("scan", help="Scan explicit roots without formal ingest")
    catalog_scan.add_argument("--root", action="append", required=True, metavar="ALIAS=PATH")
    catalog_scan.add_argument("--output", required=True)
    catalog_scan.add_argument("--policy", default=None, help="Optional catalog policy JSON; defaults to the packaged policy")
    catalog_scan.add_argument("--candidate-limit", type=int, default=450)
    catalog_scan.add_argument("--max-hash-bytes", type=int, default=512 * 1024 * 1024)
    catalog_scan.add_argument("--checkpoint-interval", type=int, default=250)

    storage = subcommands.add_parser(
        "storage-check", help="Read-only duplicate storage check against corpus roots"
    )
    storage.add_argument(
        "--scan",
        action="append",
        required=True,
        metavar="PATH",
        help="Directory to scan for corpus duplicates or internal duplicate groups",
    )
    storage.add_argument(
        "--corpus",
        action="append",
        default=None,
        metavar="PATH",
        help="Corpus root override (defaults to config corpus_roots)",
    )
    storage.add_argument("--output", default=None, help="Optional JSON output file")

    thesis_review = subcommands.add_parser(
        "thesis-review", help="Init or validate a thesis_review review directory"
    )
    thesis_review_commands = thesis_review.add_subparsers(
        dest="thesis_review_command", required=True
    )
    tr_init = thesis_review_commands.add_parser(
        "init", help="Scaffold a review directory from templates"
    )
    tr_init.add_argument("directory", help="Review directory to create")
    tr_init.add_argument(
        "--paper", default=None, help="Thesis file path to record in versions.sha256"
    )
    tr_validate = thesis_review_commands.add_parser(
        "validate", help="Audit a review directory"
    )
    tr_validate.add_argument("directory", help="Review directory to audit")
    tr_validate.add_argument(
        "--hashes", action="store_true", help="Also compute markdown file hashes"
    )
    tr_validate.add_argument(
        "--strict", action="store_true", help="Exit with status 1 when errors are present"
    )
    return parser


def _parse_updates(values: list[str]) -> dict[str, object]:
    updates: dict[str, object] = {}
    for assignment in values:
        if "=" not in assignment:
            raise PolicyError("--set values must use FIELD=VALUE")
        field, value = assignment.split("=", 1)
        field = field.strip()
        value = value.strip()
        if field == "metadata_json":
            try:
                value = json.loads(value)
            except json.JSONDecodeError as exc:
                raise PolicyError("metadata_json must be valid JSON") from exc
        updates[field] = value
    return updates


def _load_runner_profile(profile_file: str | None, profile_json: str | None) -> RunnerProfile:
    try:
        if profile_json is not None:
            value = json.loads(profile_json)
        else:
            value = json.loads(Path(profile_file).read_text(encoding="utf-8"))
        return RunnerProfile.from_mapping(value)
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise PolicyError("runner profile is not valid canonical JSON") from exc


def _load_provider_profile(profile_file: str | None, profile_json: str | None) -> ProviderProfile:
    try:
        if profile_json is not None:
            value = json.loads(profile_json)
        elif profile_file is not None:
            value = json.loads(Path(profile_file).read_text(encoding="utf-8"))
        else:
            raise ValueError("provider profile input is required")
        return ProviderProfile.from_mapping(value)
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise PolicyError("provider profile is not valid strict JSON") from exc


def _load_portability_profile(profile_file: str | None, profile_json: str | None) -> dict:
    try:
        if profile_json is not None:
            value = json.loads(profile_json)
        elif profile_file is not None:
            value = json.loads(Path(profile_file).read_text(encoding="utf-8"))
        else:
            raise ValueError("portability profile input is required")
        if not isinstance(value, dict):
            raise ValueError("portability profile must be an object")
        return value
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise PolicyError("portability profile is not valid strict JSON") from exc


def _load_json_arg(value: str | None, *, name: str) -> object:
    if value is None:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"{name} must be valid JSON") from exc


def _hermetic_transport(response_json: str) -> HermeticTransport:
    value = _load_json_arg(response_json, name="--response-json")
    if not isinstance(value, dict):
        raise PolicyError("--response-json must be a JSON object")
    allowed = {"status_code", "body", "headers", "provider_call_id", "dispatch_known"}
    if set(value) - allowed:
        raise PolicyError("--response-json contains unsupported transport fields")
    base = TransportResponse(value.get("status_code", 200), value.get("body", {}), value.get("headers", {}), value.get("provider_call_id", ""), value.get("dispatch_known", True))

    def handler(_request: bytes, _headers, idempotency_key: str) -> TransportResponse:
        # CLI input is an injected fixture template.  Reusing it across a
        # finite bounded loop still gets a distinct server-visible call ID,
        # so provider-call idempotency cannot collapse separate iterations.
        call_id = f"{base.provider_call_id}:{idempotency_key}" if base.provider_call_id else f"hermetic:{idempotency_key}"
        return TransportResponse(base.status_code, base.body, base.headers, call_id, base.dispatch_known)

    return HermeticTransport(handler=handler)


def _redact_max_output(value, *, allow_confirmation_phrase: bool = False):
    forbidden = {"fencing_token", "api_key", "secret", "password", "access_token", "refresh_token", "token", "prompt", "raw_response", "source_text", "full_text", "absolute_path", "confirmation_phrase"}
    if allow_confirmation_phrase:
        forbidden.remove("confirmation_phrase")
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            lowered = str(key).casefold()
            if lowered in forbidden or any(fragment in lowered for fragment in ("prompt", "source_text", "full_text", "passage_text", "raw_response", "api_key", "secret", "password")):
                continue
            redacted[key] = _redact_max_output(item, allow_confirmation_phrase=allow_confirmation_phrase)
        return redacted
    if isinstance(value, list):
        return [_redact_max_output(item, allow_confirmation_phrase=allow_confirmation_phrase) for item in value]
    if isinstance(value, str) and (value.startswith(("/", "\\\\")) or (len(value) > 2 and value[1] == ":" and value[2] in {"\\", "/"})):
        return "[redacted]"
    return value


def _run(args: argparse.Namespace) -> dict:
    if args.command == "catalog":
        if args.catalog_command != "scan":
            raise PolicyError("unsupported catalog command")
        return run_catalog_scan(
            args.root,
            args.output,
            candidate_limit=args.candidate_limit,
            max_hash_bytes=args.max_hash_bytes,
            checkpoint_interval=args.checkpoint_interval,
            policy_path=args.policy,
            progress=lambda event: print(json.dumps({"catalog_progress": event}, ensure_ascii=False), file=sys.stderr),
        )
    if args.command == "doctor":
        return run_doctor(
            Path(args.config),
            manifest_path=args.manifest,
            strict=args.strict,
            deep=args.deep,
            show_paths=args.show_paths,
        )
    if args.command == "max":
        if args.max_command == "external-agent-discover":
            return ExternalAgentService.discover()
        database = resolve_control_database(explicit=getattr(args, "max_database", None), config_path=args.config)
        actor = Actor(
            actor_id="local-admin",
            # Max leases span separate CLI processes.  Keep the administrator
            # session stable so a fencing token acquired by ``max start`` can
            # be presented by the subsequent explicit pause/resume/cancel
            # commands; the repository still enforces actor, session, expiry,
            # and fencing-token checks.
            session_id="research-kb-max-cli-admin",
            actor_kind="user",
            role="admin",
            framework="research-kb-cli",
        )
        service = MaxAdminService(database, actor)
        command = {
            "live-canary-snapshot-live-preview": "live-canary-snapshot-execution-preview",
            "live-canary-snapshot-live-authorize": "live-canary-snapshot-execution-authorize",
            "live-canary-snapshot-live-execute": "live-canary-snapshot-execution",
            "live-canary-snapshot-live-status": "live-canary-snapshot-execution-status",
            "live-canary-snapshot-live-verify": "live-canary-snapshot-execution-verify",
        }.get(args.max_command, args.max_command)
        if command in {
            "host-list", "host-describe", "host-register", "host-installation-register",
            "host-installation-status",
            "backend-list", "backend-describe", "backend-register", "portability-status",
            "portability-quiescent", "profile-disable", "profile-revoke", "bind-backend",
            "preview-backend-handoff", "approve-backend-handoff", "verify-portability",
            "rehydration-packet-status", "rehydration-packet-read", "acknowledge-rehydration",
            "normalized-result-record",
        }:
            portability = MaxPortabilityService(service.repository, actor)
            if command == "host-list":
                return portability.list_hosts()
            if command == "host-describe":
                return portability.describe_host(host_profile_id=args.host_profile_id, host_kind=args.host_kind)
            if command == "host-register":
                return portability.register_host_profile(profile=_load_portability_profile(args.profile_file, args.profile_json))
            if command == "host-installation-register":
                return portability.register_host_installation(
                    host_profile_id=args.host_profile_id,
                    package_identity_hash=args.package_identity_hash,
                    canonical_skill_hash=args.canonical_skill_hash,
                    adapter_hash=args.adapter_hash,
                    capability_artifact_hash=args.capability_artifact_hash,
                    attestation_id=args.attestation_id,
                    registered=not args.not_registered,
                    attested=not args.not_attested,
                    bindable=not args.not_bindable,
                )
            if command == "host-installation-status":
                return portability.host_installation_status(host_profile_id=args.host_profile_id)
            if command == "backend-list":
                return portability.list_backends()
            if command == "backend-describe":
                return portability.describe_backend(
                    backend_profile_id=args.backend_profile_id,
                    backend_kind=args.backend_kind,
                    provider_name=args.provider_name,
                    model_identity=args.model_identity,
                )
            if command == "backend-register":
                return portability.register_backend_profile(profile=_load_portability_profile(args.profile_file, args.profile_json))
            if command == "portability-status":
                return portability.status(run_id=args.run_id)
            if command == "portability-quiescent":
                return portability.assert_portability_quiescent(run_id=args.run_id)
            if command == "profile-disable":
                return portability.disable_profile(profile_kind=args.profile_kind, profile_id=args.profile_id, reason=args.reason)
            if command == "profile-revoke":
                return portability.revoke_profile(profile_kind=args.profile_kind, profile_id=args.profile_id, reason=args.reason)
            if command == "bind-backend":
                return portability.bind_backend(
                    run_id=args.run_id,
                    host_profile_id=args.host_profile_id,
                    backend_profile_id=args.backend_profile_id,
                    source_policy_hash=args.source_policy_hash,
                    budget_hash=args.budget_hash,
                    capability_manifest_hash=args.capability_manifest_hash,
                )
            if command == "preview-backend-handoff":
                return portability.preview_backend_handoff(
                    run_id=args.run_id,
                    new_backend_profile_id=args.new_backend_profile_id,
                    new_host_profile_id=args.new_host_profile_id,
                    reason=args.reason,
                    ttl_seconds=args.ttl_seconds,
                )
            if command == "approve-backend-handoff":
                return portability.approve_backend_handoff(
                    handoff_approval_id=args.handoff_approval_id,
                    confirmation_phrase=args.confirmation_phrase,
                )
            if command == "rehydration-packet-status":
                return portability.rehydration_packet_status(packet_id=args.packet_id)
            if command == "rehydration-packet-read":
                return portability.read_rehydration_packet(
                    packet_id=args.packet_id,
                    page_size=args.page_size,
                    cursor=args.cursor,
                )
            if command == "acknowledge-rehydration":
                return portability.acknowledge_rehydration(
                    packet_id=args.packet_id,
                    packet_hash=args.packet_hash,
                    handoff_id=args.handoff_id,
                    new_binding_id=args.new_binding_id,
                    target_host_profile_id=args.target_host_profile_id,
                    target_installation_id=args.target_installation_id,
                    target_installation_hash=args.target_installation_hash,
                    adapter_capability_hash=args.adapter_capability_hash,
                    target_session=args.target_session,
                    observed_checkpoint_hash=args.observed_checkpoint_hash,
                    observed_state_hash=args.observed_state_hash,
                    rehydrated_state_hash=args.rehydrated_state_hash,
                    manifest_root=args.manifest_root,
                    manifest_count=args.manifest_count,
                    read_complete=args.read_complete,
                )
            if command == "normalized-result-record":
                if args.result_json is not None:
                    raw_result = _load_json_arg(args.result_json, name="--result-json")
                else:
                    try:
                        raw_result = json.loads(Path(args.result_file).read_text(encoding="utf-8"))
                    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                        raise PolicyError("normalized result file is not valid JSON") from exc
                if not isinstance(raw_result, dict):
                    raise PolicyError("--result-json/--result-file must contain an object")
                return portability.record_normalized_result(
                    run_id=args.run_id,
                    binding_id=args.binding_id,
                    result=NormalizedAgentResult.from_mapping(raw_result),
                    project_id=args.project_id,
                    iteration_id=args.iteration_id,
                    invocation_id=args.invocation_id,
                    intent_id=args.intent_id,
                    input_state_hash=args.input_state_hash,
                    checkpoint_id=args.checkpoint_id,
                    invocation_hash=args.invocation_hash,
                )
            return portability.verify(run_id=args.run_id)
        if command in {"canary-preflight", "canary-execute"}:
            # The source database is read from the explicitly selected
            # config, while the Max control database remains the explicit
            # --database argument.  No client request/policy material is
            # accepted by this compact surface.
            source_database = Settings.load(Path(args.config)).database
            capsules = LiveExecutionCapsuleStore(
                service.repository,
                source_database=source_database,
            )
            if command == "canary-preflight":
                return capsules.create_preview(
                    preparation_preview_id=args.capsule_preparation_preview_id,
                    actor=actor,
                    ttl_seconds=args.ttl_seconds,
                )
            return capsules.execute(
                capsule_hash=args.capsule_hash,
                confirmation=args.capsule_confirmation,
                actor=actor,
            )
        if command == "init":
            return service.initialize(fixture=getattr(args, "fixture", False))
        if command == "propose":
            if args.charter_json is not None:
                try:
                    charter = json.loads(args.charter_json)
                except json.JSONDecodeError as exc:
                    raise PolicyError("--charter-json must be canonical JSON") from exc
                return service.propose(project_id=args.project_id, charter=charter)
            return service.propose_json_file(project_id=args.project_id, charter_path=args.charter)
        if command == "approve":
            return service.approve(run_id=args.run_id, charter_hash=args.charter_hash, reason=args.reason, ttl_seconds=args.ttl_seconds)
        if command == "start":
            return service.start(run_id=args.run_id, lease_ttl=args.lease_ttl)
        if command == "pause":
            return service.pause(run_id=args.run_id, fencing_token=args.fencing_token)
        if command == "resume":
            return service.resume(run_id=args.run_id, fencing_token=args.fencing_token, lease_ttl=args.lease_ttl, expected_state_version=args.expected_state_version, expected_checkpoint_id=args.expected_checkpoint_id, expected_state_hash=args.expected_state_hash)
        if command == "cancel":
            return service.cancel(run_id=args.run_id, fencing_token=args.fencing_token)
        if command == "status":
            return service.status(run_id=args.run_id)
        if command == "events":
            return service.events(run_id=args.run_id, cursor=args.cursor, limit=args.limit)
        if command == "verify":
            return service.verify(run_id=args.run_id)
        if command == "register-profile":
            profile = _load_runner_profile(args.profile_file, args.profile_json)
            return MaxRunnerService(database, actor).register_profile(profile=profile)
        if command == "handoff":
            profile = _load_runner_profile(args.profile_file, args.profile_json)
            runner_actor = Actor(args.runner_id, args.runner_session, args.runner_kind, "runner", "research-kb-cli")
            return MaxRunnerService(database, actor).handoff(run_id=args.run_id, profile=profile, runner_actor=runner_actor, admin_fencing_token=args.admin_fencing_token, lease_ttl=args.lease_ttl)
        if command == "run-next":
            profile = _load_runner_profile(args.profile_file, args.profile_json)
            runner_actor = Actor(args.runner_id, args.runner_session, args.runner_kind, "runner", "research-kb-cli")
            return MaxRunnerService(database, actor).run_next(run_id=args.run_id, profile=profile, runner_actor=runner_actor, lease_ttl=args.lease_ttl)
        if command == "simulate-next":
            profile = _load_runner_profile(args.profile_file, args.profile_json)
            runner_actor = Actor(args.runner_id, args.runner_session, args.runner_kind, "runner", "research-kb-cli")
            service = MaxRunnerService(database, actor, adapter=ScriptedFakeAdapter(), gateway=FixtureResearchGateway())
            service.usage_authority = FixtureUsageAuthority(service.repository)
            service.repository.usage_authority = service.usage_authority
            return service.simulate_next(run_id=args.run_id, profile=profile, runner_actor=runner_actor, lease_ttl=args.lease_ttl, fixture=args.fixture)
        if command == "runner-status":
            return MaxRunnerService(database, actor).runner_status(run_id=args.run_id)
        if command == "ambiguous-decision":
            return MaxRunnerService(database, actor).ambiguous_decision(run_id=args.run_id, logical_call_id=args.logical_call_id, decision=args.decision)
        if command == "provider-validate":
            profile = _load_provider_profile(args.provider_profile_file, args.provider_profile_json)
            value = profile.to_mapping()
            value["endpoint_origin"] = "[redacted]"
            value["credential_ref"] = {"kind": profile.credential_ref.kind, "name": "[redacted]"}
            return {"valid": True, "profile_hash": profile.profile_hash, "pricing_hash": profile.pricing.pricing_hash, "profile": value, "transport": "injected_hermetic_only", "live_provider": "disabled"}
        if command == "provider-register":
            profile = _load_provider_profile(args.provider_profile_file, args.provider_profile_json)
            return MaxProviderService(database, actor).register(profile=profile)
        if command == "provider-show":
            return MaxProviderService(database, actor).show(profile_hash=args.profile_hash, profile_id=args.profile_id, profile_version=args.profile_version)
        if command == "provider-bind":
            return MaxProviderService(database, actor).bind(run_id=args.run_id, profile_hash=args.profile_hash)
        if command == "grant-live":
            caps = _load_json_arg(args.caps_json, name="--caps-json")
            if not isinstance(caps, dict):
                raise PolicyError("--caps-json must be a JSON object")
            return MaxProviderService(database, actor).grant_live(run_id=args.run_id, profile_hash=args.profile_hash, caps=caps, reason=args.reason, ttl_seconds=args.ttl_seconds)
        if command == "grant-status":
            return MaxProviderService(database, actor).grant_status(run_id=args.run_id)
        if command == "consume-live-grant":
            return MaxProviderService(database, actor).consume_live_grant(run_id=args.run_id, grant_id=args.grant_id)
        if command == "authorize-live":
            caps = _load_json_arg(args.caps_json, name="--caps-json")
            network_policy = _load_json_arg(args.network_policy_json, name="--network-policy-json")
            if not isinstance(caps, dict) or not isinstance(network_policy, dict):
                raise PolicyError("live authorization caps and network policy must be JSON objects")
            return MaxProviderService(database, actor).authorize_live(run_id=args.run_id, grant_id=args.grant_id, caps=caps, network_policy=network_policy, reason=args.reason, ttl_seconds=args.ttl_seconds, profile_hash=args.profile_hash)
        if command == "provider-live-preflight":
            if args.authorization_id is None and args.grant_id is None:
                raise PolicyError("provider-live-preflight requires --authorization-id or --grant-id")
            if args.authorization_id is not None and args.grant_id is not None:
                raise PolicyError("provider-live-preflight accepts only one authorization selector")
            return MaxProviderService(database, actor).live_preflight(run_id=args.run_id, authorization_id=args.authorization_id, grant_id=args.grant_id)
        if command == "provider-network-policy-show":
            return MaxProviderService(database, actor).network_policy_status(network_policy_hash_value=args.network_policy_hash)
        if command == "provider-network-policy-register":
            network_policy = _load_json_arg(args.network_policy_json, name="--network-policy-json")
            if not isinstance(network_policy, dict):
                raise PolicyError("--network-policy-json must be a JSON object")
            return MaxProviderService(database, actor).register_network_policy(policy=network_policy)
        if command == "live-authorization-status":
            return MaxProviderService(database, actor).live_authorization_status(run_id=args.run_id, authorization_id=args.authorization_id)
        if command == "revoke-live-authorization":
            return MaxProviderService(database, actor).revoke_live_authorization(authorization_id=args.authorization_id, reason=args.reason)
        if command == "expire-live-authorization":
            return MaxProviderService(database, actor).expire_live_authorization(authorization_id=args.authorization_id, reason=args.reason)
        if command == "live-bundle-create":
            return MaxProviderService(database, actor).create_live_bundle(run_id=args.run_id, grant_id=args.grant_id, authorization_ids=args.authorization_id)
        if command == "live-bundle-status":
            return MaxProviderService(database, actor).live_bundle_status(run_id=args.run_id, bundle_id=args.bundle_id)
        if command == "revoke-live-bundle":
            return MaxProviderService(database, actor).revoke_live_bundle(bundle_id=args.bundle_id, reason=args.reason)
        if command == "live-iteration-approve":
            return MaxProviderService(database, actor).approve_live_iteration(run_id=args.run_id, grant_id=args.grant_id, bundle_id=args.bundle_id, provider_profile_hash=args.provider_profile_hash, runner_profile_hash=args.runner_profile_hash, reason=args.reason, ttl_seconds=args.ttl_seconds)
        if command == "live-iteration-approval-status":
            return MaxProviderService(database, actor).live_iteration_approval_status(run_id=args.run_id)
        if command == "provider-live-smoke":
            service = MaxProviderService(database, actor)
            preflight = service.live_preflight(run_id=args.run_id, authorization_id=args.authorization_id)
            if not preflight.get("ok"):
                raise MaxControlError("provider-live-smoke preflight is not currently eligible")
            status = service.live_authorization_status(run_id=args.run_id, authorization_id=args.authorization_id)
            authorizations = status.get("authorizations", [])
            if len(authorizations) != 1 or authorizations[0].get("authorization_hash") != args.authorization_hash or authorizations[0].get("profile_hash") != args.profile_hash:
                raise MaxControlError("provider-live-smoke authorization/profile confirmation mismatch")
            if authorizations[0].get("state") != "active" or authorizations[0].get("consumption_id") is not None:
                raise MaxControlError("provider-live-smoke requires one active unconsumed authorization")
            if args.execute:
                raise MaxControlError("MR-2B1A offline stage refuses production provider-live-smoke execution; use an injected fixture test")
            return {"ok": True, "prepared": True, "executed": False, "run_id": args.run_id, "authorization_id": args.authorization_id, "profile_hash": args.profile_hash, "request": {"kind": "fixed_offline_smoke", "max_provider_calls": 1, "max_input_tokens": 512, "max_output_tokens": 32, "timeout_seconds": 30, "allow_redirects": False}}
        if command in {"scheduler-tick", "scheduler-run-bounded"}:
            profile = _load_provider_profile(getattr(args, "provider_profile_file", None), getattr(args, "provider_profile_json", None))
            policy_value = _load_json_arg(getattr(args, "policy_json", None), name="--policy-json")
            policy = SchedulerPolicy.from_mapping(policy_value) if isinstance(policy_value, dict) else None
            worker = Actor(args.worker_id, args.worker_session, "worker", "runner", "research-kb-cli")
            transport = _hermetic_transport(args.response_json)
            scheduler = MaxSchedulerService(database, actor, worker_actor=worker)
            if command == "scheduler-tick":
                return scheduler.tick(run_id=args.run_id, profile=profile, grant_id=args.grant_id, transport=transport, policy=policy, lease_ttl=args.lease_ttl)
            return scheduler.run_bounded(run_id=args.run_id, profile=profile, grant_id=args.grant_id, transport=transport, max_ticks=args.max_ticks, policy=policy, lease_ttl=args.lease_ttl)
        if command == "scheduler-status":
            return MaxSchedulerService(database, actor, worker_actor=actor).status(run_id=args.run_id)
        if command == "scheduler-verify":
            return MaxSchedulerService(database, actor, worker_actor=actor).verify(run_id=args.run_id)
        if command == "worker-command":
            return MaxWorkerService(database, actor).command(run_id=args.run_id, command=args.action, reason=args.reason)
        if command == "worker-status":
            return MaxWorkerService(database, actor).status(run_id=args.run_id)
        if command == "worker-verify":
            return MaxWorkerService(database, actor).verify(run_id=args.run_id)
        if command == "acquisition-propose":
            try:
                if args.acquisition_request_json is not None:
                    request = json.loads(args.acquisition_request_json)
                else:
                    request = json.loads(Path(args.acquisition_request_file).read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise PolicyError("acquisition request is not valid strict JSON") from exc
            if not isinstance(request, dict):
                raise PolicyError("acquisition request must be a JSON object")
            return MaxAcquisitionService(database, actor).propose(request=request)
        if command == "acquisition-decision":
            return MaxAcquisitionService(database, actor).decide(request_id=args.request_id, decision=args.decision, reason=args.reason, validation_hash=args.validation_hash, dry_run_manifest_hash=args.dry_run_manifest_hash)
        if command == "acquisition-authorize-worker":
            return MaxAcquisitionService(database, actor).authorize_worker(request_id=args.request_id, worker_id=args.worker_id, worker_session=args.worker_session, max_candidates=args.max_candidates, max_bytes=args.max_bytes, ttl_seconds=args.ttl_seconds, reason=args.reason)
        if command == "acquisition-claim":
            worker = Actor(args.worker_id, args.worker_session, "worker", "acquisition", "research-kb-cli")
            return MaxAcquisitionService(database, worker).claim(request_id=args.request_id, worker_grant_id=args.worker_grant_id)
        if command == "acquisition-validate-stage":
            return MaxAcquisitionService(database, actor).validate_stage(request_id=args.request_id, claim_id=args.claim_id, staging_run=args.staging_run, existing_content_hashes=frozenset(args.existing_content_hash))
        if command == "acquisition-status":
            return MaxAcquisitionService(database, actor).status(run_id=args.run_id, request_id=args.request_id)
        if command == "acquisition-verify":
            return MaxAcquisitionService(database, actor).verify(run_id=args.run_id)
        if command in {"live-canary-snapshot-execution-preview", "live-canary-snapshot-execution-authorize", "live-canary-snapshot-execution", "live-canary-snapshot-execution-status", "live-canary-snapshot-execution-verify"}:
            repository = MaxControlRepository(database)
            source_database = Settings.load(args.config).database
            live_service = NativeLiveCanaryService(repository, actor, source_database=source_database)
            if command == "live-canary-snapshot-execution-preview":
                return live_service.create_execution_preview(approval_id=args.approval_id, ttl_seconds=args.ttl_seconds)
            if command == "live-canary-snapshot-execution-authorize":
                return live_service.authorize_execution(execution_preview_id=args.execution_preview_id, confirmation_phrase=args.confirmation_phrase)
            if command == "live-canary-snapshot-execution":
                return live_service.execute(execution_authorization_id=args.execution_authorization_id, execution_authorization_hash=args.execution_authorization_hash, allow_execute=args.execute)
            if command == "live-canary-snapshot-execution-status":
                return live_service.status(execution_preview_id=args.execution_preview_id, execution_authorization_id=args.execution_authorization_id, run_id=args.run_id)
            return live_service.verify(run_id=args.run_id)
        if command == "live-canary-prepare-intent":
            caps = _load_json_arg(args.caps_json, name="--caps-json")
            if not isinstance(caps, dict):
                raise PolicyError("--caps-json must be a JSON object")
            return MaxCanaryService(database, actor).prepare_intent(
                run_id=args.run_id,
                provider_profile_hash=args.provider_profile_hash,
                source_egress_policy_hash=args.source_egress_policy_hash,
                candidate_wheel_sha256=args.candidate_wheel_sha256,
                source_manifest_sha256=args.source_manifest_sha256,
                source_tree_sha256=args.source_tree_sha256,
                engine_version=args.engine_version,
                caps=caps,
            )
        if command == "preparation-handoff":
            worker = Actor(args.worker_id, args.worker_session, args.worker_kind, "runner", "research-kb-cli")
            return MaxCanaryService(database, actor).handoff_preparation(
                run_id=args.run_id,
                snapshot_id=args.snapshot_id,
                preview_id=args.preview_id,
                dns_authority_id=args.dns_authority_id,
                dns_request_id=args.dns_request_id,
                preparation_claim_id=args.preparation_claim_id,
                fencing_token=args.fencing_token,
                worker=worker,
                reservation_id=args.reservation_id,
            )
        if command == "preparation-handoff-close":
            return MaxCanaryService(database, actor).preparation_handoffs(
                source_database=Settings.load(args.config).database
            ).close_waiting_handoff(
                run_id=args.run_id,
                handoff_id=args.handoff_id,
                state=args.state,
                actor=actor,
                reason=args.reason,
            )
        if command in {"live-canary-snapshot-dns-receipt", "live-canary-snapshot-dns-execute", "live-canary-snapshot-dns-recover", "live-canary-snapshot-dns-status", "live-canary-snapshot-dns-verify", "live-canary-snapshot-approval-preview", "live-canary-snapshot-authorize", "live-canary-snapshot-execute", "live-canary-snapshot-native-status"}:
            repository = MaxControlRepository(database)
            injected_transport = _hermetic_transport(args.response_json) if getattr(args, "response_json", None) else None
            source_database = Settings.load(args.config).database
            native_service = NativePreparationService(repository, actor, source_database=source_database, transport=injected_transport)
            if command == "live-canary-snapshot-dns-receipt":
                if not repository.is_fixture_database():
                    raise MaxControlError("client-supplied DNS receipts are fixture/admin compatibility only; use the server-owned DNS execute command")
                bounded = _load_json_arg(args.bounded_result_json, name="--bounded-result-json")
                if not isinstance(bounded, dict):
                    raise PolicyError("--bounded-result-json must be a JSON object")
                return native_service.record_dns_receipt(preview_id=args.preview_id, request_id=args.request_id, bounded_result=bounded)
            if command == "live-canary-snapshot-dns-execute":
                return native_service.execute_dns(preview_id=args.preview_id, request_id=args.request_id, confirmation_phrase=args.confirmation_phrase, allow_execute=args.execute)
            if command == "live-canary-snapshot-dns-recover":
                return native_service.recover_dns_unknown(attempt_id=args.attempt_id, reason=args.reason)
            if command == "live-canary-snapshot-dns-status":
                return native_service.dns_attempt_status(attempt_id=args.attempt_id, request_id=args.request_id)
            if command == "live-canary-snapshot-dns-verify":
                return native_service.dns_attempt_verify(attempt_id=args.attempt_id)
            if command == "live-canary-snapshot-approval-preview":
                return native_service.create_approval_preview(
                    preparation_preview_id=args.preview_id,
                    preview_ttl_seconds=args.preview_ttl_seconds,
                    approval_ttl_seconds=args.approval_ttl_seconds,
                )
            if command == "live-canary-snapshot-authorize":
                if args.preview_id is not None or args.expires_at is not None or args.approval_preview_id is None:
                    raise MaxControlError("live-canary-snapshot-authorize accepts only --approval-preview-id and the exact Live Approval Preview phrase")
                return native_service.authorize(approval_preview_id=args.approval_preview_id, confirmation_phrase=args.confirmation_phrase)
            if command == "live-canary-snapshot-native-status":
                return native_service.status(preview_id=args.preview_id, run_id=args.run_id, authority_id=args.authority_id)
            if bool(args.authority_id) == bool(args.preview_id):
                raise PolicyError("native snapshot execute requires exactly one of --authority-id or --preview-id")
            if args.preview_id:
                return native_service.execute_from_preview(preview_id=args.preview_id, allow_execute=args.execute)
            return native_service.execute(authority_id=args.authority_id, allow_execute=args.execute)
        if command in {"live-canary-snapshot-create", "live-canary-snapshot-status", "live-canary-preview-from-snapshot", "live-canary-dns-request"}:
            from .max_research.lifetime_separation import PreparationSnapshotStore
            snapshots = PreparationSnapshotStore(MaxControlRepository(database))
            if command == "live-canary-snapshot-create":
                source = _load_json_arg(args.source_binding_json, name="--source-binding-json")
                preparation = _load_json_arg(args.preparation_json, name="--preparation-json")
                caps = _load_json_arg(args.caps_json, name="--caps-json")
                release = _load_json_arg(args.release_identity_json, name="--release-identity-json")
                if not all(isinstance(value, dict) for value in (source, preparation, caps, release)):
                    raise PolicyError("Snapshot JSON arguments must be objects")
                return snapshots.create_snapshot(run_id=args.run_id, source_binding=source, preparation=preparation, caps=caps, release_identity=release, actor=actor, review_ttl_seconds=args.review_ttl_seconds)
            if command == "live-canary-snapshot-status":
                release = None
                if args.release_identity_json:
                    release = _load_json_arg(args.release_identity_json, name="--release-identity-json")
                    if not isinstance(release, dict):
                        raise PolicyError("--release-identity-json must be an object")
                return snapshots.status(snapshot_id=args.snapshot_id, release_identity=release)
            if command == "live-canary-preview-from-snapshot":
                dns = _load_json_arg(args.dns_policy_json, name="--dns-policy-json")
                if not isinstance(dns, dict):
                    raise PolicyError("--dns-policy-json must be an object")
                return snapshots.preview_from_snapshot(snapshot_id=args.snapshot_id, dns_policy=dns, actor=actor, review_ttl_seconds=args.review_ttl_seconds)
            return snapshots.create_dns_only_request(preview_id=args.preview_id, actor=actor, ttl_seconds=args.ttl_seconds)
        if command in {"live-canary-preview", "live-canary-authorize", "live-canary-revoke"}:
            repository = MaxControlRepository(database)
            canary = LiveCanaryAuthorityStore(repository)
            if command == "live-canary-preview":
                if getattr(args, "authority_id", None):
                    return canary.preview_from_authority(authority_id=args.authority_id, actor=actor)
                if not getattr(args, "value_json", None):
                    raise PolicyError("live-canary-preview requires --authority-id or --value-json")
                if not getattr(args, "fixture", False) or not repository.is_fixture_database():
                    raise MaxControlError("client-supplied live-Canary preview bindings remain fixture-only; production Preview must use --authority-id")
                value = _load_json_arg(args.value_json, name="--value-json")
                if not isinstance(value, dict):
                    raise PolicyError("--value-json must be a JSON object")
                return canary.preview(value=value, actor=actor)
            if command == "live-canary-authorize":
                return canary.authorize(preview_id=args.preview_id, preview_hash=args.preview_hash, confirmation_phrase=args.confirmation_phrase, expires_at=args.expires_at, actor=actor, reason=args.reason)
            return canary.revoke(approval_id=args.approval_id, actor=actor, reason=args.reason)
        if command in {"live-canary-preflight", "live-canary-status"}:
            repository = MaxControlRepository(database)
            canary = LiveCanaryAuthorityStore(repository)
            if getattr(args, "authority_id", None):
                return canary.authority_preflight(authority_id=args.authority_id)
            if command == "live-canary-preflight" and getattr(args, "preview_id", None):
                return canary.validate_live_execution_plan(preview_id=args.preview_id)
            return canary.status(preview_id=getattr(args, "preview_id", None), run_id=getattr(args, "run_id", None))
        if command == "live-canary-execute":
            repository = MaxControlRepository(database)
            executor = LiveCanaryExecutor(repository, LiveCanaryAuthorityStore(repository), provider_store=ProviderStore(repository), live_network_enabled=bool(args.execute))
            return executor.execute(
                authority_id=args.authority_id,
                approval_id=args.approval_id,
                allow_execute=args.execute,
            )
        if command == "live-canary-reconcile":
            repository = MaxControlRepository(database)
            executor = LiveCanaryExecutor(repository, LiveCanaryAuthorityStore(repository))
            return executor.reconcile(permit_id=args.permit_id, actor=actor, confirmation_phrase=args.confirmation_phrase, allow_reconcile=args.reconcile)
        if command in {"long-run-preview", "long-run-authorize"}:
            caps = _load_json_arg(args.caps_json, name="--caps-json")
            if not isinstance(caps, dict):
                raise PolicyError("--caps-json must be a JSON object")
            if command == "long-run-preview":
                return service.long_run_preview(run_id=args.run_id, source_egress_policy_hash=args.source_egress_policy_hash, caps=caps, not_before=args.not_before, expires_at=args.expires_at)
            return service.long_run_authorize(run_id=args.run_id, source_egress_policy_hash=args.source_egress_policy_hash, caps=caps, not_before=args.not_before, expires_at=args.expires_at, confirmation_hash=args.confirmation_hash)
        if command == "long-run-status":
            if args.run_id is None and args.window_id is None:
                raise PolicyError("long-run-status requires --run-id or --window-id")
            return service.long_run_status(run_id=args.run_id, window_id=args.window_id)
        if command == "long-run-renew":
            caps = _load_json_arg(args.caps_json, name="--caps-json")
            if not isinstance(caps, dict):
                raise PolicyError("--caps-json must be a JSON object")
            return service.long_run_renew(window_id=args.window_id, caps=caps, not_before=args.not_before, expires_at=args.expires_at, confirmation_hash=args.confirmation_hash, reason=args.reason, source_egress_policy_hash=args.source_egress_policy_hash)
        if command == "long-run-renew-preview":
            caps = _load_json_arg(args.caps_json, name="--caps-json")
            if not isinstance(caps, dict):
                raise PolicyError("--caps-json must be a JSON object")
            return service.long_run_renew_preview(window_id=args.window_id, caps=caps, not_before=args.not_before, expires_at=args.expires_at, reason=args.reason, source_egress_policy_hash=args.source_egress_policy_hash)
        if command == "long-run-control":
            return service.long_run_control(window_id=args.window_id, command=args.action, reason=args.reason)
        if command == "long-run-verify":
            return service.long_run_verify(run_id=args.run_id)
        if command == "source-egress-policy":
            policy = _load_json_arg(args.policy_json, name="--policy-json")
            if not isinstance(policy, dict):
                raise PolicyError("--policy-json must be a JSON object")
            return service.source_egress_policy(run_id=args.run_id, policy=policy)
        if command == "source-egress-preflight":
            return service.source_egress_preflight(policy_id=args.policy_id, purpose=args.purpose, passage_id=args.passage_id, source_role=args.source_role, evidential_function=args.evidential_function)
        if command == "source-egress-status":
            if args.run_id is None and args.policy_id is None:
                raise PolicyError("source-egress-status requires --run-id or --policy-id")
            return service.source_egress_status(run_id=args.run_id, policy_id=args.policy_id)
        if command == "source-packet-status":
            return service.source_packet_status(receipt_id=args.receipt_id)
        if command == "source-egress-verify":
            return service.source_egress_verify(run_id=args.run_id)
        raise PolicyError("unsupported Max control command")
    settings = Settings.load(Path(args.config))
    actor = Actor(
        actor_id="local-admin",
        session_id=f"cli-{uuid.uuid4().hex}",
        actor_kind="user",
        role="admin",
        framework="research-kb-cli",
    )
    service = AdminService(settings, actor)
    if args.command == "storage-check":
        report = run_storage_check(
            corpus_roots=[Path(value) for value in (args.corpus or list(settings.corpus_roots))],
            scan_roots=[Path(value) for value in args.scan],
        )
        if args.output:
            Path(args.output).write_text(
                json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        return report
    if args.command == "thesis-review":
        if args.thesis_review_command == "init":
            created = scaffold_review_dir(
                Path(args.directory).resolve(),
                paper_path=Path(args.paper).resolve() if args.paper else None,
            )
            return {
                "ok": True,
                "directory": str(Path(args.directory).resolve()),
                "created": [str(item) for item in created],
            }
        result = audit_review_dir(Path(args.directory).resolve(), hashes=args.hashes)
        if args.strict and result.errors:
            raise PolicyError("thesis-review validation found errors")
        return result.as_dict()
    if args.command == "init":
        service.initialize()
        return {"ok": True, "database": str(settings.database), "schema": SCHEMA_VERSION}
    if args.command == "status":
        return service.status()
    if args.command == "project":
        if args.project_command == "create":
            return service.create_project(
                project_id=args.project_id, title=args.title, objective=args.objective
            )
        if args.project_command == "list":
            return service.list_projects()
        return service.archive_project(project_id=args.project_id)
    if args.command == "ingest":
        return service.ingest(
            project_id=args.project_id, manifest_path=args.manifest, dry_run=args.dry_run
        )
    if args.command == "metadata":
        if args.metadata_command == "show":
            return service.metadata_show(project_id=args.project_id, document_id=args.document_id)
        return service.metadata_update(
            project_id=args.project_id,
            document_id=args.document_id,
            updates=_parse_updates(args.set),
            reason=args.reason,
        )
    if args.command == "approval":
        if args.approval_command == "list":
            return service.list_approvals(project_id=args.project_id, status=args.status)
        return service.decide_approval(
            request_id=args.request_id, approve=args.approve, note=args.note
        )
    if args.command == "backup":
        return service.backup(output=args.output)
    if args.command == "restore":
        return service.restore(backup_path=args.backup_path, output=args.output)
    if args.command == "token":
        return service.cleanup_expired_tokens()
    if args.command == "reindex":
        return service.reindex()
    raise AssertionError(args.command)  # pragma: no cover


def main() -> None:
    try:
        args = _parser().parse_args()
        result = _run(args)
        if args.command == "doctor":
            if args.json:
                print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            else:
                print(format_doctor_text(result))
            raise SystemExit(int(result.get("exit_code", 2)))
    except (PolicyError, MaxControlError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2) from exc
    except (OSError, sqlite3.Error, ValueError):
        print(json.dumps({"ok": False, "error": "operation failed"}), file=sys.stderr)
        raise SystemExit(2) from None
    if args.command == "max":
        result = _redact_max_output(
            result,
            allow_confirmation_phrase=(
                getattr(args, "max_command", None)
                in {"live-canary-snapshot-approval-preview", "canary-preflight", "preview-backend-handoff"}
            ),
        )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
