"""MR-2A bounded runner public API."""

from .adapter import FixtureResearchGateway, FixtureUsageAuthority, ScriptedFakeAdapter
from .contracts import (
    AdapterCapabilities,
    DeliberationCallSpec,
    DispatchUnknown,
    InferenceProfile,
    ModelAdapter,
    ModelCallIntent,
    ModelCallResult,
    ModelCallStatus,
    ModelIdentity,
    ModelRequestEnvelope,
    ModelResponseEnvelope,
    RecoveryDisposition,
    ResearchGateway,
    RolePacket,
    RunnerPlan,
    RunnerProfile,
    RunnerProposal,
)
from .planner import build_plan


def __getattr__(name: str):
    # Lazy import avoids a package cycle: persistence.runner imports the
    # provider-neutral contracts while max_research.persistence is importing.
    if name in {"BoundedRunner", "InjectedRunnerCrash", "UsageDispute"}:
        from .runner import BoundedRunner, InjectedRunnerCrash, UsageDispute
        return {"BoundedRunner": BoundedRunner, "InjectedRunnerCrash": InjectedRunnerCrash, "UsageDispute": UsageDispute}[name]
    raise AttributeError(name)

__all__ = [
    "AdapterCapabilities", "BoundedRunner", "DeliberationCallSpec", "DispatchUnknown", "FixtureResearchGateway", "FixtureUsageAuthority", "InferenceProfile", "InjectedRunnerCrash", "ModelAdapter", "ModelCallIntent", "ModelCallResult", "ModelCallStatus", "ModelIdentity", "ModelRequestEnvelope", "ModelResponseEnvelope", "RecoveryDisposition", "ResearchGateway", "RolePacket", "RunnerPlan", "RunnerProfile", "RunnerProposal", "ScriptedFakeAdapter", "UsageDispute", "build_plan",
]
