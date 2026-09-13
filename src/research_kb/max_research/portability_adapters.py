"""Thin, host-neutral adapters for the Max portability control surface.

The adapters deliberately do not open a control database or choose a backend.
They receive a small JSON CLI callable from the host integration and pass only
server-owned identifiers and hashes through it.  The same implementation is
used by the four named host adapters so portability means a common protocol,
not four subtly different persistence implementations.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .contract import canonical_json
from .portability import NormalizedAgentResult


JsonCommand = Callable[[Sequence[str]], Mapping[str, Any]]


def sha256_file(path: str | Path) -> str:
    """Hash one explicitly supplied file without returning its contents."""

    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class InstallationEvidence:
    package_identity_hash: str
    canonical_skill_hash: str
    adapter_hash: str
    capability_artifact_hash: str
    attestation_id: str

    def to_mapping(self) -> dict[str, str]:
        return {
            "package_identity_hash": self.package_identity_hash,
            "canonical_skill_hash": self.canonical_skill_hash,
            "adapter_hash": self.adapter_hash,
            "capability_artifact_hash": self.capability_artifact_hash,
            "attestation_id": self.attestation_id,
        }


class MaxPortabilityAdapter:
    """A redacted adapter facade for one declared Agent Host kind."""

    host_kind: str

    def __init__(self, host_kind: str, command: JsonCommand):
        if host_kind not in {"codex", "luna", "qoder", "hermes"}:
            raise ValueError("unsupported portability host kind")
        self.host_kind = host_kind
        self._command = command

    def discover(self) -> Mapping[str, Any]:
        """Discover a declarative host descriptor through the admin surface."""

        result = self._command(("host-describe", "--host-kind", self.host_kind))
        host = result.get("host_profile")
        if not isinstance(host, Mapping) or host.get("host_kind") != self.host_kind:
            raise ValueError("server returned an invalid host descriptor")
        if host.get("registered") is False and any(host.get(key) is not None for key in ("canonical_skill_hash", "adapter_hash")):
            raise ValueError("declarative host descriptor manufactured an installation hash")
        return result

    def verify_installation(self, *, host_profile_id: str) -> Mapping[str, Any]:
        result = self._command(("host-installation-status", "--host-profile-id", host_profile_id))
        if result.get("host_kind") != self.host_kind:
            raise ValueError("installation evidence belongs to a different host kind")
        return result

    def attest_installation(self, *, host_profile_id: str, evidence: InstallationEvidence) -> Mapping[str, Any]:
        args = [
            "host-installation-register",
            "--host-profile-id", host_profile_id,
            "--package-identity-hash", evidence.package_identity_hash,
            "--canonical-skill-hash", evidence.canonical_skill_hash,
            "--adapter-hash", evidence.adapter_hash,
            "--capability-artifact-hash", evidence.capability_artifact_hash,
            "--attestation-id", evidence.attestation_id,
        ]
        return self._command(tuple(args))

    def lookup_run(self, *, run_id: str) -> Mapping[str, Any]:
        return self._command(("portability-status", "--run-id", run_id))

    def assert_quiescent(self, *, run_id: str) -> Mapping[str, Any]:
        return self._command(("portability-quiescent", "--run-id", run_id))

    def recover_packet(
        self,
        *,
        packet_id: str,
        acknowledge: bool = False,
        target_proof: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        """Read a packet, optionally acknowledging it with target proof.

        A production acknowledgement cannot be a blind two-argument call.  A
        caller must first read the complete server-owned manifest and provide
        the target-bound proof returned by that protocol.  The legacy
        two-argument shape remains useful only for the explicitly marked
        fixture database.
        """

        packet = self._command(("rehydration-packet-read", "--packet-id", packet_id))
        if not acknowledge:
            return packet
        value = packet.get("packet")
        if not isinstance(value, Mapping) or not isinstance(value.get("packet_hash"), str):
            raise ValueError("server returned an invalid rehydration packet")
        args = [
            "acknowledge-rehydration",
            "--packet-id", packet_id,
            "--packet-hash", str(value["packet_hash"]),
        ]
        if target_proof is not None:
            required = {
                "handoff_id": "--handoff-id",
                "new_binding_id": "--new-binding-id",
                "target_host_profile_id": "--target-host-profile-id",
                "target_installation_id": "--target-installation-id",
                "target_installation_hash": "--target-installation-hash",
                "adapter_capability_hash": "--adapter-capability-hash",
                "target_session": "--target-session",
                "observed_checkpoint_hash": "--observed-checkpoint-hash",
                "observed_state_hash": "--observed-state-hash",
                "rehydrated_state_hash": "--rehydrated-state-hash",
                "manifest_root": "--manifest-root",
                "manifest_count": "--manifest-count",
            }
            missing = [key for key in required if key not in target_proof or target_proof[key] is None]
            if missing or target_proof.get("read_complete") is not True:
                raise ValueError("target_proof is incomplete")
            for key, flag in required.items():
                args.extend((flag, str(target_proof[key])))
            args.append("--read-complete")
        return self._command(tuple(args))

    def rehydration_status(self, *, packet_id: str) -> Mapping[str, Any]:
        return self._command(("rehydration-packet-status", "--packet-id", packet_id))

    def submit_result(
        self,
        *,
        run_id: str,
        binding_id: str,
        result: NormalizedAgentResult | Mapping[str, Any],
        iteration_id: str | None = None,
        invocation_id: str | None = None,
        intent_id: str | None = None,
        input_state_hash: str | None = None,
        checkpoint_id: str | None = None,
        invocation_hash: str | None = None,
    ) -> Mapping[str, Any]:
        value = result if isinstance(result, NormalizedAgentResult) else NormalizedAgentResult.from_mapping(result)
        args: list[str] = [
            "normalized-result-record",
            "--run-id", run_id,
            "--binding-id", binding_id,
            "--result-json", canonical_json(value.to_mapping()),
        ]
        optional = (
            ("--iteration-id", iteration_id),
            ("--invocation-id", invocation_id),
            ("--intent-id", intent_id),
            ("--input-state-hash", input_state_hash),
            ("--checkpoint-id", checkpoint_id),
            ("--invocation-hash", invocation_hash),
        )
        for flag, item in optional:
            if item is not None:
                args.extend((flag, item))
        return self._command(tuple(args))

    def verify(self, *, run_id: str | None = None) -> Mapping[str, Any]:
        args = ["verify-portability"]
        if run_id is not None:
            args.extend(("--run-id", run_id))
        return self._command(tuple(args))


class CodexPortabilityAdapter(MaxPortabilityAdapter):
    host_kind = "codex"

    def __init__(self, command: JsonCommand):
        super().__init__(self.host_kind, command)


class LunaPortabilityAdapter(MaxPortabilityAdapter):
    host_kind = "luna"

    def __init__(self, command: JsonCommand):
        super().__init__(self.host_kind, command)


class QoderPortabilityAdapter(MaxPortabilityAdapter):
    host_kind = "qoder"

    def __init__(self, command: JsonCommand):
        super().__init__(self.host_kind, command)


class HermesPortabilityAdapter(MaxPortabilityAdapter):
    host_kind = "hermes"

    def __init__(self, command: JsonCommand):
        super().__init__(self.host_kind, command)


__all__ = [
    "CodexPortabilityAdapter",
    "HermesPortabilityAdapter",
    "InstallationEvidence",
    "LunaPortabilityAdapter",
    "MaxPortabilityAdapter",
    "QoderPortabilityAdapter",
    "sha256_file",
]
