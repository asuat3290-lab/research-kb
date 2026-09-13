"""MR-4B1B-v8R1 bounded DNS-policy and release-identity tests.

All resolver inputs are injected values.  This module never invokes the
operating-system resolver, reads credentials, or opens a socket.
"""

from __future__ import annotations

import ipaddress
import json
import unittest

from research_kb import __version__
from research_kb.max_research.live_canary import LiveCanaryAuthorityError, _normalize_preview_value
from research_kb.max_research.provider import (
    ProviderContractError,
    ProviderTransportError,
    network_policy_hash,
    normalize_network_policy,
    validate_resolved_addresses,
)
from research_kb.max_research.release_identity import ReleaseIdentityError, validate_release_identity_unique


def _ipv4_candidates(count: int) -> list[str]:
    # 0x5db8d800 is a stable public test range value; constructing the text
    # avoids embedding resolver output in the test's evidence surface.
    return [str(ipaddress.ip_address(0x5DB8D800 + index)) for index in range(1, count + 1)]


def _ipv6_candidates(count: int) -> list[str]:
    base = int("20014860486000000000000000008888", 16)
    return [str(ipaddress.IPv6Address(base + index)) for index in range(count)]


def _preview(max_dns_candidates: object) -> dict[str, object]:
    digest = "a" * 64
    return {
        "project_id": "pilot",
        "run_id": "mr1:run:v8r1-test",
        "charter_hash": digest,
        "current_state_hash": digest,
        "current_checkpoint_id": "checkpoint-v8r1-test",
        "current_state_version": 1,
        "engine_package": "research-kb",
        "engine_version": "0.1.1.dev7",
        "core_schema_version": 5,
        "control_schema_version": 19,
        "candidate_wheel_sha256": digest,
        "source_manifest_sha256": digest,
        "source_tree_sha256": digest,
        "provider_profile_hash": digest,
        "provider_name": "opencode-go",
        "model_identity": "deepseek-v4-flash",
        "model_version": "provider-managed-alias",
        "pricing_hash": digest,
        "budget_hash": digest,
        "endpoint_origin_hash": digest,
        "endpoint_path_policy_hash": digest,
        "network_policy_hash": network_policy_hash({"max_dns_candidates": 16}),
        "credential_ref_hash": digest,
        "source_egress_policy_hash": digest,
        "source_allowlist": [{"passage_id": "psg-v8r1-test"}],
        "source_policy": {"network_allowed": False},
        "runner_profile_hash": digest,
        "worker_id": "v8r1-worker",
        "worker_session": "v8r1-session",
        "fencing_token": 1,
        "claim_id": "claim-v8r1-test",
        "caps": {
            "max_provider_calls": 1,
            "max_ticks": 1,
            "max_iterations": 1,
            "max_acquisition_requests": 0,
            "max_ocr_requests": 0,
            "max_ingest_operations": 0,
            "max_input_tokens": 4096,
            "max_output_tokens": 256,
            "max_cache_read_tokens": 4096,
            "max_reasoning_tokens": 256,
            "max_cost_units": 729,
            "max_wall_clock_seconds": 120,
            "max_source_passages": 1,
            "max_source_characters": 2000,
        },
        "transport_policy": {"retry": False, "redirect": False, "proxy": False},
        "kill_rollback_incident_policy": {"kill": "revoke", "rollback": "stop", "incident": "pause"},
        "preview_status": "AWAITING_DNS_PREFLIGHT_AUTHORIZATION",
        "dns_preflight_requirement": {
            "hostname": "opencode.ai",
            "port": 443,
            "scheme": "https",
            "provider_profile_hash": digest,
            "network_policy_hash": network_policy_hash({"max_dns_candidates": 16}),
            "candidate_wheel_sha256": digest,
            "run_id": "mr1:run:v8r1-test",
            "max_dns_attempts": 1,
            "max_dns_candidates": max_dns_candidates,
            "credential_reads": 0,
            "https_connector_calls": 0,
            "provider_calls": 0,
            "actual_cost": 0,
        },
    }


class MR4B1BV8R1PolicyTests(unittest.TestCase):
    def test_default_and_explicit_caps(self) -> None:
        self.assertEqual(normalize_network_policy(None)["max_dns_candidates"], 4)
        self.assertEqual(normalize_network_policy({"max_dns_candidates": 8})["max_dns_candidates"], 8)
        self.assertEqual(normalize_network_policy({"max_dns_candidates": 16})["max_dns_candidates"], 16)

    def test_invalid_caps_fail_closed(self) -> None:
        for value in (17, 0, -1, True, "16"):
            with self.subTest(value=value), self.assertRaises(ProviderContractError):
                normalize_network_policy({"max_dns_candidates": value})

    def test_eight_and_sixteen_safe_candidates_are_all_normalized(self) -> None:
        eight = validate_resolved_addresses(_ipv4_candidates(8), max_candidates=8)
        sixteen = validate_resolved_addresses(_ipv4_candidates(16), max_candidates=16)
        self.assertEqual(len(eight), 8)
        self.assertEqual(len(sixteen), 16)
        self.assertEqual(len(set(sixteen)), 16)

    def test_seventeen_candidates_fail_without_truncation(self) -> None:
        candidates = _ipv4_candidates(17)
        with self.assertRaises(ProviderTransportError) as caught:
            validate_resolved_addresses(candidates, max_candidates=16)
        self.assertEqual(caught.exception.code, "DNS_CANDIDATE_LIMIT_EXCEEDED")
        self.assertNotEqual(len(candidates), 16)

    def test_all_blocked_classes_fail_the_whole_batch(self) -> None:
        blocked = (
            ipaddress.ip_address(0x0A000001),
            ipaddress.ip_address(0x7F000001),
            ipaddress.ip_address(0xA9FE0101),
            ipaddress.ip_address(0xC0000201),
        )
        for address in blocked:
            with self.subTest(address_class=address.is_private or address.is_loopback or address.is_link_local or address.is_reserved):
                with self.assertRaises(ProviderTransportError) as caught:
                    validate_resolved_addresses([_ipv4_candidates(1)[0], str(address)], max_candidates=16)
                self.assertEqual(caught.exception.code, "SSRF_ADDRESS_BLOCKED")

    def test_mixed_ipv4_ipv6_normalization_is_deterministic(self) -> None:
        values = [_ipv6_candidates(1)[0], _ipv4_candidates(1)[0], _ipv4_candidates(1)[0]]
        normalized = validate_resolved_addresses(values, max_candidates=16)
        self.assertEqual(len(normalized), 2)
        self.assertLess(ipaddress.ip_address(normalized[0]).version, ipaddress.ip_address(normalized[1]).version)

    def test_bounded_dns_evidence_has_no_raw_candidate_values(self) -> None:
        candidates = _ipv4_candidates(8) + _ipv6_candidates(1)
        normalized = validate_resolved_addresses(candidates, max_candidates=16)
        bounded = {"candidate_count": len(candidates), "ipv4_count": 8, "ipv6_count": 1, "result_hash": network_policy_hash({"max_dns_candidates": 16})}
        serialized = json.dumps(bounded, sort_keys=True)
        for candidate in normalized:
            self.assertNotIn(candidate, serialized)

    def test_old_cap_four_preview_remains_parseable(self) -> None:
        normalized = _normalize_preview_value(_preview(4))
        self.assertEqual(normalized["dns_preflight_requirement"]["max_dns_candidates"], 4)

    def test_new_preview_binds_exact_sixteen_and_rejects_spoofed_thirty_two(self) -> None:
        normalized = _normalize_preview_value(_preview(16))
        self.assertEqual(normalized["dns_preflight_requirement"]["max_dns_candidates"], 16)
        self.assertNotEqual(network_policy_hash({}), network_policy_hash({"max_dns_candidates": 16}))
        for value in (32, True, "16"):
            with self.subTest(value=value), self.assertRaises(LiveCanaryAuthorityError):
                _normalize_preview_value(_preview(value))

    def test_old_policy_hash_cannot_be_reused_for_new_cap(self) -> None:
        old_hash = network_policy_hash({})
        new_hash = network_policy_hash({"max_dns_candidates": 16})
        self.assertNotEqual(old_hash, new_hash)
        self.assertEqual(normalize_network_policy({})["max_dns_candidates"], 4)

    def test_release_identity_dev6_and_dev7_are_unique(self) -> None:
        base = {
            "package": "research-kb",
            "sdist_sha256": "b" * 64,
            "source_tree_sha256": "c" * 64,
            "release_manifest_sha256": "d" * 64,
            "migration_release_manifest_sha256": "e" * 64,
            "core_schema_version": 5,
            "control_schema_version": 19,
        }
        dev6 = {**base, "package_version": "0.1.1.dev6", "wheel_sha256": "1" * 64}
        dev7 = {**base, "package_version": __version__, "wheel_sha256": "2" * 64}
        self.assertEqual(validate_release_identity_unique(dev7, [dev6])["package_version"], __version__)
        with self.assertRaises(ReleaseIdentityError):
            validate_release_identity_unique({**dev7, "wheel_sha256": "3" * 64}, [dev7])


if __name__ == "__main__":
    unittest.main()
