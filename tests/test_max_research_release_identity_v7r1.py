from __future__ import annotations

import unittest

from research_kb.max_research.live_canary import _preview_confirmation_phrase, _safe_json
from research_kb.max_research.long_run import SourceEgressPolicy
from research_kb.max_research.release_identity import (
    ReleaseIdentityError,
    assert_preview_release_binding,
    validate_release_identity_unique,
)


def _identity(version: str = "0.1.1.dev6", wheel: str = "a" * 64) -> dict[str, object]:
    return {
        "package": "research-kb",
        "package_version": version,
        "wheel_sha256": wheel,
        "sdist_sha256": "b" * 64,
        "source_tree_sha256": "c" * 64,
        "release_manifest_sha256": "d" * 64,
        "migration_release_manifest_sha256": "e" * 64,
        "core_schema_version": 5,
        "control_schema_version": 19,
    }


class ReleaseIdentityV7R1Tests(unittest.TestCase):
    def test_one_release_identity_cannot_have_two_wheel_hashes(self) -> None:
        with self.assertRaisesRegex(ReleaseIdentityError, "wheel_sha256"):
            validate_release_identity_unique(_identity(wheel="f" * 64), [_identity()])

    def test_registered_version_content_drift_fails_closed(self) -> None:
        changed = _identity()
        changed["source_tree_sha256"] = "f" * 64
        with self.assertRaisesRegex(ReleaseIdentityError, "source_tree_sha256"):
            validate_release_identity_unique(changed, [_identity()])

    def test_dev5_and_dev6_are_distinct_release_identities(self) -> None:
        dev5 = _identity(version="0.1.1.dev5", wheel="1" * 64)
        dev6 = _identity(version="0.1.1.dev6", wheel="2" * 64)
        self.assertEqual(validate_release_identity_unique(dev6, [dev5])["package_version"], "0.1.1.dev6")

    def test_preview_binds_release_and_schema_identity(self) -> None:
        identity = _identity()
        preview = {
            "engine_package": "research-kb",
            "engine_version": "0.1.1.dev6",
            "candidate_wheel_sha256": identity["wheel_sha256"],
            "source_tree_sha256": identity["source_tree_sha256"],
            "core_schema_version": 5,
            "control_schema_version": 19,
        }
        assert_preview_release_binding(preview, identity)
        preview["candidate_wheel_sha256"] = "f" * 64
        with self.assertRaisesRegex(ReleaseIdentityError, "candidate_wheel_sha256"):
            assert_preview_release_binding(preview, identity)

    def test_dns_pending_preview_does_not_mint_live_canary_phrase(self) -> None:
        self.assertEqual(_preview_confirmation_phrase("a" * 64, "AWAITING_DNS_PREFLIGHT_AUTHORIZATION"), "")
        self.assertEqual(_preview_confirmation_phrase("a" * 64, None), "APPROVE MR-4B1 CANARY " + "a" * 64)

    def test_source_binding_allows_only_hash_metadata(self) -> None:
        value = {
            "document_content_hash": "a" * 64,
            "passage_content_hash": "b" * 64,
            "citation_locator_hash": "c" * 64,
            "metadata_hash": "d" * 64,
            "source_policy_hash": "e" * 64,
        }
        self.assertEqual(_safe_json(value, "source binding"), value)
        with self.assertRaisesRegex(Exception, "prohibited"):
            _safe_json({"source_content": "raw"}, "source binding")

    def test_core_research_object_is_a_governed_source_role(self) -> None:
        policy = SourceEgressPolicy(
            {
                "allowed_purposes": ["supports"],
                "allowed_projects": ["pilot"],
                "allow_document_ids": ["doc_6102ba2b793e3983c38e"],
                "allow_passage_ids": ["psg_00000000000000000001"],
                "allowed_source_versions": ["publisher-pdf"],
                "source_role_policy": {
                    "allowed_roles": ["core_research_object"],
                    "allowed_functions": ["supports"],
                },
                "reliability_policy": {"allowed_statuses": ["unverified"]},
                "verification_policy": {"allowed_statuses": ["unverified"]},
                "max_packets": 1,
                "max_documents": 1,
                "max_passages": 1,
                "max_excerpt_characters": 1000,
                "max_context_characters": 0,
                "max_document_characters": 1000,
                "max_passage_characters": 1000,
                "max_source_characters": 1000,
                "max_source_tokens": 256,
                "max_packet_source_tokens": 256,
                "full_document_prohibited": True,
                "expires_at": "2030-01-01T00:00:00.000Z",
                "authority_reason": "release identity regression",
            }
        )
        self.assertEqual(policy.allowed_roles, ("core_research_object",))


if __name__ == "__main__":
    unittest.main()
