"""Offline tests for the server-owned dev20 host credential boundary."""

from __future__ import annotations

import unittest
from collections.abc import Iterator, Mapping
from unittest.mock import patch

from _mr4b1b_schema22_fixture import Schema22NativeFixture
from research_kb.max_research.convergence import LiveExecutionCapsuleStore, _OneShotCachingResolver
from research_kb.max_research.provider import (
    BoundHostEnvironmentCredentialResolver,
    CredentialRef,
    InjectedDNSResolver,
    InjectedHTTPSConnector,
    ProviderTransportError,
    ProviderUsageAuthority,
    TransportResponse,
    credential_reference_hash,
)
from research_kb.max_research.provider.live import make_convergence_transport_factory


class _NonEnumeratingEnvironment(Mapping[str, object]):
    def __init__(self, values: dict[str, object]) -> None:
        self.values = values
        self.get_calls: list[tuple[str, object]] = []

    def __getitem__(self, key: str) -> object:
        raise AssertionError("environment enumeration or item lookup was not allowed")

    def __iter__(self) -> Iterator[str]:
        raise AssertionError("environment enumeration was not allowed")

    def __len__(self) -> int:
        raise AssertionError("environment enumeration was not allowed")

    def get(self, key: str, default: object = None) -> object:
        self.get_calls.append((key, default))
        return self.values.get(key, default)


class BoundHostEnvironmentCredentialResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.reference = CredentialRef("environment", "OPENCODE_GO_API_KEY")
        self.reference_hash = credential_reference_hash(self.reference)

    def _resolver(self, environment: Mapping[str, object], **kwargs: object) -> BoundHostEnvironmentCredentialResolver:
        return BoundHostEnvironmentCredentialResolver(
            self.reference,
            self.reference_hash,
            environment=environment,
            **kwargs,
        )

    def _assert_code(self, code: str, callback) -> None:
        with self.assertRaises(ProviderTransportError) as caught:
            callback()
        self.assertEqual(caught.exception.code, code)
        self.assertNotIn(self.reference.name, str(caught.exception))

    def test_exact_process_environment_lookup_and_success_counters(self) -> None:
        environment = _NonEnumeratingEnvironment({self.reference.name: "fake-value"})
        resolver = self._resolver(environment, platform="linux")

        self.assertEqual(resolver.resolve(self.reference), "fake-value")
        self.assertEqual(environment.get_calls.__len__(), 1)
        self.assertEqual(resolver.credential_resolution_attempts, 1)
        self.assertEqual(resolver.credential_reads_succeeded, 1)
        self.assertEqual(resolver.read_count, 1)
        self.assertEqual(resolver.last_source_category, "process_environment")

    def test_process_hit_never_queries_registry(self) -> None:
        registry_calls: list[str] = []

        def registry_query(name: str):
            registry_calls.append(name)
            raise AssertionError("registry fallback was not allowed after a process hit")

        resolver = self._resolver(
            {self.reference.name: "fake-value"},
            registry_query=registry_query,
            platform="win32",
        )
        self.assertEqual(resolver.resolve(self.reference), "fake-value")
        self.assertEqual(registry_calls, [])

    def test_windows_user_environment_hkcu_exact_reg_sz_fallback(self) -> None:
        calls: list[str] = []

        def registry_query(name: str):
            calls.append(name)
            return ("fake-value", "REG_SZ")

        resolver = self._resolver({}, registry_query=registry_query, platform="win32")
        self.assertEqual(resolver.resolve(self.reference), "fake-value")
        self.assertEqual(calls, [self.reference.name])
        self.assertEqual(resolver.last_source_category, "windows_user_environment")
        self.assertEqual(resolver.credential_resolution_attempts, 1)
        self.assertEqual(resolver.credential_reads_succeeded, 1)

    def test_windows_integer_reg_sz_type_is_accepted_without_expansion(self) -> None:
        resolver = self._resolver(
            {},
            registry_query=lambda name: ("fake-value", 1),
            platform="win32",
        )
        self.assertEqual(resolver.resolve(self.reference), "fake-value")

    def test_missing_or_non_windows_value_fails_closed_without_success_read(self) -> None:
        resolver = self._resolver({}, platform="linux")
        self._assert_code("CREDENTIAL_RESOLUTION_FAILED", lambda: resolver.resolve(self.reference))
        self.assertEqual(resolver.credential_resolution_attempts, 1)
        self.assertEqual(resolver.credential_reads_succeeded, 0)
        self.assertEqual(resolver.read_count, 0)
        self.assertIsNone(resolver.last_source_category)

    def test_invalid_process_value_does_not_fallback_to_registry(self) -> None:
        registry_calls: list[str] = []

        def registry_query(name: str):
            registry_calls.append(name)
            return ("fake-value", "REG_SZ")

        resolver = self._resolver(
            {self.reference.name: "bad\nvalue"},
            registry_query=registry_query,
            platform="win32",
        )
        self._assert_code("CREDENTIAL_RESOLUTION_FAILED", lambda: resolver.resolve(self.reference))
        self.assertEqual(registry_calls, [])
        self.assertEqual(resolver.credential_reads_succeeded, 0)

    def test_registry_type_and_value_validation(self) -> None:
        for registry_result in (
            ("fake-value", "REG_EXPAND_SZ"),
            ("fake-value", "REG_BINARY"),
            ("", "REG_SZ"),
            ("bad\rvalue", "REG_SZ"),
            ("x" * 8193, "REG_SZ"),
            (b"binary", "REG_SZ"),
            ("fake-value",),
            None,
        ):
            with self.subTest(registry_result=type(registry_result).__name__):
                resolver = self._resolver(
                    {},
                    registry_query=lambda name, result=registry_result: result,
                    platform="win32",
                )
                self._assert_code("CREDENTIAL_RESOLUTION_FAILED", lambda: resolver.resolve(self.reference))
                self.assertEqual(resolver.credential_reads_succeeded, 0)

    def test_wrong_reference_kind_hash_name_and_replay_fail_closed(self) -> None:
        with self.assertRaises(ProviderTransportError) as wrong_kind:
            BoundHostEnvironmentCredentialResolver(
                CredentialRef("external", "OPENCODE_GO_API_KEY"),
                self.reference_hash,
            )
        self.assertEqual(wrong_kind.exception.code, "CREDENTIAL_REFERENCE_FORBIDDEN")

        self._assert_code(
            "CREDENTIAL_REFERENCE_BINDING_MISMATCH",
            lambda: BoundHostEnvironmentCredentialResolver(self.reference, "0" * 64),
        )
        self._assert_code(
            "CREDENTIAL_REFERENCE_INVALID",
            lambda: BoundHostEnvironmentCredentialResolver(
                CredentialRef("environment", "not-safe"),
                self.reference_hash,
            ),
        )

        resolver = self._resolver({self.reference.name: "fake-value"}, platform="linux")
        resolver.resolve(self.reference)
        self._assert_code("CREDENTIAL_RESOLUTION_RETRY_FORBIDDEN", lambda: resolver.resolve(self.reference))
        self.assertEqual(resolver.credential_resolution_attempts, 1)
        self.assertEqual(resolver.credential_reads_succeeded, 1)

    def test_only_bound_credential_ref_is_accepted(self) -> None:
        resolver = self._resolver({self.reference.name: "fake-value"}, platform="linux")
        self._assert_code("CREDENTIAL_REFERENCE_FORBIDDEN", lambda: resolver.resolve(self.reference.name))


def _provider_response(model: str) -> dict[str, object]:
    proposal = {
        "objects": [],
        "relations": [],
        "artifact_links": [],
        "record_refs": [],
        "strategy": None,
        "output_summary": "bounded fake result",
        "role_outputs": [],
        "deliberation": None,
    }
    return {
        "id": "credential-closure-hermetic-call",
        "object": "chat.completion",
        "model": model,
        "choices": [{
            "index": 0,
            "finish_reason": "stop",
            "message": {
                "role": "assistant",
                "content": __import__("json").dumps(proposal, separators=(",", ":")),
            },
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }


class BoundHostProductionShapedTests(unittest.TestCase):
    def test_non_fixture_production_shaped_flow_uses_bound_host_resolver(self) -> None:
        fixture = Schema22NativeFixture(
            legacy_dns_receipt=False,
            fixture_control=False,
            credential_kind="environment",
            credential_name="SCHEMA22_HERMETIC_CREDENTIAL",
        )
        try:
            store = LiveExecutionCapsuleStore(
                fixture.repo,
                source_database=fixture.source_database,
                expected_release_identity=fixture.release,
            )
            injected = InjectedDNSResolver({
                "opencode.ai": ("93.184.216.34",),
                "provider.invalid": ("93.184.216.34",),
            })
            cached = _OneShotCachingResolver(injected)
            connector = InjectedHTTPSConnector(
                TransportResponse(
                    200,
                    _provider_response(fixture.profile.model_identity),
                    {"content-type": "application/json"},
                    "credential-closure-hermetic-call",
                    True,
                )
            )
            credential = BoundHostEnvironmentCredentialResolver(
                fixture.profile.credential_ref,
                credential_reference_hash(fixture.profile.credential_ref),
                environment={fixture.profile.credential_ref.name: "fake-value"},
                platform="linux",
            )
            factory = make_convergence_transport_factory(
                cached,
                connector=connector,
                credential_resolver=credential,
            )
            import research_kb.max_research.request_builder as request_builder_module

            with patch.object(request_builder_module, "CORE_DATABASE", fixture.source_database):
                preview = store.create_preview(
                    preparation_preview_id=fixture.preview["preview_id"],
                    actor=fixture.admin,
                    ttl_seconds=3600,
                )
                result = store.execute(
                    capsule_hash=str(preview["capsule_hash"]),
                    confirmation=str(preview["confirmation"]),
                    actor=fixture.admin,
                    resolver=cached,
                    transport_factory=factory,
                    usage_authority=ProviderUsageAuthority(),
                    live_network_enabled=True,
                )
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["outcome"], "AUTHORITATIVE_PROVIDER_RESULT")
            self.assertEqual(credential.credential_resolution_attempts, 1)
            self.assertEqual(credential.credential_reads_succeeded, 1)
            self.assertEqual(credential.last_source_category, "process_environment")
            self.assertEqual(connector.network_call_count, 1)
            self.assertTrue(store.verify(capsule_hash=str(preview["capsule_hash"]))["ok"])
        finally:
            fixture.close()


if __name__ == "__main__":
    unittest.main()
