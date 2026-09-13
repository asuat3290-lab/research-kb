"""MR-4B1B-v7R offline transport-boundary regression tests.

These tests use the existing server-issued fixture permits and injected DNS,
credential, and connector seams.  They never call an operating-system
resolver, read an environment credential, or open a socket.
"""

from __future__ import annotations

import json
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from typing import Any, Iterator

from research_kb.max_research.provider import (
    InjectedCredentialResolver,
    InjectedDNSResolver,
    InjectedHTTPSConnector,
    OpenAICompatibleHTTPSLiveTransport,
    ProviderContractError,
    ProviderTransportError,
    TransportResponse,
    normalize_network_policy,
)
from research_kb.max_research.provider.live import validate_resolved_addresses
from research_kb.max_research.live_canary import LiveCanaryAuthorityError, LiveCanaryAuthorityStore
from research_kb.max_research.production_bridge import LiveCanaryExecutor

import tests.test_max_research_mr2b1a as _mr2b1a_fixture
import tests.test_max_research_mr4b1b_r as _mr4b1br_fixture


class _RaisingResolver:
    def __init__(self) -> None:
        self.lookup_count = 0

    def resolve(self, _host: str, _port: int):
        self.lookup_count += 1
        raise RuntimeError("offline resolver fixture failure")


class _SlowConnector(InjectedHTTPSConnector):
    def request(self, **kwargs: Any) -> TransportResponse:
        time.sleep(0.02)
        return super().request(**kwargs)


class MR4B1BV7RTransportTests(unittest.TestCase):
    @contextmanager
    def _case(
        self,
        *,
        answers: list[Any] | None = None,
        resolver: Any | None = None,
        credential_values: dict[str, str] | None = None,
        connector: Any | None = None,
        callback: Any | None = None,
        network_policy: dict[str, Any] | None = None,
    ) -> Iterator[tuple[Any, Any, bytes, str, OpenAICompatibleHTTPSLiveTransport, Any, Any, Any]]:
        fixture = _mr2b1a_fixture.MR2B1ATests("test_start_send_and_settled_replay_have_one_physical_call")
        fixture.setUp()
        try:
            permit, _request, body, fence, idempotency_key = fixture._started_permit()
            credential_name, credential_value = _mr2b1a_fixture._credential_fixture()
            credential_resolver = InjectedCredentialResolver(credential_values if credential_values is not None else {credential_name: credential_value})
            dns_resolver = resolver or InjectedDNSResolver({"provider.invalid": tuple(answers if answers is not None else ["93.184.216.34"])})
            https_connector = connector if connector is not None else InjectedHTTPSConnector(TransportResponse(200, b"{}", {"content-type": "application/json"}, "offline-call", True))
            transport = OpenAICompatibleHTTPSLiveTransport(
                endpoint_origin=fixture.profile.endpoint_origin,
                endpoint_path_policy=fixture.profile.endpoint_path_policy,
                credential_ref=fixture.profile.credential_ref,
                network_policy=network_policy or _mr2b1a_fixture._policy(),
                credential_resolver=credential_resolver,
                permit=permit,
                permit_validator=fixture.store.validate_live_dispatch_permit,
                dns_resolver=dns_resolver,
                connector=https_connector,
                network_event_callback=callback,
            )
            yield fixture, permit, body, idempotency_key, transport, credential_resolver, dns_resolver, https_connector
        finally:
            fixture.tearDown()

    def _send(self, transport: OpenAICompatibleHTTPSLiveTransport, body: bytes, key: str) -> TransportResponse:
        return transport.send(body, headers={"Content-Type": "application/json"}, timeout_ms=1000, idempotency_key=key)

    def test_policy_keeps_default_four_and_allows_reviewed_explicit_cap(self) -> None:
        self.assertEqual(normalize_network_policy(_mr2b1a_fixture._policy())["max_dns_candidates"], 4)
        self.assertEqual(normalize_network_policy({**_mr2b1a_fixture._policy(), "max_dns_candidates": 8})["max_dns_candidates"], 8)
        self.assertEqual(normalize_network_policy({**_mr2b1a_fixture._policy(), "max_dns_candidates": 16})["max_dns_candidates"], 16)
        for invalid in (17, 0, -1, True, "16"):
            with self.subTest(invalid=invalid), self.assertRaises(ProviderContractError):
                normalize_network_policy({**_mr2b1a_fixture._policy(), "max_dns_candidates": invalid})

    def test_dns_empty_limit_malformed_and_exception_are_pre_send(self) -> None:
        cases = [
            ([], "DNS_RESULT_EMPTY"),
            (["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222", "4.2.2.2"], "DNS_CANDIDATE_LIMIT_EXCEEDED"),
            (["not-an-ip"], "DNS_ADDRESS_INVALID"),
        ]
        for answers, expected in cases:
            with self.subTest(expected=expected):
                with self._case(answers=answers) as (_fixture, _permit, body, key, transport, credential, dns, connector):
                    with self.assertRaises(ProviderTransportError) as caught:
                        self._send(transport, body, key)
                    self.assertEqual(caught.exception.code, expected)
                    self.assertEqual(dns.lookup_count, 1)
                    self.assertEqual(credential.read_count, 0)
                    self.assertEqual(connector.network_call_count, 0)

        with self._case(resolver=_RaisingResolver()) as (_fixture, _permit, body, key, transport, credential, dns, connector):
            with self.assertRaises(ProviderTransportError) as caught:
                self._send(transport, body, key)
            self.assertEqual(caught.exception.code, "DNS_RESOLUTION_FAILED")
            self.assertEqual(dns.lookup_count, 1)
            self.assertEqual(credential.read_count, 0)
            self.assertEqual(connector.network_call_count, 0)

    def test_all_ssrf_candidates_are_checked_before_credential_or_connector(self) -> None:
        blocked = ["10.0.0.1", "127.0.0.1", "169.254.1.1", "192.0.2.1", "224.0.0.1"]
        for address in blocked:
            with self.subTest(address_class=address):
                with self._case(answers=["93.184.216.34", address]) as (_fixture, _permit, body, key, transport, credential, dns, connector):
                    with self.assertRaises(ProviderTransportError) as caught:
                        self._send(transport, body, key)
                    self.assertEqual(caught.exception.code, "SSRF_ADDRESS_BLOCKED")
                    self.assertEqual(dns.lookup_count, 1)
                    self.assertEqual(credential.read_count, 0)
                    self.assertEqual(connector.network_call_count, 0)

    def test_mixed_ipv4_ipv6_is_normalized_and_sends_once(self) -> None:
        with self._case(answers=["2606:4700:4700::1111", "93.184.216.34", "93.184.216.34"]) as (_fixture, _permit, body, key, transport, credential, dns, connector):
            response = self._send(transport, body, key)
            self.assertEqual(response.provider_call_id, "offline-call")
            self.assertEqual(dns.lookup_count, 1)
            self.assertEqual(credential.read_count, 1)
            self.assertEqual(connector.network_call_count, 1)
            self.assertEqual(connector.requests[0]["address"], "93.184.216.34")

    def test_missing_credential_and_disabled_connector_are_pre_send(self) -> None:
        with self._case(credential_values={}) as (_fixture, _permit, body, key, transport, credential, dns, connector):
            with self.assertRaises(ProviderTransportError) as caught:
                self._send(transport, body, key)
            self.assertEqual(caught.exception.code, "CREDENTIAL_RESOLUTION_FAILED")
            self.assertEqual(dns.lookup_count, 1)
            self.assertEqual(credential.read_count, 1)
            self.assertEqual(connector.network_call_count, 0)

        with self._case(connector=None) as (_fixture, _permit, body, key, transport, credential, dns, _connector):
            transport.connector = None
            with self.assertRaises(ProviderTransportError) as caught:
                self._send(transport, body, key)
            self.assertEqual(caught.exception.code, "LIVE_PROVIDER_DISABLED")
            self.assertEqual(dns.lookup_count, 1)
            self.assertEqual(credential.read_count, 1)
            self.assertEqual(transport.network_call_count, 0)

    def test_boundary_callback_is_once_and_callback_failure_blocks_connector(self) -> None:
        boundary_events: list[str] = []

        def callback(_permit: Any) -> None:
            boundary_events.append("crossed")

        with self._case(callback=None) as (_fixture, permit, body, key, transport, credential, dns, connector):
            transport.configure_boundary_callbacks(send_boundary_callback=callback)
            self._send(transport, body, key)
            with self.assertRaises(ProviderTransportError) as retry:
                self._send(transport, body, key)
            self.assertEqual(retry.exception.code, "PHYSICAL_CALL_RETRY_FORBIDDEN")
            self.assertEqual(boundary_events, ["crossed"])
            self.assertEqual(connector.network_call_count, 1)

        def failing_callback(_permit: Any) -> None:
            raise RuntimeError("offline boundary callback failure")

        with self._case(callback=None) as (_fixture, _permit, body, key, transport, _credential, _dns, connector):
            transport.configure_boundary_callbacks(send_boundary_callback=failing_callback)
            with self.assertRaises(ProviderTransportError) as caught:
                self._send(transport, body, key)
            self.assertEqual(caught.exception.code, "HTTP_BOUNDARY_CALLBACK_FAILED")
            self.assertEqual(connector.network_call_count, 0)

    def test_dns_exception_has_durable_bounded_audit_and_no_raw_values(self) -> None:
        persisted: list[str] = []

        with self._case(resolver=_RaisingResolver(), callback=None) as (fixture, permit, body, key, transport, _credential, _dns, _connector):
            def audit(event_type: str, payload: dict[str, Any]) -> None:
                persisted.append(event_type)
                fixture.store.record_live_network_access_event(
                    authorization_id=permit.authorization_id,
                    run_id=permit.run_id,
                    project_id=permit.project_id,
                    event_type=event_type,
                    actor=fixture.worker,
                    provider_attempt_id=permit.attempt_id,
                    claim_id=permit.claim_id,
                    fencing_token=int(permit.fencing_token),
                    details=payload,
                )

            transport.configure_boundary_callbacks(network_event_callback=audit)
            with self.assertRaises(ProviderTransportError) as caught:
                self._send(transport, body, key)
            self.assertEqual(caught.exception.code, "DNS_RESOLUTION_FAILED")
            self.assertEqual(persisted, ["transport_preflight_started", "dns_resolution_started", "dns_resolution_completed"])
            with closing(fixture.repo._connect(read_only=True)) as connection:
                rows = list(connection.execute("SELECT payload_json FROM max_live_network_access_events WHERE authorization_id=? ORDER BY sequence_no", (permit.authorization_id,)))
            serialized = json.dumps([json.loads(row[0]) for row in rows], ensure_ascii=False)
            self.assertNotIn("93.184.216.34", serialized)
            self.assertNotIn("offline resolver fixture failure", serialized)
            self.assertTrue(fixture.store.verify_live_network(run_id=permit.run_id)["ok"])

    def test_twenty_concurrent_sends_have_one_physical_connector_call(self) -> None:
        with self._case(connector=_SlowConnector()) as (_fixture, _permit, body, key, transport, _credential, _dns, connector):
            def invoke() -> str:
                try:
                    self._send(transport, body, key)
                    return "ok"
                except ProviderTransportError as exc:
                    return exc.code

            with ThreadPoolExecutor(max_workers=20) as pool:
                results = list(pool.map(lambda _index: invoke(), range(20)))
            self.assertEqual(results.count("ok"), 1)
            self.assertEqual(connector.network_call_count, 1)
            self.assertEqual(transport.network_call_count, 1)

    def test_bridge_dns_failure_is_known_pre_send_without_legacy_marker(self) -> None:
        fixture = _mr4b1br_fixture.MR4B1BRTest("test_hermetic_executor_success_calls_fake_transport_once_and_settles")
        fixture.setUp()
        created: dict[str, Any] = {}
        try:
            preview, inputs, registration = fixture._execution_inputs()

            def factory(*, profile: Any, permit: Any, provider_store: Any) -> OpenAICompatibleHTTPSLiveTransport:
                credential_name = profile.credential_ref.name
                credential = InjectedCredentialResolver({credential_name: "offline-injected-credential"})
                dns = InjectedDNSResolver({"provider.invalid": []})
                connector = InjectedHTTPSConnector()
                transport = OpenAICompatibleHTTPSLiveTransport(
                    endpoint_origin=profile.endpoint_origin,
                    endpoint_path_policy=profile.endpoint_path_policy,
                    credential_ref=profile.credential_ref,
                    network_policy=_mr4b1br_fixture._network_policy(),
                    credential_resolver=credential,
                    permit=permit,
                    permit_validator=provider_store.validate_live_dispatch_permit,
                    dns_resolver=dns,
                    connector=connector,
                )
                created.update(transport=transport, dns=dns, credential=credential, connector=connector)
                return transport

            executor = LiveCanaryExecutor(fixture.repo, fixture.authority, provider_store=fixture.store, transport_factory=factory, live_network_enabled=True)
            with self.assertRaises(LiveCanaryAuthorityError) as caught:
                executor.execute_fixture(
                    authority_id=registration["authority_id"],
                    approval_id=inputs["approval"]["approval_id"],
                    preview_hash=preview["preview_hash"],
                    confirmation_phrase=preview["confirmation_phrase"],
                    actor=fixture.worker,
                    worker_id=fixture.worker.actor_id,
                    worker_session=fixture.worker.session_id,
                    fencing_token=fixture.fencing_token,
                    claim_id=fixture.claim_id,
                    request={"phase": "offline-dns-failure"},
                    logical_call_id=fixture.intent.logical_call_id,
                    idempotency_key=fixture.intent.idempotency_key,
                    authorization_id=inputs["authorization"]["authorization_id"],
                    grant_id=inputs["grant"]["grant_id"],
                    source_permit_validator=lambda: True,
                    allow_execute=True,
                )
            self.assertIn("KNOWN_PRE_SEND_FAILURE", str(caught.exception))
            self.assertEqual(created["dns"].lookup_count, 1)
            self.assertEqual(created["credential"].read_count, 0)
            self.assertEqual(created["connector"].network_call_count, 0)
            with closing(fixture.repo._connect(read_only=True)) as connection:
                outcome = connection.execute("SELECT permit_id, outcome, outcome_json FROM max_live_canary_outcomes ORDER BY created_at DESC LIMIT 1").fetchone()
                self.assertIsNotNone(outcome)
                self.assertEqual(outcome[1], "aborted")
                self.assertEqual(json.loads(outcome[2])["diagnostics"]["error_code"], "DNS_RESULT_EMPTY")
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_events WHERE permit_id=? AND event_type='send_started'", (outcome[0],)).fetchone()[0], 0)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_network_attempt_records").fetchone()[0], 0)
            classification = fixture.authority.classify_provider_boundary(permit_id=str(outcome[0]))
            self.assertEqual(classification["failure_class"], "KNOWN_PRE_SEND_FAILURE")
            self.assertFalse(classification["send_boundary_reached"])
        finally:
            fixture.tearDown()

    def test_address_normalization_does_not_persist_raw_candidates(self) -> None:
        normalized = validate_resolved_addresses([("93.184.216.34", 443), ("2606:4700:4700::1111", 443, 0, 0)])
        self.assertEqual(normalized, ("93.184.216.34", "2606:4700:4700::1111"))


if __name__ == "__main__":
    unittest.main()
