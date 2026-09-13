from __future__ import annotations

import unittest

from test_max_research_mr4b1b_r import _profile_mapping

from research_kb.max_research.provider.contract import (
    ProviderContractError,
    ProviderProfile,
    TokenEnvelope,
    normalize_openai_compatible_usage,
    token_envelope_within_caps,
)


class MR4B1BV5RContractTest(unittest.TestCase):
    def _exact_profile(self) -> ProviderProfile:
        mapping = _profile_mapping()
        mapping.update(
            {
                "profile_id": "mr4b1b-v5r-exact-profile",
                "provider_name": "opencode-go",
                "model_identity": "deepseek-v4-flash",
                "request_limits": {
                    "max_request_bytes": 65536,
                    "max_response_bytes": 262144,
                    "max_prompt_chars": 12000,
                    "max_json_depth": 16,
                    "max_input_tokens": 4096,
                    "max_output_tokens": 256,
                    "max_cache_read_tokens": 4096,
                    "max_reasoning_tokens": 256,
                },
                "inference_defaults": {
                    "temperature": 0,
                    "max_input_tokens": 4096,
                    "max_output_tokens": 256,
                    "max_cache_read_tokens": 4096,
                    "max_reasoning_tokens": 256,
                },
                "pricing": {
                    "pricing_id": "mr4b1b-v5r-exact-price",
                    "pricing_version": "2026-08-14",
                    "currency": "USD",
                    "unit": "micro_usd",
                    "input_per_1k": "140.0",
                    "output_per_1k": "280.0",
                    "cache_per_1k": "2.8",
                    "reasoning_per_1k": "280.0",
                    "effective_at": "2026-08-14T00:00:00.000Z",
                    "source_label": "offline-fixture",
                },
            }
        )
        return ProviderProfile.from_mapping(mapping)

    def test_exact_profile_uses_four_components_and_preserves_729_cost(self) -> None:
        profile = self._exact_profile()
        maximum = profile.authority_maximum_usage()
        self.assertEqual(
            maximum,
            {
                "input_tokens": 4096,
                "cache_read_tokens": 4096,
                "output_tokens": 256,
                "reasoning_tokens": 256,
            },
        )
        envelope = TokenEnvelope.from_mapping(maximum)
        self.assertEqual(envelope.family_totals(), {"input_family_tokens": 8192, "output_family_tokens": 512})
        self.assertTrue(
            token_envelope_within_caps(
                maximum,
                {
                    "max_input_tokens": 4096,
                    "max_cache_read_tokens": 4096,
                    "max_output_tokens": 256,
                    "max_reasoning_tokens": 256,
                },
            )
        )
        self.assertEqual(profile.pricing.cost_units_for_usage(maximum), 729)

    def test_component_and_derived_family_boundary_matrix(self) -> None:
        caps = {
            "max_input_tokens": 4096,
            "max_cache_read_tokens": 4096,
            "max_output_tokens": 256,
            "max_reasoning_tokens": 256,
        }
        self.assertTrue(token_envelope_within_caps({"input_tokens": 4096, "cache_read_tokens": 4096, "output_tokens": 256, "reasoning_tokens": 256}, caps))
        for component, value in (("input_tokens", 4097), ("cache_read_tokens", 4097), ("output_tokens", 257), ("reasoning_tokens", 257)):
            usage = {"input_tokens": 0, "cache_read_tokens": 0, "output_tokens": 0, "reasoning_tokens": 0}
            usage[component] = value
            self.assertFalse(token_envelope_within_caps(usage, caps), component)
        with self.assertRaises(ProviderContractError) as caught:
            TokenEnvelope.from_mapping({"input_tokens": 1, "input_family_tokens": 1})
        self.assertEqual(caught.exception.code, "USAGE_DISPUTE")

    def test_openai_compatible_usage_normalizes_details_without_double_counting(self) -> None:
        raw = {
            "prompt_tokens": 8192,
            "input_tokens": 8192,
            "completion_tokens": 512,
            "output_tokens": 512,
            "prompt_tokens_details": {"cached_tokens": 4096},
            "input_tokens_details": {"cached_tokens": 4096},
            "completion_tokens_details": {"reasoning_tokens": 256},
            "output_tokens_details": {"reasoning_tokens": 256},
            "total_tokens": 8704,
        }
        self.assertEqual(
            normalize_openai_compatible_usage(raw),
            {"cache_read_tokens": 4096, "input_tokens": 4096, "output_tokens": 256, "reasoning_tokens": 256},
        )

    def test_openai_compatible_usage_conflicts_and_unknowns_fail_closed(self) -> None:
        cases = (
            {"prompt_tokens": 8, "input_tokens": 9, "completion_tokens": 1},
            {"prompt_tokens": 8, "completion_tokens": 1, "prompt_tokens_details": {"cached_tokens": 9}},
            {"prompt_tokens": 8, "completion_tokens": 1, "total_tokens": 8},
            {"prompt_tokens": 8, "completion_tokens": 1, "unknown": 0},
            {"prompt_tokens": 8, "completion_tokens": 1, "completion_tokens_details": {"reasoning_tokens": 1, "other": 1}},
        )
        for raw in cases:
            with self.subTest(keys=sorted(raw)):
                with self.assertRaises(ProviderContractError) as caught:
                    normalize_openai_compatible_usage(raw)
                self.assertEqual(caught.exception.code, "USAGE_DISPUTE")


if __name__ == "__main__":
    unittest.main()
