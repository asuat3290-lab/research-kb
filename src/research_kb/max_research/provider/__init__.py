"""MR-2B0 provider contract, hermetic transport, codec and usage authority."""

from .adapter import OpenAICompatibleAdapter
from .bundle import LiveAuthorizationBundleStore, LiveAuthorizationPoolAdapter
from .execution import LIVE_EXECUTION_ACK, LiveIterationApprovalStore, LiveRunnerExecutor, live_execution_confirmation_hash
from .codec import DecodedProviderResponse, EncodedProviderRequest, OpenAICompatibleCodec, ProviderCodecError, TrustedSourceData
from .contract import (
    CredentialRef,
    PricingSnapshot,
    ProviderCapabilities,
    ProviderContractError,
    ProviderProfile,
    TokenEnvelope,
    assert_token_envelope_within_caps,
    normalize_openai_compatible_usage,
    normalize_usage,
    token_envelope_within_caps,
)
from .store import ProviderStore
from .live import (
    InjectedDNSResolver,
    InjectedHTTPSConnector,
    LiveDispatchPermit, LiveNetworkAuthorization,
    LiveProviderTransportFactory, ProductionProviderTransportFactory,
    OpenAICompatibleHTTPSLiveTransport,
    OpenAICompatibleHTTPSTransport,
    ProductionHTTPSProviderTransport,
    credential_reference_hash,
    default_live_transport,
    endpoint_hashes,
    network_policy_hash,
    normalize_network_policy,
    validate_endpoint_static,
    validate_resolved_addresses,
)
from .live_adapter import LiveOpenAICompatibleAdapter
from .transport import BoundHostEnvironmentCredentialResolver, DisabledLiveTransport, EnvironmentCredentialResolver, HermeticTransport, InjectedCredentialResolver, InjectedHermeticTransport, NullCredentialResolver, ProviderTransportError, SecureEnvironmentCredentialResolver, TransportResponse
from .usage import PROVIDER_USAGE_AUTHORITY_ID, ProviderCallRecord, ProviderUsageAttestation, ProviderUsageAuthority

__all__ = [
    "CredentialRef", "DecodedProviderResponse", "DisabledLiveTransport", "EncodedProviderRequest", "EnvironmentCredentialResolver", "HermeticTransport", "InjectedCredentialResolver", "InjectedDNSResolver", "InjectedHTTPSConnector", "InjectedHermeticTransport", "LIVE_EXECUTION_ACK", "LiveAuthorizationBundleStore", "LiveAuthorizationPoolAdapter", "LiveDispatchPermit", "LiveIterationApprovalStore", "LiveNetworkAuthorization", "LiveOpenAICompatibleAdapter", "LiveProviderTransportFactory", "LiveRunnerExecutor", "NullCredentialResolver", "OpenAICompatibleAdapter", "OpenAICompatibleCodec", "OpenAICompatibleHTTPSLiveTransport", "OpenAICompatibleHTTPSTransport", "PricingSnapshot", "PROVIDER_USAGE_AUTHORITY_ID", "ProductionHTTPSProviderTransport", "ProductionProviderTransportFactory", "ProviderCallRecord", "ProviderCapabilities", "ProviderCodecError", "ProviderContractError", "ProviderProfile", "ProviderStore", "ProviderTransportError", "ProviderUsageAttestation", "ProviderUsageAuthority", "SecureEnvironmentCredentialResolver", "TokenEnvelope", "TransportResponse", "TrustedSourceData", "assert_token_envelope_within_caps", "credential_reference_hash", "default_live_transport", "endpoint_hashes", "live_execution_confirmation_hash", "network_policy_hash", "normalize_network_policy", "normalize_openai_compatible_usage", "normalize_usage", "token_envelope_within_caps", "validate_endpoint_static", "validate_resolved_addresses",
]

__all__.append("BoundHostEnvironmentCredentialResolver")
