# Codex portability adapter

`CodexPortabilityAdapter` declares host kind `codex` and uses the packaged
`max-research-portability` Skill with the administrator `research-kb max`
JSON surface. Its hermetic flow is discovery → installation attestation →
explicit Run lookup/quiescence → packet read/acknowledgement → bounded result
submission → verification. It passes server-owned IDs and hashes only; it
does not select a provider, contain credentials, open SQLite, or implement a
second persistence protocol. A declarative host descriptor is not an
executable installation until the control plane accepts attestation.
