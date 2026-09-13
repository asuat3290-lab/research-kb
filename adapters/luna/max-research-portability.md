# Luna portability adapter

`LunaPortabilityAdapter` declares host kind `luna` and follows the same
server-owned discovery, attestation, Run lookup, rehydration packet recovery,
bounded-result submission, and verification flow as every supported host.
The adapter passes explicit IDs and hashes to the administrator JSON CLI. It
does not select a provider, contain credentials, open SQLite, or turn a
declarative host kind into a claim of executable installation.
