# Hermes portability adapter

`HermesPortabilityAdapter` declares host kind `hermes` and uses the shared
server-owned portability protocol for discovery, installation attestation,
Run lookup, durable rehydration packet recovery, bounded result submission,
and verification. It passes no source prose, prompt, response, token, or
credential value, and it does not open SQLite or select a backend implicitly.
