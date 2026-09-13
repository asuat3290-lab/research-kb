# Qoder portability adapter

`QoderPortabilityAdapter` declares host kind `qoder` and exposes only the
common administrator-CLI protocol: discovery, installation attestation,
explicit Run/binding lookup, quiescence, packet read/acknowledgement,
invocation-attributed bounded result submission, and verification. It never
opens SQLite, embeds a credential, selects a backend from a process name, or
claims executable portability without a server-owned attestation.
