# Contributing

This is an open-source development snapshot under the [MIT License](LICENSE).
Contributions are welcome under the same license. Submit only material you have
the right to contribute; preserve third-party notices and attribution.

## Useful first contributions

- Reproduce installation in an isolated Windows environment and document missing prerequisites.
- Improve a synthetic external-agent handoff example without real research data.
- Add tests for source-version binding, project scope, or candidate-only submission.
- Propose research-quality evaluations separately from operational uptime tests.

Read [AGENTS.md](AGENTS.md) before changing code. Preserve the separation between
worker and admin permissions, the 12 researcher tools, and the separate Max surface.
Never loosen validation just to make an example pass.

## A useful issue or pull request

Include the commit, OS/Python version, minimal reproduction, expected and actual
behavior, and tests actually run. Mark tests not run; do not reuse historical
acceptance counts as evidence for a new patch. Use synthetic IDs and temporary
databases. Never attach credentials, private source text, live databases, approval
tokens, or full personal configs. For sensitive reports, contact the owner privately.
