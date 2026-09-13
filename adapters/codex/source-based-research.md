---
template: true
adapter: codex
canonical_dependency: canonical
---

# research-kb Codex adapter template

Use these installation/workspace placeholders:

- canonical Skill: <RESEARCH_KB_CANONICAL_SKILL>
- runtime root: <RESEARCH_KB_RUNTIME_ROOT>
- config: <RESEARCH_KB_CONFIG>
- Python: <PYTHON_EXECUTABLE>
- project ID: <PROJECT_ID>

1. Locate and load the complete canonical Skill or its byte-identical runtime copy.
2. Confirm research-kb MCP is visible and exposes exactly 12 tools.
3. Require an explicit project ID from the user, controlled configuration, or
   project registry. Stop when missing or ambiguous.
4. Hand control to the canonical Skill. Do not copy its research, checkpoint,
   role-mapping or citation rules here.

Template only: it does not install Skills, modify manifests or databases, or
change global Codex configuration.
