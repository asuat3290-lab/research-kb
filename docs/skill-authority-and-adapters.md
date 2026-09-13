# Canonical Skill and cross-agent adapter authority

This document defines the SG-1B2 packaging and deployment boundary. It does
not install or update any Agent configuration.

## One semantic authority

The repository file
skills/source-based-research/SKILL.md is the canonical Skill. It is the only
semantic authority for the research workflow, evidence rules, source roles,
citation constraints, and checkpoint protocol.

The runtime deployment under
workspace/.agents/skills/source-based-research/SKILL.md is a controlled
deployment copy. It must be byte-identical to the canonical file. A runtime
copy is not an independent fork and must not contain project-specific rules.
Project IDs come only from an explicit user instruction, approved
project-level configuration, or a formal project registry.

The System Manifest is the authority for the canonical and runtime SHA-256
values and for the raw-byte SHA-256 of every declared adapter template. Each
adapter declaration must contain a 64-character hexadecimal
`content_sha256`. There is no second Skill lock file. An Agent must not
accept a changed hash automatically.

## Thin adapters

The repository contains platform-neutral templates under:

- adapters/codex/source-based-research.md
- adapters/luna/source-based-research.md
- adapters/qoder/source-based-research.md
- adapters/opencode/source-based-research.md

Each template is deliberately small. It only locates and loads the complete
canonical Skill or its byte-identical runtime deployment, checks that the
research-kb MCP server is visible with exactly 12 tools, requires an explicit
<PROJECT_ID>, and hands control to the canonical Skill. It must not copy the
research loop, checkpoint protocol, source-role rules, or citation rules.

The templates use placeholders such as <RESEARCH_KB_RUNTIME_ROOT>,
<RESEARCH_KB_CONFIG>, <PYTHON_EXECUTABLE>, and <PROJECT_ID>. They do not
declare vendor-specific APIs or personal absolute paths. A template is not an
installation: a platform-specific installation requires separate human
approval and review of that platform's actual Skill/configuration format.

If the MCP server is unavailable, the live tool set is not exactly 12, the
canonical/runtime Skill is missing or drifting, or the project ID is missing
or ambiguous, the adapter stops. It does not modify the Skill, manifest,
database, or global configuration.

## Doctor checks

doctor --deep checks only the canonical file, runtime file, and explicit
adapter files declared by the manifest. It does not scan global Agent Skill
directories and it does not recurse through an external parent directory.

The expected healthy findings include:

- canonical_skill_hash_ok
- runtime_skill_hash_ok
- skill_source_runtime_ok
- adapter_template_hash_ok
- adapter_template_ok

Doctor processes each declared adapter in this order: safely resolve the
single declared path, reject boundary escapes and symlink/junction/reparse
points, check existence, read UTF-8, hash the original file bytes, compare
the manifest hash, and then run the thin-adapter semantic checks. A matching
hash produces `adapter_template_hash_ok` at INFO. Any hash drift is
`adapter_template_hash_drift` at P1, even when the adapter still passes every
thin-adapter heuristic. A required missing adapter is P1; an optional missing
adapter is P2. An existing adapter with a semantic problem remains P1 even
when its hash is correct. Canonical/runtime absence, hash drift, byte drift,
unsafe boundaries, or reparse-point paths are also P1 findings. Findings
redact local paths and never emit Skill text or research content.

## Installed Codex adapter

An installed adapter is a separate control-plane object from the repository
template. The optional `[skill_authority.installations]` declarations record
the rendered Skill and metadata files, the installed global files, their
boundaries, and one SHA-256 for each file. The rendered files must be inside
the runtime root; installed files use an environment placeholder such as
`${USERPROFILE}` and are checked as one explicit file each. Doctor never
recurses through a global Skill directory.

For a required installation, an unresolved environment variable, unsafe or
reparse-point path, missing file, UTF-8 failure, hash drift, rendered/installed
byte mismatch, invalid frontmatter, invalid UI metadata, missing exact-12
contract, missing project-id fail-closed rule, or copied canonical Skill is
P1. Healthy checks include `installed_adapter_skill_hash_ok`,
`installed_adapter_metadata_hash_ok`, `installed_adapter_bytes_ok`, and
`installed_adapter_contract_ok`. Doctor only reports these conditions; it
never installs, overwrites, rolls back, or accepts a new hash.

The global Codex Skill and metadata are backed up before replacement under a
version directory named by the old Skill SHA-256. The backup manifest records
only the backup schema, relative file names, old hashes, UTC time, and
`replacement_phase`; it contains no tokens or research content.

## Codex local MCP installation

The runtime manifest may also declare a `[mcp_authority]` section with a
Codex installation. This is a semantic authority for one named
`mcp_servers.research-kb-pilot` subtable, not a hash of the complete global
Codex configuration. Unrelated Codex settings and unrelated MCP servers,
including `node_repl`, are intentionally outside this authority.

The declaration fixes the external config file boundary, server name,
`stdio` transport, command, ordered arguments, working directory, enabled and
required flags, startup/tool timeouts, and the exact twelve enabled tools.
The config path may use `${USERPROFILE}`; doctor resolves one explicit file
only and never scans the global Codex directory.

Static doctor checks are P1 for a missing or invalid config, missing server
table, command/argument/cwd/enabled/timeout drift, disabled server, non-stdio
transport, missing/duplicate/extra enabled tools, URLs, auth fields,
`disabled_tools`, or dangerous environment keys such as `PYTHONPATH` and
credential/token variables. `--deep` additionally starts the exact declared
stdio command with the declared cwd, initializes an official MCP client, and
checks `list_tools()` for the same twelve names. It reports only counts and
field names; it never emits config contents, credentials, or stderr text.

Installation is manual and reversible: save the complete old Codex config
under `workspace/backups/codex-config/sg1b2c/<old-config-sha256>/`, verify the
backup hash, atomically install the reviewed file, and verify TOML plus the
normalized target subtable. On failure restore the complete old config and
verify its hash. A later config drift is diagnosed; doctor never accepts a
new command, path, tool list, or timeout automatically.

## Controlled change and release

Before changing the canonical, runtime, or adapter file, preserve the old
manifest. After the change, run the doctor and expect the corresponding hash
drift finding. Review the diff manually, compute the new raw-byte SHA-256, and
update the manifest only after explicit human approval. Run the doctor again.
Agents must not perform this acceptance step on their own; a hash update in
this round authorizes only the four currently reviewed adapter templates.

## Manual rollback

Rollback is deliberately manual and does not delete the backup. Confirm the
two hashes in `backup-manifest.json`, restore `SKILL.md` and
`agents/openai.yaml` together from the matching old-hash directory, verify
both old hashes, restore the corresponding installation declaration in the
runtime manifest, and run `doctor --deep` again. If only one global file was
replaced, restore both files before treating the installation as recovered.

Distribution artifacts include the canonical Skill, all adapter templates,
and this governance documentation. Installing an artifact does not authorize
changes to a user's global Codex, Luna, Qoder, or OpenCode configuration.
