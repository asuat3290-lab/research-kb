# Research report template

Use this template with `submit_research_report`. Keep the report candidate/draft until a human approves it.

## Mode

- `evidence mode`: verify source consistency and exact quotes; do not turn a quote into a truth claim.
- `discovery mode`: connect at least two sources and make the inferential move explicit. If the corpus is too small, report the gap instead of manufacturing novelty.

## Question

State the research question and scope.

## Short answer

Give the answer first, separating source facts, interpretations, and inferences.

## Source-grounded claims

For each claim include `epistemic_status` and linked verified evidence where required. In prose, cite as:

> Author, year, page/location, passage_id

## Cross-source discovery

Include a concept matrix, normative-premise comparison, conflicts/tensions, boundary conditions or counterexamples, missing source types, a reframed question, and competing explanations. Provide 3-6 leads. Each lead must include:

- `idea`
- `source_bridges`
- `supporting_passage_ids`
- `why_not_literature_summary`
- `possible_counterevidence`
- `missing_evidence`
- `next_search`
- `epistemic_status`
- `confidence`

Submit only the 1-3 most valuable leads as candidate hypotheses. Never invent a lead to meet a count.

## Objections and alternatives

State the strongest objection, at least one alternative explanation, unresolved questions, and evidence limits.

## Full source table

End with every source used, represented by its structured `citation_record`. Do not include local file paths.

| document_id | citation_record |
|---|---|
| `...` | Author, year, title, container, volume/issue/pages, DOI; use `unknown` for missing fields |

## Evidence citation map

End with every evidence row in this order: evidence ID, passage ID, document ID, citation record, locator.

| evidence_id | passage_id | document_id | citation_record | citation_locator |
|---|---|---|---|---|
| `...` | `...` | `...` | structured record | page/location + source_version |

## Approval state

Record that the report is `candidate` or `draft`, and include any pending approval request ID. Do not claim accepted evidence or an accepted conclusion before human approval.


## Integrity rule

The citation fields in a submitted report are display hints only. The service replaces them with records generated from the active project database. A report must therefore supply valid project-scoped IDs; it must not rely on client-provided author, date, DOI, page, or source-version values.

## Contextual source roles

Do not give a document a permanent high/low research rank. Separate the stable, document-level integrity record from the dynamic role a source plays for this question, subtask, or claim.

### Research scope

State the current research question, the active subtasks, the relevant claims, and the limits of the comparison. A role assignment is meaningful only within this scope.

### Source Role Map

Include one assignment for each document/subtask/claim combination that matters. The minimum fields are:

- `research_question`
- `subtask`
- `document_id`
- `citation_identity` (author/title or a service-recoverable citation identity)
- `role_type`
- `evidential_function`
- `rationale`
- `can_support`
- `cannot_support`
- `directness`: `direct`, `indirect`, or `contextual`
- `confidence`
- `provisional`
- `supporting_passage_ids`
- `competing_or_alternative_sources`

The same document may be a core object source for one question, historical background for another, and counterevidence or discovery-only material for a third. Role labels are provisional and must not be inferred from author fame, a fixed topic label, or global `reliability_status`/`verification_status`.

### Claim–Evidence–Role Matrix

| claim or subtask | document_id | passage_id | role_type | evidential_function | directness | epistemic_status | confidence |
|---|---|---|---|---|---|---|---|
| `...` | `...` | `...` | `...` | `supports/counters/contextualizes/competing_explanation/identifies_transmission/discovery_only` | `...` | fact/inference/hypothesis | `...` |

Use the service-generated `citation_record`, `citation_locator`, and `source_links` for source identity and passage relations. A free-text claim or client-supplied bibliography is not authoritative.

### Role changes

Never silently overwrite a role. Record every meaningful reclassification with:

- `previous_role`
- `new_role`
- `reason_for_change`
- `affected_subtask_or_claim`

Also retain the affected `document_id`, `passage_id` values, and the date or checkpoint item that records the change. A change in research relevance does not change document integrity or metadata.

### Limitations

State when a source is high-quality but does not directly prove the current claim, when conceptual similarity does not establish influence, and when the corpus lacks a source type needed to test an explanation. Do not manufacture a role, novelty, or counterexample. Keep the report in `draft` or `candidate` status until the user approves the relevant evidence; do not auto-approve.
