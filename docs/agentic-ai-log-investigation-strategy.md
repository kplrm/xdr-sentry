# XDR Sentry Agentic AI Strategy for Security Log Investigation

## 1. Why XDR Sentry (and why now)
XDR Sentry should be built as a goal-driven investigation system, not a bulk summarizer. The core problem with many AI SOC experiences is that they push large alert sets into an LLM and ask it to "find attacks," which increases hallucination risk, weakens traceability, and reduces analyst trust.

XDR Sentry should instead use bounded, multi-agent workflows that:
- start from explicit investigation goals,
- select and validate evidence in stages,
- expose uncertainty,
- require human approval for high-impact actions.

Investigation execution is agentic and LLM-assisted by design.
If no LLM provider key is configured, the run must fail fast with a clear validation error instead of silently falling back to non-agentic execution.

Goal selection must support two modes:
- Human-defined goal: analyst writes the investigation goal directly.
- Agent-proposed goal: agent suggests goals from external threat intelligence sources plus current OpenSearch index landscape.

The analyst must always choose which goal to execute.

## 2. External feedback and market signals

### 2.1 What users appreciate in Attack Discovery
From Elastic docs and public descriptions, users value:
- fast correlation-style summaries across many alerts,
- configurable scope (KQL, time range, count of alerts),
- integration into case and investigation workflows,
- saved/scheduled runs for repeatable investigations.

### 2.2 Problems users report with Attack Discovery
From Elastic community feedback, users reported:
- token/context length constraints with larger alert volumes,
- mixed output quality,
- duplicate/repetitive alert selection in the analysis set,
- unclear alert selection behavior,
- desire for tighter control over which alerts are included (status, time windows, host/network focus, manual alert selection).

These are exactly the gaps XDR Sentry should target.

### 2.3 Latest agentic SOC projects to learn from
- Microsoft Security Copilot agents: role-specific autonomous triage agents, explicit feedback loops, and human-controlled approvals.
- CrowdStrike Charlotte AI Detection Triage: autonomous detection triage with true/false positive classification, recommended actions, and bounded autonomy.
- Google SecOps Triage and Investigation Agent (TIN): iterative query refinement, enrichment, and analyst-facing investigation acceleration.
- Trend Micro Cybertron direction: cyber model + agentic memory + explainable automation for SOC workflows.

## 3. Product principles for XDR Sentry
1. Goal-first investigation
Every run starts from a user goal (for example: "validate lateral movement on host X in last 6h"), not from an unbounded prompt.

Goal-first in XDR Sentry means analyst-controlled goal selection, not analyst-only goal creation.
The platform should allow either:
- human-authored goals, or
- agent-suggested goals generated from trusted external sources and local index context.

2. Bounded autonomy
Agents can plan and execute within policy limits, but disruptive actions always require analyst approval.

3. Evidence-grounded conclusions
Every conclusion must cite source documents, fields, and query steps.

4. Schema-aware reasoning
The system must detect ECS compliance level per index and adapt safely to non-ECS fields.

5. Human override everywhere
Analysts can force include, force exclude, pin entities, or lock mappings at any step.

6. Quality is measured, not assumed
All runs are scored for evidence coverage, contradiction risk, and analyst acceptance.

## 4. Proposed XDR Sentry multi-agent architecture

### 4.1 Agent roles
1. Scope Agent
- Converts analyst intent into an execution plan.
- Proposes index set, time window, filters, and budget.
- Supports dual goal input modes: human goal or agent-proposed goal.

2. Goal Discovery Agent
- Continuously gathers candidate goals from enabled external sources.
- Reads OpenSearch index names and index-pattern metadata to infer relevant technologies.
- Produces ranked goal proposals with source citations and confidence.

3. Schema Agent
- Profiles field availability across selected indices.
- Builds ECS and non-ECS mapping confidence map.

4. Selection Agent
- Pulls candidate events/alerts.
- De-duplicates near-identical records.
- Clusters events by entities/techniques/timeline.

5. Enrichment Agent
- Adds context: entity history, threat intel, prior case evidence, baseline behavior.

6. Hypothesis Agent
- Produces competing hypotheses with confidence and required evidence.

7. Validation Agent
- Verifies each claim against retrieved evidence.
- Flags unsupported statements and contradictions.

8. Decision Agent
- Creates analyst-ready outcomes: likely true positive, likely benign, inconclusive.
- Proposes next actions and confidence rationale.

### 4.2 Investigation memory model
- Run memory: ephemeral context for current run.
- Case memory: persistent context for a single case.
- Tenant memory: approved mapping packs, playbooks, and policy defaults.

### 4.3 OpenSearch-native execution model
- Use point-in-time snapshots for consistent long-running investigations.
- Persist investigation graph in an index: entities, relationships, hypotheses, evidence links, verdicts.
- Maintain an explainability ledger containing executed queries, tool calls, and evidence references.

## 5. Human-in-the-loop design (high priority)

### 5.1 Human context controls before execution
Before any run, the analyst can set:
- indices to include/exclude,
- time window and event-status filters,
- max events and cost budget,
- entity constraints (host, user, process, IP),
- mandatory evidence sources.

Before execution, the analyst also chooses the goal mode:
- Use human-authored goal, or
- Use one of the agent-proposed goals.

Source configuration must be available in both goal modes (human-defined and agent-proposed):
- enable or disable predefined trusted sources,
- add custom source URLs,
- remove outdated custom sources.

In human-defined mode, configured sources are still consumed during Source Intel phase for threat context enrichment.
In agent-proposed mode, configured sources are used both for goal generation and investigation-time enrichment.

### 5.2 Human control during execution
- Live plan review: analysts can approve, pause, or edit plan steps.
- Schema confirmation step: map unknown fields before agents use them.
- Dedup preview: inspect and override grouped duplicates.

### 5.3 Human approvals after reasoning
Require approval for:
- external-side effects outside investigation context,
- optional endpoint response proposals,
- persistent detection-content updates.

XDR Sentry MVP should not include case lifecycle management features (open/close/share cases).

## 5.4 External source strategy for agent-proposed goals
The Goal Discovery Agent should support a source registry with:
- predefined high-reputation source presets (toggle on/off per source),
- user-defined custom sources,
- health checks and freshness timestamps.

Initial predefined source families:
- major vendor security research blogs,
- vulnerability advisories and KEV-style feeds,
- trusted threat-intel and incident writeup sources.

Initial predefined trusted sources (enabled/disabled per source):
- CISA Known Exploited Vulnerabilities catalog and alerts.
- NVD / CVE feeds for vulnerability context.
- US-CERT and equivalent national CERT advisories.
- Mandiant / Google Cloud Security research.
- Microsoft Security Blog.
- CrowdStrike threat research and incident writeups.
- Palo Alto Networks Unit 42 research.
- Cisco Talos intelligence updates.
- Recorded Future or equivalent intelligence reports (if licensed).
- Curated public repositories of detection and threat content (for example Sigma and ATT&CK-related references).

Custom-source support must allow analysts to:
- add arbitrary source URLs,
- tag them by type (news, advisory, blog, repository),
- set trust level and cadence,
- disable without deleting.

Each proposed goal must include:
- source URL(s),
- publication time,
- extracted threat theme,
- mapped candidate technologies observed in local indices.

## 5.5 Dynamic technology inference from OpenSearch indices
Because index sets change over time, XDR Sentry should periodically discover technologies by:
- reading current index names and aliases,
- matching naming patterns (for example cloud, endpoint, identity, firewall, dns, proxy, k8s),
- validating with sampled field signatures.

This allows the Goal Discovery Agent to suggest goals relevant to what is currently ingested, even when indices are added or removed.

All inferred technologies should be reviewable and editable by the analyst before execution.

## 5.6 LLM provider configuration (OpenAI-compatible)
XDR Sentry should support OpenAI-compatible APIs with:
- out-of-the-box presets for NVIDIA-hosted endpoints and Groq Cloud,
- custom base URL for any OpenAI-compatible provider,
- user-provided API key.

Security and UX requirements:
- API key input is masked and never re-displayed in plain text.
- Store provider configuration securely and scope by tenant/space.
- Validate connectivity and model list before first run.
- Support per-run model override when policy allows.

Current MVP implementation note:
- Configuration save/load is implemented.
- API key remains input-only in UI displays.
- Current storage is in-memory server state for MVP and resets on restart.
- Next hardening step is persistent tenant/space-scoped storage.

## 6. Schema intelligence for ECS and non-ECS data

### 6.1 Field capability registry
For each index pattern, store:
- known ECS fields,
- custom aliases,
- semantic type confidence,
- owner-curated mapping notes.

### 6.2 Mapping confidence labels
Each mapped field receives confidence level:
- high: exact ECS or validated mapping,
- medium: inferred mapping with supporting evidence,
- low: weak/ambiguous mapping.

Low-confidence mappings should reduce final verdict confidence automatically.

### 6.3 Non-ECS safe mode
If critical fields are missing or inconsistent:
- split run into sub-investigations by index family,
- disable high-confidence verdicts,
- ask analyst to confirm or correct mappings.

## 7. Anti-hallucination and safety controls
1. Retrieval-only claim policy
No claim without cited evidence objects.

2. Two-pass validation
Pass 1 generates findings, pass 2 attempts to disprove findings.

3. Contradiction detector
Detects inconsistent entity timelines, impossible sequence ordering, or field misuse.

4. Explicit uncertainty output
Require "unknown" and "insufficient evidence" outcomes when evidence is weak.

5. Prompt and policy versioning
Every run stores policy version, prompt template version, and toolchain version.

6. Injection-resistant tool sandboxing
Restrict which tools/indices each agent may access based on role and tenant policy.

## 8. Creative features to differentiate XDR Sentry
1. Investigation Blueprint Templates
Goal-specific templates (ransomware, credential abuse, lateral movement, data exfiltration) with pre-validated query plans.

2. Scope Diff and Replay
Compare two runs and show what changed (scope, evidence, verdict) to reduce analyst confusion.

3. Field Drift Radar
Continuously detect schema drift across indices and alert admins before investigations degrade.

4. Evidence Density Meter
Visual signal for how much of each conclusion is supported by high-confidence evidence.

5. Hypothesis Tournament Mode
Competing hypotheses are ranked by disconfirming evidence, reducing one-track bias.

6. Analyst Coaching Loop
When analysts override agent output, capture reason codes and use them to improve future ranking and prompts.

7. Cost Guardrails Dashboard
Show token, query, and runtime budget per run/team/tenant; enforce hard limits.

8. Action Readiness Score
A score showing whether evidence quality is sufficient to justify containment or escalation.

9. Trust Calibration View
Track historical precision of the system per detection type and data source.

10. Controlled Auto-Mode
Allow safe partial automation only for low-risk investigation tasks (evidence packaging, timeline generation, and hypothesis comparison reports).

11. External Threat Pulse to Goal Pipeline
Continuously convert trusted-source updates into candidate investigation goals aligned to currently active indices.

12. Source Trust Controls
Per-source toggles, freshness controls, and citation visibility so analysts can decide what outside intelligence influences agent-proposed goals.

## 9. Single MVP roadmap

### MVP scope (single roadmap)
- Scope Agent + Schema Agent + Selection Agent + Decision Agent.
- Add Goal Discovery Agent for agent-proposed goals.
- Manual approvals for all external actions.
- Evidence-cited findings with confidence labels.
- Basic dedup, clustering, and index inclusion controls.
- External source registry with predefined trusted sources and custom source support.
- Dynamic index-based technology inference for goal relevance.
- OpenAI-compatible provider config with NVIDIA and Groq presets plus custom URL.
- KPI instrumentation and shadow mode.

### 9.1 Current MVP behavior snapshot (conversation-aligned)
- Running an investigation requires a valid goal and an LLM API key.
- Investigation flow is phase-based (Source Intel, Scope, Schema, Selection, Hypothesis, Validation, Decision).
- Each phase is executed using predefined backend scripts surfaced as tool calls to the LLM.
- Workflow graph is interactive; clicking a phase filters logs and shows the phase script purpose/instructions.
- Live activity log is timestamped and phase-tagged.
- Goal discovery supports predefined trusted sources plus custom source URLs.
- Provider configuration supports save/load in MVP (in-memory persistence caveat above).

## 10. Evaluation framework and KPIs

### SOC impact metrics
- Mean time to first useful investigation output,
- mean time to investigate,
- false positive handling efficiency,
- analyst acceptance rate of recommendations,
- investigation rerun rate due to missing context.

### Model and workflow quality metrics
- Evidence citation coverage,
- unsupported claim rate,
- contradiction rate,
- dedup efficiency,
- schema mapping confidence distribution,
- cost per investigation and P95 runtime.

### Rollout method
- Stage 1: shadow mode only.
- Stage 2: analyst-assisted mode.
- Stage 3: bounded autonomy for low-risk actions.
- Stage 4: optional expanded autonomy by policy.

## 11. Open product questions
1. What should be the default autonomy profile for new tenants?
2. What minimum evidence threshold is required before a "likely attack" verdict?
3. Which predefined external sources should be enabled by default?
4. Which external enrichment sources are required for MVP?
5. How much per-tenant customization can be supported without operational complexity?
6. Should mapping packs be curated-only or community-extendable?

## 12. Source list
- Elastic Attack Discovery documentation:
  https://www.elastic.co/guide/en/security/current/attack-discovery.html
- Elastic Agent Builder documentation:
  https://www.elastic.co/docs/solutions/security/ai/agent-builder/agent-builder
- Elastic community thread, Attack Discovery Questions and Feedback:
  https://discuss.elastic.co/t/attack-discovery-questions-and-feedback/364109
- Microsoft Security Copilot agents announcement:
  https://www.microsoft.com/en-us/security/blog/2025/03/24/microsoft-unveils-microsoft-security-copilot-agents-and-new-protections-for-ai/
- CrowdStrike Charlotte AI Detection Triage:
  https://www.crowdstrike.com/en-us/blog/agentic-ai-innovation-in-cybersecurity-charlotte-ai-detection-triage/
- Google Cloud Security, Agentic AI for Security Operations:
  https://cloud.google.com/security/resources/agentic-soc
- Google SecOps Triage and Investigation Agent docs:
  https://docs.cloud.google.com/chronicle/docs/secops/triage-investigation-agent
- Trend Micro Cybertron direction:
  https://www.trendmicro.com/en_us/research/25/c/cybertron-ai-security.html
- Trend Micro agentic architecture case study (AWS):
  https://aws.amazon.com/solutions/case-studies/trendmicro/

## 13. Live agent feedback UX for investigations
To keep humans in control during long-running agent workflows, XDR Sentry should provide continuous status visibility in the Investigation tab.

### 13.1 Recommendation: hybrid feedback (visual + text)
Use a hybrid model instead of text-only or spinner-only:
- Visual progress indicator for quick recognition of state changes.
- Structured textual event log for traceability and analyst confidence.

Why:
- Progress visibility reduces uncertainty and increases willingness to wait.
- Indeterminate-only indicators are acceptable for short phases, but for longer phases users should see progress and meaningful status text.

### 13.2 Proposed UI pattern for XDR Sentry
1. Phase timeline (top)
- Source Intel -> Scope -> Schema -> Selection -> Hypothesis -> Validation -> Decision.
- Current phase highlighted.

2. Determinate progress bar (middle)
- Use percent-done for steps expected to exceed around 10 seconds.
- For short or unpredictable steps, use indeterminate animation temporarily.

3. Live textual activity stream (bottom)
- Timestamped entries like:
  - "Fetched 4/6 enabled external sources"
  - "Profiled 112 indices; inferred technologies: endpoint, identity, network"
  - "Generated 3 candidate goals; selected goal #2"
  - "Validation pass complete: 2 unsupported claims removed"

4. Explainability snapshot panel
- Shows current tool call/query summary and latest evidence IDs used by the active phase.

5. Controls
- Pause, cancel, and retry current phase.
- Optional "run in background" mode with toast/notification on completion.
- Click phase in the workflow graph to focus the corresponding logs and script card.

### 13.3 Practical guidance for MVP
- Always show immediate acknowledgement of "Start agentic investigation".
- Use concise status text with explicit phase labels.
- Prefer simple linear progress + text log over complex animation-heavy UI for SOC tools.
- Keep log entries exportable for auditability.

### 13.4 Source basis for this UX decision
- NN/g on progress indicators and visibility of system status:
  https://www.nngroup.com/articles/progress-indicators/
- Smashing Magazine synthesis of determinate vs indeterminate indicators and wait-time UX:
  https://www.smashingmagazine.com/2016/12/best-practices-for-animated-progress-indicators/
