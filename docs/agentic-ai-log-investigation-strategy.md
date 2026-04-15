# XDR Sentry Agentic Investigation Strategy

## 1. Purpose

XDR Sentry is a goal-driven investigation system for structured logs. It is not a bulk alert summarizer and it must not invent an attack narrative from unrelated records.

Every run starts from an explicit investigation goal, profiles the selected data before reasoning about attacks, and only reports conclusions that are supported by validated local evidence.

## 2. Investigation Contract

Every investigation follows this order:

1. understand and approve the goal,
2. identify which indices are available,
3. determine what each selected index actually contains,
4. decide whether the data is understandable enough to investigate,
5. research current relevant threat context,
6. test local evidence against suspicious and benign explanations,
7. produce a traceable conclusion.

If the selected data cannot be understood with enough confidence, XDR Sentry must stop clearly instead of forcing a narrative.

## 3. Core Principles

1. Goal first.
2. Understand the data before reasoning about attacks.
3. ECS first, but not ECS only.
4. Evidence first, narrative last.
5. External research generates tests, not conclusions.
6. Competing hypotheses are mandatory.
7. Human control remains first-class.
8. Unknown is a valid outcome.

## 4. Data Understanding Layer

Before threat reasoning begins, XDR Sentry builds an index profile for each selected index or index family.

That profile should answer:

- what the index likely contains,
- which fields are meaningful,
- whether it appears fit for investigation,
- whether it should be investigated together with other indices or split into a separate branch,
- whether it should be excluded because the data is too ambiguous.

The profile is built from multiple exploratory steps rather than a single sample. At minimum this includes mappings, sampled documents, field population checks, and distributions for meaningful fields or time slices.

## 5. Schema Understanding

XDR Sentry prefers ECS semantics when they are available, but it must also work with non-ECS structured logs when their meaning can be inferred safely.

Each branch keeps an explainable understanding level:

- high confidence: strong ECS alignment or clearly validated semantics,
- medium confidence: partially inferred but usable semantics,
- low confidence: ambiguous or unsafe semantics.

Low-confidence branches should either be isolated from the rest of the investigation or stopped entirely if the goal depends on missing concepts such as time, action, source, destination, process, or user.

## 6. External Research Layer

External research is mandatory but subordinate to local evidence.

Research should:

- derive topics from the approved goal and detected technologies,
- use trusted and current sources,
- identify current attacks, campaigns, vulnerabilities, and behaviours,
- turn those findings into local tests and questions.

External context must never be used by itself to claim that an attack occurred.

## 7. Evidence And Hypothesis Testing

XDR Sentry converts data understanding plus external research into explicit suspicious and benign hypotheses.

The investigation layer then:

- collects bounded evidence,
- pivots across hosts, users, IPs, containers, services, or other meaningful entities,
- builds focused timelines,
- challenges leading hypotheses with contradictions and missing expected evidence,
- ranks explanations by evidentiary strength.

Every major claim must remain linked to concrete evidence cards and the index branch that produced them.

## 8. Decision Model

Allowed final states are:

- Likely attack story identified
- Correlated activity identified but attack not established
- No supported attack story found in scope
- Inconclusive
- Unable to proceed

The distinction between the last two matters:

- Inconclusive means the investigation ran, but the evidence remained weak, partial, or contradictory.
- Unable to proceed means the logs were not understandable enough for a reliable investigation in the first place.

## 9. Agent Roles

1. Goal Agent
2. Index Understanding Agent
3. Research Agent
4. Correlation Agent
5. Hypothesis Agent
6. Challenger Agent
7. Decision Agent
8. Reporting Agent

These roles follow the ordered workflow and exist to prevent the system from jumping straight to storytelling.

## 10. Investigation State And Retrieval

Each run should produce a compact set of investigation records:

- run record,
- index profile,
- research note,
- evidence card,
- hypothesis record,
- decision record,
- audit record.

Retrieval for later stages should remain layered and focused. Reporting should read validated evidence and explicit limitations, not large raw log dumps.

## 11. Reporting Contract

Every report includes:

- the investigation goal,
- the indices used,
- what each relevant index appeared to contain,
- the main supporting evidence,
- key limitations or contradictions,
- the reason for the selected final state,
- recommended next actions.

If the investigation splits into branches, XDR Sentry reports a branch-level conclusion and an overall synthesis. The final explanation must only use validated evidence.
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
