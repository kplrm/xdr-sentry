# XDR Sentry

XDR Sentry is a goal-driven investigation plugin for structured OpenSearch logs. It profiles the selected data before doing any threat reasoning, tests competing explanations against local evidence, and returns one explicit final outcome instead of inventing an attack story from mixed records.

## Operating Model

Every investigation follows this order:

1. Approve the goal and scope.
2. Discover and profile available indices.
3. Decide whether the logs are understandable enough to investigate.
4. Pull current external threat context.
5. Collect bounded evidence and test competing hypotheses.
6. Select one allowed final state and report from validated evidence only.

## Design Principles

- Goal first.
- Understand data before reasoning about attacks.
- ECS first, but not ECS only.
- Evidence first, narrative last.
- Unknown is a valid outcome.
- Human control remains first-class.

## Final Outcomes

- Likely attack story identified
- Correlated activity identified but attack not established
- No supported attack story found in scope
- Inconclusive
- Unable to proceed

## Ownership

This repo owns the investigation workflow, index understanding, research-driven hypothesis testing, and evidence-backed reporting for XDR Sentry.

See `docs/agentic-ai-log-investigation-strategy.md` for the detailed workflow and reporting contract.

## Development

```bash
cd /home/kplrm/github/xdr-sentry
yarn build --opensearch-dashboards-version 3.5.0
```
