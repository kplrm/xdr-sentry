const SOURCE_PRESETS = [
  {
    id: 'cisa-alerts',
    name: 'CISA Alerts',
    url: 'https://www.cisa.gov/uscert/ncas/alerts.xml',
    type: 'advisory',
    reputation: 'high',
  },
  {
    id: 'cisa-kev',
    name: 'CISA KEV Catalog',
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    type: 'advisory',
    reputation: 'high',
  },
  {
    id: 'msrc-blog',
    name: 'Microsoft Security Blog',
    url: 'https://www.microsoft.com/en-us/security/blog/feed/',
    type: 'blog',
    reputation: 'high',
  },
  {
    id: 'unit42',
    name: 'Palo Alto Unit 42',
    url: 'https://unit42.paloaltonetworks.com/feed/',
    type: 'blog',
    reputation: 'high',
  },
  {
    id: 'talos',
    name: 'Cisco Talos',
    url: 'https://blog.talosintelligence.com/rss/',
    type: 'blog',
    reputation: 'high',
  },
  {
    id: 'sigma',
    name: 'SigmaHQ (curated detection repository)',
    url: 'https://github.com/SigmaHQ/sigma',
    type: 'repository',
    reputation: 'high',
  },
];

const TECHNOLOGY_KEYWORDS: Record<string, string[]> = {
  endpoint: ['endpoint', 'edr', 'osquery', 'sysmon', 'process', 'host'],
  identity: ['identity', 'auth', 'entra', 'okta', 'iam', 'sso', 'aad'],
  cloud: ['cloud', 'aws', 'gcp', 'azure', 'k8s', 'kubernetes', 'eks', 'aks', 'gke'],
  network: ['firewall', 'proxy', 'dns', 'netflow', 'zeek', 'suricata', 'ids', 'ips', 'vpn'],
  email: ['email', 'exchange', 'm365', 'o365', 'smtp', 'phish'],
  web: ['waf', 'http', 'nginx', 'apache', 'web'],
};

interface ProviderConfig {
  preset: string;
  baseUrl: string;
  model: string;
  apiKey: string;
}

const DEFAULT_PROVIDER_CONFIG: ProviderConfig = {
  preset: 'nvidia',
  baseUrl: 'https://integrate.api.nvidia.com/v1',
  model: 'meta/llama-3.1-70b-instruct',
  apiKey: '',
};

let providerConfigStore: ProviderConfig = { ...DEFAULT_PROVIDER_CONFIG };

const AGENT_PHASE_SCRIPTS = [
  {
    id: 'source-intel',
    name: 'Source Intel',
    toolName: 'run_source_intel_script',
    purpose: 'Ingest enabled trusted and custom external threat sources for the current run.',
    instructions:
      'Call run_source_intel_script first. Then summarize the strongest threat themes and source coverage as strict JSON.',
  },
  {
    id: 'scope',
    name: 'Scope',
    toolName: 'run_scope_script',
    purpose: 'Define investigation scope from current index landscape and goal.',
    instructions:
      'Call run_scope_script first. Then summarize scope boundaries, included data domains, and unknowns as strict JSON.',
  },
  {
    id: 'schema',
    name: 'Schema',
    toolName: 'run_schema_script',
    purpose: 'Profile field availability and ECS alignment confidence.',
    instructions:
      'Call run_schema_script first. Then summarize schema confidence and any mapping risks as strict JSON.',
  },
  {
    id: 'selection',
    name: 'Selection',
    toolName: 'run_selection_script',
    purpose: 'Retrieve bounded evidence from selected indices.',
    instructions:
      'Call run_selection_script first. Then summarize selected evidence quality, coverage, and any retrieval gaps as strict JSON.',
  },
  {
    id: 'hypothesis',
    name: 'Hypothesis',
    toolName: 'run_hypothesis_script',
    purpose: 'Generate competing hypotheses from evidence.',
    instructions:
      'Call run_hypothesis_script first. Then summarize top hypotheses with confidence and disconfirming evidence needs as strict JSON.',
  },
  {
    id: 'validation',
    name: 'Validation',
    toolName: 'run_validation_script',
    purpose: 'Attach references and evaluate evidence sufficiency.',
    instructions:
      'Call run_validation_script first. Then summarize evidence quality and uncertainty as strict JSON.',
  },
  {
    id: 'decision',
    name: 'Decision',
    toolName: 'run_decision_script',
    purpose: 'Produce analyst-ready outcome and recommended next actions.',
    instructions:
      'Call run_decision_script first. Then produce decision summary with recommended next steps as strict JSON.',
  },
];

interface InvestigationState {
  selectedGoal: string;
  enabledSources: Array<{ id: string; name: string; url: string }>;
  threatSignals: any[];
  inferredTechnologies: string[];
  usedIndices: string[];
  hits: any[];
  findings: any;
  hypotheses: string[];
  evidenceIds: string[];
}

function parseJsonBody(rawBody: any): any {
  if (!rawBody) {
    return {};
  }
  if (typeof rawBody === 'string') {
    try {
      return JSON.parse(rawBody);
    } catch {
      return {};
    }
  }
  return rawBody;
}

function extractIndexArray(indicesResponse: any): any[] {
  if (Array.isArray(indicesResponse?.body)) {
    return indicesResponse.body;
  }
  if (Array.isArray(indicesResponse)) {
    return indicesResponse;
  }
  return [];
}

function inferTechnologies(indexNames: string[]): string[] {
  const found = new Set<string>();
  const joined = indexNames.join(' ').toLowerCase();
  for (const [tech, keywords] of Object.entries(TECHNOLOGY_KEYWORDS)) {
    if (keywords.some((kw) => joined.includes(kw))) {
      found.add(tech);
    }
  }
  if (found.size === 0 && indexNames.length > 0) {
    found.add('general-security');
  }
  return Array.from(found);
}

async function safeFetchText(url: string): Promise<string> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 4500);
  try {
    const response = await fetch(url, { signal: controller.signal as any });
    if (!response.ok) {
      return '';
    }
    return await response.text();
  } catch {
    return '';
  } finally {
    clearTimeout(timeout);
  }
}

function extractHeadlines(raw: string): string[] {
  if (!raw) {
    return [];
  }

  // Try RSS item titles first.
  const rssTitles = Array.from(raw.matchAll(/<title>([^<]{10,200})<\/title>/gi)).map((m) => m[1]?.trim() ?? '');
  const filteredRss = rssTitles.filter((title) => !/rss|feed|xml/i.test(title)).slice(0, 8);
  if (filteredRss.length > 0) {
    return filteredRss;
  }

  // Fallback for JSON-like feeds.
  const jsonStyle = Array.from(raw.matchAll(/"(?:title|shortDescription)"\s*:\s*"([^"]{12,220})"/gi)).map(
    (m) => m[1]?.trim() ?? ''
  );
  return jsonStyle.slice(0, 8);
}

async function buildExternalSignals(enabledSources: Array<{ id: string; url: string; name: string }>): Promise<any[]> {
  const signals: any[] = [];
  for (const source of enabledSources) {
    const text = await safeFetchText(source.url);
    const headlines = extractHeadlines(text).slice(0, 3);
    for (const headline of headlines) {
      signals.push({
        sourceId: source.id,
        sourceName: source.name,
        sourceUrl: source.url,
        headline,
      });
    }
  }
  return signals;
}

function buildSuggestedGoals(technologies: string[], signals: any[]): any[] {
  const goals: any[] = [];

  for (const signal of signals.slice(0, 6)) {
    const tech = technologies.length > 0 ? technologies[goals.length % technologies.length] : 'general-security';
    goals.push({
      id: `signal-${goals.length + 1}`,
      title: `Investigate potential ${tech} exposure related to: ${signal.headline}`,
      rationale: `Derived from ${signal.sourceName} and local index technology inference (${technologies.join(', ') || 'none'}).`,
      sources: [signal.sourceUrl],
      confidence: 'medium',
      type: 'external-signal',
    });
  }

  if (goals.length === 0) {
    for (const tech of technologies.slice(0, 5)) {
      goals.push({
        id: `tech-${tech}`,
        title: `Investigate suspicious ${tech} activity in the current telemetry window`,
        rationale: `No live external signals were fetched; generated from active index technology inference for ${tech}.`,
        sources: [],
        confidence: 'medium',
        type: 'technology-inference',
      });
    }
  }

  return goals;
}

function pickInvestigationIndices(indices: string[]): string[] {
  return indices.filter((name) => !name.startsWith('.')).slice(0, 12);
}

function extractHits(searchResponse: any): any[] {
  const body = searchResponse?.body ?? searchResponse;
  return body?.hits?.hits ?? [];
}

function extractHost(hit: any): string {
  return hit?._source?.host?.name ?? hit?._source?.agent?.name ?? 'unknown-host';
}

function extractUser(hit: any): string {
  return hit?._source?.user?.name ?? hit?._source?.user?.id ?? 'unknown-user';
}

function summarizeFindings(hits: any[]): any {
  const hostCount = new Map<string, number>();
  const userCount = new Map<string, number>();

  for (const hit of hits) {
    const host = extractHost(hit);
    const user = extractUser(hit);
    hostCount.set(host, (hostCount.get(host) ?? 0) + 1);
    userCount.set(user, (userCount.get(user) ?? 0) + 1);
  }

  const topHosts = Array.from(hostCount.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([name, count]) => ({ name, count }));
  const topUsers = Array.from(userCount.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([name, count]) => ({ name, count }));

  return {
    sampledEvents: hits.length,
    topHosts,
    topUsers,
  };
}

function flattenObjectKeys(value: any, prefix = '', acc: Set<string> = new Set<string>()): string[] {
  if (value === null || value === undefined) {
    return Array.from(acc);
  }
  if (typeof value !== 'object') {
    if (prefix) {
      acc.add(prefix);
    }
    return Array.from(acc);
  }
  if (Array.isArray(value)) {
    if (value.length > 0) {
      flattenObjectKeys(value[0], prefix ? `${prefix}[]` : '[]', acc);
    } else if (prefix) {
      acc.add(prefix);
    }
    return Array.from(acc);
  }

  for (const [key, nestedValue] of Object.entries(value)) {
    const nextPrefix = prefix ? `${prefix}.${key}` : key;
    acc.add(nextPrefix);
    flattenObjectKeys(nestedValue, nextPrefix, acc);
  }
  return Array.from(acc);
}

function buildToolSchemasForPhase(toolName: string): any[] {
  const commonParameters = {
    type: 'object',
    properties: {
      note: {
        type: 'string',
        description: 'Optional note from the LLM about why this tool is called.',
      },
    },
    required: [],
  };

  return [
    {
      type: 'function',
      function: {
        name: toolName,
        description: `Execute predefined ${toolName} investigation script against OpenSearch evidence.`,
        parameters: commonParameters,
      },
    },
  ];
}

async function callOpenAICompatibleChat(provider: any, body: any): Promise<any> {
  const baseUrl = String(provider?.baseUrl ?? '').replace(/\/$/, '');
  const model = String(provider?.model ?? '');
  const apiKey = String(provider?.apiKey ?? '');

  if (!baseUrl || !model || !apiKey) {
    throw new Error('Provider base URL, model, and API key are required for agentic investigations.');
  }

  const response = await fetch(`${baseUrl}/chat/completions`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model,
      temperature: 0.1,
      ...body,
    }),
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = payload?.error?.message ?? payload?.message ?? response.statusText;
    throw new Error(`LLM request failed: ${message}`);
  }

  const message = payload?.choices?.[0]?.message;
  if (!message) {
    throw new Error('LLM response did not contain a message payload.');
  }
  return message;
}

async function runPhaseToolScript(
  toolName: string,
  context: any,
  state: InvestigationState,
  activityLog: Array<{ ts: string; phase: string; message: string }>
): Promise<any> {
  const client = context.core.opensearch.client.asCurrentUser;
  const now = () => new Date().toISOString();
  const log = (phase: string, message: string) => activityLog.push({ ts: now(), phase, message });

  if (toolName === 'run_source_intel_script') {
    if (state.enabledSources.length === 0) {
      state.threatSignals = [];
      const emptyResult = {
        enabledSourceCount: 0,
        signalCount: 0,
        topSignals: [],
      };
      log('source-intel', 'No enabled sources configured for this run.');
      return emptyResult;
    }

    const signals = await buildExternalSignals(state.enabledSources);
    state.threatSignals = signals;
    const result = {
      enabledSourceCount: state.enabledSources.length,
      signalCount: signals.length,
      topSignals: signals.slice(0, 8).map((signal) => ({
        sourceName: signal.sourceName,
        sourceUrl: signal.sourceUrl,
        headline: signal.headline,
      })),
    };
    log('source-intel', `Source Intel script collected ${signals.length} signals from ${state.enabledSources.length} sources.`);
    return result;
  }

  if (toolName === 'run_scope_script') {
    const indicesResponse = await client.cat.indices({ format: 'json', h: 'index' });
    const rows = extractIndexArray(indicesResponse);
    const indexNames = rows.map((row: any) => row.index).filter(Boolean);
    const inferredTechnologies = inferTechnologies(indexNames);
    const usedIndices = pickInvestigationIndices(indexNames);

    state.inferredTechnologies = inferredTechnologies;
    state.usedIndices = usedIndices;

    const result = {
      selectedGoal: state.selectedGoal,
      totalIndices: indexNames.length,
      usedIndices,
      inferredTechnologies,
    };
    log('scope', `Scope script completed with ${usedIndices.length} selected indices.`);
    return result;
  }

  if (toolName === 'run_schema_script') {
    const indexInput = state.usedIndices.length > 0 ? state.usedIndices : ['*'];
    const response = await client.search({
      index: indexInput,
      ignore_unavailable: true,
      allow_no_indices: true,
      body: {
        size: 8,
        sort: ['_doc'],
        query: {
          match_all: {},
        },
      },
    });
    const hits = extractHits(response);
    const keys = new Set<string>();
    for (const hit of hits) {
      const source = hit?._source ?? {};
      for (const key of flattenObjectKeys(source)) {
        keys.add(key);
      }
    }

    const sampleFields = Array.from(keys).slice(0, 60);
    const ecsCandidates = sampleFields.filter((field) =>
      ['@timestamp', 'event.category', 'host.name', 'user.name', 'process.name', 'agent.name'].some((seed) =>
        field.includes(seed)
      )
    );

    const result = {
      sampledDocuments: hits.length,
      sampledFieldCount: sampleFields.length,
      ecsCandidateCount: ecsCandidates.length,
      sampledFields: sampleFields,
    };
    log('schema', `Schema script profiled ${sampleFields.length} fields across sampled documents.`);
    return result;
  }

  if (toolName === 'run_selection_script') {
    const response = await client.search({
      index: state.usedIndices.length > 0 ? state.usedIndices : ['*'],
      ignore_unavailable: true,
      allow_no_indices: true,
      body: {
        size: 120,
        sort: ['_doc'],
        query: {
          match_all: {},
        },
      },
    });
    const hits = extractHits(response);
    state.hits = hits;

    const result = {
      retrievedEvents: hits.length,
      indices: state.usedIndices,
      sampleEventIds: hits.slice(0, 15).map((hit) => hit?._id).filter(Boolean),
    };
    log('selection', `Selection script retrieved ${hits.length} events.`);
    return result;
  }

  if (toolName === 'run_hypothesis_script') {
    const findings = summarizeFindings(state.hits);
    const hypotheses: string[] = [
      'Potential coordinated activity from repeated host-user clusters.',
      'Concentrated activity may indicate privileged account misuse.',
      'Observed activity may still be benign but requires timeline pivots.',
    ];

    state.findings = findings;
    state.hypotheses = hypotheses;

    const result = {
      findings,
      hypotheses,
    };
    log('hypothesis', `Hypothesis script produced ${hypotheses.length} hypotheses.`);
    return result;
  }

  if (toolName === 'run_validation_script') {
    const evidenceIds = state.hits.slice(0, 20).map((hit) => hit?._id).filter(Boolean);
    state.evidenceIds = evidenceIds;
    const result = {
      evidenceIds,
      evidenceCoverage: {
        referencedEvents: evidenceIds.length,
        sampledEvents: state.hits.length,
      },
      uncertainty: evidenceIds.length === 0 ? 'high' : evidenceIds.length < 5 ? 'medium' : 'low',
    };
    log('validation', `Validation script attached ${evidenceIds.length} evidence references.`);
    return result;
  }

  if (toolName === 'run_decision_script') {
    const hasEvidence = state.evidenceIds.length > 0;
    const result = {
      recommendation: hasEvidence ? 'continue_investigation' : 'insufficient_evidence',
      confidence: hasEvidence ? 'medium' : 'low',
      nextActions: hasEvidence
        ? ['Pivot by top hosts', 'Pivot by top users', 'Correlate with external threat signals']
        : ['Increase evidence window', 'Adjust scope constraints', 'Verify ingestion health'],
    };
    log('decision', `Decision script completed with recommendation: ${result.recommendation}.`);
    return result;
  }

  throw new Error(`Unsupported tool script: ${toolName}`);
}

async function executePhaseWithAgent(
  context: any,
  provider: any,
  phase: any,
  state: InvestigationState,
  activityLog: Array<{ ts: string; phase: string; message: string }>
): Promise<string> {
  const now = () => new Date().toISOString();
  const log = (phaseName: string, message: string) => activityLog.push({ ts: now(), phase: phaseName, message });

  const systemMessage =
    'You are the XDR Sentry investigation agent. Always call the provided tool before producing your response. Respond with compact JSON.';
  const userMessage = {
    role: 'user',
    content: [
      `Investigation goal: ${state.selectedGoal}`,
      `Phase: ${phase.name}`,
      `Script purpose: ${phase.purpose}`,
      `Required script instructions: ${phase.instructions}`,
      `Enabled source count: ${state.enabledSources.length}`,
      `Current threat signal count: ${state.threatSignals.length}`,
      `Current technologies: ${state.inferredTechnologies.join(', ') || 'none'}`,
      `Current selected indices: ${state.usedIndices.join(', ') || 'none'}`,
    ].join('\n'),
  };

  const tools = buildToolSchemasForPhase(phase.toolName);

  const assistantWithToolCall = await callOpenAICompatibleChat(provider, {
    messages: [
      { role: 'system', content: systemMessage },
      userMessage,
    ],
    tools,
    tool_choice: {
      type: 'function',
      function: {
        name: phase.toolName,
      },
    },
  });

  const toolCalls = Array.isArray(assistantWithToolCall?.tool_calls) ? assistantWithToolCall.tool_calls : [];
  if (toolCalls.length === 0) {
    throw new Error(`LLM did not issue the expected tool call for phase ${phase.id}.`);
  }

  const toolMessages: any[] = [];
  for (const toolCall of toolCalls) {
    const name = toolCall?.function?.name ?? phase.toolName;
    const toolOutput = await runPhaseToolScript(name, context, state, activityLog);
    toolMessages.push({
      role: 'tool',
      tool_call_id: toolCall.id,
      name,
      content: JSON.stringify(toolOutput),
    });
  }

  const finalAssistant = await callOpenAICompatibleChat(provider, {
    messages: [
      { role: 'system', content: systemMessage },
      userMessage,
      {
        role: 'assistant',
        content: assistantWithToolCall?.content ?? '',
        tool_calls: toolCalls,
      },
      ...toolMessages,
    ],
  });

  const phaseSummary = String(finalAssistant?.content ?? '').trim();
  log(phase.id, phaseSummary ? `Agent synthesis ready for ${phase.name}.` : `Agent returned empty synthesis for ${phase.name}.`);
  return phaseSummary;
}

async function runAgenticInvestigation(context: any, body: any): Promise<any> {
  const activityLog: Array<{ ts: string; phase: string; message: string }> = [];
  const phases: Array<{ name: string; status: 'completed' | 'failed'; detail: string }> = [];

  const now = () => new Date().toISOString();
  const log = (phase: string, message: string) => activityLog.push({ ts: now(), phase, message });

  const selectedGoal = String(body?.selectedGoal ?? '').trim();
  const provider = body?.provider ?? {};
  const enabledSourceIds: string[] = Array.isArray(body?.enabledSourceIds) ? body.enabledSourceIds : [];
  const customSources: Array<{ id: string; name: string; url: string }> = Array.isArray(body?.customSources)
    ? body.customSources
    : [];

  const presetSources = SOURCE_PRESETS.filter((preset) => enabledSourceIds.includes(preset.id)).map((preset) => ({
    id: preset.id,
    name: preset.name,
    url: preset.url,
  }));
  const normalizedCustomSources = customSources
    .filter((source) => source?.url && source?.name)
    .map((source) => ({
      id: source.id,
      name: source.name,
      url: source.url,
    }));
  const enabledSources = [...presetSources, ...normalizedCustomSources];

  const llmProviderConfigured = Boolean(provider?.apiKey);
  if (!selectedGoal) {
    throw new Error('An investigation goal is required before running the agent.');
  }
  if (!llmProviderConfigured) {
    throw new Error('LLM API key is required. Save provider configuration with a valid key and retry.');
  }

  const state: InvestigationState = {
    selectedGoal,
    enabledSources,
    threatSignals: [],
    inferredTechnologies: [],
    usedIndices: [],
    hits: [],
    findings: {
      sampledEvents: 0,
      topHosts: [],
      topUsers: [],
    },
    hypotheses: [],
    evidenceIds: [],
  };

  log('execution', 'Starting LLM-assisted investigation workflow.');

  const phaseSummaries: Record<string, string> = {};
  for (const phase of AGENT_PHASE_SCRIPTS) {
    try {
      log(phase.id, `Executing predefined script ${phase.toolName}.`);
      const summary = await executePhaseWithAgent(context, provider, phase, state, activityLog);
      phaseSummaries[phase.id] = summary;
      phases.push({
        name: phase.name,
        status: 'completed',
        detail: summary || `${phase.name} completed by LLM agent with predefined script.`,
      });
    } catch (error: any) {
      phases.push({
        name: phase.name,
        status: 'failed',
        detail: error?.message ?? 'unknown error',
      });
      log(phase.id, `Phase failed: ${error?.message ?? 'unknown error'}`);
      throw new Error(`Phase ${phase.name} failed: ${error?.message ?? 'unknown error'}`);
    }
  }

  log('execution', 'LLM-assisted investigation workflow completed.');

  return {
    selectedGoal,
    executionMode: 'llm-assisted',
    llmProviderConfigured,
    llmProviderUsed: true,
    provider: {
      preset: provider?.preset ?? 'custom',
      baseUrl: provider?.baseUrl ?? '',
      model: provider?.model ?? '',
      hasApiKey: Boolean(provider?.apiKey),
    },
    inferredTechnologies: state.inferredTechnologies,
    usedIndices: state.usedIndices,
    phases,
    activityLog,
    findings: state.findings,
    hypotheses: state.hypotheses,
    evidenceIds: state.evidenceIds,
    enabledSources: state.enabledSources,
    sourceSignalCount: state.threatSignals.length,
    phaseScripts: AGENT_PHASE_SCRIPTS,
    phaseSummaries,
    status: 'completed',
  };
}

export function registerSentryRoutes(router: any): void {
  router.get(
    {
      path: '/api/xdr_sentry/source_presets',
      validate: false,
    },
    async (_context: any, _request: any, response: any) => {
      return response.ok({ body: { presets: SOURCE_PRESETS } });
    }
  );

  router.get(
    {
      path: '/api/xdr_sentry/agent_scripts',
      validate: false,
    },
    async (_context: any, _request: any, response: any) => {
      return response.ok({
        body: {
          scripts: AGENT_PHASE_SCRIPTS,
        },
      });
    }
  );

  router.get(
    {
      path: '/api/xdr_sentry/index_profile',
      validate: false,
    },
    async (context: any, _request: any, response: any) => {
      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const indicesResponse = await client.cat.indices({ format: 'json', h: 'index,status,health,docs.count' });
        const rows = extractIndexArray(indicesResponse);
        const indexNames = rows.map((row: any) => row.index).filter(Boolean);
        const technologies = inferTechnologies(indexNames);

        return response.ok({
          body: {
            indices: rows,
            technologies,
          },
        });
      } catch (error: any) {
        return response.customError({
          statusCode: 500,
          body: { message: `Failed to profile indices: ${error?.message ?? 'unknown error'}` },
        });
      }
    }
  );

  router.post(
    {
      path: '/api/xdr_sentry/provider_config',
      validate: {
        body: (value: any) => value,
      },
    },
    async (_context: any, request: any, response: any) => {
      const body = parseJsonBody(request.body);
      providerConfigStore = {
        preset: body?.preset ?? providerConfigStore.preset,
        baseUrl: body?.baseUrl ?? providerConfigStore.baseUrl,
        model: body?.model ?? providerConfigStore.model,
        apiKey: body?.apiKey ?? providerConfigStore.apiKey,
      };

      return response.ok({
        body: {
          provider: {
            preset: providerConfigStore.preset,
            baseUrl: providerConfigStore.baseUrl,
            model: providerConfigStore.model,
            hasApiKey: Boolean(providerConfigStore.apiKey),
          },
        },
      });
    }
  );

  router.get(
    {
      path: '/api/xdr_sentry/provider_config',
      validate: false,
    },
    async (_context: any, _request: any, response: any) => {
      return response.ok({
        body: {
          provider: {
            ...providerConfigStore,
            hasApiKey: Boolean(providerConfigStore.apiKey),
          },
        },
      });
    }
  );

  router.post(
    {
      path: '/api/xdr_sentry/propose_goals',
      validate: {
        body: (value: any) => value,
      },
    },
    async (context: any, request: any, response: any) => {
      const body = parseJsonBody(request.body);
      const enabledSourceIds: string[] = Array.isArray(body.enabledSourceIds) ? body.enabledSourceIds : [];
      const customSources: Array<{ id: string; name: string; url: string }> = Array.isArray(body.customSources)
        ? body.customSources
        : [];

      try {
        const client = context.core.opensearch.client.asCurrentUser;
        const indicesResponse = await client.cat.indices({ format: 'json', h: 'index' });
        const rows = extractIndexArray(indicesResponse);
        const indexNames = rows.map((row: any) => row.index).filter(Boolean);
        const technologies = inferTechnologies(indexNames);

        const presetSources = SOURCE_PRESETS.filter((preset) => enabledSourceIds.includes(preset.id));
        const enabledSources = [...presetSources, ...customSources.filter((source) => source?.url)];

        const signals = await buildExternalSignals(enabledSources as any);
        const goals = buildSuggestedGoals(technologies, signals);

        return response.ok({
          body: {
            goals,
            technologies,
            signalCount: signals.length,
          },
        });
      } catch (error: any) {
        return response.customError({
          statusCode: 500,
          body: { message: `Failed to propose goals: ${error?.message ?? 'unknown error'}` },
        });
      }
    }
  );

  router.post(
    {
      path: '/api/xdr_sentry/investigation_preview',
      validate: {
        body: (value: any) => value,
      },
    },
    async (_context: any, request: any, response: any) => {
      const body = parseJsonBody(request.body);
      const selectedGoal = body.selectedGoal ?? '';
      const provider = body.provider ?? {};
      const technologies = Array.isArray(body.technologies) ? body.technologies : [];

      const plan = {
        selectedGoal,
        technologies,
        provider: {
          preset: provider.preset ?? 'custom',
          baseUrl: provider.baseUrl ?? '',
          model: provider.model ?? '',
          hasApiKey: Boolean(provider.apiKey),
        },
        steps: [
          'Resolve scope and index set from current OpenSearch state',
          'Profile ECS/non-ECS fields and build confidence map',
          'Run deduplicated evidence retrieval queries',
          'Generate competing hypotheses with evidence links',
          'Return investigation narrative and uncertainty notes',
        ],
      };

      return response.ok({ body: { plan } });
    }
  );

  router.post(
    {
      path: '/api/xdr_sentry/run_investigation',
      validate: {
        body: (value: any) => value,
      },
    },
    async (context: any, request: any, response: any) => {
      try {
        const body = parseJsonBody(request.body);
        const result = await runAgenticInvestigation(context, body);
        return response.ok({ body: { result } });
      } catch (error: any) {
        const message = error?.message ?? 'unknown error';
        const isBadRequest =
          /required|invalid|missing/i.test(String(message)) || /goal|api key|provider/i.test(String(message));
        return response.customError({
          statusCode: isBadRequest ? 400 : 500,
          body: { message: `Failed to run investigation: ${message}` },
        });
      }
    }
  );
}
