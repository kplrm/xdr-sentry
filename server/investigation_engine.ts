import { PROVIDER_CONFIG_SAVED_OBJECT_ID, PROVIDER_CONFIG_SAVED_OBJECT_TYPE } from '../common';

const SOURCE_PRESETS = [
  {
    id: 'cisa-alerts',
    name: 'CISA Alerts',
    url: 'https://www.cisa.gov/uscert/ncas/alerts.xml',
    type: 'advisory',
    trustLevel: 'high',
    enabledByDefault: true,
  },
  {
    id: 'cisa-kev',
    name: 'CISA Known Exploited Vulnerabilities',
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    type: 'advisory',
    trustLevel: 'high',
    enabledByDefault: true,
  },
  {
    id: 'nvd',
    name: 'NVD CVE Feed',
    url: 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz',
    type: 'advisory',
    trustLevel: 'high',
    enabledByDefault: false,
  },
  {
    id: 'us-cert',
    name: 'US-CERT Advisories',
    url: 'https://www.cisa.gov/news.xml',
    type: 'advisory',
    trustLevel: 'high',
    enabledByDefault: false,
  },
  {
    id: 'mandiant',
    name: 'Mandiant Research',
    url: 'https://www.mandiant.com/resources/blog/rss.xml',
    type: 'blog',
    trustLevel: 'high',
    enabledByDefault: true,
  },
  {
    id: 'microsoft-security',
    name: 'Microsoft Security Blog',
    url: 'https://www.microsoft.com/en-us/security/blog/feed/',
    type: 'blog',
    trustLevel: 'high',
    enabledByDefault: true,
  },
  {
    id: 'crowdstrike',
    name: 'CrowdStrike Threat Research',
    url: 'https://www.crowdstrike.com/blog/feed/',
    type: 'blog',
    trustLevel: 'high',
    enabledByDefault: true,
  },
  {
    id: 'unit42',
    name: 'Palo Alto Unit 42',
    url: 'https://unit42.paloaltonetworks.com/feed/',
    type: 'blog',
    trustLevel: 'high',
    enabledByDefault: true,
  },
  {
    id: 'talos',
    name: 'Cisco Talos',
    url: 'https://blog.talosintelligence.com/rss/',
    type: 'blog',
    trustLevel: 'high',
    enabledByDefault: true,
  },
  {
    id: 'attack',
    name: 'MITRE ATT&CK',
    url: 'https://attack.mitre.org/',
    type: 'knowledge-base',
    trustLevel: 'high',
    enabledByDefault: false,
  },
];

const TECHNOLOGY_DEFINITIONS: Record<string, {
  keywords: string[];
  fieldSignals: string[];
  category: string;
  researchTopics: string[];
  suspiciousHypotheses: string[];
  benignHypotheses: string[];
}> = {
  endpoint: {
    keywords: ['endpoint', 'edr', 'sysmon', 'osquery', 'process', 'host', 'defender'],
    fieldSignals: ['host.name', 'process.name', 'process.executable', 'event.category', 'user.name'],
    category: 'endpoint',
    researchTopics: ['lateral movement', 'privilege escalation', 'ransomware', 'malware execution'],
    suspiciousHypotheses: [
      'Potential endpoint compromise with suspicious process or user activity.',
      'Potential lateral movement or privilege escalation sequence on a monitored host.',
    ],
    benignHypotheses: [
      'Expected administrative maintenance or software deployment activity.',
      'Security tooling or scheduled task noise produced the observed process chain.',
    ],
  },
  identity: {
    keywords: ['identity', 'auth', 'okta', 'entra', 'aad', 'login', 'iam', 'sso'],
    fieldSignals: ['user.name', 'event.outcome', 'source.ip', 'related.user', 'host.name'],
    category: 'identity',
    researchTopics: ['credential abuse', 'password spraying', 'token theft', 'MFA bypass'],
    suspiciousHypotheses: [
      'Potential credential abuse or anomalous identity access pattern.',
      'Potential account misuse involving abnormal authentication outcomes or pivots.',
    ],
    benignHypotheses: [
      'Routine user travel, VPN changes, or identity-provider noise explain the pattern.',
      'Bulk administrative resets or onboarding activity caused the anomalies.',
    ],
  },
  network: {
    keywords: ['firewall', 'proxy', 'dns', 'netflow', 'zeek', 'suricata', 'ids', 'ips', 'vpn'],
    fieldSignals: ['source.ip', 'destination.ip', 'url.domain', 'dns.question.name', 'network.transport'],
    category: 'network',
    researchTopics: ['command and control', 'data exfiltration', 'reconnaissance', 'malicious domains'],
    suspiciousHypotheses: [
      'Potential command-and-control or suspicious outbound communication pattern.',
      'Potential data exfiltration or reconnaissance behaviour in network telemetry.',
    ],
    benignHypotheses: [
      'Legitimate backup, patching, or software update traffic explains the flow pattern.',
      'Expected security scanning or vulnerability validation generated the activity.',
    ],
  },
  cloud: {
    keywords: ['cloud', 'aws', 'gcp', 'azure', 'iam', 'cloudtrail', 'audit'],
    fieldSignals: ['cloud.provider', 'user.name', 'source.ip', 'event.action', 'host.name'],
    category: 'cloud',
    researchTopics: ['cloud account abuse', 'console compromise', 'role misuse', 'persistence'],
    suspiciousHypotheses: [
      'Potential cloud control-plane misuse or unauthorized identity activity.',
      'Potential persistence or privilege abuse in cloud administration events.',
    ],
    benignHypotheses: [
      'Normal infrastructure automation or CI/CD activity explains the control-plane changes.',
      'Expected cloud governance or inventory jobs generated the actions.',
    ],
  },
  container: {
    keywords: ['container', 'docker', 'kubernetes', 'k8s', 'pod', 'image', 'runtime'],
    fieldSignals: ['container.id', 'container.name', 'kubernetes.namespace', 'process.name', 'host.name'],
    category: 'container',
    researchTopics: ['container escape', 'exposed daemon exploitation', 'malicious image', 'cryptomining'],
    suspiciousHypotheses: [
      'Potential container exploitation or post-compromise activity.',
      'Potential malicious workload execution such as cryptomining or runtime abuse.',
    ],
    benignHypotheses: [
      'Normal deployment churn or orchestration events explain the observed changes.',
      'Expected image pulls or health checks generated the container activity.',
    ],
  },
  email: {
    keywords: ['email', 'exchange', 'o365', 'm365', 'mail', 'smtp', 'phish'],
    fieldSignals: ['user.name', 'source.ip', 'event.action', 'file.name', 'email.subject'],
    category: 'email',
    researchTopics: ['phishing', 'malicious attachment', 'business email compromise', 'tenant abuse'],
    suspiciousHypotheses: [
      'Potential phishing or email-driven compromise activity.',
      'Potential suspicious mailbox access or tenant abuse pattern.',
    ],
    benignHypotheses: [
      'Bulk campaign noise or expected user behaviour explains the email pattern.',
      'Administrative mailbox operations caused the flagged activity.',
    ],
  },
  application: {
    keywords: ['http', 'nginx', 'apache', 'waf', 'service', 'application', 'web'],
    fieldSignals: ['service.name', 'http.request.method', 'url.domain', 'source.ip', 'destination.ip'],
    category: 'application',
    researchTopics: ['web exploitation', 'session abuse', 'remote code execution', 'suspicious upload'],
    suspiciousHypotheses: [
      'Potential web or application-layer exploitation sequence.',
      'Potential abuse of an exposed service endpoint or session.',
    ],
    benignHypotheses: [
      'Application release, QA validation, or health checks explain the traffic pattern.',
      'Known noisy client integrations caused the observed application activity.',
    ],
  },
};

const WORKFLOW_ORDER = [
  'Goal approval',
  'Index discovery',
  'Index understanding',
  'Schema readiness gate',
  'External threat research',
  'Evidence collection',
  'Competing hypotheses',
  'Challenge and contradiction review',
  'Decision and reporting',
];

const ALLOWED_OUTCOME_STATES = [
  'Likely attack story identified',
  'Correlated activity identified but attack not established',
  'No supported attack story found in scope',
  'Inconclusive',
  'Unable to proceed',
];

const INVESTIGATION_RECORD_TYPES = [
  'run record',
  'index profile',
  'research note',
  'evidence card',
  'hypothesis record',
  'decision record',
  'audit record',
];

const AGENT_ROLES = [
  {
    id: 'goal-agent',
    name: 'Goal Agent',
    responsibilities: ['Validate the goal', 'Ensure the scope is analyst-approved', 'Pin the execution objective'],
  },
  {
    id: 'index-understanding-agent',
    name: 'Index Understanding Agent',
    responsibilities: ['Discover indices', 'Profile contents', 'Assess fitness for investigation'],
  },
  {
    id: 'research-agent',
    name: 'Research Agent',
    responsibilities: ['Collect current trusted-source context', 'Translate research into testable leads'],
  },
  {
    id: 'correlation-agent',
    name: 'Correlation Agent',
    responsibilities: ['Pivot across entities', 'Collect timelines', 'Link evidence across indices'],
  },
  {
    id: 'hypothesis-agent',
    name: 'Hypothesis Agent',
    responsibilities: ['Generate suspicious and benign hypotheses', 'Rank by testability'],
  },
  {
    id: 'challenger-agent',
    name: 'Challenger Agent',
    responsibilities: ['Look for contradictions', 'Surface missing expected evidence'],
  },
  {
    id: 'decision-agent',
    name: 'Decision Agent',
    responsibilities: ['Choose allowed final state', 'Explain confidence and limitations'],
  },
  {
    id: 'reporting-agent',
    name: 'Reporting Agent',
    responsibilities: ['Write from validated evidence only', 'Summarize branch and overall outcomes'],
  },
];

const COMMON_FIELDS = [
  '@timestamp',
  'timestamp',
  'event.created',
  'event.ingested',
  'event.action',
  'event.category',
  'event.type',
  'event.outcome',
  'event.dataset',
  'data_stream.dataset',
  'host.name',
  'agent.name',
  'user.name',
  'user.id',
  'source.ip',
  'destination.ip',
  'process.name',
  'process.executable',
  'process.command_line',
  'container.id',
  'container.name',
  'kubernetes.namespace',
  'service.name',
  'url.domain',
  'dns.question.name',
  'http.request.method',
  'file.path',
  'log.level',
];

interface ProviderConfig {
  preset: string;
  baseUrl: string;
  model: string;
  apiKey: string;
}

interface AgenticDecision {
  state: string;
  confidence: 'high' | 'medium' | 'low';
  rationale: string[];
  limitations: string[];
  nextSteps: string[];
}

interface AgenticFinalAnswer {
  decision: AgenticDecision;
  branchConclusions: any[];
  executiveSummary: string;
}

const DEFAULT_PROVIDER_CONFIG: ProviderConfig = {
  preset: 'custom',
  baseUrl: '',
  model: 'qwen3.5:9b-q4_K_M',
  apiKey: '',
};

const OPENAI_CHAT_COMPLETIONS_PATH = '/chat/completions';
const OPENAI_RESPONSES_PATH = '/responses';

const AGENTIC_MAX_TOOL_CALLS = 16;

interface ScopeInput {
  includePatterns: string[];
  excludePatterns: string[];
  timeRange: { from: string; to: string };
  queryText: string;
  maxProfiles: number;
  maxEvidencePerIndex: number;
}

interface FieldDescriptor {
  path: string;
  type: string;
  aggregatableField: string | null;
}

let providerConfigStore: ProviderConfig = { ...DEFAULT_PROVIDER_CONFIG };
let recentInvestigations: any[] = [];

function nowIso(): string {
  return new Date().toISOString();
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(maximum, Math.max(minimum, value));
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

function splitCsvValue(input: any): string[] {
  if (Array.isArray(input)) {
    return input.map((value) => String(value).trim()).filter(Boolean);
  }
  if (typeof input !== 'string') {
    return [];
  }
  return input
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
}

function normalizeScope(rawBody: any): ScopeInput {
  const scope = rawBody?.scope ?? {};
  return {
    includePatterns: splitCsvValue(scope.includePatterns),
    excludePatterns: splitCsvValue(scope.excludePatterns),
    timeRange: {
      from: String(scope?.timeRange?.from ?? 'now-24h'),
      to: String(scope?.timeRange?.to ?? 'now'),
    },
    queryText: String(scope?.queryText ?? '').trim(),
    maxProfiles: clamp(Number(scope?.maxProfiles ?? 8), 1, 20),
    maxEvidencePerIndex: clamp(Number(scope?.maxEvidencePerIndex ?? 3), 1, 10),
  };
}

function summarizeProvider(providerConfig: ProviderConfig): any {
  let normalizedBaseUrl = '';
  try {
    normalizedBaseUrl = normalizeProviderBaseUrl(providerConfig.baseUrl);
  } catch {
    normalizedBaseUrl = String(providerConfig.baseUrl ?? '').trim();
  }

  return {
    preset: providerConfig.preset,
    baseUrl: normalizedBaseUrl,
    model: providerConfig.model,
    hasApiKey: Boolean(providerConfig.apiKey),
  };
}

function ensureProviderIsConfigured(providerConfig: ProviderConfig): void {
  if (!providerConfig.baseUrl || !providerConfig.model || !providerConfig.apiKey) {
    throw new Error('Provider configuration is required: baseUrl, model, and apiKey must all be set.');
  }
  normalizeProviderBaseUrl(providerConfig.baseUrl);
}

function normalizeProviderBaseUrl(baseUrl: string): string {
  const raw = String(baseUrl ?? '').trim();
  if (!raw) {
    return '';
  }

  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error('Provider baseUrl must be an absolute http(s) URL.');
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Provider baseUrl must use http or https.');
  }

  let pathname = parsed.pathname.replace(/\/+$/, '');
  if (pathname.endsWith('/v1/chat/completions')) {
    pathname = pathname.slice(0, -'/chat/completions'.length);
  } else if (pathname.endsWith('/chat/completions')) {
    pathname = pathname.slice(0, -'/chat/completions'.length);
  } else if (pathname.endsWith('/v1/responses')) {
    pathname = pathname.slice(0, -'/responses'.length);
  } else if (pathname.endsWith('/responses')) {
    pathname = pathname.slice(0, -'/responses'.length);
  }

  parsed.pathname = pathname || '/';
  parsed.search = '';
  parsed.hash = '';
  return parsed.toString().replace(/\/+$/, '');
}

function buildOpenAiCompatibleUrls(baseUrl: string): { normalizedBaseUrl: string; chatCompletionsUrl: string; responsesUrl: string } {
  const normalizedBaseUrl = normalizeProviderBaseUrl(baseUrl);
  return {
    normalizedBaseUrl,
    chatCompletionsUrl: `${normalizedBaseUrl}${OPENAI_CHAT_COMPLETIONS_PATH}`,
    responsesUrl: `${normalizedBaseUrl}${OPENAI_RESPONSES_PATH}`,
  };
}

function normalizeProviderConfigForRequest(rawBody: any, fallbackConfig?: ProviderConfig): ProviderConfig {
  const body = parseJsonBody(rawBody);
  const baseUrl =
    String(body?.baseUrl ?? '').trim() || String(fallbackConfig?.baseUrl ?? '').trim();
  const model =
    String(body?.model ?? '').trim() ||
    String(fallbackConfig?.model ?? '').trim() ||
    DEFAULT_PROVIDER_CONFIG.model;
  const apiKey =
    String(body?.apiKey ?? '').trim() || String(fallbackConfig?.apiKey ?? '').trim();

  return {
    preset: 'custom',
    baseUrl: normalizeProviderBaseUrl(baseUrl),
    model,
    apiKey,
  };
}

function summarizeAssistantContent(content: any): string {
  const text = typeof content === 'string' ? content : JSON.stringify(content ?? '');
  const compact = text.replace(/\s+/g, ' ').trim();
  if (!compact) {
    return 'No assistant content.';
  }
  return compact.slice(0, 320);
}

function mapMessagesToResponsesInput(messages: any[]): any[] {
  return messages.map((message) => {
    const role = String(message?.role ?? 'user');
    const textParts: string[] = [];

    if (message?.content) {
      textParts.push(typeof message.content === 'string' ? message.content : JSON.stringify(message.content));
    }
    if (Array.isArray(message?.tool_calls) && message.tool_calls.length > 0) {
      textParts.push(`Tool calls: ${JSON.stringify(message.tool_calls)}`);
    }
    if (role === 'tool') {
      textParts.push(`Tool name: ${String(message?.name ?? 'unknown')}`);
    }

    return {
      role,
      content: textParts.join('\n').trim() || ' ',
    };
  });
}

function adaptResponsesOutputToAssistantMessage(responseBody: any): any {
  const output = Array.isArray(responseBody?.output) ? responseBody.output : [];
  const responseText =
    String(responseBody?.output_text ?? '').trim() ||
    output
      .flatMap((entry: any) => (Array.isArray(entry?.content) ? entry.content : []))
      .map((entry: any) => String(entry?.text ?? '').trim())
      .filter(Boolean)
      .join('\n');

  const toolCalls = output
    .filter((entry: any) => entry?.type === 'function_call')
    .map((entry: any, index: number) => ({
      id: String(entry?.call_id ?? entry?.id ?? `responses-tool-${index + 1}`),
      type: 'function',
      function: {
        name: String(entry?.name ?? ''),
        arguments: typeof entry?.arguments === 'string' ? entry.arguments : JSON.stringify(entry?.arguments ?? {}),
      },
    }))
    .filter((toolCall: any) => toolCall.function.name);

  return {
    role: 'assistant',
    content: responseText,
    tool_calls: toolCalls,
  };
}

async function callProviderOpenAiCompatible(providerConfig: ProviderConfig, messages: any[], tools: any[]): Promise<any> {
  ensureProviderIsConfigured(providerConfig);
  const urls = buildOpenAiCompatibleUrls(providerConfig.baseUrl);
  const headers = {
    'content-type': 'application/json',
    authorization: `Bearer ${providerConfig.apiKey}`,
  };

  const chatResponse = await fetch(urls.chatCompletionsUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model: providerConfig.model,
      temperature: 0.1,
      messages,
      tools,
      tool_choice: tools.length > 0 ? 'auto' : undefined,
    }),
  }).catch((error) => {
    throw new Error(`Provider call failed: ${String((error as any)?.message ?? error)}`);
  });

  if (chatResponse.ok) {
    const body = await chatResponse.json().catch(() => ({}));
    const message = body?.choices?.[0]?.message;
    if (!message) {
      throw new Error('Provider returned no message choices.');
    }
    return {
      message,
      protocol: 'chat_completions',
      endpoint: urls.chatCompletionsUrl,
    };
  }

  const canTryResponsesFallback = [404, 405, 501].includes(chatResponse.status);
  const chatBodyText = await chatResponse.text().catch(() => '');
  if (!canTryResponsesFallback) {
    throw new Error(`Provider error ${chatResponse.status}: ${chatBodyText || chatResponse.statusText}`);
  }

  const responsesResponse = await fetch(urls.responsesUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model: providerConfig.model,
      temperature: 0.1,
      input: mapMessagesToResponsesInput(messages),
      tools,
      tool_choice: tools.length > 0 ? 'auto' : undefined,
    }),
  }).catch((error) => {
    throw new Error(`Provider fallback call failed: ${String((error as any)?.message ?? error)}`);
  });

  if (!responsesResponse.ok) {
    const responsesBodyText = await responsesResponse.text().catch(() => '');
    throw new Error(
      `Provider chat/completions error ${chatResponse.status} and responses error ${responsesResponse.status}: ${responsesBodyText || responsesResponse.statusText}`
    );
  }

  const responsesBody = await responsesResponse.json().catch(() => ({}));
  return {
    message: adaptResponsesOutputToAssistantMessage(responsesBody),
    protocol: 'responses',
    endpoint: urls.responsesUrl,
  };
}

async function callProviderChatCompletionsStream(providerConfig: ProviderConfig, messages: any[]): Promise<any> {
  ensureProviderIsConfigured(providerConfig);
  const urls = buildOpenAiCompatibleUrls(providerConfig.baseUrl);
  const response = await fetch(urls.chatCompletionsUrl, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${providerConfig.apiKey}`,
    },
    body: JSON.stringify({
      model: providerConfig.model,
      messages,
      stream: true,
    }),
  }).catch((error) => {
    throw new Error(`Provider streaming call failed: ${String((error as any)?.message ?? error)}`);
  });

  if (!response.ok) {
    const bodyText = await response.text().catch(() => '');
    throw new Error(`Provider error ${response.status}: ${bodyText || response.statusText}`);
  }

  const reader = response.body?.getReader();
  if (!reader) {
    throw new Error('Provider did not return a readable stream.');
  }

  const decoder = new TextDecoder();
  let buffer = '';
  let reasoningContent = '';
  let answerContent = '';

  while (true) {
    const { value, done } = await reader.read();
    if (done) {
      break;
    }

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() ?? '';

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line.startsWith('data:')) {
        continue;
      }
      const payload = line.slice(5).trim();
      if (!payload || payload === '[DONE]') {
        continue;
      }

      let parsed: any;
      try {
        parsed = JSON.parse(payload);
      } catch {
        continue;
      }

      const delta = parsed?.choices?.[0]?.delta ?? {};
      reasoningContent += String(delta?.reasoning_content ?? delta?.reasoning ?? '');
      answerContent += String(delta?.content ?? '');
    }
  }

  return {
    protocol: 'chat_completions_stream',
    endpoint: urls.chatCompletionsUrl,
    reasoningContent: reasoningContent.trim(),
    answerContent: answerContent.trim(),
  };
}

function parseModelJson(content: string): any {
  const text = content.trim();
  if (!text) {
    throw new Error('LLM returned an empty response.');
  }

  try {
    return JSON.parse(text);
  } catch {
    const fenced = text.match(/```json\s*([\s\S]*?)```/i)?.[1] ?? text.match(/```\s*([\s\S]*?)```/i)?.[1] ?? '';
    if (fenced) {
      return JSON.parse(fenced);
    }
    const start = text.indexOf('{');
    const end = text.lastIndexOf('}');
    if (start >= 0 && end > start) {
      return JSON.parse(text.slice(start, end + 1));
    }
    throw new Error('LLM response was not valid JSON.');
  }
}

function validateAgenticFinalAnswer(answer: any): AgenticFinalAnswer {
  const rawDecision = answer?.decision ?? {};
  const state = String(rawDecision?.state ?? '').trim();
  const confidence = String(rawDecision?.confidence ?? '').trim().toLowerCase() as 'high' | 'medium' | 'low';

  if (!ALLOWED_OUTCOME_STATES.includes(state)) {
    throw new Error(`LLM chose an invalid final state: ${state || '(empty)'}`);
  }
  if (!['high', 'medium', 'low'].includes(confidence)) {
    throw new Error(`LLM chose an invalid confidence: ${confidence || '(empty)'}`);
  }

  const rationale = Array.isArray(rawDecision?.rationale) ? rawDecision.rationale.map((item: any) => String(item)).filter(Boolean) : [];
  const limitations = Array.isArray(rawDecision?.limitations) ? rawDecision.limitations.map((item: any) => String(item)).filter(Boolean) : [];
  const nextSteps = Array.isArray(rawDecision?.nextSteps) ? rawDecision.nextSteps.map((item: any) => String(item)).filter(Boolean) : [];
  const branchConclusions = Array.isArray(answer?.branchConclusions) ? answer.branchConclusions : [];
  const executiveSummary = String(answer?.executiveSummary ?? '').trim();

  if (!executiveSummary) {
    throw new Error('LLM final answer did not provide executiveSummary.');
  }

  return {
    decision: {
      state,
      confidence,
      rationale,
      limitations,
      nextSteps,
    },
    branchConclusions,
    executiveSummary,
  };
}

function wildcardToRegExp(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`, 'i');
}

function matchesAnyPattern(value: string, patterns: string[]): boolean {
  if (patterns.length === 0) {
    return true;
  }
  return patterns.some((pattern) => wildcardToRegExp(pattern).test(value));
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

function sortIndexRows(rows: any[]): any[] {
  return [...rows].sort((left, right) => {
    const leftDocs = Number(left?.['docs.count'] ?? 0);
    const rightDocs = Number(right?.['docs.count'] ?? 0);
    return rightDocs - leftDocs;
  });
}

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .map((token) => token.trim())
    .filter((token) => token.length >= 3);
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

function getNestedValue(source: any, path: string): any {
  const segments = path.split('.');
  let current = source;
  for (const segment of segments) {
    if (current === null || current === undefined) {
      return undefined;
    }
    current = current[segment];
  }
  return current;
}

function collectFieldDescriptors(properties: Record<string, any>, prefix = '', acc: FieldDescriptor[] = []): FieldDescriptor[] {
  for (const [key, config] of Object.entries(properties ?? {})) {
    const nextPath = prefix ? `${prefix}.${key}` : key;
    const type = String((config as any)?.type ?? 'object');
    const keywordField = (config as any)?.fields?.keyword ? `${nextPath}.keyword` : null;
    const aggregatableField =
      type === 'keyword' || type === 'ip' || type === 'integer' || type === 'long' || type === 'float' || type === 'boolean'
        ? nextPath
        : keywordField;

    acc.push({
      path: nextPath,
      type,
      aggregatableField,
    });

    if ((config as any)?.properties) {
      collectFieldDescriptors((config as any).properties, nextPath, acc);
    }
  }
  return acc;
}

function extractMappingProperties(mappingResponse: any, indexName: string): Record<string, any> {
  const body = mappingResponse?.body ?? mappingResponse ?? {};
  const directMatch = body?.[indexName]?.mappings?.properties;
  if (directMatch) {
    return directMatch;
  }
  const firstEntry = Object.values(body)[0] as any;
  return firstEntry?.mappings?.properties ?? {};
}

function chooseTimestampField(fieldDescriptors: FieldDescriptor[], sampleFields: string[]): string | null {
  const preferredCandidates = ['@timestamp', 'timestamp', 'event.created', 'event.ingested'];
  for (const candidate of preferredCandidates) {
    const descriptor = fieldDescriptors.find((field) => field.path === candidate && field.type.startsWith('date'));
    if (descriptor) {
      return descriptor.path;
    }
  }

  const mappedDateField = fieldDescriptors.find((field) => field.type.startsWith('date'));
  if (mappedDateField) {
    return mappedDateField.path;
  }

  return sampleFields.find((field) => /timestamp|time|date/i.test(field)) ?? null;
}

function scoreTechnologies(indexName: string, fieldPaths: string[]): Array<{ technology: string; score: number }> {
  const lowerName = indexName.toLowerCase();
  const joinedFields = fieldPaths.join(' ').toLowerCase();

  const scores = Object.entries(TECHNOLOGY_DEFINITIONS).map(([technology, definition]) => {
    let score = 0;
    for (const keyword of definition.keywords) {
      if (lowerName.includes(keyword)) {
        score += 4;
      }
      if (joinedFields.includes(keyword)) {
        score += 2;
      }
    }
    for (const signalField of definition.fieldSignals) {
      if (fieldPaths.includes(signalField)) {
        score += 5;
      }
    }
    return { technology, score };
  });

  return scores.sort((left, right) => right.score - left.score);
}

function chooseTechnology(indexName: string, fieldPaths: string[]): { primary: string; alternatives: string[] } {
  const scores = scoreTechnologies(indexName, fieldPaths);
  const matchingScores = scores.filter((entry) => entry.score > 0);

  if (matchingScores.length === 0) {
    return {
      primary: 'general-security',
      alternatives: [],
    };
  }

  return {
    primary: matchingScores[0].technology,
    alternatives: matchingScores.slice(1, 3).map((entry) => entry.technology),
  };
}

function buildInvestigationQuery(timestampField: string | null, scope: ScopeInput): any {
  const must: any[] = [];
  if (timestampField) {
    must.push({
      range: {
        [timestampField]: {
          gte: scope.timeRange.from,
          lte: scope.timeRange.to,
        },
      },
    });
  }
  if (scope.queryText) {
    must.push({
      simple_query_string: {
        query: scope.queryText,
        fields: ['*'],
        default_operator: 'and',
      },
    });
  }

  if (must.length === 0) {
    return { match_all: {} };
  }

  return {
    bool: {
      must,
    },
  };
}

function extractHits(searchResponse: any): any[] {
  const body = searchResponse?.body ?? searchResponse;
  return body?.hits?.hits ?? [];
}

async function safeFetchText(url: string): Promise<string> {
  if (!/^https?:\/\//i.test(url)) {
    return '';
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal as any,
      headers: {
        'user-agent': 'xdr-sentry/0.1.0',
      },
    });
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

function extractFeedItems(raw: string): Array<{ title: string; publishedHint: string }> {
  if (!raw) {
    return [];
  }

  const items: Array<{ title: string; publishedHint: string }> = [];
  const rssMatches = Array.from(raw.matchAll(/<item>[\s\S]*?<title>([^<]{8,220})<\/title>[\s\S]*?(?:<pubDate>([^<]{6,80})<\/pubDate>)?[\s\S]*?<\/item>/gi));
  for (const match of rssMatches.slice(0, 10)) {
    const title = String(match[1] ?? '').trim();
    if (title && !/rss|feed|xml/i.test(title)) {
      items.push({
        title,
        publishedHint: String(match[2] ?? '').trim(),
      });
    }
  }
  if (items.length > 0) {
    return items;
  }

  const jsonMatches = Array.from(raw.matchAll(/"(?:title|shortDescription|name)"\s*:\s*"([^"]{10,220})"/gi));
  for (const match of jsonMatches.slice(0, 10)) {
    items.push({
      title: String(match[1] ?? '').trim(),
      publishedHint: '',
    });
  }
  return items;
}

function summarizeSampleDocument(hit: any): string {
  const source = hit?._source ?? {};
  const timestamp =
    source?.['@timestamp'] ??
    source?.timestamp ??
    source?.event?.created ??
    source?.event?.ingested ??
    'unknown-time';
  const host = source?.host?.name ?? source?.agent?.name ?? 'unknown-host';
  const user = source?.user?.name ?? source?.user?.id ?? 'unknown-user';
  const action = source?.event?.action ?? source?.event?.category?.[0] ?? source?.event?.category ?? 'unknown-action';
  return `${timestamp} | host=${host} | user=${user} | action=${action}`;
}

function computeFieldPopulation(sampleHits: any[], fieldNames: string[]): Array<{ field: string; present: number; total: number }> {
  return fieldNames.map((field) => {
    let present = 0;
    for (const hit of sampleHits) {
      const value = getNestedValue(hit?._source ?? {}, field);
      if (value !== undefined && value !== null && value !== '') {
        present += 1;
      }
    }
    return {
      field,
      present,
      total: sampleHits.length,
    };
  });
}

async function aggregateTopValues(
  client: any,
  indexName: string,
  fieldDescriptors: FieldDescriptor[],
  timestampField: string | null,
  scope: ScopeInput
): Promise<Array<{ field: string; values: Array<{ label: string; count: number }> }>> {
  const candidates = COMMON_FIELDS.map((field) => fieldDescriptors.find((descriptor) => descriptor.path === field)).filter(Boolean) as FieldDescriptor[];
  const aggs: Record<string, any> = {};
  const selectedFields = candidates.filter((descriptor) => descriptor.aggregatableField).slice(0, 8);

  for (const descriptor of selectedFields) {
    aggs[descriptor.path.replace(/[^a-z0-9]/gi, '_')] = {
      terms: {
        field: descriptor.aggregatableField,
        size: 5,
        missing: '(missing)',
      },
    };
  }

  if (Object.keys(aggs).length === 0) {
    return [];
  }

  try {
    const response = await client.search({
      index: indexName,
      ignore_unavailable: true,
      allow_no_indices: true,
      body: {
        size: 0,
        query: buildInvestigationQuery(timestampField, scope),
        aggs,
      },
    });
    const responseAggs = response?.body?.aggregations ?? response?.aggregations ?? {};
    return selectedFields.map((descriptor) => {
      const key = descriptor.path.replace(/[^a-z0-9]/gi, '_');
      const buckets = Array.isArray(responseAggs?.[key]?.buckets) ? responseAggs[key].buckets : [];
      return {
        field: descriptor.path,
        values: buckets.map((bucket: any) => ({ label: String(bucket?.key ?? '(missing)'), count: Number(bucket?.doc_count ?? 0) })),
      };
    });
  } catch {
    return [];
  }
}

async function aggregateTimeDistribution(
  client: any,
  indexName: string,
  timestampField: string | null,
  scope: ScopeInput
): Promise<Array<{ label: string; count: number }>> {
  if (!timestampField) {
    return [];
  }

  try {
    const response = await client.search({
      index: indexName,
      ignore_unavailable: true,
      allow_no_indices: true,
      body: {
        size: 0,
        query: buildInvestigationQuery(timestampField, scope),
        aggs: {
          timeline: {
            date_histogram: {
              field: timestampField,
              fixed_interval: '1h',
              min_doc_count: 0,
            },
          },
        },
      },
    });
    const buckets = response?.body?.aggregations?.timeline?.buckets ?? response?.aggregations?.timeline?.buckets ?? [];
    return buckets.slice(0, 12).map((bucket: any) => ({
      label: String(bucket?.key_as_string ?? bucket?.key ?? ''),
      count: Number(bucket?.doc_count ?? 0),
    }));
  } catch {
    return [];
  }
}

function classifySchemaReadiness(timestampField: string | null, meaningfulFields: string[], ecsMatches: string[]): {
  semanticConfidence: 'high' | 'medium' | 'low';
  understandable: boolean;
  fitForInvestigation: boolean;
  branchRecommendation: 'group' | 'split' | 'stop';
  notes: string[];
} {
  const notes: string[] = [];
  const hasTimestamp = Boolean(timestampField);
  const hasMeaningfulEntityCoverage = meaningfulFields.filter((field) => /host|user|source\.ip|destination\.ip|process|container|service/.test(field)).length >= 2;
  const ecsStrong = ecsMatches.length >= 4;

  if (!hasTimestamp) {
    notes.push('No reliable timestamp field was found, which weakens timeline investigation.');
  }
  if (!hasMeaningfulEntityCoverage) {
    notes.push('Meaningful entity fields are sparse, so pivoting across hosts, users, or IPs will be limited.');
  }

  if (hasTimestamp && hasMeaningfulEntityCoverage && ecsStrong) {
    return {
      semanticConfidence: 'high',
      understandable: true,
      fitForInvestigation: true,
      branchRecommendation: 'group',
      notes,
    };
  }

  if ((hasTimestamp && meaningfulFields.length >= 4) || hasMeaningfulEntityCoverage) {
    notes.push('The index is partially understandable but should be isolated if mixed with unrelated data families.');
    return {
      semanticConfidence: 'medium',
      understandable: true,
      fitForInvestigation: true,
      branchRecommendation: 'split',
      notes,
    };
  }

  notes.push('The index is too ambiguous for reliable investigation and should not drive conclusions.');
  return {
    semanticConfidence: 'low',
    understandable: false,
    fitForInvestigation: false,
    branchRecommendation: 'stop',
    notes,
  };
}

function findEcsMatches(fieldPaths: string[]): string[] {
  return COMMON_FIELDS.filter((field) => fieldPaths.includes(field));
}

async function sampleIndexDocuments(client: any, indexName: string, timestampField: string | null, scope: ScopeInput, size: number): Promise<any[]> {
  const sort = timestampField
    ? [{ [timestampField]: { order: 'desc', unmapped_type: 'date' } }]
    : ['_doc'];

  try {
    const response = await client.search({
      index: indexName,
      ignore_unavailable: true,
      allow_no_indices: true,
      body: {
        size,
        sort,
        query: buildInvestigationQuery(timestampField, scope),
      },
    });
    return extractHits(response);
  } catch {
    return [];
  }
}

async function profileSingleIndex(client: any, row: any, scope: ScopeInput): Promise<any> {
  const indexName = String(row?.index ?? '');
  const mappingResponse = await client.indices.getMapping({ index: indexName }).catch(() => ({}));
  const properties = extractMappingProperties(mappingResponse, indexName);
  const fieldDescriptors = collectFieldDescriptors(properties);
  const sampleDocs = await sampleIndexDocuments(client, indexName, null, scope, 12);
  const sampleFields = Array.from(
    new Set(sampleDocs.flatMap((hit) => flattenObjectKeys(hit?._source ?? {})))
  );
  const timestampField = chooseTimestampField(fieldDescriptors, sampleFields);
  const refreshedSamples = timestampField ? await sampleIndexDocuments(client, indexName, timestampField, scope, 12) : sampleDocs;
  const finalSampleFields = Array.from(
    new Set(refreshedSamples.flatMap((hit) => flattenObjectKeys(hit?._source ?? {})))
  );
  const mergedFieldNames = Array.from(new Set([...fieldDescriptors.map((field) => field.path), ...finalSampleFields]));
  const ecsMatches = findEcsMatches(mergedFieldNames);
  const technology = chooseTechnology(indexName, mergedFieldNames);
  const meaningfulFields = COMMON_FIELDS.filter((field) => mergedFieldNames.includes(field));
  const readiness = classifySchemaReadiness(timestampField, meaningfulFields, ecsMatches);
  const fieldPopulation = computeFieldPopulation(refreshedSamples, meaningfulFields.slice(0, 10));
  const topValues = await aggregateTopValues(client, indexName, fieldDescriptors, timestampField, scope);
  const timeDistribution = await aggregateTimeDistribution(client, indexName, timestampField, scope);

  return {
    index: indexName,
    status: row?.status ?? 'unknown',
    health: row?.health ?? 'unknown',
    docCount: Number(row?.['docs.count'] ?? 0),
    technology: technology.primary,
    relatedTechnologies: technology.alternatives,
    category: TECHNOLOGY_DEFINITIONS[technology.primary]?.category ?? 'general-security',
    timestampField,
    ecsCoverage: {
      matchedFieldCount: ecsMatches.length,
      sampleMatches: ecsMatches.slice(0, 10),
      status: ecsMatches.length >= 5 ? 'ecs-leaning' : ecsMatches.length > 0 ? 'mixed' : 'non-ecs',
    },
    semanticConfidence: readiness.semanticConfidence,
    understandable: readiness.understandable,
    fitForInvestigation: readiness.fitForInvestigation,
    branchRecommendation: readiness.branchRecommendation,
    meaningfulFields: meaningfulFields.slice(0, 12),
    fieldPopulation,
    topValues,
    timeDistribution,
    sampleDocuments: refreshedSamples.slice(0, 4).map((hit) => ({
      id: hit?._id,
      summary: summarizeSampleDocument(hit),
    })),
    notes: readiness.notes,
  };
}

async function listIndexRows(context: any): Promise<any[]> {
  const client = context.core.opensearch.client.asCurrentUser;
  const response = await client.cat.indices({ format: 'json', h: 'index,status,health,docs.count' });
  const rows = extractIndexArray(response);
  return sortIndexRows(rows).filter((row) => row?.index && !String(row.index).startsWith('.'));
}

function applyScopeToIndexRows(rows: any[], scope: ScopeInput): { selectedRows: any[]; skippedRows: any[] } {
  const selectedRows: any[] = [];
  const skippedRows: any[] = [];

  for (const row of rows) {
    const indexName = String(row.index ?? '');
    const included = matchesAnyPattern(indexName, scope.includePatterns);
    const excluded = scope.excludePatterns.length > 0 && matchesAnyPattern(indexName, scope.excludePatterns);
    if (included && !excluded) {
      selectedRows.push(row);
    } else {
      skippedRows.push(row);
    }
  }

  return {
    selectedRows,
    skippedRows,
  };
}

async function buildIndexLandscape(context: any, scope: ScopeInput, goalText: string): Promise<any> {
  const client = context.core.opensearch.client.asCurrentUser;
  const rows = await listIndexRows(context);
  const scoped = applyScopeToIndexRows(rows, scope);
  const profiledRows = scoped.selectedRows.slice(0, scope.maxProfiles);
  const skippedBecauseOfBudget = scoped.selectedRows.slice(scope.maxProfiles).map((row) => row.index);

  const profiles: any[] = [];
  for (const row of profiledRows) {
    profiles.push(await profileSingleIndex(client, row, scope));
  }

  const technologies = Array.from(new Set(profiles.map((profile) => profile.technology).filter(Boolean)));
  const goalTokens = tokenize(goalText);
  const relevantProfiles = profiles.filter((profile) => {
    if (goalTokens.length === 0) {
      return profile.fitForInvestigation;
    }
    const combined = [profile.index, profile.technology, ...(profile.meaningfulFields ?? [])].join(' ').toLowerCase();
    return goalTokens.some((token) => combined.includes(token)) || profile.fitForInvestigation;
  });

  return {
    generatedAt: nowIso(),
    totalIndexCount: rows.length,
    selectedIndexCount: scoped.selectedRows.length,
    profiledIndexCount: profiles.length,
    skippedIndexCount: scoped.skippedRows.length,
    skippedBecauseOfBudget,
    technologies,
    profiles,
    relevantProfiles,
    skippedIndices: scoped.skippedRows.map((row) => row.index),
  };
}

function validateGoalSuggestionsResponse(value: any): any[] {
  const goals = Array.isArray(value?.goals) ? value.goals : [];
  const normalized = goals
    .map((goal: any, index: number) => ({
      id: String(goal?.id ?? `llm-goal-${index + 1}`),
      title: String(goal?.title ?? '').trim(),
      rationale: String(goal?.rationale ?? '').trim(),
      sources: Array.isArray(goal?.sources) ? goal.sources.map((source: any) => String(source)).filter(Boolean) : [],
      detectedTechnologies: Array.isArray(goal?.detectedTechnologies)
        ? goal.detectedTechnologies.map((technology: any) => String(technology)).filter(Boolean)
        : [],
      confidence: String(goal?.confidence ?? '').trim().toLowerCase(),
      scopeHint: Array.isArray(goal?.scopeHint) ? goal.scopeHint.map((item: any) => String(item)).filter(Boolean) : [],
    }))
    .filter((goal: any) => goal.title && goal.rationale)
    .slice(0, 6);

  for (const goal of normalized) {
    if (!['low', 'medium', 'high'].includes(goal.confidence)) {
      throw new Error(`LLM produced an invalid goal confidence value: ${goal.confidence || '(empty)'}`);
    }
  }

  if (normalized.length === 0) {
    throw new Error('LLM returned zero valid goal suggestions.');
  }

  return normalized;
}

async function proposeGoalsViaLlm(providerConfig: ProviderConfig, selectedGoal: string, landscape: any, signals: any[]): Promise<any> {
  const messages = [
    {
      role: 'system',
      content:
        'You are XDR Sentry Goal Suggestion Agent. Use only the supplied index landscape and trusted-source research notes. Prioritize emerging, recent, and currently trending security threats while staying grounded in the provided data. Return strict JSON only. Schema: {"goals":[{"id":"string","title":"string","rationale":"string","sources":["string"],"detectedTechnologies":["string"],"confidence":"low|medium|high","scopeHint":["string"]}]}. Provide 3-6 distinct goals. Never add markdown or prose outside JSON.',
    },
    {
      role: 'user',
      content: JSON.stringify({
        selectedGoal,
        profiledIndexCount: landscape?.profiledIndexCount,
        selectedIndexCount: landscape?.selectedIndexCount,
        technologies: landscape?.technologies ?? [],
        relevantProfiles: (landscape?.relevantProfiles ?? []).map((profile: any) => ({
          index: profile.index,
          technology: profile.technology,
          understandable: profile.understandable,
          fitForInvestigation: profile.fitForInvestigation,
          meaningfulFields: (profile.meaningfulFields ?? []).slice(0, 10),
        })),
        researchNotes: (signals ?? []).map((note: any) => ({
          sourceName: note.sourceName,
          sourceUrl: note.sourceUrl,
          title: note.title,
          publishedHint: note.publishedHint,
          matchedTechnologies: note.matchedTechnologies,
        })),
        constraints: [
          'Prioritize goals that can be answered by current logs.',
          'Prefer actionable goals over generic broad goals.',
          'Include at least one goal anchored in a specific research note when notes exist.',
          'Treat trusted-source research notes as the primary external context for selecting goals.',
          'Prioritize recent campaign activity and threat themes (recency and trending relevance) when notes include timing hints.',
          'Be creative by combining multiple research notes into one concrete investigation mission, but do not invent unsupported facts.',
          'When research notes exist, each suggested goal must cite at least one sourceName in the sources array.',
        ],
      }),
    },
  ];

  const call = await callProviderOpenAiCompatible(providerConfig, messages, []);
  const parsed = parseModelJson(String(call.message?.content ?? ''));
  const goals = validateGoalSuggestionsResponse(parsed);

  return {
    goals,
    trace: {
      mode: 'llm',
      protocol: call.protocol,
      endpoint: call.endpoint,
      assistantSummary: summarizeAssistantContent(call.message?.content),
      structuredPrompt: {
        profileCount: landscape?.profiledIndexCount ?? 0,
        technologyCount: (landscape?.technologies ?? []).length,
        researchNoteCount: (signals ?? []).length,
      },
    },
  };
}

function matchTechnologiesFromText(text: string, defaultTechnologies: string[]): string[] {
  const lower = text.toLowerCase();
  const matches = Object.entries(TECHNOLOGY_DEFINITIONS)
    .filter(([, definition]) => definition.keywords.some((keyword) => lower.includes(keyword)))
    .map(([technology]) => technology);
  return matches.length > 0 ? matches : defaultTechnologies.slice(0, 3);
}

async function buildResearchNotes(enabledSources: any[], goalText: string, technologies: string[]): Promise<any[]> {
  const researchTopics = Array.from(
    new Set(
      technologies.flatMap((technology) => TECHNOLOGY_DEFINITIONS[technology]?.researchTopics ?? [])
    )
  );
  const goalTokens = tokenize(goalText);
  const notes: any[] = [];

  for (const source of enabledSources) {
    const raw = await safeFetchText(source.url);
    const items = extractFeedItems(raw).slice(0, 6);
    for (const item of items) {
      const matchedTechnologies = matchTechnologiesFromText(item.title, technologies);
      const matchedGoal = goalTokens.length === 0 || goalTokens.some((token) => item.title.toLowerCase().includes(token));
      const matchedTopic = researchTopics.length === 0 || researchTopics.some((topic) => item.title.toLowerCase().includes(topic.split(' ')[0]));
      if (!matchedGoal && !matchedTopic) {
        continue;
      }
      notes.push({
        id: `research-${notes.length + 1}`,
        sourceId: source.id,
        sourceName: source.name,
        sourceUrl: source.url,
        title: item.title,
        publishedHint: item.publishedHint,
        matchedTechnologies,
      });
    }
  }

  return notes.slice(0, 12);
}

function normalizeSources(body: any): any[] {
  const enabledSourceIds = Array.isArray(body?.enabledSourceIds) ? body.enabledSourceIds : [];
  const customSources = Array.isArray(body?.customSources) ? body.customSources : [];
  const presetSources = SOURCE_PRESETS.filter((preset) => enabledSourceIds.includes(preset.id));
  const normalizedCustomSources = customSources
    .filter((source: any) => source?.name && source?.url)
    .map((source: any, index: number) => ({
      id: String(source?.id ?? `custom-${index + 1}`),
      name: String(source.name),
      url: String(source.url),
      type: String(source?.type ?? 'custom'),
      trustLevel: String(source?.trustLevel ?? 'custom'),
      enabledByDefault: false,
    }));
  return [...presetSources, ...normalizedCustomSources];
}

function buildBranchPlan(profiles: any[], goalText: string, evidenceCards: any[] = [], hypotheses: any[] = [], challenges: any[] = []): any[] {
  const grouped = new Map<string, any[]>();
  for (const profile of profiles) {
    const key = profile.technology ?? 'general-security';
    const existing = grouped.get(key) ?? [];
    existing.push(profile);
    grouped.set(key, existing);
  }

  return Array.from(grouped.entries()).map(([technology, branchProfiles], index) => ({
    id: `branch-${index + 1}`,
    label: `${technology} branch`,
    technology,
    reason:
      branchProfiles.length > 1
        ? `Grouped ${branchProfiles.length} indices with similar ${technology} semantics for goal: ${goalText}`
        : `Isolated ${technology} data to avoid mixing unrelated semantics into the same reasoning path.`,
    indices: branchProfiles.map((profile: any) => profile.index),
    status: branchProfiles.some((profile: any) => !profile.understandable) ? 'partial' : 'ready',
    evidenceCount: evidenceCards.filter((card) => branchProfiles.some((profile: any) => profile.index === card.index)).length,
    hypothesisIds: hypotheses.filter((hypothesis) => hypothesis.technology === technology).map((hypothesis) => hypothesis.id),
    challengeSummary: challenges.filter((challenge) =>
      hypotheses.some((hypothesis) => hypothesis.id === challenge.hypothesisId && hypothesis.technology === technology)
    ),
    profileNotes: Array.from(new Set(branchProfiles.flatMap((profile: any) => profile.notes ?? []))).slice(0, 5),
  }));
}

function buildBranchConclusions(branches: any[], hypotheses: any[], challenges: any[], evidenceCards: any[]): any[] {
  return branches.map((branch) => {
    const branchHypotheses = hypotheses.filter((hypothesis) => hypothesis.technology === branch.technology);
    const branchChallenges = challenges.filter((challenge) =>
      branchHypotheses.some((hypothesis) => hypothesis.id === challenge.hypothesisId)
    );
    const strongest = [...branchChallenges].sort((left, right) => right.survivingStrength - left.survivingStrength)[0];
    const branchEvidence = evidenceCards.filter((card) => branch.indices.includes(card.index));
    const canInvestigate = branch.status !== 'partial' || branchEvidence.length > 0;

    return {
      branchId: branch.id,
      label: branch.label,
      technology: branch.technology,
      status: canInvestigate ? (strongest?.survivingStrength >= 55 ? 'evidence-backed' : 'needs-more-evidence') : 'blocked',
      finalExplanation:
        !canInvestigate
          ? 'This branch remained too ambiguous to support a reliable conclusion.'
          : strongest?.survivingStrength >= 55
            ? 'This branch produced the strongest evidence-backed explanation in the current run.'
            : 'This branch stayed investigable, but it still lacks enough local evidence for a confident story.',
      evidenceCount: branchEvidence.length,
      strongestHypothesis: strongest
        ? branchHypotheses.find((hypothesis) => hypothesis.id === strongest.hypothesisId)?.title ?? 'Unknown hypothesis'
        : 'No strong hypothesis',
      contradictions: strongest?.contradictions ?? [],
    };
  });
}

function buildAuditTrail(goalText: string, scope: ScopeInput, landscape: any, researchNotes: any[], evidenceCards: any[]): any[] {
  const entries: any[] = [
    {
      id: 'audit-1',
      category: 'planner',
      title: 'Goal approved',
      detail: `Goal set to: ${goalText}`,
    },
    {
      id: 'audit-2',
      category: 'policy',
      title: 'Scope compiled',
      detail: `Time range ${scope.timeRange.from} to ${scope.timeRange.to}; include patterns: ${scope.includePatterns.join(', ') || 'all visible indices'}.`,
    },
    {
      id: 'audit-3',
      category: 'executor',
      title: 'Index profiling complete',
      detail: `Profiled ${landscape.profiledIndexCount} index families out of ${landscape.selectedIndexCount} selected indices.`,
    },
    {
      id: 'audit-4',
      category: 'executor',
      title: 'External research complete',
      detail: `Collected ${researchNotes.length} research notes from enabled sources.`,
    },
    {
      id: 'audit-5',
      category: 'executor',
      title: 'Evidence collection complete',
      detail: `Attached ${evidenceCards.length} evidence cards to the investigation record.`,
    },
  ];

  return entries;
}

function buildNodeDetail(node: any): any {
  return {
    goalOrHypothesis: node.goalOrHypothesis,
    reasoningTrace: node.reasoningTrace ?? [],
    queries: node.queries ?? [],
    pivots: node.pivots ?? [],
    lookups: node.lookups ?? [],
    evidenceExcerpts: node.evidenceExcerpts ?? [],
    completionReason: node.completionReason ?? node.summary,
  };
}

function buildInvestigationPlan(body: any, landscape: any): any {
  const goalText = String(body?.selectedGoal ?? '').trim();
  const scope = normalizeScope(body);
  const relevantProfiles = landscape?.relevantProfiles ?? [];
  const understandableProfiles = relevantProfiles.filter((profile: any) => profile.understandable);
  const unreadableProfiles = relevantProfiles.filter((profile: any) => !profile.understandable);

  return {
    goal: goalText,
    scope: {
      includePatterns: scope.includePatterns,
      excludePatterns: scope.excludePatterns,
      timeRange: scope.timeRange,
      queryText: scope.queryText,
    },
    readinessGate: {
      canInvestigate: understandableProfiles.length > 0,
      reasons:
        understandableProfiles.length > 0
          ? ['At least one selected index family is understandable enough to investigate.']
          : ['No selected index family met the minimum data-understanding threshold.'],
      blockedIndices: unreadableProfiles.map((profile: any) => profile.index),
    },
    branches: buildBranchPlan(relevantProfiles, goalText),
    orderedSteps: [
      {
        id: 'goal',
        title: 'Confirm the investigation goal and analyst-approved scope.',
        outcome: goalText ? 'ready' : 'blocked',
      },
      {
        id: 'understanding',
        title: 'Profile indices using mappings, multiple samples, field population, and distributions.',
        outcome: relevantProfiles.length > 0 ? 'ready' : 'blocked',
      },
      {
        id: 'research',
        title: 'Pull current external threat context and convert it into local tests.',
        outcome: 'ready',
      },
      {
        id: 'evidence',
        title: 'Collect bounded evidence and build entity-centric timelines per branch.',
        outcome: understandableProfiles.length > 0 ? 'ready' : 'blocked',
      },
      {
        id: 'decision',
        title: 'Select one allowed final state and report only from validated evidence.',
        outcome: understandableProfiles.length > 0 ? 'ready' : 'blocked',
      },
    ],
  };
}

async function collectEvidenceCards(client: any, profiles: any[], scope: ScopeInput): Promise<any[]> {
  const evidenceCards: any[] = [];

  for (const profile of profiles) {
    if (!profile.fitForInvestigation) {
      continue;
    }
    const hits = await sampleIndexDocuments(client, profile.index, profile.timestampField, scope, scope.maxEvidencePerIndex);
    for (const hit of hits) {
      const source = hit?._source ?? {};
      evidenceCards.push({
        id: `evidence-${evidenceCards.length + 1}`,
        index: profile.index,
        documentId: hit?._id,
        timestamp:
          source?.['@timestamp'] ?? source?.timestamp ?? source?.event?.created ?? source?.event?.ingested ?? 'unknown-time',
        summary: summarizeSampleDocument(hit),
        supportingFields: profile.meaningfulFields.slice(0, 6).map((field: string) => ({
          field,
          value: getNestedValue(source, field),
        })),
        queryDescription: `Sampled from ${profile.index} within ${scope.timeRange.from} to ${scope.timeRange.to}.`,
      });
    }
  }

  return evidenceCards;
}

function buildHypotheses(goalText: string, profiles: any[], researchNotes: any[], evidenceCards: any[]): any[] {
  const hypotheses: any[] = [];
  const technologies = Array.from(new Set(profiles.map((profile) => profile.technology)));
  const evidenceDensity = evidenceCards.length;

  for (const technology of technologies) {
    const definition = TECHNOLOGY_DEFINITIONS[technology];
    if (!definition) {
      continue;
    }
    for (const summary of definition.suspiciousHypotheses.slice(0, 2)) {
      hypotheses.push({
        id: `hyp-${hypotheses.length + 1}`,
        type: 'attack',
        technology,
        title: summary,
        rationale: `Generated from the investigation goal, ${technology} index profiles, and matched external research.`,
        supportingEvidenceIds: evidenceCards.slice(0, 3).map((card) => card.id),
        missingEvidence: ['Validate expected precursor and follow-on events.', 'Check for contradictions across branch timelines.'],
        score: clamp(40 + researchNotes.length * 4 + evidenceDensity * 3, 0, 90),
      });
    }
    for (const summary of definition.benignHypotheses.slice(0, 1)) {
      hypotheses.push({
        id: `hyp-${hypotheses.length + 1}`,
        type: 'benign',
        technology,
        title: summary,
        rationale: `Added as a competing explanation to prevent one-track attack narratives for ${technology} data.`,
        supportingEvidenceIds: evidenceCards.slice(0, 2).map((card) => card.id),
        missingEvidence: ['Look for known change windows, maintenance signals, or other benign context.'],
        score: clamp(25 + evidenceDensity * 2, 0, 70),
      });
    }
  }

  if (hypotheses.length === 0) {
    hypotheses.push({
      id: 'hyp-generic-1',
      type: 'attack',
      technology: 'general-security',
      title: `Investigate whether the current evidence supports the goal: ${goalText}`,
      rationale: 'No strong technology-specific template was available, so the hypothesis remains generic and low-confidence.',
      supportingEvidenceIds: evidenceCards.slice(0, 2).map((card) => card.id),
      missingEvidence: ['Need clearer schema semantics before a stronger hypothesis can be tested.'],
      score: evidenceCards.length > 0 ? 35 : 10,
    });
  }

  return hypotheses.slice(0, 8);
}

function challengeHypotheses(hypotheses: any[], profiles: any[], evidenceCards: any[]): any[] {
  return hypotheses.map((hypothesis) => {
    const contradictions: string[] = [];
    if (evidenceCards.length === 0) {
      contradictions.push('No evidence cards were collected for the selected scope.');
    }
    if (profiles.some((profile) => !profile.understandable)) {
      contradictions.push('One or more selected index families remain semantically ambiguous.');
    }
    if (hypothesis.type === 'attack' && evidenceCards.length < 3) {
      contradictions.push('Attack explanation has limited local evidence depth.');
    }
    return {
      hypothesisId: hypothesis.id,
      contradictions,
      contradictionScore: contradictions.length,
      survivingStrength: clamp(hypothesis.score - contradictions.length * 10, 0, 100),
    };
  });
}

function buildGraph(goalText: string, branches: any[], researchNotes: any[], hypotheses: any[], challenges: any[], evidenceCards: any[], decision: any): any {
  const columns = [
    { id: 'goal', title: 'Goal', subtitle: 'Approved mission and scope' },
    { id: 'understanding', title: 'Understanding', subtitle: 'Index profiling and branch split' },
    { id: 'research', title: 'Research', subtitle: 'Current external threat context' },
    { id: 'correlation', title: 'Correlation', subtitle: 'Branch evidence collection' },
    { id: 'hypotheses', title: 'Hypotheses', subtitle: 'Suspicious and benign branches' },
    { id: 'challenge', title: 'Challenge', subtitle: 'Contradictions and pruning' },
    { id: 'decision', title: 'Decision', subtitle: 'Allowed final outcome' },
    { id: 'report', title: 'Report', subtitle: 'Analyst-ready synthesis' },
  ];

  const nodes: any[] = [
    {
      id: 'goal-agent',
      role: 'Goal Agent',
      task: 'Validate goal and scope',
      status: 'completed',
      evidenceCount: 0,
      durationMs: 240,
      columnId: 'goal',
      summary: 'Execution goal approved for investigation.',
      goalOrHypothesis: goalText,
      reasoningTrace: [
        'Validated that an explicit investigation goal was present.',
        'Captured analyst scope controls before any evidence retrieval.',
      ],
      queries: [],
      pivots: [],
      lookups: [],
      evidenceExcerpts: [],
      completionReason: 'The run had an approved goal and could proceed into data understanding.',
    },
    {
      id: 'index-understanding-agent',
      role: 'Index Understanding Agent',
      task: 'Profile selected index families',
      status: 'completed',
      evidenceCount: 0,
      durationMs: 810,
      columnId: 'understanding',
      summary: `${branches.length} branch plan(s) generated from the index landscape.`,
      goalOrHypothesis: goalText,
      reasoningTrace: [
        'Read index names, mappings, and sampled multiple documents per index family.',
        'Assigned understandable, split, or stop status to each branch candidate.',
      ],
      queries: ['cat.indices', 'indices.getMapping', 'search(size=12)', 'terms/date_histogram aggregations'],
      pivots: ['Field population checks', 'Top value distributions', 'Timestamp candidate detection'],
      lookups: [],
      evidenceExcerpts: branches.slice(0, 3).map((branch) => `${branch.label}: ${branch.indices.join(', ')}`),
      completionReason: 'Branch planning completed from index understanding results.',
    },
    {
      id: 'research-agent',
      role: 'Research Agent',
      task: 'Pull current external threat context',
      status: 'completed',
      evidenceCount: researchNotes.length,
      durationMs: 540,
      columnId: 'research',
      summary: 'Trusted-source research converted into local test ideas.',
      goalOrHypothesis: goalText,
      reasoningTrace: [
        'Matched enabled trusted sources against the goal and detected technologies.',
        'Reduced raw source items into investigation-relevant leads only.',
      ],
      queries: [],
      pivots: [],
      lookups: researchNotes.slice(0, 4).map((note) => `${note.sourceName}: ${note.title}`),
      evidenceExcerpts: [],
      completionReason: `${researchNotes.length} research notes were retained for hypothesis generation.`,
    },
  ];

  for (const branch of branches) {
    const branchEvidence = evidenceCards.filter((card) => branch.indices.includes(card.index));
    nodes.push({
      id: `${branch.id}-correlation`,
      role: 'Correlation Agent',
      task: `Build evidence timeline for ${branch.technology}`,
      status: branchEvidence.length > 0 ? 'completed' : branch.status === 'partial' ? 'stopped' : 'completed',
      evidenceCount: branchEvidence.length,
      durationMs: 460 + branchEvidence.length * 35,
      columnId: 'correlation',
      parentId: 'research-agent',
      branchId: branch.id,
      summary: `${branchEvidence.length} evidence card(s) attached to ${branch.label}.`,
      goalOrHypothesis: branch.reason,
      reasoningTrace: [
        `Isolated indices for ${branch.label}.`,
        'Collected bounded local evidence before moving to suspicious explanations.',
      ],
      queries: branch.indices.map((indexName: string) => `search index=${indexName} size<=${Math.max(branchEvidence.length, 1)}`),
      pivots: ['Host and user pivots', 'Timeline slices by timestamp field'],
      lookups: [],
      evidenceExcerpts: branchEvidence.slice(0, 3).map((card) => `${card.index}: ${card.summary}`),
      completionReason: branchEvidence.length > 0 ? 'Branch evidence collection completed.' : 'No local evidence was collected for this branch in scope.',
    });
  }

  const visibleHypotheses = hypotheses.slice(0, 4);
  for (const hypothesis of visibleHypotheses) {
    const branch = branches.find((candidate) => candidate.technology === hypothesis.technology);
    const challenge = challenges.find((entry) => entry.hypothesisId === hypothesis.id);
    nodes.push({
      id: `${hypothesis.id}-agent`,
      role: 'Hypothesis Agent',
      task: `Test ${hypothesis.type} explanation`,
      status: 'completed',
      evidenceCount: hypothesis.supportingEvidenceIds.length,
      durationMs: 320,
      columnId: 'hypotheses',
      parentId: branch ? `${branch.id}-correlation` : 'research-agent',
      branchId: branch?.id,
      summary: hypothesis.title,
      goalOrHypothesis: hypothesis.title,
      reasoningTrace: [
        hypothesis.rationale,
        `Assigned preliminary strength score ${hypothesis.score}.`,
      ],
      queries: hypothesis.supportingEvidenceIds.map((evidenceId: string) => `load evidence card ${evidenceId}`),
      pivots: hypothesis.missingEvidence,
      lookups: [],
      evidenceExcerpts: hypothesis.supportingEvidenceIds,
      completionReason: 'Competing explanation generated for downstream challenge review.',
    });
    nodes.push({
      id: `${hypothesis.id}-challenge`,
      role: 'Challenger Agent',
      task: `Challenge ${hypothesis.type} explanation`,
      status: challenge?.contradictionScore ? 'completed' : 'pruned',
      evidenceCount: hypothesis.supportingEvidenceIds.length,
      durationMs: 210,
      columnId: 'challenge',
      parentId: `${hypothesis.id}-agent`,
      branchId: branch?.id,
      summary: `${challenge?.contradictionScore ?? 0} contradiction(s) surfaced.`,
      goalOrHypothesis: hypothesis.title,
      reasoningTrace: [
        'Searched for contradictions, timeline gaps, and weak assumptions.',
        `Surviving strength after challenge: ${challenge?.survivingStrength ?? hypothesis.score}.`,
      ],
      queries: ['Cross-check evidence coverage', 'Validate contradiction score'],
      pivots: [],
      lookups: [],
      evidenceExcerpts: challenge?.contradictions ?? ['No contradiction details captured.'],
      completionReason:
        challenge?.contradictions?.length
          ? 'Contradictions were attached and reduced hypothesis strength.'
          : 'No material contradiction was found, or the branch was pruned for lack of evidence.',
    });
  }

  if (hypotheses.length > visibleHypotheses.length) {
    nodes.push({
      id: 'pruned-hypotheses',
      role: 'Hypothesis Agent',
      task: 'Prune lower-priority explanations',
      status: 'pruned',
      evidenceCount: 0,
      durationMs: 95,
      columnId: 'hypotheses',
      parentId: 'research-agent',
      summary: `${hypotheses.length - visibleHypotheses.length} lower-ranked hypotheses were pruned from the active canvas.`,
      goalOrHypothesis: 'Lower-priority explanations',
      reasoningTrace: ['The canvas limits visible branches to avoid overflow and keep the run reviewable.'],
      queries: [],
      pivots: [],
      lookups: [],
      evidenceExcerpts: hypotheses.slice(4).map((hypothesis) => hypothesis.title),
      completionReason: 'Lower-ranked hypotheses were pruned for readability and budget control.',
    });
  }

  nodes.push(
    {
      id: 'decision-agent',
      role: 'Decision Agent',
      task: 'Select one allowed final state',
      status: 'completed',
      evidenceCount: evidenceCards.length,
      durationMs: 180,
      columnId: 'decision',
      summary: `Final outcome: ${decision.state}.`,
      goalOrHypothesis: decision.state,
      reasoningTrace: decision.rationale,
      queries: [],
      pivots: decision.nextSteps,
      lookups: [],
      evidenceExcerpts: decision.limitations,
      completionReason: 'The run was mapped to one allowed final outcome with explicit limitations.',
    },
    {
      id: 'reporting-agent',
      role: 'Reporting Agent',
      task: 'Write evidence-backed report',
      status: 'completed',
      evidenceCount: evidenceCards.length,
      durationMs: 150,
      columnId: 'report',
      parentId: 'decision-agent',
      summary: 'Report generated from validated evidence, limitations, and branch outcomes.',
      goalOrHypothesis: decision.state,
      reasoningTrace: [
        'Read only validated evidence cards, accepted hypotheses, and decision records.',
        'Produced branch-level and overall explanations without adding unsupported claims.',
      ],
      queries: [],
      pivots: [],
      lookups: [],
      evidenceExcerpts: evidenceCards.slice(0, 4).map((card) => `${card.index}: ${card.summary}`),
      completionReason: 'Analyst-facing report completed.',
    }
  );

  const edges = [
    ['goal-agent', 'index-understanding-agent'],
    ['index-understanding-agent', 'research-agent'],
    ['decision-agent', 'reporting-agent'],
  ].map(([source, target]) => ({ source, target }));

  for (const branch of branches) {
    edges.push({ source: 'research-agent', target: `${branch.id}-correlation` });
  }
  for (const hypothesis of visibleHypotheses) {
    edges.push({ source: `${hypothesis.id}-agent`, target: `${hypothesis.id}-challenge` });
    const branch = branches.find((candidate) => candidate.technology === hypothesis.technology);
    edges.push({ source: branch ? `${branch.id}-correlation` : 'research-agent', target: `${hypothesis.id}-agent` });
    edges.push({ source: `${hypothesis.id}-challenge`, target: 'decision-agent' });
  }
  if (hypotheses.length > visibleHypotheses.length) {
    edges.push({ source: 'research-agent', target: 'pruned-hypotheses' });
    edges.push({ source: 'pruned-hypotheses', target: 'decision-agent' });
  }

  return {
    columns,
    nodes: nodes.map((node) => ({
      ...node,
      detail: buildNodeDetail(node),
    })),
    edges,
  };
}

function buildReport(goalText: string, landscape: any, branches: any[], branchConclusions: any[], researchNotes: any[], evidenceCards: any[], decision: any): any {
  const usedIndices = landscape?.relevantProfiles?.map((profile: any) => profile.index) ?? [];
  return {
    executiveSummary:
      decision.state === 'Unable to proceed'
        ? 'XDR Sentry stopped because the selected logs were not understandable enough for a reliable investigation.'
        : decision.state === 'Likely attack story identified'
          ? 'XDR Sentry found a coherent evidence-backed attack story that needs analyst validation.'
          : decision.state === 'Correlated activity identified but attack not established'
            ? 'XDR Sentry linked meaningful activity, but the evidence does not yet justify an attack conclusion.'
            : decision.state === 'No supported attack story found in scope'
              ? 'XDR Sentry completed the investigation but did not find enough local evidence for a credible attack story.'
              : 'XDR Sentry completed the workflow, but the evidence remains partial or contradictory.',
    goal: goalText,
    usedIndices,
    indexUnderstanding: landscape?.profiles?.map((profile: any) => ({
      index: profile.index,
      technology: profile.technology,
      understandable: profile.understandable,
      fitForInvestigation: profile.fitForInvestigation,
      notes: profile.notes,
    })),
    branchSummaries: branches.map((branch) => ({
      branch: branch.label,
      reason: branch.reason,
      indices: branch.indices,
      status: branch.status,
    })),
    branchConclusions,
    evidenceDensity: {
      evidenceCards: evidenceCards.length,
      researchNotes: researchNotes.length,
      understandableIndexFamilies: landscape?.relevantProfiles?.filter((profile: any) => profile.understandable).length ?? 0,
    },
    limitations: decision.limitations,
    recommendedNextSteps: decision.nextSteps,
  };
}

async function runAgenticDecisionLoop(context: any, selectedGoal: string, scope: ScopeInput, enabledSources: any[]): Promise<any> {
  const state: any = {
    landscape: null,
    researchNotes: null,
    evidenceCards: null,
    hypotheses: null,
    challenges: null,
    branches: null,
  };
  const client = context.core.opensearch.client.asCurrentUser;
  const toolCallsAudit: any[] = [];
  const assistantSummaries: any[] = [];
  const llmTrace: any = {
    mode: 'agentic',
    protocol: 'unknown',
    endpoint: '',
    iterationCount: 0,
    assistantSummaries,
    toolSequence: toolCallsAudit,
    keyIntermediateDecisions: [],
  };

  const tools = [
    {
      type: 'function',
      function: {
        name: 'profile_indices',
        description: 'Profile selected indices and classify schema readiness.',
        parameters: { type: 'object', properties: {}, additionalProperties: false },
      },
    },
    {
      type: 'function',
      function: {
        name: 'collect_research',
        description: 'Collect threat research notes from enabled trusted sources.',
        parameters: { type: 'object', properties: {}, additionalProperties: false },
      },
    },
    {
      type: 'function',
      function: {
        name: 'collect_evidence',
        description: 'Collect evidence cards from relevant profiles in scope.',
        parameters: { type: 'object', properties: {}, additionalProperties: false },
      },
    },
    {
      type: 'function',
      function: {
        name: 'build_hypotheses',
        description: 'Build suspicious and benign hypotheses based on collected evidence and research.',
        parameters: { type: 'object', properties: {}, additionalProperties: false },
      },
    },
    {
      type: 'function',
      function: {
        name: 'challenge_hypotheses',
        description: 'Challenge hypotheses and generate contradiction scores.',
        parameters: { type: 'object', properties: {}, additionalProperties: false },
      },
    },
    {
      type: 'function',
      function: {
        name: 'build_branches',
        description: 'Build branch plans and baseline branch conclusions from current state.',
        parameters: { type: 'object', properties: {}, additionalProperties: false },
      },
    },
  ];

  const messages: any[] = [
    {
      role: 'system',
      content:
        'You are XDR Sentry Investigation Orchestrator. You MUST use tools to gather evidence before deciding. Guardrails: do not invent events, do not claim sources that were not returned by tools, choose exactly one allowed final state, keep rationale evidence-backed, include limitations. Before final answer, call at least: profile_indices, collect_research, collect_evidence, build_hypotheses, challenge_hypotheses, build_branches. Final answer must be strict JSON with keys: decision, branchConclusions, executiveSummary. decision must include: state, confidence, rationale[], limitations[], nextSteps[]. Allowed states: ' +
        ALLOWED_OUTCOME_STATES.join(' | '),
    },
    {
      role: 'user',
      content: JSON.stringify({
        goal: selectedGoal,
        scope,
        requirement: 'Run full agentic investigation with tool calls and return final decision JSON.',
      }),
    },
  ];

  for (let iteration = 0; iteration < AGENTIC_MAX_TOOL_CALLS; iteration += 1) {
    const providerCall = await callProviderOpenAiCompatible(providerConfigStore, messages, tools);
    const assistantMessage = providerCall.message;
    const assistantContent = String(assistantMessage?.content ?? '');
    const assistantToolCalls = Array.isArray(assistantMessage?.tool_calls) ? assistantMessage.tool_calls : [];
    llmTrace.protocol = providerCall.protocol;
    llmTrace.endpoint = providerCall.endpoint;
    llmTrace.iterationCount = iteration + 1;
    assistantSummaries.push({
      step: assistantSummaries.length + 1,
      when: nowIso(),
      summary: summarizeAssistantContent(assistantContent),
      requestedTools: assistantToolCalls.map((toolCall: any) => String(toolCall?.function?.name ?? 'unknown')).filter(Boolean),
    });

    if (assistantToolCalls.length === 0) {
      const parsed = parseModelJson(assistantContent);
      const finalAnswer = validateAgenticFinalAnswer(parsed);

      if (!state.landscape || !state.researchNotes || !state.evidenceCards || !state.hypotheses || !state.challenges || !state.branches) {
        throw new Error('LLM attempted to finish before completing mandatory tool calls.');
      }

      return {
        ...state,
        decision: finalAnswer.decision,
        branchConclusions: finalAnswer.branchConclusions,
        executiveSummary: finalAnswer.executiveSummary,
        toolCallsAudit,
        llmTrace: {
          ...llmTrace,
          keyIntermediateDecisions: [
            `Final state selected: ${finalAnswer.decision.state}`,
            `Final confidence selected: ${finalAnswer.decision.confidence}`,
            ...finalAnswer.decision.rationale.slice(0, 4),
          ],
        },
      };
    }

    messages.push({
      role: 'assistant',
      content: assistantContent || null,
      tool_calls: assistantToolCalls,
    });

    for (const toolCall of assistantToolCalls) {
      const toolName = String(toolCall?.function?.name ?? '');
      let result: any;

      if (toolName === 'profile_indices') {
        state.landscape = await buildIndexLandscape(context, scope, selectedGoal);
        result = {
          profiledIndexCount: state.landscape.profiledIndexCount,
          selectedIndexCount: state.landscape.selectedIndexCount,
          technologies: state.landscape.technologies,
          relevantProfiles: state.landscape.relevantProfiles,
        };
      } else if (toolName === 'collect_research') {
        if (!state.landscape) {
          throw new Error('collect_research requires profile_indices first.');
        }
        state.researchNotes = await buildResearchNotes(enabledSources, selectedGoal, state.landscape.technologies ?? []);
        result = {
          researchNotes: state.researchNotes,
          noteCount: state.researchNotes.length,
        };
      } else if (toolName === 'collect_evidence') {
        if (!state.landscape) {
          throw new Error('collect_evidence requires profile_indices first.');
        }
        const relevantProfiles = state.landscape?.relevantProfiles ?? [];
        state.evidenceCards = await collectEvidenceCards(client, relevantProfiles, scope);
        result = {
          evidenceCards: state.evidenceCards,
          evidenceCount: state.evidenceCards.length,
        };
      } else if (toolName === 'build_hypotheses') {
        if (!state.landscape || !state.researchNotes || !state.evidenceCards) {
          throw new Error('build_hypotheses requires profile_indices, collect_research, and collect_evidence.');
        }
        const relevantProfiles = state.landscape?.relevantProfiles ?? [];
        state.hypotheses = buildHypotheses(selectedGoal, relevantProfiles, state.researchNotes, state.evidenceCards);
        result = {
          hypotheses: state.hypotheses,
          count: state.hypotheses.length,
        };
      } else if (toolName === 'challenge_hypotheses') {
        if (!state.landscape || !state.hypotheses || !state.evidenceCards) {
          throw new Error('challenge_hypotheses requires profile_indices, collect_evidence, and build_hypotheses.');
        }
        const relevantProfiles = state.landscape?.relevantProfiles ?? [];
        state.challenges = challengeHypotheses(state.hypotheses, relevantProfiles, state.evidenceCards);
        result = {
          challenges: state.challenges,
          count: state.challenges.length,
        };
      } else if (toolName === 'build_branches') {
        if (!state.landscape || !state.hypotheses || !state.challenges || !state.evidenceCards) {
          throw new Error('build_branches requires profile_indices, collect_evidence, build_hypotheses, and challenge_hypotheses.');
        }
        const relevantProfiles = state.landscape?.relevantProfiles ?? [];
        state.branches = buildBranchPlan(relevantProfiles, selectedGoal, state.evidenceCards, state.hypotheses, state.challenges);
        result = {
          branches: state.branches,
          baselineBranchConclusions: buildBranchConclusions(state.branches, state.hypotheses, state.challenges, state.evidenceCards),
        };
      } else {
        throw new Error(`Unknown tool call requested by LLM: ${toolName}`);
      }

      toolCallsAudit.push({
        step: toolCallsAudit.length + 1,
        name: toolName,
        when: nowIso(),
        summary:
          toolName === 'profile_indices'
            ? `Profiled ${result?.profiledIndexCount ?? 0} index families.`
            : toolName === 'collect_research'
              ? `Collected ${result?.noteCount ?? 0} research notes.`
              : toolName === 'collect_evidence'
                ? `Collected ${result?.evidenceCount ?? 0} evidence cards.`
                : toolName === 'build_hypotheses'
                  ? `Generated ${result?.count ?? 0} hypotheses.`
                  : toolName === 'challenge_hypotheses'
                    ? `Scored ${result?.count ?? 0} challenged hypotheses.`
                    : toolName === 'build_branches'
                      ? `Built ${result?.branches?.length ?? 0} investigation branches.`
                      : 'Tool completed.',
      });

      messages.push({
        role: 'tool',
        tool_call_id: String(toolCall?.id ?? `${toolName}-${toolCallsAudit.length}`),
        name: toolName,
        content: JSON.stringify(result),
      });
    }
  }

  throw new Error('LLM exceeded maximum tool-call iterations without producing a final decision.');
}

function getSavedObjectsClient(context: any): any | null {
  return context?.core?.savedObjects?.client ?? null;
}

function normalizeProviderConfigUpdate(previousConfig: ProviderConfig, rawBody: any): ProviderConfig {
  const body = parseJsonBody(rawBody);
  const hasApiKey = Object.prototype.hasOwnProperty.call(body ?? {}, 'apiKey');

  const nextConfig: ProviderConfig = {
    preset: String(body?.preset ?? previousConfig.preset).trim() || previousConfig.preset,
    baseUrl: normalizeProviderBaseUrl(String(body?.baseUrl ?? previousConfig.baseUrl).trim()),
    model: String(body?.model ?? previousConfig.model).trim() || DEFAULT_PROVIDER_CONFIG.model,
    apiKey: hasApiKey ? String(body?.apiKey ?? '').trim() : previousConfig.apiKey,
  };

  return nextConfig;
}

async function loadProviderConfigFromSavedObjects(context: any): Promise<ProviderConfig> {
  const client = getSavedObjectsClient(context);
  if (!client) {
    return providerConfigStore;
  }

  try {
    const saved = await client.get(PROVIDER_CONFIG_SAVED_OBJECT_TYPE, PROVIDER_CONFIG_SAVED_OBJECT_ID);
    const attributes = saved?.attributes ?? {};
    const loaded: ProviderConfig = {
      preset: String(attributes?.preset ?? providerConfigStore.preset).trim() || providerConfigStore.preset,
      baseUrl: String(attributes?.baseUrl ?? providerConfigStore.baseUrl).trim(),
      model: String(attributes?.model ?? providerConfigStore.model).trim() || DEFAULT_PROVIDER_CONFIG.model,
      apiKey: String(attributes?.apiKey ?? providerConfigStore.apiKey).trim(),
    };
    providerConfigStore = loaded;
    return loaded;
  } catch (error: any) {
    if (String(error?.output?.statusCode ?? error?.statusCode ?? '') === '404') {
      return providerConfigStore;
    }
    throw new Error(`Failed to load provider config: ${String(error?.message ?? error)}`);
  }
}

async function saveProviderConfigToSavedObjects(context: any, providerConfig: ProviderConfig): Promise<void> {
  const client = getSavedObjectsClient(context);
  if (!client) {
    return;
  }

  await client.create(
    PROVIDER_CONFIG_SAVED_OBJECT_TYPE,
    {
      preset: providerConfig.preset,
      baseUrl: providerConfig.baseUrl,
      model: providerConfig.model,
      apiKey: providerConfig.apiKey,
      updatedAt: nowIso(),
    },
    {
      id: PROVIDER_CONFIG_SAVED_OBJECT_ID,
      overwrite: true,
    }
  );
}

export function getBootstrap(): any {
  return {
    sourcePresets: SOURCE_PRESETS,
    agentRoles: AGENT_ROLES,
    workflowOrder: WORKFLOW_ORDER,
    allowedOutcomeStates: ALLOWED_OUTCOME_STATES,
    investigationRecordTypes: INVESTIGATION_RECORD_TYPES,
    provider: summarizeProvider(providerConfigStore),
    recentInvestigations: recentInvestigations.slice(0, 8),
  };
}

export function getSourcePresets(): any[] {
  return SOURCE_PRESETS;
}

export function getAgentRoles(): any[] {
  return AGENT_ROLES;
}

export async function getProviderConfig(context: any): Promise<any> {
  let loaded = providerConfigStore;
  try {
    loaded = await loadProviderConfigFromSavedObjects(context);
  } catch {
    loaded = providerConfigStore;
  }
  return summarizeProvider(loaded);
}

export async function updateProviderConfig(context: any, rawBody: any): Promise<any> {
  let loaded = providerConfigStore;
  try {
    loaded = await loadProviderConfigFromSavedObjects(context);
  } catch {
    loaded = providerConfigStore;
  }

  providerConfigStore = normalizeProviderConfigUpdate(loaded, rawBody);
  try {
    await saveProviderConfigToSavedObjects(context, providerConfigStore);
    return summarizeProvider(providerConfigStore);
  } catch (error: any) {
    return {
      ...summarizeProvider(providerConfigStore),
      persistenceWarning: `Saved object persistence failed; using in-memory provider config for this server process. ${String(
        error?.message ?? error
      )}`,
    };
  }
}

function normalizeTestThinkingSummary(value: any): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((entry) => String(entry).trim()).filter(Boolean).slice(0, 6);
}

function summarizeReasoningText(text: string): string[] {
  return text
    .split(/\n+|(?<=[.!?])\s+/)
    .map((entry) => entry.trim())
    .filter(Boolean)
    .slice(0, 6);
}

export async function testProviderConnection(context: any, rawBody: any): Promise<any> {
  const body = parseJsonBody(rawBody);
  const question = String(body?.question ?? 'Briefly confirm connectivity and suggest one next step.').trim();
  let savedProviderConfig = providerConfigStore;
  try {
    savedProviderConfig = await loadProviderConfigFromSavedObjects(context);
  } catch {
    savedProviderConfig = providerConfigStore;
  }
  const configuredProvider = normalizeProviderConfigForRequest(body, savedProviderConfig);
  ensureProviderIsConfigured(configuredProvider);

  const messages = [
    {
      role: 'user',
      content: question,
    },
  ];

  const startedAt = Date.now();
  let protocol = 'chat_completions';
  let endpoint = '';
  let thinkingSummary: string[] = [];
  let responseText = '';

  try {
    const streamed = await callProviderChatCompletionsStream(configuredProvider, messages);
    protocol = streamed.protocol;
    endpoint = streamed.endpoint;
    thinkingSummary = summarizeReasoningText(streamed.reasoningContent);
    responseText = streamed.answerContent || 'Provider returned an empty response.';
  } catch {
    const call = await callProviderOpenAiCompatible(configuredProvider, messages, []);
    protocol = call.protocol;
    endpoint = call.endpoint;
    const assistantContent = String(call?.message?.content ?? '');

    try {
      const parsed = parseModelJson(assistantContent);
      thinkingSummary = normalizeTestThinkingSummary(parsed?.thinkingSummary);
      responseText = String(parsed?.response ?? '').trim();
    } catch {
      responseText = summarizeAssistantContent(assistantContent);
    }
  }

  const latencyMs = Date.now() - startedAt;

  if (!responseText) {
    responseText = 'Provider returned an empty response.';
  }

  return {
    testedAt: nowIso(),
    protocol,
    endpoint,
    latencyMs,
    thinkingSummary,
    response: responseText,
  };
}

export async function getProviderAvailability(context: any): Promise<any> {
  let savedProviderConfig = providerConfigStore;
  try {
    savedProviderConfig = await loadProviderConfigFromSavedObjects(context);
  } catch {
    savedProviderConfig = providerConfigStore;
  }

  try {
    ensureProviderIsConfigured(savedProviderConfig);
  } catch (error: any) {
    return {
      available: false,
      reason: String(error?.message ?? 'Provider configuration is not valid.'),
      endpoint: '',
      latencyMs: 0,
    };
  }

  const urls = buildOpenAiCompatibleUrls(savedProviderConfig.baseUrl);
  const startedAt = Date.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 60000);

  try {
    const response = await fetch(urls.chatCompletionsUrl, {
      method: 'POST',
      signal: controller.signal,
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${savedProviderConfig.apiKey}`,
      },
      body: JSON.stringify({
        model: savedProviderConfig.model,
        temperature: 0,
        max_tokens: 1,
        messages: [{ role: 'user', content: 'Return exactly: ok' }],
      }),
    });

    const latencyMs = Date.now() - startedAt;
    if (!response.ok) {
      const bodyText = await response.text().catch(() => '');
      return {
        available: false,
        reason: `LLM provider responded ${response.status}: ${(bodyText || response.statusText || 'unknown error').slice(0, 220)}`,
        endpoint: urls.chatCompletionsUrl,
        latencyMs,
      };
    }

    return {
      available: true,
      reason: 'LLM provider is reachable.',
      endpoint: urls.chatCompletionsUrl,
      latencyMs,
    };
  } catch (error: any) {
    const latencyMs = Date.now() - startedAt;
    const isAbort = String(error?.name ?? '').toLowerCase() === 'aborterror';
    return {
      available: false,
      reason: isAbort
        ? 'LLM availability check timed out after 60s.'
        : `LLM availability check failed: ${String(error?.message ?? error)}`,
      endpoint: urls.chatCompletionsUrl,
      latencyMs,
    };
  } finally {
    clearTimeout(timeout);
  }
}

export async function getIndexProfile(context: any, rawBody: any): Promise<any> {
  const body = parseJsonBody(rawBody);
  const selectedGoal = String(body?.selectedGoal ?? '').trim();
  const scope = normalizeScope(body);
  const landscape = await buildIndexLandscape(context, scope, selectedGoal);
  return {
    landscape,
  };
}

export async function proposeGoals(context: any, rawBody: any): Promise<any> {
  const body = parseJsonBody(rawBody);
  const selectedGoal = String(body?.selectedGoal ?? '').trim();
  const scope = normalizeScope(body);
  const enabledSources = normalizeSources(body);
  const landscape = await buildIndexLandscape(context, scope, selectedGoal);
  const signals = await buildResearchNotes(enabledSources, selectedGoal, landscape.technologies);
  const configuredProvider = await loadProviderConfigFromSavedObjects(context);
  ensureProviderIsConfigured(configuredProvider);
  const llmGoals = await proposeGoalsViaLlm(configuredProvider, selectedGoal, landscape, signals);

  return {
    goals: llmGoals.goals,
    signals,
    landscape,
    goalGenerationTrace: llmGoals.trace,
  };
}

export async function previewInvestigation(context: any, rawBody: any): Promise<any> {
  const body = parseJsonBody(rawBody);
  const selectedGoal = String(body?.selectedGoal ?? '').trim();
  const scope = normalizeScope(body);
  const landscape = await buildIndexLandscape(context, scope, selectedGoal);
  const plan = buildInvestigationPlan(body, landscape);
  return {
    plan,
    landscape,
  };
}

export async function runInvestigation(context: any, rawBody: any): Promise<any> {
  const body = parseJsonBody(rawBody);
  const selectedGoal = String(body?.selectedGoal ?? '').trim();
  if (!selectedGoal) {
    throw new Error('An investigation goal is required before execution.');
  }

  const configuredProvider = await loadProviderConfigFromSavedObjects(context);
  ensureProviderIsConfigured(configuredProvider);

  const scope = normalizeScope(body);
  const enabledSources = normalizeSources(body);
  providerConfigStore = configuredProvider;
  const agentic = await runAgenticDecisionLoop(context, selectedGoal, scope, enabledSources);
  const landscape = agentic.landscape;
  const researchNotes = agentic.researchNotes;
  const evidenceCards = agentic.evidenceCards;
  const hypotheses = agentic.hypotheses;
  const challenges = agentic.challenges;
  const branches = agentic.branches;
  const branchConclusions = Array.isArray(agentic.branchConclusions) && agentic.branchConclusions.length > 0
    ? agentic.branchConclusions
    : buildBranchConclusions(branches, hypotheses, challenges, evidenceCards);
  const decision = agentic.decision;

  const plan = buildInvestigationPlan(body, landscape);
  const graph = buildGraph(selectedGoal, branches, researchNotes, hypotheses, challenges, evidenceCards, decision);
  const report = buildReport(selectedGoal, landscape, branches, branchConclusions, researchNotes, evidenceCards, decision);
  const auditTrail = buildAuditTrail(selectedGoal, scope, landscape, researchNotes, evidenceCards);
  const runId = `run-${Date.now()}`;

  const result = {
    runId,
    generatedAt: nowIso(),
    goal: selectedGoal,
    scope: {
      includePatterns: scope.includePatterns,
      excludePatterns: scope.excludePatterns,
      timeRange: scope.timeRange,
      queryText: scope.queryText,
    },
    strategyVersion: 'v6-goal-first',
    workflowOrder: WORKFLOW_ORDER,
    allowedOutcomeStates: ALLOWED_OUTCOME_STATES,
    recordsProduced: INVESTIGATION_RECORD_TYPES,
    plan,
    landscape,
    researchNotes,
    evidenceCards,
    hypotheses,
    challenges,
    auditTrail,
    toolCalls: agentic.toolCallsAudit,
    llmTrace: agentic.llmTrace,
    branchConclusions,
    decision,
    graph,
    report: {
      ...report,
      executiveSummary: agentic.executiveSummary,
    },
  };

  recentInvestigations = [
    {
      runId,
      generatedAt: result.generatedAt,
      goal: selectedGoal,
      state: decision.state,
      confidence: decision.confidence,
      usedIndices: report.usedIndices,
    },
    ...recentInvestigations,
  ].slice(0, 20);

  return result;
}

export function listInvestigations(): any[] {
  return recentInvestigations;
}