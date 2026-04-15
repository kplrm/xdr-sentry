import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  EuiBadge,
  EuiButton,
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiCallOut,
  EuiCodeBlock,
  EuiFieldSearch,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiFlyoutHeader,
  EuiForm,
  EuiFormRow,
  EuiHorizontalRule,
  EuiLoadingSpinner,
  EuiPage,
  EuiPageBody,
  EuiPageHeader,
  EuiPanel,
  EuiRadio,
  EuiSelect,
  EuiSpacer,
  EuiSuperDatePicker,
  EuiSwitch,
  EuiTab,
  EuiTabs,
  EuiText,
  EuiTextArea,
  EuiTitle,
} from '@elastic/eui';
import { CoreStart } from '../../../OpenSearch-Dashboards/src/core/public';

interface Props {
  basename: string;
  http: CoreStart['http'];
  notifications: CoreStart['notifications'];
}

interface SourcePreset {
  id: string;
  name: string;
  url: string;
  type: string;
  trustLevel: string;
  enabledByDefault: boolean;
}

interface AgentRole {
  id: string;
  name: string;
  responsibilities: string[];
}

interface CustomSource {
  id: string;
  name: string;
  url: string;
  type: string;
}

interface SuggestedGoal {
  id: string;
  title: string;
  rationale: string;
  sources: string[];
  detectedTechnologies: string[];
  confidence: string;
  scopeHint?: string[];
}

interface ProviderConfigView {
  preset: string;
  baseUrl: string;
  model: string;
  hasApiKey: boolean;
}

interface GoalGenerationTrace {
  mode: string;
  protocol?: string;
  endpoint?: string;
  assistantSummary?: string;
}

interface ProviderTestLogEntry {
  testedAt: string;
  protocol: string;
  endpoint: string;
  latencyMs: number;
  thinkingSummary: string[];
  response: string;
}

type AppTabId = 'strategy' | 'investigation' | 'history';

const DEFAULT_GOAL = 'Inspect Docker-related logs for signs of exploitation, daemon abuse, or post-compromise behavior.';
const DEFAULT_PROVIDER_MODEL = 'qwen3.5:9b-q4_K_M';

function getOutcomeColor(state: string): 'success' | 'warning' | 'danger' | 'primary' | 'hollow' {
  if (state === 'Likely attack story identified') {
    return 'danger';
  }
  if (state === 'Unable to proceed') {
    return 'warning';
  }
  if (state === 'Correlated activity identified but attack not established') {
    return 'primary';
  }
  if (state === 'No supported attack story found in scope') {
    return 'success';
  }
  return 'hollow';
}

function getNodeTone(status: string): string {
  if (status === 'completed') {
    return 'isCompleted';
  }
  if (status === 'stopped') {
    return 'isStopped';
  }
  if (status === 'pruned') {
    return 'isPruned';
  }
  if (status === 'failed') {
    return 'isFailed';
  }
  return 'isQueued';
}

function getLandscapeStatus(profile: any): string {
  if (!profile?.understandable) {
    return 'stop';
  }
  if (!profile?.fitForInvestigation) {
    return 'split';
  }
  return profile?.branchRecommendation ?? 'group';
}

function formatCount(value: number | undefined): string {
  return String(value ?? 0);
}

export const XdrSentryApp: React.FC<Props> = ({ http, notifications }) => {
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<AppTabId>('investigation');

  const [sourcePresets, setSourcePresets] = useState<SourcePreset[]>([]);
  const [agentRoles, setAgentRoles] = useState<AgentRole[]>([]);
  const [workflowOrder, setWorkflowOrder] = useState<string[]>([]);
  const [allowedOutcomeStates, setAllowedOutcomeStates] = useState<string[]>([]);
  const [recordTypes, setRecordTypes] = useState<string[]>([]);
  const [history, setHistory] = useState<any[]>([]);

  const [goalMode, setGoalMode] = useState<'human' | 'agent'>('human');
  const [humanGoal, setHumanGoal] = useState(DEFAULT_GOAL);
  const [selectedGoalId, setSelectedGoalId] = useState('');
  const [suggestedGoals, setSuggestedGoals] = useState<SuggestedGoal[]>([]);
  const [researchSignals, setResearchSignals] = useState<any[]>([]);
  const [goalGenerationTrace, setGoalGenerationTrace] = useState<GoalGenerationTrace | null>(null);

  const [providerConfig, setProviderConfig] = useState<ProviderConfigView>({
    preset: 'custom',
    baseUrl: '',
    model: DEFAULT_PROVIDER_MODEL,
    hasApiKey: false,
  });
  const [providerBaseUrlInput, setProviderBaseUrlInput] = useState('');
  const [providerModelInput, setProviderModelInput] = useState(DEFAULT_PROVIDER_MODEL);
  const [providerApiKeyInput, setProviderApiKeyInput] = useState('');
  const [providerTestLog, setProviderTestLog] = useState<ProviderTestLogEntry | null>(null);
  const [testingProviderConnection, setTestingProviderConnection] = useState(false);
  const [loadingProviderConfig, setLoadingProviderConfig] = useState(false);
  const [savingProviderConfig, setSavingProviderConfig] = useState(false);
  const [isProviderFlyoutOpen, setIsProviderFlyoutOpen] = useState(false);

  const [enabledSourceIds, setEnabledSourceIds] = useState<string[]>([]);
  const [customSources, setCustomSources] = useState<CustomSource[]>([]);
  const [newSourceName, setNewSourceName] = useState('');
  const [newSourceUrl, setNewSourceUrl] = useState('');
  const [newSourceType, setNewSourceType] = useState('custom');

  const [includePatterns, setIncludePatterns] = useState('');
  const [excludePatterns, setExcludePatterns] = useState('');
  const [timeFrom, setTimeFrom] = useState('now-24h');
  const [timeTo, setTimeTo] = useState('now');
  const [queryText, setQueryText] = useState('');
  const [maxProfiles, setMaxProfiles] = useState('8');
  const [maxEvidencePerIndex, setMaxEvidencePerIndex] = useState('3');

  const [landscape, setLandscape] = useState<any | null>(null);
  const [plan, setPlan] = useState<any | null>(null);
  const [result, setResult] = useState<any | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState('');

  const [profiling, setProfiling] = useState(false);
  const [suggestingGoals, setSuggestingGoals] = useState(false);
  const [buildingPlan, setBuildingPlan] = useState(false);
  const [runningInvestigation, setRunningInvestigation] = useState(false);
  const [goalSuggestionActivity, setGoalSuggestionActivity] = useState<string[]>([]);
  const [goalSuggestionPendingLine, setGoalSuggestionPendingLine] = useState('');
  const [goalSuggestionAutoScroll, setGoalSuggestionAutoScroll] = useState(true);
  const [providerTestActivity, setProviderTestActivity] = useState<string[]>([]);
  const suggestGoalsAbortControllerRef = useRef<AbortController | null>(null);
  const suggestGoalsTickerRef = useRef<number | null>(null);
  const suggestGoalsStartedAtRef = useRef<number | null>(null);
  const goalThinkingLogRef = useRef<HTMLDivElement | null>(null);

  const appendGoalSuggestionLog = useCallback((line: string) => {
    setGoalSuggestionPendingLine('');
    setGoalSuggestionActivity((previous) => [...previous, line]);
  }, []);

  const updateGoalSuggestionPendingLine = useCallback((line: string) => {
    setGoalSuggestionPendingLine(line);
  }, []);

  const clearSuggestGoalsTicker = useCallback(() => {
    if (suggestGoalsTickerRef.current !== null) {
      window.clearInterval(suggestGoalsTickerRef.current);
      suggestGoalsTickerRef.current = null;
    }
  }, []);

  const stopSuggestGoals = useCallback(() => {
    const elapsedMarker = Math.max(
      0,
      Math.round((Date.now() - Number(suggestGoalsStartedAtRef.current ?? Date.now())) / 1000)
    );
    if (suggestGoalsAbortControllerRef.current) {
      suggestGoalsAbortControllerRef.current.abort();
      suggestGoalsAbortControllerRef.current = null;
    }
    clearSuggestGoalsTicker();
    setGoalSuggestionPendingLine('');
    setSuggestingGoals(false);
    appendGoalSuggestionLog(`[${elapsedMarker}s] Goal suggestion stopped by analyst.`);
  }, [appendGoalSuggestionLog, clearSuggestGoalsTicker]);

  const requestBody = useMemo(
    () => ({
      selectedGoal: goalMode === 'human' ? humanGoal.trim() : '',
      enabledSourceIds,
      customSources,
      scope: {
        includePatterns,
        excludePatterns,
        timeRange: {
          from: timeFrom,
          to: timeTo,
        },
        queryText,
        maxProfiles,
        maxEvidencePerIndex,
      },
    }),
    [
      customSources,
      enabledSourceIds,
      excludePatterns,
      goalMode,
      humanGoal,
      includePatterns,
      maxEvidencePerIndex,
      maxProfiles,
      queryText,
      timeFrom,
      timeTo,
    ]
  );

  const resolveSelectedGoal = useCallback(() => {
    if (goalMode === 'human') {
      return humanGoal.trim();
    }
    return suggestedGoals.find((goal) => goal.id === selectedGoalId)?.title ?? '';
  }, [goalMode, humanGoal, selectedGoalId, suggestedGoals]);

  const loadBootstrap = useCallback(async () => {
    setLoading(true);
    try {
      const response = await http.get('/api/xdr_sentry/bootstrap');
      const presets = response?.sourcePresets ?? [];
      setSourcePresets(presets);
      setAgentRoles(response?.agentRoles ?? []);
      setWorkflowOrder(response?.workflowOrder ?? []);
      setAllowedOutcomeStates(response?.allowedOutcomeStates ?? []);
      setRecordTypes(response?.investigationRecordTypes ?? []);
      setHistory(response?.recentInvestigations ?? []);
      const provider = response?.provider;
      if (provider) {
        const normalizedProvider = {
          preset: provider?.preset ?? 'custom',
          baseUrl: provider?.baseUrl ?? '',
          model: provider?.model || DEFAULT_PROVIDER_MODEL,
          hasApiKey: Boolean(provider?.hasApiKey),
        };
        setProviderConfig(normalizedProvider);
        setProviderBaseUrlInput(normalizedProvider.baseUrl);
        setProviderModelInput(normalizedProvider.model);
      }
      setEnabledSourceIds(
        presets.filter((preset: SourcePreset) => preset.enabledByDefault).map((preset: SourcePreset) => preset.id)
      );
    } catch (error: any) {
      notifications.toasts.addDanger(`Failed to initialize XDR Sentry: ${error?.message ?? 'unknown error'}`);
    } finally {
      setLoading(false);
    }
  }, [http, notifications]);

  useEffect(() => {
    loadBootstrap();
  }, [loadBootstrap]);

  const loadProviderConfig = useCallback(async () => {
    try {
      setLoadingProviderConfig(true);
      const response = await http.get('/api/xdr_sentry/provider_config');
      const provider = response?.provider;
      const normalizedProvider = {
        preset: provider?.preset ?? 'custom',
        baseUrl: provider?.baseUrl ?? '',
        model: provider?.model || DEFAULT_PROVIDER_MODEL,
        hasApiKey: Boolean(provider?.hasApiKey),
      };
      setProviderConfig(normalizedProvider);
      setProviderBaseUrlInput(normalizedProvider.baseUrl);
      setProviderModelInput(normalizedProvider.model);
    } catch (error: any) {
      notifications.toasts.addDanger(`Failed to load provider config: ${error?.message ?? 'unknown error'}`);
    } finally {
      setLoadingProviderConfig(false);
    }
  }, [http, notifications]);

  useEffect(() => {
    loadProviderConfig();
  }, [loadProviderConfig]);

  useEffect(() => {
    return () => {
      if (suggestGoalsAbortControllerRef.current) {
        suggestGoalsAbortControllerRef.current.abort();
      }
      clearSuggestGoalsTicker();
    };
  }, [clearSuggestGoalsTicker]);

  useEffect(() => {
    if (!goalSuggestionAutoScroll) {
      return;
    }
    const node = goalThinkingLogRef.current;
    if (!node) {
      return;
    }
    node.scrollTop = node.scrollHeight;
  }, [goalSuggestionActivity, goalSuggestionAutoScroll, goalSuggestionPendingLine]);

  const handleGoalThinkingScroll = useCallback(() => {
    const node = goalThinkingLogRef.current;
    if (!node) {
      return;
    }
    const distanceFromBottom = node.scrollHeight - node.scrollTop - node.clientHeight;
    setGoalSuggestionAutoScroll(distanceFromBottom <= 12);
  }, []);

  const saveProviderConfig = async () => {
    try {
      setSavingProviderConfig(true);
      const payload: any = {
        preset: 'custom',
        baseUrl: providerBaseUrlInput,
        model: providerModelInput.trim() || DEFAULT_PROVIDER_MODEL,
      };
      if (providerApiKeyInput.trim()) {
        payload.apiKey = providerApiKeyInput.trim();
      }

      const response = await http.post('/api/xdr_sentry/provider_config', {
        body: JSON.stringify(payload),
      });
      const provider = response?.provider;
      const normalizedProvider = {
        preset: provider?.preset ?? 'custom',
        baseUrl: provider?.baseUrl ?? '',
        model: provider?.model || DEFAULT_PROVIDER_MODEL,
        hasApiKey: Boolean(provider?.hasApiKey),
      };
      setProviderConfig(normalizedProvider);
      setProviderBaseUrlInput(normalizedProvider.baseUrl);
      setProviderModelInput(normalizedProvider.model);
      setProviderApiKeyInput('');
      setIsProviderFlyoutOpen(false);
      if (provider?.persistenceWarning) {
        notifications.toasts.addWarning(String(provider.persistenceWarning));
        notifications.toasts.addSuccess('Provider configuration saved for the current server process.');
      } else {
        notifications.toasts.addSuccess('Provider configuration saved persistently.');
      }
    } catch (error: any) {
      notifications.toasts.addDanger(`Failed to save provider config: ${error?.message ?? 'unknown error'}`);
    } finally {
      setSavingProviderConfig(false);
    }
  };

  const testProviderConnection = async () => {
    const effectiveBaseUrl = providerBaseUrlInput.trim() || providerConfig.baseUrl;
    const effectiveModel = providerModelInput.trim() || providerConfig.model || DEFAULT_PROVIDER_MODEL;
    const hasEffectiveApiKey = Boolean(providerApiKeyInput.trim() || providerConfig.hasApiKey);

    if (!effectiveBaseUrl || !effectiveModel || !hasEffectiveApiKey) {
      notifications.toasts.addWarning('Enter base URL, model, and API key, or save the provider first so the test can reuse the stored key.');
      return;
    }

    const startedAt = Date.now();
    const phaseMessages = [
      'Opening provider connection...',
      'Sending test prompt to model...',
      'Waiting for streamed reasoning tokens...',
      'Continuing to collect streamed answer...',
    ];
    let phaseIndex = 0;
    setProviderTestLog(null);
    setProviderTestActivity(['[0s] Starting provider test.']);
    const ticker = window.setInterval(() => {
      phaseIndex += 1;
      const elapsed = Math.round((Date.now() - startedAt) / 1000);
      const message = phaseMessages[Math.min(phaseIndex, phaseMessages.length - 1)];
      setProviderTestActivity((previous) => [...previous, `[${elapsed}s] ${message}`].slice(-24));
    }, 1400);

    try {
      setTestingProviderConnection(true);
      const response = await http.post('/api/xdr_sentry/test_provider', {
        body: JSON.stringify({
          baseUrl: providerBaseUrlInput,
          model: providerModelInput.trim() || DEFAULT_PROVIDER_MODEL,
          apiKey: providerApiKeyInput.trim(),
          question: 'Why is the sky blue?',
        }),
      });
      const elapsed = Math.round((Date.now() - startedAt) / 1000);
      const thinkingLines = Array.isArray(response?.thinkingSummary)
        ? response.thinkingSummary.map((line: string, index: number) => `[${elapsed}s] thinking ${index + 1}: ${line}`)
        : [];
      setProviderTestActivity((previous) =>
        [
          ...previous,
          `[${elapsed}s] Stream completed via ${String(response?.protocol ?? 'unknown protocol')}.`,
          ...thinkingLines,
          `[${elapsed}s] response: ${String(response?.response ?? 'No response returned by provider test.').slice(0, 220)}`,
        ].slice(-28)
      );
      setProviderTestLog({
        testedAt: String(response?.testedAt ?? new Date().toISOString()),
        protocol: String(response?.protocol ?? 'unknown'),
        endpoint: String(response?.endpoint ?? 'unknown-endpoint'),
        latencyMs: Number(response?.latencyMs ?? 0),
        thinkingSummary: Array.isArray(response?.thinkingSummary) ? response.thinkingSummary : [],
        response: String(response?.response ?? 'No response returned by provider test.'),
      });
      notifications.toasts.addSuccess('Provider connection test completed.');
    } catch (error: any) {
      const elapsed = Math.round((Date.now() - startedAt) / 1000);
      setProviderTestActivity((previous) =>
        [...previous, `[${elapsed}s] Test failed: ${String(error?.message ?? 'unknown error')}`].slice(-28)
      );
      notifications.toasts.addDanger(`Provider connection test failed: ${error?.message ?? 'unknown error'}`);
    } finally {
      window.clearInterval(ticker);
      setTestingProviderConnection(false);
    }
  };

  const closeProviderFlyout = () => {
    setIsProviderFlyoutOpen(false);
    setProviderApiKeyInput('');
  };

  const toggleSourcePreset = (sourceId: string, checked: boolean) => {
    if (checked) {
      setEnabledSourceIds((previous) => Array.from(new Set([...previous, sourceId])));
      return;
    }
    setEnabledSourceIds((previous) => previous.filter((id) => id !== sourceId));
  };

  const addCustomSource = () => {
    if (!newSourceName.trim() || !newSourceUrl.trim()) {
      notifications.toasts.addWarning('Custom source name and URL are required.');
      return;
    }

    setCustomSources((previous) => [
      ...previous,
      {
        id: `custom-${Date.now()}`,
        name: newSourceName.trim(),
        url: newSourceUrl.trim(),
        type: newSourceType,
      },
    ]);
    setNewSourceName('');
    setNewSourceUrl('');
    setNewSourceType('custom');
  };

  const removeCustomSource = (sourceId: string) => {
    setCustomSources((previous) => previous.filter((source) => source.id !== sourceId));
  };

  const refreshLandscape = useCallback(
    async (showToast: boolean) => {
      try {
        setProfiling(true);
        const response = await http.post('/api/xdr_sentry/index_profile', {
          body: JSON.stringify({
            ...requestBody,
            selectedGoal: resolveSelectedGoal(),
          }),
        });
        setLandscape(response?.landscape ?? null);
        if (showToast) {
          notifications.toasts.addSuccess('Index understanding refreshed.');
        }
      } catch (error: any) {
        notifications.toasts.addDanger(`Failed to profile indices: ${error?.message ?? 'unknown error'}`);
      } finally {
        setProfiling(false);
      }
    },
    [http, notifications, requestBody, resolveSelectedGoal]
  );

  const suggestGoals = async () => {
    if (!providerConfig.baseUrl.trim() || !providerConfig.hasApiKey) {
      notifications.toasts.addWarning('Save a valid LLM provider configuration before requesting goal suggestions.');
      appendGoalSuggestionLog('[0s] Goal suggestion blocked: no valid saved LLM provider configuration.');
      return;
    }

    if (suggestingGoals) {
      return;
    }

    appendGoalSuggestionLog('---');
    appendGoalSuggestionLog(`[${new Date().toISOString()}] New goal suggestion run started.`);
    updateGoalSuggestionPendingLine('[0s] Checking saved LLM provider availability...');
    try {
      const availability = await http.get('/api/xdr_sentry/provider_availability');
      if (!availability?.available) {
        const reason = String(availability?.reason ?? 'provider availability check failed');
        appendGoalSuggestionLog(`[0s] Goal suggestion blocked: ${reason}`);
        notifications.toasts.addDanger(`Cannot start goal suggestion: ${reason}`);
        return;
      }
      appendGoalSuggestionLog(`[0s] Provider reachable at ${String(availability?.endpoint ?? providerConfig.baseUrl)}.`);
    } catch (error: any) {
      const reason = String(error?.message ?? 'provider availability check failed');
      appendGoalSuggestionLog(`[0s] Goal suggestion blocked: ${reason}`);
      notifications.toasts.addDanger(`Cannot start goal suggestion: ${reason}`);
      return;
    }

    const startedAt = Date.now();
    suggestGoalsStartedAtRef.current = startedAt;
    const phaseMessages = [
      'Compiling selected scope and index hints...',
      'Collecting trusted-source registry research notes...',
      'Asking LLM for recent and trending threat missions...',
      'Waiting for LLM goal response...',
    ];
    let phaseIndex = 0;
    const controller = new AbortController();
    suggestGoalsAbortControllerRef.current = controller;
    setGoalGenerationTrace(null);
    setGoalSuggestionAutoScroll(true);
    appendGoalSuggestionLog('[0s] Goal suggestion started.');
    appendGoalSuggestionLog('[0s] Compiling selected scope and index hints.');
    suggestGoalsTickerRef.current = window.setInterval(() => {
      const elapsed = Math.round((Date.now() - startedAt) / 1000);
      phaseIndex += 1;
      if (phaseIndex < phaseMessages.length) {
        appendGoalSuggestionLog(`[${elapsed}s] ${phaseMessages[phaseIndex]}`);
        return;
      }
      updateGoalSuggestionPendingLine(
        `[${elapsed}s] Waiting for provider response. Trusted-source context and LLM reasoning may take time.`
      );
    }, 1300);
    const autoStopTimeout = window.setTimeout(() => {
      if (suggestGoalsAbortControllerRef.current === controller) {
        controller.abort();
        suggestGoalsAbortControllerRef.current = null;
        setGoalSuggestionPendingLine('');
        appendGoalSuggestionLog('[300s] Goal suggestion timed out while waiting for LLM response.');
      }
    }, 300000);

    try {
      setSuggestingGoals(true);
      const response = await http.post('/api/xdr_sentry/propose_goals', {
        body: JSON.stringify(requestBody),
        signal: controller.signal,
      });
      setSuggestedGoals(response?.goals ?? []);
      setResearchSignals(response?.signals ?? []);
      setLandscape(response?.landscape ?? null);
      setGoalGenerationTrace(response?.goalGenerationTrace ?? null);
      const elapsed = Math.round((Date.now() - startedAt) / 1000);
      const goalCount = Array.isArray(response?.goals) ? response.goals.length : 0;
      const topGoalLines = (response?.goals ?? [])
        .slice(0, 3)
        .map((goal: SuggestedGoal, index: number) => `[${elapsed}s] candidate ${index + 1}: ${goal.title}`);
      const assistantSummary = String(response?.goalGenerationTrace?.assistantSummary ?? '').trim();
      appendGoalSuggestionLog(`[${elapsed}s] Completed: ${goalCount} goal suggestions generated.`);
      if (assistantSummary) {
        appendGoalSuggestionLog(`[${elapsed}s] LLM summary: ${assistantSummary.slice(0, 260)}`);
      }
      for (const line of topGoalLines) {
        appendGoalSuggestionLog(line);
      }
      if ((response?.goals ?? []).length > 0) {
        setSelectedGoalId(response.goals[0].id);
      }
    } catch (error: any) {
      const elapsed = Math.round((Date.now() - startedAt) / 1000);
      if (error?.name === 'AbortError') {
        appendGoalSuggestionLog(`[${elapsed}s] Goal suggestion aborted before completion.`);
        return;
      }
      appendGoalSuggestionLog(`[${elapsed}s] Goal suggestion failed: ${String(error?.message ?? 'unknown error')}`);
      notifications.toasts.addDanger(`Failed to suggest goals: ${error?.message ?? 'unknown error'}`);
    } finally {
      window.clearTimeout(autoStopTimeout);
      clearSuggestGoalsTicker();
      setGoalSuggestionPendingLine('');
      if (suggestGoalsAbortControllerRef.current === controller) {
        suggestGoalsAbortControllerRef.current = null;
      }
      suggestGoalsStartedAtRef.current = null;
      setSuggestingGoals(false);
    }
  };

  const previewPlan = async () => {
    const resolvedGoal = resolveSelectedGoal();
    if (!resolvedGoal) {
      notifications.toasts.addWarning('Approve a goal before building the investigation plan.');
      return;
    }

    try {
      setBuildingPlan(true);
      const response = await http.post('/api/xdr_sentry/investigation_preview', {
        body: JSON.stringify({
          ...requestBody,
          selectedGoal: resolvedGoal,
        }),
      });
      setPlan(response?.plan ?? null);
      setLandscape(response?.landscape ?? null);
      setResult(null);
    } catch (error: any) {
      notifications.toasts.addDanger(`Failed to build investigation plan: ${error?.message ?? 'unknown error'}`);
    } finally {
      setBuildingPlan(false);
    }
  };

  const runGoalInvestigation = async () => {
    const resolvedGoal = resolveSelectedGoal();
    if (!resolvedGoal) {
      notifications.toasts.addWarning('Approve a goal before starting the investigation.');
      return;
    }

    try {
      setRunningInvestigation(true);
      const response = await http.post('/api/xdr_sentry/run_investigation', {
        body: JSON.stringify({
          ...requestBody,
          selectedGoal: resolvedGoal,
        }),
      });
      const nextResult = response?.result ?? null;
      setResult(nextResult);
      setLandscape(nextResult?.landscape ?? null);
      setPlan(nextResult?.plan ?? null);
      setSelectedNodeId(nextResult?.graph?.nodes?.[0]?.id ?? '');
      setActiveTab('investigation');
      setHistory((previous) =>
        [
          nextResult
            ? {
                runId: nextResult.runId,
                generatedAt: nextResult.generatedAt,
                goal: nextResult.goal,
                state: nextResult?.decision?.state,
                confidence: nextResult?.decision?.confidence,
                usedIndices: nextResult?.report?.usedIndices ?? [],
              }
            : null,
          ...previous,
        ].filter(Boolean)
      );
      notifications.toasts.addSuccess('Investigation completed.');
    } catch (error: any) {
      notifications.toasts.addDanger(`Failed to run investigation: ${error?.message ?? 'unknown error'}`);
    } finally {
      setRunningInvestigation(false);
    }
  };

  const selectedGoal = resolveSelectedGoal();
  const graphColumns = result?.graph?.columns ?? [];
  const graphNodes = result?.graph?.nodes ?? [];
  const selectedNode = graphNodes.find((node: any) => node.id === selectedNodeId) ?? graphNodes[0];
  const selectedNodeIncoming = (result?.graph?.edges ?? []).filter((edge: any) => edge.target === selectedNode?.id);
  const selectedNodeOutgoing = (result?.graph?.edges ?? []).filter((edge: any) => edge.source === selectedNode?.id);
  const profileCards = landscape?.profiles ?? [];
  const branchCards = result?.branchConclusions ?? [];

  if (loading) {
    return (
      <EuiPage>
        <EuiPageBody>
          <div className="xdrSentryLoading">
            <EuiLoadingSpinner size="xl" />
          </div>
        </EuiPageBody>
      </EuiPage>
    );
  }

  return (
    <EuiPage className="xdrSentryPage">
      <EuiPageBody component="div" className="xdrSentryBody">
        <EuiPageHeader>
          <EuiTitle>
            <h1>XDR Sentry</h1>
          </EuiTitle>
        </EuiPageHeader>

        <EuiPanel className="xdrSentryHero" paddingSize="none" hasShadow={false}>
          <div className="xdrSentryHero__backdrop" />
          <div className="xdrSentryHero__content">
            <div>
              <p className="xdrSentryEyebrow">Goal-Driven Investigation System</p>
              <h2 className="xdrSentryHero__title">Understand the data first. Only then test attack stories.</h2>
            </div>
          </div>
        </EuiPanel>

        <EuiSpacer size="m" />
        <EuiTabs>
          <EuiTab onClick={() => setActiveTab('strategy')} isSelected={activeTab === 'strategy'}>
            Strategy
          </EuiTab>
          <EuiTab onClick={() => setActiveTab('investigation')} isSelected={activeTab === 'investigation'}>
            Investigation
          </EuiTab>
          <EuiTab onClick={() => setActiveTab('history')} isSelected={activeTab === 'history'}>
            History
          </EuiTab>
        </EuiTabs>

        <EuiSpacer size="m" />

        {activeTab === 'strategy' ? (
          <div className="xdrSentryStrategyGrid">
            <EuiPanel className="xdrSentryCard" paddingSize="m">
              <p className="xdrSentryEyebrow">Execution Contract</p>
              <EuiTitle size="s">
                <h3>Ordered workflow, not storytelling</h3>
              </EuiTitle>
              <EuiSpacer size="s" />
              {workflowOrder.map((step, index) => (
                <div className="xdrSentryTimelineItem" key={step}>
                  <div className="xdrSentryTimelineItem__index">{index + 1}</div>
                  <div className="xdrSentryTimelineItem__text">{step}</div>
                </div>
              ))}
            </EuiPanel>

            <EuiPanel className="xdrSentryCard" paddingSize="m">
              <p className="xdrSentryEyebrow">Outcome Model</p>
              <EuiTitle size="s">
                <h3>Allowed final states</h3>
              </EuiTitle>
              <EuiSpacer size="s" />
              <div className="xdrSentryBadgeCloud">
                {allowedOutcomeStates.map((state) => (
                  <EuiBadge key={state} color={getOutcomeColor(state)}>
                    {state}
                  </EuiBadge>
                ))}
              </div>
              <EuiSpacer size="m" />
              <EuiCallOut color="warning" size="s" title="Unknown is a valid outcome">
                <p>The system should stop or stay inconclusive when the logs are unclear, rather than force a confident attack narrative.</p>
              </EuiCallOut>
            </EuiPanel>

            <EuiPanel className="xdrSentryCard" paddingSize="m">
              <p className="xdrSentryEyebrow">Agent Roles</p>
              <EuiTitle size="s">
                <h3>Specialists on the canvas</h3>
              </EuiTitle>
              <EuiSpacer size="s" />
              {agentRoles.map((role) => (
                <div className="xdrSentryRoleRow" key={role.id}>
                  <div>
                    <strong>{role.name}</strong>
                    <div>{role.responsibilities.join(' | ')}</div>
                  </div>
                </div>
              ))}
            </EuiPanel>

            <EuiPanel className="xdrSentryCard" paddingSize="m">
              <p className="xdrSentryEyebrow">Investigation Records</p>
              <EuiTitle size="s">
                <h3>Persisted run artifacts</h3>
              </EuiTitle>
              <EuiSpacer size="s" />
              <div className="xdrSentryRecordGrid">
                {recordTypes.map((recordType) => (
                  <div className="xdrSentryRecordPill" key={recordType}>
                    {recordType}
                  </div>
                ))}
              </div>
            </EuiPanel>
          </div>
        ) : null}

        {activeTab === 'investigation' ? (
          <div className="xdrSentryWorkbench">
            <div className="xdrSentryWorkbench__mission">
              <EuiPanel className="xdrSentryCard" paddingSize="m">
                <p className="xdrSentryEyebrow">Mission Control</p>
                <EuiTitle size="s">
                  <h3>Goal and scope</h3>
                </EuiTitle>
                <EuiSpacer size="s" />
                <div className="xdrSentryMissionHeader">
                  <EuiText size="s" color="subdued">
                    <p>Goal discovery uses selected scope plus enabled trusted sources.</p>
                  </EuiText>
                  <div className="xdrSentryMissionHeader__actions">
                    <EuiButton color={suggestingGoals ? 'danger' : 'primary'} onClick={suggestingGoals ? stopSuggestGoals : suggestGoals}>
                      {suggestingGoals ? 'Stop' : 'Suggest goals'}
                    </EuiButton>
                  </div>
                </div>
                <EuiSpacer size="m" />
                <div className="xdrSentryGoalLayout">
                  <div className="xdrSentryGoalLayout__main">
                    <EuiRadio
                      id="goal-mode-human"
                      label="Use a human-authored goal"
                      checked={goalMode === 'human'}
                      onChange={() => setGoalMode('human')}
                    />
                    <EuiRadio
                      id="goal-mode-agent"
                      label="Use an agent-suggested goal"
                      checked={goalMode === 'agent'}
                      onChange={() => setGoalMode('agent')}
                    />

                    <EuiSpacer size="m" />
                    {goalMode === 'human' ? (
                      <EuiFormRow label="Approved investigation goal">
                        <EuiTextArea
                          value={humanGoal}
                          onChange={(event) => setHumanGoal(event.target.value)}
                          rows={5}
                          placeholder="Describe the investigation goal."
                        />
                      </EuiFormRow>
                    ) : (
                      <>
                        <EuiCallOut title="Generate and approve a goal before execution" color="warning" size="s">
                          <p>Goal suggestions combine the current index landscape with enabled trusted-source research.</p>
                        </EuiCallOut>
                        {goalGenerationTrace ? (
                          <>
                            <EuiSpacer size="s" />
                            <EuiCallOut title="Goal generation used Agentic AI" color="success" size="s">
                              <p>Protocol: {goalGenerationTrace.protocol || 'unknown'}.</p>
                              <p>{goalGenerationTrace.assistantSummary || 'No assistant summary captured.'}</p>
                            </EuiCallOut>
                          </>
                        ) : null}
                        <EuiSpacer size="m" />
                        {suggestedGoals.length === 0 ? (
                          <EuiText size="s">
                            <p>No suggestions yet. Run goal discovery after setting source and scope controls.</p>
                          </EuiText>
                        ) : (
                          suggestedGoals.map((goal) => (
                            <button
                              type="button"
                              key={goal.id}
                              className={`xdrSentryGoalOption ${selectedGoalId === goal.id ? 'isSelected' : ''}`}
                              onClick={() => setSelectedGoalId(goal.id)}
                            >
                              <div className="xdrSentryGoalOption__header">
                                <strong>{goal.title}</strong>
                                <EuiBadge color="hollow">{goal.confidence}</EuiBadge>
                              </div>
                              <div className="xdrSentryGoalOption__body">{goal.rationale}</div>
                              <div className="xdrSentryBadgeCloud">
                                {(goal.detectedTechnologies ?? []).map((technology) => (
                                  <EuiBadge key={`${goal.id}-${technology}`}>{technology}</EuiBadge>
                                ))}
                              </div>
                            </button>
                          ))
                        )}
                      </>
                    )}
                  </div>
                  <EuiPanel className="xdrSentryThinkingPanel xdrSentryGoalLayout__thinking" color="subdued" paddingSize="s">
                    <EuiText size="s">
                      <strong>Goal discovery thinking</strong>
                    </EuiText>
                    {suggestingGoals ? (
                      <>
                        <EuiSpacer size="s" />
                        <EuiLoadingSpinner size="m" />
                      </>
                    ) : null}
                    <EuiSpacer size="s" />
                    <div className="xdrSentryThinkingLog" role="log" aria-live="polite" ref={goalThinkingLogRef} onScroll={handleGoalThinkingScroll}>
                      {goalSuggestionActivity.length === 0 ? (
                        <p className="xdrSentryThinkingLog__line xdrSentryThinkingLog__line--placeholder">No goal discovery activity yet.</p>
                      ) : goalSuggestionActivity.map((line, index) => (
                        <p className="xdrSentryThinkingLog__line" key={`goal-thinking-${index}`}>
                          {line}
                        </p>
                      ))}
                      {goalSuggestionPendingLine ? (
                        <p className="xdrSentryThinkingLog__line xdrSentryThinkingLog__line--pending">
                          <span className="xdrSentryThinkingLog__emoji" aria-hidden="true">⏳</span> {goalSuggestionPendingLine}
                        </p>
                      ) : null}
                    </div>
                  </EuiPanel>
                </div>

                <EuiSpacer size="m" />
                <EuiTitle size="xs">
                  <h4>Scope compiler</h4>
                </EuiTitle>
                <EuiSpacer size="s" />
                <EuiFlexGroup gutterSize="s">
                  <EuiFlexItem>
                    <EuiFormRow label="Include index patterns (comma separated)">
                      <EuiFieldText value={includePatterns} onChange={(event) => setIncludePatterns(event.target.value)} />
                    </EuiFormRow>
                  </EuiFlexItem>
                  <EuiFlexItem>
                    <EuiFormRow label="Exclude index patterns (comma separated)">
                      <EuiFieldText value={excludePatterns} onChange={(event) => setExcludePatterns(event.target.value)} />
                    </EuiFormRow>
                  </EuiFlexItem>
                </EuiFlexGroup>
                <EuiFlexGroup gutterSize="s">
                  <EuiFlexItem>
                    <EuiFormRow label="Query filter" helpText="Use your Discover query expression to narrow the evidence scan.">
                      <EuiFieldSearch
                        fullWidth
                        value={queryText}
                        onChange={(event) => setQueryText(event.target.value)}
                        placeholder="event.category:process and host.name:prod-*"
                      />
                    </EuiFormRow>
                  </EuiFlexItem>
                  <EuiFlexItem>
                    <EuiFormRow label="Time range" helpText="Discover-style picker for investigation time boundaries.">
                      <EuiSuperDatePicker
                        start={timeFrom}
                        end={timeTo}
                        onTimeChange={({ start, end }) => {
                          setTimeFrom(start);
                          setTimeTo(end);
                        }}
                        showUpdateButton={false}
                      />
                    </EuiFormRow>
                  </EuiFlexItem>
                </EuiFlexGroup>
                <EuiFlexGroup gutterSize="s">
                  <EuiFlexItem>
                    <EuiFormRow
                      label="Max index families to profile"
                      helpText="Upper bound on how many matched index families will go through full understanding analysis in this run."
                    >
                      <EuiFieldText value={maxProfiles} onChange={(event) => setMaxProfiles(event.target.value)} />
                    </EuiFormRow>
                  </EuiFlexItem>
                  <EuiFlexItem>
                    <EuiFormRow
                      label="Max sampled evidence docs per index"
                      helpText="Upper bound of document samples collected from each eligible index family for evidence cards."
                    >
                      <EuiFieldText value={maxEvidencePerIndex} onChange={(event) => setMaxEvidencePerIndex(event.target.value)} />
                    </EuiFormRow>
                  </EuiFlexItem>
                </EuiFlexGroup>
              </EuiPanel>

              <EuiSpacer size="m" />
              <EuiPanel className="xdrSentryCard" paddingSize="m">
                <p className="xdrSentryEyebrow">Research Sources</p>
                <EuiTitle size="s">
                  <h3>Trusted-source registry</h3>
                </EuiTitle>
                <EuiSpacer size="s" />
                <div className="xdrSentrySourceTable" role="table" aria-label="Trusted source registry">
                  <div className="xdrSentrySourceTable__head" role="row">
                    <div>Source</div>
                    <div>Type</div>
                    <div>URL</div>
                    <div>Trust</div>
                    <div>Enabled</div>
                  </div>
                  {sourcePresets.map((preset) => (
                    <div className="xdrSentrySourceTable__row" key={preset.id} role="row">
                      <div className="xdrSentrySourceCell__name"><strong>{preset.name}</strong></div>
                      <div>{preset.type}</div>
                      <div className="xdrSentrySourceCell__url">{preset.url}</div>
                      <div>{preset.trustLevel}</div>
                      <div>
                        <EuiSwitch
                          compressed
                          showLabel={false}
                          label={preset.name}
                          checked={enabledSourceIds.includes(preset.id)}
                          onChange={(event) => toggleSourcePreset(preset.id, event.target.checked)}
                        />
                      </div>
                    </div>
                  ))}
                </div>

                <EuiHorizontalRule margin="m" />
                <EuiTitle size="xs">
                  <h4>Add custom source</h4>
                </EuiTitle>
                <EuiSpacer size="s" />
                <EuiFormRow label="Name">
                  <EuiFieldText value={newSourceName} onChange={(event) => setNewSourceName(event.target.value)} />
                </EuiFormRow>
                <EuiFormRow label="URL">
                  <EuiFieldText value={newSourceUrl} onChange={(event) => setNewSourceUrl(event.target.value)} />
                </EuiFormRow>
                <EuiFormRow label="Type">
                  <EuiSelect
                    options={[
                      { value: 'custom', text: 'Custom' },
                      { value: 'blog', text: 'Blog' },
                      { value: 'advisory', text: 'Advisory' },
                      { value: 'repository', text: 'Repository' },
                    ]}
                    value={newSourceType}
                    onChange={(event) => setNewSourceType(event.target.value)}
                  />
                </EuiFormRow>
                <EuiButton size="s" onClick={addCustomSource}>Add custom source</EuiButton>

                {customSources.length > 0 ? <EuiSpacer size="m" /> : null}
                {customSources.map((source) => (
                  <div className="xdrSentryCustomSource" key={source.id}>
                    <div>
                      <strong>{source.name}</strong>
                      <div>{source.url}</div>
                    </div>
                    <EuiButtonEmpty color="danger" size="s" onClick={() => removeCustomSource(source.id)}>
                      Remove
                    </EuiButtonEmpty>
                  </div>
                ))}
              </EuiPanel>
            </div>

            <div className="xdrSentryWorkbench__canvas">
              <EuiPanel className="xdrSentryCard xdrSentryCard--flat" paddingSize="m">
                <div className="xdrSentryToolbar">
                  <div>
                    <p className="xdrSentryEyebrow">Run Controls</p>
                    <h3 className="xdrSentryToolbar__title">{selectedGoal || 'Approve a goal to begin'}</h3>
                  </div>
                  <div className="xdrSentryToolbar__actions">
                    <EuiButtonIcon
                      iconType="gear"
                      aria-label="Open LLM provider settings"
                      onClick={() => setIsProviderFlyoutOpen(true)}
                      title="Open LLM provider settings"
                    />
                    <EuiButton onClick={() => refreshLandscape(true)} isLoading={profiling}>Refresh index understanding</EuiButton>
                    <EuiButton onClick={previewPlan} isLoading={buildingPlan}>Preview plan</EuiButton>
                    <EuiButton fill onClick={runGoalInvestigation} isLoading={runningInvestigation}>Run investigation</EuiButton>
                  </div>
                </div>
              </EuiPanel>

              <EuiSpacer size="m" />
              <div className="xdrSentrySummaryBand">
                <div className="xdrSentrySummaryChip">
                  <span className="xdrSentrySummaryChip__label">Readiness</span>
                  <strong>{plan?.readinessGate?.canInvestigate ? 'Investigable' : 'Awaiting readiness'}</strong>
                </div>
                <div className="xdrSentrySummaryChip">
                  <span className="xdrSentrySummaryChip__label">Research notes</span>
                  <strong>{formatCount(researchSignals.length || result?.researchNotes?.length)}</strong>
                </div>
                <div className="xdrSentrySummaryChip">
                  <span className="xdrSentrySummaryChip__label">Evidence cards</span>
                  <strong>{formatCount(result?.evidenceCards?.length)}</strong>
                </div>
                <div className="xdrSentrySummaryChip">
                  <span className="xdrSentrySummaryChip__label">Outcome</span>
                  <EuiBadge color={getOutcomeColor(result?.decision?.state ?? 'Inconclusive')}>
                    {result?.decision?.state ?? 'Not run yet'}
                  </EuiBadge>
                </div>
              </div>

              {researchSignals.length > 0 ? (
                <>
                  <EuiSpacer size="m" />
                  <EuiPanel className="xdrSentryCard" paddingSize="m">
                    <p className="xdrSentryEyebrow">Matched external research</p>
                    <div className="xdrSentryFeedList">
                      {researchSignals.map((signal) => (
                        <div className="xdrSentryFeedItem" key={signal.id}>
                          <strong>{signal.title}</strong>
                          <span>{signal.sourceName}</span>
                        </div>
                      ))}
                    </div>
                  </EuiPanel>
                </>
              ) : null}

              {profileCards.length > 0 ? (
                <>
                  <EuiSpacer size="m" />
                  <EuiPanel className="xdrSentryCard" paddingSize="m">
                    <p className="xdrSentryEyebrow">Index atlas</p>
                    <EuiTitle size="s">
                      <h3>What the selected logs appear to contain</h3>
                    </EuiTitle>
                    <EuiSpacer size="s" />
                    <div className="xdrSentryAtlasGrid">
                      {profileCards.map((profile: any) => (
                        <div className="xdrSentryAtlasCard" key={profile.index}>
                          <div className="xdrSentryAtlasCard__header">
                            <strong>{profile.index}</strong>
                            <EuiBadge color={profile.understandable ? 'success' : 'warning'}>
                              {getLandscapeStatus(profile)}
                            </EuiBadge>
                          </div>
                          <div className="xdrSentryAtlasCard__meta">
                            <span>{profile.technology}</span>
                            <span>{profile.ecsCoverage?.status}</span>
                            <span>{profile.timestampField ?? 'no timestamp'}</span>
                          </div>
                          <p>{(profile.notes ?? [])[0] ?? 'Index family is currently fit for investigation.'}</p>
                          <div className="xdrSentryBadgeCloud">
                            {(profile.meaningfulFields ?? []).slice(0, 5).map((field: string) => (
                              <EuiBadge key={`${profile.index}-${field}`} color="hollow">
                                {field}
                              </EuiBadge>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  </EuiPanel>
                </>
              ) : null}

              {plan ? (
                <>
                  <EuiSpacer size="m" />
                  <EuiPanel className="xdrSentryCard" paddingSize="m">
                    <p className="xdrSentryEyebrow">Plan preview</p>
                    <EuiCallOut
                      title={plan?.readinessGate?.canInvestigate ? 'Ready to investigate' : 'Blocked by data readiness gate'}
                      color={plan?.readinessGate?.canInvestigate ? 'success' : 'warning'}
                      size="s"
                    >
                      <p>{(plan?.readinessGate?.reasons ?? []).join(' ')}</p>
                    </EuiCallOut>
                    <EuiSpacer size="m" />
                    <div className="xdrSentryBranchGrid">
                      {(plan?.branches ?? []).map((branch: any) => (
                        <div className="xdrSentryBranchCard" key={branch.id}>
                          <div className="xdrSentryBranchCard__header">
                            <strong>{branch.label}</strong>
                            <EuiBadge color={branch.status === 'ready' ? 'success' : 'warning'}>{branch.status}</EuiBadge>
                          </div>
                          <p>{branch.reason}</p>
                          <div className="xdrSentryBranchCard__indices">{(branch.indices ?? []).join(', ')}</div>
                        </div>
                      ))}
                    </div>
                  </EuiPanel>
                </>
              ) : null}

              {result ? (
                <>
                  <EuiSpacer size="m" />
                  <EuiPanel className="xdrSentryCard" paddingSize="m">
                    <div className="xdrSentryResultHeader">
                      <div>
                        <p className="xdrSentryEyebrow">Investigation outcome</p>
                        <h3 className="xdrSentryResultHeader__title">{result?.report?.executiveSummary}</h3>
                      </div>
                      <EuiBadge color={getOutcomeColor(result?.decision?.state)}>{result?.decision?.state}</EuiBadge>
                    </div>
                    <p className="xdrSentryResultHeader__confidence">Confidence: {result?.decision?.confidence}</p>
                  </EuiPanel>

                  <EuiSpacer size="m" />
                  <div className="xdrSentryGraphLayout">
                    <EuiPanel className="xdrSentryCard xdrSentryCanvasCard" paddingSize="m">
                      <p className="xdrSentryEyebrow">Live investigation graph</p>
                      <div className="xdrSentryGraphRail">
                        {graphColumns.map((column: any, index: number) => (
                          <div className="xdrSentryGraphRail__step" key={column.id}>
                            <div className="xdrSentryGraphRail__dot">{index + 1}</div>
                            <div>
                              <strong>{column.title}</strong>
                              <span>{column.subtitle}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                      <div className="xdrSentryGraphColumns">
                        {graphColumns.map((column: any) => (
                          <div className="xdrSentryGraphColumn" key={column.id}>
                            <div className="xdrSentryGraphColumn__header">
                              <strong>{column.title}</strong>
                              <span>{column.subtitle}</span>
                            </div>
                            <div className="xdrSentryGraphColumn__body">
                              {graphNodes.filter((node: any) => node.columnId === column.id).map((node: any) => (
                                <button
                                  type="button"
                                  key={node.id}
                                  className={`xdrSentryNodeCard ${getNodeTone(node.status)} ${selectedNode?.id === node.id ? 'isSelected' : ''}`}
                                  onClick={() => setSelectedNodeId(node.id)}
                                >
                                  <div className="xdrSentryNodeCard__header">
                                    <span className="xdrSentryNodeCard__status">{node.status}</span>
                                    <span className="xdrSentryNodeCard__duration">{node.durationMs} ms</span>
                                  </div>
                                  <strong>{node.role}</strong>
                                  <div className="xdrSentryNodeCard__task">{node.task}</div>
                                  <div className="xdrSentryNodeCard__summary">{node.summary}</div>
                                  <div className="xdrSentryNodeCard__meta">
                                    <span>{node.evidenceCount} evidence</span>
                                    {node.branchId ? <span>{node.branchId}</span> : null}
                                  </div>
                                </button>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </EuiPanel>

                    <EuiPanel className="xdrSentryCard xdrSentryInspector" paddingSize="m">
                      <p className="xdrSentryEyebrow">Agent detail</p>
                      {selectedNode ? (
                        <>
                          <div className="xdrSentryInspector__header">
                            <div>
                              <h3>{selectedNode.role}</h3>
                              <p>{selectedNode.task}</p>
                            </div>
                            <EuiBadge color="hollow">{selectedNode.status}</EuiBadge>
                          </div>
                          <div className="xdrSentryInspector__section">
                            <strong>Focus</strong>
                            <p>{selectedNode.detail?.goalOrHypothesis}</p>
                          </div>
                          <div className="xdrSentryInspector__section">
                            <strong>Reasoning trace</strong>
                            {(selectedNode.detail?.reasoningTrace ?? []).map((entry: string, index: number) => (
                              <div className="xdrSentryInspector__listItem" key={`${selectedNode.id}-trace-${index}`}>{entry}</div>
                            ))}
                          </div>
                          <div className="xdrSentryInspector__section">
                            <strong>Queries and pivots</strong>
                            {[...(selectedNode.detail?.queries ?? []), ...(selectedNode.detail?.pivots ?? [])].map((entry: string, index: number) => (
                              <div className="xdrSentryInspector__listItem" key={`${selectedNode.id}-query-${index}`}>{entry}</div>
                            ))}
                          </div>
                          <div className="xdrSentryInspector__section">
                            <strong>Lookups and evidence excerpts</strong>
                            {[...(selectedNode.detail?.lookups ?? []), ...(selectedNode.detail?.evidenceExcerpts ?? [])].map((entry: string, index: number) => (
                              <div className="xdrSentryInspector__listItem" key={`${selectedNode.id}-lookup-${index}`}>{entry}</div>
                            ))}
                          </div>
                          <div className="xdrSentryInspector__section">
                            <strong>Completion reason</strong>
                            <p>{selectedNode.detail?.completionReason}</p>
                          </div>
                          <div className="xdrSentryInspector__section">
                            <strong>Dependencies</strong>
                            <p>Incoming: {selectedNodeIncoming.map((edge: any) => edge.source).join(', ') || 'none'}</p>
                            <p>Outgoing: {selectedNodeOutgoing.map((edge: any) => edge.target).join(', ') || 'none'}</p>
                          </div>
                        </>
                      ) : (
                        <EuiText size="s">
                          <p>Select a node on the graph to inspect its details.</p>
                        </EuiText>
                      )}
                    </EuiPanel>
                  </div>

                  <EuiSpacer size="m" />
                  <div className="xdrSentryEvidenceLayout">
                    <EuiPanel className="xdrSentryCard" paddingSize="m">
                      <p className="xdrSentryEyebrow">Branch conclusions</p>
                      <div className="xdrSentryBranchGrid">
                        {branchCards.map((branch: any) => (
                          <div className="xdrSentryBranchCard" key={branch.branchId}>
                            <div className="xdrSentryBranchCard__header">
                              <strong>{branch.label}</strong>
                              <EuiBadge color={branch.status === 'evidence-backed' ? 'danger' : branch.status === 'blocked' ? 'warning' : 'primary'}>
                                {branch.status}
                              </EuiBadge>
                            </div>
                            <p>{branch.finalExplanation}</p>
                            <div className="xdrSentryBranchCard__indices">{branch.strongestHypothesis}</div>
                          </div>
                        ))}
                      </div>
                    </EuiPanel>

                    <EuiPanel className="xdrSentryCard" paddingSize="m">
                      <p className="xdrSentryEyebrow">Evidence cards</p>
                      <div className="xdrSentryEvidenceGrid">
                        {(result?.evidenceCards ?? []).map((card: any) => (
                          <div className="xdrSentryEvidenceCard" key={card.id}>
                            <div className="xdrSentryEvidenceCard__header">
                              <strong>{card.index}</strong>
                              <span>{card.timestamp}</span>
                            </div>
                            <div className="xdrSentryEvidenceCard__summary">{card.summary}</div>
                            {(card.supportingFields ?? []).slice(0, 3).map((field: any) => (
                              <div className="xdrSentryEvidenceCard__field" key={`${card.id}-${field.field}`}>
                                <span>{field.field}</span>
                                <strong>{String(field.value ?? 'n/a')}</strong>
                              </div>
                            ))}
                          </div>
                        ))}
                      </div>
                    </EuiPanel>
                  </div>

                  <EuiSpacer size="m" />
                  <EuiPanel className="xdrSentryCard" paddingSize="m">
                    <p className="xdrSentryEyebrow">LLM execution trace</p>
                    <div className="xdrSentryReportGrid">
                      <div>
                        <strong>Mode</strong>
                        <p>{result?.llmTrace?.mode ?? 'n/a'}</p>
                      </div>
                      <div>
                        <strong>Protocol and endpoint</strong>
                        <p>{`${result?.llmTrace?.protocol ?? 'unknown'} | ${result?.llmTrace?.endpoint ?? 'n/a'}`}</p>
                      </div>
                      <div>
                        <strong>Assistant summaries</strong>
                        <p>
                          {(result?.llmTrace?.assistantSummaries ?? [])
                            .map((entry: any) => `${entry.step}. ${entry.summary}`)
                            .join(' | ') || 'No summaries captured.'}
                        </p>
                      </div>
                      <div>
                        <strong>Key intermediate decisions</strong>
                        <p>{(result?.llmTrace?.keyIntermediateDecisions ?? []).join(' | ') || 'No decision trace captured.'}</p>
                      </div>
                    </div>
                    <EuiSpacer size="s" />
                    <EuiCodeBlock language="json" isCopyable>
                      {JSON.stringify(result?.llmTrace ?? {}, null, 2)}
                    </EuiCodeBlock>
                  </EuiPanel>

                  <EuiSpacer size="m" />
                  <EuiPanel className="xdrSentryCard" paddingSize="m">
                    <p className="xdrSentryEyebrow">Analyst report</p>
                    <div className="xdrSentryReportGrid">
                      <div>
                        <strong>Goal</strong>
                        <p>{result?.report?.goal}</p>
                      </div>
                      <div>
                        <strong>Indices used</strong>
                        <p>{(result?.report?.usedIndices ?? []).join(', ') || 'none'}</p>
                      </div>
                      <div>
                        <strong>Main gaps</strong>
                        <p>{(result?.report?.limitations ?? []).join(' ') || 'None recorded.'}</p>
                      </div>
                      <div>
                        <strong>Recommended next steps</strong>
                        <p>{(result?.report?.recommendedNextSteps ?? []).join(' | ')}</p>
                      </div>
                    </div>
                    <EuiSpacer size="m" />
                    <EuiCodeBlock language="json" isCopyable>
                      {JSON.stringify(
                        {
                          auditTrail: result?.auditTrail,
                          branchConclusions: result?.branchConclusions,
                          decision: result?.decision,
                          llmTrace: result?.llmTrace,
                        },
                        null,
                        2
                      )}
                    </EuiCodeBlock>
                  </EuiPanel>
                </>
              ) : null}
            </div>
          </div>
        ) : null}

        {activeTab === 'history' ? (
          <div className="xdrSentryHistoryGrid">
            <EuiPanel className="xdrSentryCard" paddingSize="m">
              <p className="xdrSentryEyebrow">Recent runs</p>
              {history.length === 0 ? (
                <EuiText size="s">
                  <p>No investigations have been run yet.</p>
                </EuiText>
              ) : (
                history.map((entry) => (
                  <div className="xdrSentryHistoryRow" key={entry.runId}>
                    <div>
                      <strong>{entry.goal}</strong>
                      <div>{entry.generatedAt}</div>
                    </div>
                    <div className="xdrSentryHistoryRow__meta">
                      <EuiBadge color={getOutcomeColor(entry.state)}>{entry.state}</EuiBadge>
                      <span>{entry.confidence}</span>
                    </div>
                  </div>
                ))
              )}
            </EuiPanel>

            <EuiPanel className="xdrSentryCard" paddingSize="m">
              <p className="xdrSentryEyebrow">Release readiness</p>
              <EuiTitle size="s">
                <h3>xdr-security bundle expectations</h3>
              </EuiTitle>
              <EuiSpacer size="s" />
              <EuiText size="s">
                <p>xdr-sentry must ship as a required bundle artifact alongside xdr-security, xdr-coordinator, xdr-defense, and xdr-visualizer.</p>
                <p>The release wrapper should fail if the expected sentry ZIP is missing from the assembled bundle.</p>
              </EuiText>
            </EuiPanel>
          </div>
        ) : null}

        {isProviderFlyoutOpen ? (
          <EuiFlyout onClose={closeProviderFlyout} ownFocus>
            <EuiFlyoutHeader hasBorder>
              <EuiTitle size="m">
                <h2>LLM provider settings</h2>
              </EuiTitle>
              <EuiText size="s" color="subdued">
                <p>Persisted server-side and reused for goal generation and investigation runs.</p>
              </EuiText>
            </EuiFlyoutHeader>

            <EuiFlyoutBody>
              <EuiForm component="form">
                <EuiFormRow label="Base URL (OpenAI-compatible)">
                  <EuiFieldText
                    value={providerBaseUrlInput}
                    isLoading={loadingProviderConfig}
                    onChange={(event) => setProviderBaseUrlInput(event.target.value)}
                    placeholder="https://api.openai.com/v1"
                  />
                </EuiFormRow>
                <EuiFormRow label="Model">
                  <EuiFieldText
                    value={providerModelInput}
                    isLoading={loadingProviderConfig}
                    onChange={(event) => setProviderModelInput(event.target.value)}
                    placeholder={DEFAULT_PROVIDER_MODEL}
                  />
                </EuiFormRow>
                <EuiFormRow label="API key (leave blank to keep current)">
                  <EuiFieldText
                    type="text"
                    value={providerApiKeyInput}
                    onChange={(event) => setProviderApiKeyInput(event.target.value)}
                    placeholder={providerConfig.hasApiKey ? 'Stored key exists' : 'sk-...'}
                  />
                </EuiFormRow>
                <EuiButton onClick={testProviderConnection} isLoading={testingProviderConnection} iconType="inspect" size="s">
                  Test LLM connection
                </EuiButton>
                {testingProviderConnection || providerTestActivity.length > 0 || providerTestLog ? (
                  <>
                    <EuiSpacer size="m" />
                    <EuiPanel color="subdued" paddingSize="m">
                      <EuiTitle size="xs">
                        <h4>Connection Test Stream</h4>
                      </EuiTitle>
                      <EuiSpacer size="s" />
                      {testingProviderConnection ? (
                        <>
                          <EuiLoadingSpinner size="m" />
                          <EuiSpacer size="s" />
                        </>
                      ) : null}
                      {providerTestActivity.length > 0 ? (
                        <>
                          <EuiCodeBlock language="text" fontSize="s" paddingSize="s" isCopyable={false} transparentBackground>
                            {providerTestActivity.join('\n')}
                          </EuiCodeBlock>
                          <EuiSpacer size="s" />
                        </>
                      ) : null}
                      {providerTestLog ? (
                        <>
                      <EuiText size="s">
                        <p>
                          {providerTestLog.testedAt} | {providerTestLog.protocol} | {providerTestLog.latencyMs} ms
                        </p>
                        <p>{providerTestLog.endpoint}</p>
                      </EuiText>
                      {providerTestLog.thinkingSummary.length > 0 ? (
                        <>
                          <EuiSpacer size="s" />
                          <EuiText size="s">
                            <strong>Thinking summary</strong>
                            {providerTestLog.thinkingSummary.map((line, index) => (
                              <p key={`provider-thinking-${index}`}>{`${index + 1}. ${line}`}</p>
                            ))}
                          </EuiText>
                        </>
                      ) : null}
                      <EuiSpacer size="s" />
                      <EuiText size="s">
                        <strong>Response</strong>
                        <p>{providerTestLog.response}</p>
                      </EuiText>
                        </>
                      ) : null}
                    </EuiPanel>
                  </>
                ) : null}
              </EuiForm>
            </EuiFlyoutBody>

            <EuiFlyoutFooter>
              <EuiButtonEmpty onClick={closeProviderFlyout}>Cancel</EuiButtonEmpty>
              <EuiButton onClick={saveProviderConfig} isLoading={savingProviderConfig} fill>
                Save provider config
              </EuiButton>
            </EuiFlyoutFooter>
          </EuiFlyout>
        ) : null}
      </EuiPageBody>
    </EuiPage>
  );
};
