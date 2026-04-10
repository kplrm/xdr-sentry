import React, { useCallback, useEffect, useState } from 'react';
import {
  EuiBadge,
  EuiButton,
  EuiCallOut,
  EuiCodeBlock,
  EuiFieldPassword,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
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
  reputation: string;
}

interface CustomSource {
  id: string;
  name: string;
  url: string;
}

interface SuggestedGoal {
  id: string;
  title: string;
  rationale: string;
  sources: string[];
  confidence: string;
  type: string;
}

interface InvestigationPlan {
  selectedGoal: string;
  technologies: string[];
  provider: {
    preset: string;
    baseUrl: string;
    model: string;
    hasApiKey: boolean;
  };
  steps: string[];
}

interface PhaseState {
  name: string;
  status: 'completed' | 'failed';
  detail: string;
}

interface ActivityEntry {
  ts: string;
  phase: string;
  message: string;
}

interface InvestigationResult {
  selectedGoal: string;
  executionMode: 'llm-assisted' | string;
  llmProviderConfigured: boolean;
  llmProviderUsed: boolean;
  provider: {
    preset: string;
    baseUrl: string;
    model: string;
    hasApiKey: boolean;
  };
  inferredTechnologies: string[];
  usedIndices: string[];
  phases: PhaseState[];
  activityLog: ActivityEntry[];
  findings: {
    sampledEvents: number;
    topHosts: Array<{ name: string; count: number }>;
    topUsers: Array<{ name: string; count: number }>;
  };
  hypotheses: string[];
  evidenceIds: string[];
  status: 'completed' | 'partial';
}

interface AgentPhaseScript {
  id: string;
  name: string;
  toolName: string;
  purpose: string;
  instructions: string;
}

interface IndexRow {
  index?: string;
  status?: string;
  health?: string;
  ['docs.count']?: string;
}

type AppTabId = 'investigation' | 'configuration' | 'dataQuality';

const WORKFLOW_NODES: Array<{ id: string; label: string }> = [
  { id: 'source-intel', label: 'Source Intel' },
  { id: 'scope', label: 'Scope' },
  { id: 'schema', label: 'Schema' },
  { id: 'selection', label: 'Selection' },
  { id: 'hypothesis', label: 'Hypothesis' },
  { id: 'validation', label: 'Validation' },
  { id: 'decision', label: 'Decision' },
];

export const XdrSentryApp: React.FC<Props> = ({ http, notifications }) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<AppTabId>('investigation');

  const [goalMode, setGoalMode] = useState<'human' | 'agent'>('human');
  const [humanGoal, setHumanGoal] = useState<string>(
    'Investigate suspicious lateral movement in endpoint telemetry over the last 6 hours.'
  );
  const [sourcePresets, setSourcePresets] = useState<SourcePreset[]>([]);
  const [enabledSourceIds, setEnabledSourceIds] = useState<string[]>([]);
  const [customSources, setCustomSources] = useState<CustomSource[]>([]);
  const [newSourceName, setNewSourceName] = useState<string>('');
  const [newSourceUrl, setNewSourceUrl] = useState<string>('');
  const [suggestedGoals, setSuggestedGoals] = useState<SuggestedGoal[]>([]);
  const [selectedGoalId, setSelectedGoalId] = useState<string>('');

  const [technologies, setTechnologies] = useState<string[]>([]);
  const [indexRows, setIndexRows] = useState<IndexRow[]>([]);
  const [dataQualityLoading, setDataQualityLoading] = useState<boolean>(false);
  const [lastDataProfileAt, setLastDataProfileAt] = useState<string>('');

  const [providerPreset, setProviderPreset] = useState<string>('nvidia');
  const [providerUrl, setProviderUrl] = useState<string>('https://integrate.api.nvidia.com/v1');
  const [providerModel, setProviderModel] = useState<string>('meta/llama-3.1-70b-instruct');
  const [providerApiKey, setProviderApiKey] = useState<string>('');
  const [providerSaveLoading, setProviderSaveLoading] = useState<boolean>(false);

  const [plan, setPlan] = useState<InvestigationPlan | null>(null);
  const [runningPreview, setRunningPreview] = useState<boolean>(false);
  const [liveLog, setLiveLog] = useState<ActivityEntry[]>([]);
  const [livePhases, setLivePhases] = useState<string[]>([]);
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const [selectedWorkflowPhase, setSelectedWorkflowPhase] = useState<string>('');
  const [agentScripts, setAgentScripts] = useState<AgentPhaseScript[]>([]);

  const loadIndexProfile = useCallback(
    async (showToast: boolean) => {
      setDataQualityLoading(true);
      try {
        const indexRes = await http.get('/api/xdr_sentry/index_profile');
        const discoveredTech = indexRes?.technologies ?? [];
        const discoveredRows = indexRes?.indices ?? [];
        setTechnologies(discoveredTech);
        setIndexRows(discoveredRows);
        setLastDataProfileAt(new Date().toISOString());
        if (showToast) {
          notifications.toasts.addSuccess('Data quality profile refreshed.');
        }
      } catch (error: any) {
        notifications.toasts.addDanger(`Failed to profile indices: ${error?.message ?? 'unknown error'}`);
      } finally {
        setDataQualityLoading(false);
      }
    },
    [http, notifications]
  );

  const loadBootstrap = useCallback(async () => {
    setLoading(true);
    try {
      const presetsRes = await http.get('/api/xdr_sentry/source_presets');
      const presets: SourcePreset[] = presetsRes?.presets ?? [];
      setSourcePresets(presets);
      setEnabledSourceIds(presets.slice(0, 3).map((preset) => preset.id));

      const scriptsRes = await http.get('/api/xdr_sentry/agent_scripts');
      setAgentScripts(scriptsRes?.scripts ?? []);

      const providerRes = await http.get('/api/xdr_sentry/provider_config');
      const savedProvider = providerRes?.provider ?? {};
      if (savedProvider?.preset) {
        setProviderPreset(savedProvider.preset);
      }
      if (savedProvider?.baseUrl) {
        setProviderUrl(savedProvider.baseUrl);
      }
      if (savedProvider?.model) {
        setProviderModel(savedProvider.model);
      }
      if (savedProvider?.apiKey) {
        setProviderApiKey(savedProvider.apiKey);
      }

      await loadIndexProfile(false);
    } catch (error: any) {
      notifications.toasts.addDanger(`Failed to initialize XDR Sentry: ${error?.message ?? 'unknown error'}`);
    } finally {
      setLoading(false);
    }
  }, [http, loadIndexProfile, notifications]);

  useEffect(() => {
    loadBootstrap();
  }, [loadBootstrap]);

  const onTogglePreset = (presetId: string, checked: boolean) => {
    if (checked) {
      setEnabledSourceIds((previous) => Array.from(new Set([...previous, presetId])));
      return;
    }
    setEnabledSourceIds((previous) => previous.filter((id) => id !== presetId));
  };

  const addCustomSource = () => {
    if (!newSourceName.trim() || !newSourceUrl.trim()) {
      notifications.toasts.addWarning('Custom source name and URL are required.');
      return;
    }
    const id = `custom-${Date.now()}`;
    setCustomSources((previous) => [...previous, { id, name: newSourceName.trim(), url: newSourceUrl.trim() }]);
    setNewSourceName('');
    setNewSourceUrl('');
  };

  const removeCustomSource = (id: string) => {
    setCustomSources((previous) => previous.filter((source) => source.id !== id));
  };

  const proposeAgentGoals = useCallback(async (): Promise<SuggestedGoal[]> => {
    try {
      const res = await http.post('/api/xdr_sentry/propose_goals', {
        body: JSON.stringify({
          enabledSourceIds,
          customSources,
        }),
      });
      const goals: SuggestedGoal[] = res?.goals ?? [];
      setSuggestedGoals(goals);
      setTechnologies(res?.technologies ?? []);
      if (goals.length > 0) {
        setSelectedGoalId(goals[0].id);
      }
      return goals;
    } catch (error: any) {
      notifications.toasts.addDanger(`Failed to propose agent goals: ${error?.message ?? 'unknown error'}`);
      return [];
    }
  }, [customSources, enabledSourceIds, http, notifications]);

  const runInvestigationPreview = async () => {
    setLiveLog([]);
    setLivePhases([]);
    setSelectedWorkflowPhase('');
    setResult(null);

    const appendLive = (phase: string, message: string) => {
      const entry = { ts: new Date().toISOString(), phase, message };
      setLiveLog((previous) => [...previous, entry]);
      setLivePhases((previous) => (previous.includes(phase) ? previous : [...previous, phase]));
    };

    let resolvedGoal = '';
    const enabledCustomSources = customSources.filter((source) => source?.url);
    const totalEnabledSources = enabledSourceIds.length + enabledCustomSources.length;
    appendLive('source-intel', `Prepared ${totalEnabledSources} enabled source(s) for this run.`);

    if (goalMode === 'human') {
      resolvedGoal = humanGoal.trim();
      appendLive('scope', 'Using human-defined investigation goal.');
    } else {
      let goals = suggestedGoals;
      let chosenId = selectedGoalId;

      if (goals.length === 0) {
        appendLive('goal-discovery', 'Generating agent-proposed goals from enabled sources.');
        goals = await proposeAgentGoals();
      }
      if (!chosenId && goals.length > 0) {
        chosenId = goals[0].id;
        setSelectedGoalId(chosenId);
      }
      resolvedGoal = goals.find((goal) => goal.id === chosenId)?.title ?? '';
      appendLive('goal-discovery', 'Selected agent-proposed goal for execution.');
    }

    if (!resolvedGoal) {
      notifications.toasts.addWarning('Please provide or select an investigation goal first.');
      return;
    }

    try {
      setRunningPreview(true);
      appendLive('schema', 'Profiling active index landscape and technology coverage.');
      await loadIndexProfile(false);

      appendLive('execution', 'Starting investigation pipeline.');
      const res = await http.post('/api/xdr_sentry/run_investigation', {
        body: JSON.stringify({
          selectedGoal: resolvedGoal,
          technologies,
          enabledSourceIds,
          customSources: enabledCustomSources,
          provider: {
            preset: providerPreset,
            baseUrl: providerUrl,
            model: providerModel,
            apiKey: providerApiKey,
          },
        }),
      });
      const investigationResult: InvestigationResult | null = res?.result ?? null;
      setResult(investigationResult);

      if (investigationResult?.activityLog?.length) {
        setLiveLog((previous) => [...previous, ...investigationResult.activityLog]);
      }
      if (investigationResult?.phases?.length) {
        setLivePhases((previous) => {
          const names = investigationResult.phases.map((phase) => phase.name.toLowerCase());
          return Array.from(new Set([...previous, ...names]));
        });
      }

      notifications.toasts.addSuccess('Agentic investigation completed.');
    } catch (error: any) {
      notifications.toasts.addDanger(`Failed to run investigation: ${error?.message ?? 'unknown error'}`);
      appendLive('error', `Investigation failed: ${error?.message ?? 'unknown error'}`);
    } finally {
      setRunningPreview(false);
    }
  };

  const onProviderPresetChange = (preset: string) => {
    setProviderPreset(preset);
    if (preset === 'nvidia') {
      setProviderUrl('https://integrate.api.nvidia.com/v1');
      setProviderModel('meta/llama-3.1-70b-instruct');
      return;
    }
    if (preset === 'groq') {
      setProviderUrl('https://api.groq.com/openai/v1');
      setProviderModel('llama-3.3-70b-versatile');
    }
  };

  const saveProviderSettings = useCallback(async () => {
    try {
      setProviderSaveLoading(true);
      await http.post('/api/xdr_sentry/provider_config', {
        body: JSON.stringify({
          preset: providerPreset,
          baseUrl: providerUrl,
          model: providerModel,
          apiKey: providerApiKey,
        }),
      });
      notifications.toasts.addSuccess('Provider settings saved.');
    } catch (error: any) {
      notifications.toasts.addDanger(`Failed to save provider settings: ${error?.message ?? 'unknown error'}`);
    } finally {
      setProviderSaveLoading(false);
    }
  }, [http, notifications, providerApiKey, providerModel, providerPreset, providerUrl]);

  const displayedLogs = selectedWorkflowPhase
    ? liveLog.filter((entry) => entry.phase.toLowerCase() === selectedWorkflowPhase)
    : liveLog;
  const selectedScript = agentScripts.find((script) => script.id === selectedWorkflowPhase);

  if (loading) {
    return (
      <EuiPage>
        <EuiPageBody>
          <EuiLoadingSpinner size="xl" />
        </EuiPageBody>
      </EuiPage>
    );
  }

  return (
    <EuiPage>
      <EuiPageBody>
        <EuiPageHeader>
          <EuiTitle>
            <h1>XDR Sentry</h1>
          </EuiTitle>
        </EuiPageHeader>

        <EuiText>
          <p>
            Goal-driven investigation MVP with analyst-selected goal mode, source-aware agent goal suggestions, OpenSearch
            index technology inference, and OpenAI-compatible provider configuration.
          </p>
        </EuiText>

        <EuiSpacer size="m" />
        <EuiTabs>
          <EuiTab onClick={() => setActiveTab('investigation')} isSelected={activeTab === 'investigation'}>
            Investigation
          </EuiTab>
          <EuiTab onClick={() => setActiveTab('configuration')} isSelected={activeTab === 'configuration'}>
            Configuration
          </EuiTab>
          <EuiTab onClick={() => setActiveTab('dataQuality')} isSelected={activeTab === 'dataQuality'}>
            Data Quality
          </EuiTab>
        </EuiTabs>

        <EuiSpacer size="m" />

        {activeTab === 'investigation' ? (
          <>
            <EuiPanel paddingSize="m">
              <EuiTitle size="s">
                <h3>Goal selection mode</h3>
              </EuiTitle>
              <EuiSpacer size="s" />
              <EuiRadio
                id="goal-mode-human"
                label="Use human-defined goal"
                checked={goalMode === 'human'}
                onChange={() => setGoalMode('human')}
              />
              <EuiRadio
                id="goal-mode-agent"
                label="Use agent-proposed goal"
                checked={goalMode === 'agent'}
                onChange={() => setGoalMode('agent')}
              />

              <EuiSpacer size="m" />
              <EuiTitle size="xs">
                <h4>Threat source configuration (used in both goal modes)</h4>
              </EuiTitle>
              <EuiSpacer size="s" />
              {sourcePresets.map((preset) => (
                <EuiSwitch
                  key={preset.id}
                  label={`${preset.name} (${preset.type})`}
                  checked={enabledSourceIds.includes(preset.id)}
                  onChange={(event) => onTogglePreset(preset.id, event.target.checked)}
                />
              ))}

              <EuiSpacer size="m" />
              <EuiTitle size="xs">
                <h4>Add custom source</h4>
              </EuiTitle>
              <EuiSpacer size="s" />
              <EuiFormRow label="Source name">
                <EuiFieldText value={newSourceName} onChange={(event) => setNewSourceName(event.target.value)} />
              </EuiFormRow>
              <EuiFormRow label="Source URL">
                <EuiFieldText value={newSourceUrl} onChange={(event) => setNewSourceUrl(event.target.value)} />
              </EuiFormRow>
              <EuiButton size="s" onClick={addCustomSource}>
                Add custom source
              </EuiButton>

              <EuiSpacer size="s" />
              {customSources.map((source) => (
                <EuiFlexGroup key={source.id} alignItems="center" gutterSize="s">
                  <EuiFlexItem grow>
                    <EuiText size="s">
                      {source.name} - {source.url}
                    </EuiText>
                  </EuiFlexItem>
                  <EuiFlexItem grow={false}>
                    <EuiButton size="s" color="danger" onClick={() => removeCustomSource(source.id)}>
                      Remove
                    </EuiButton>
                  </EuiFlexItem>
                </EuiFlexGroup>
              ))}

              <EuiSpacer size="m" />
              {goalMode === 'human' ? (
                <EuiFormRow label="Investigation goal">
                  <EuiTextArea
                    value={humanGoal}
                    onChange={(event) => setHumanGoal(event.target.value)}
                    rows={3}
                    placeholder="Describe the investigation objective"
                  />
                </EuiFormRow>
              ) : (
                <>
                  {suggestedGoals.length === 0 ? (
                    <EuiCallOut
                      size="s"
                      title="Agent goals are generated automatically when running investigation"
                      color="primary"
                    >
                      Enabled source presets and custom sources are used as input for goal generation.
                    </EuiCallOut>
                  ) : null}

                  <EuiSpacer size="m" />
                  {suggestedGoals.map((goal) => (
                    <EuiPanel key={goal.id} color={selectedGoalId === goal.id ? 'primary' : 'subdued'} paddingSize="s">
                      <EuiSwitch
                        label={goal.title}
                        checked={selectedGoalId === goal.id}
                        onChange={(event) => {
                          if (event.target.checked) {
                            setSelectedGoalId(goal.id);
                          }
                        }}
                      />
                      <EuiText size="s">{goal.rationale}</EuiText>
                    </EuiPanel>
                  ))}
                </>
              )}
            </EuiPanel>

            <EuiSpacer size="m" />
            <EuiButton fill onClick={runInvestigationPreview} isLoading={runningPreview}>
              Start agentic investigation
            </EuiButton>

            <EuiSpacer size="m" />
            <EuiPanel paddingSize="m">
              <EuiTitle size="xs">
                <h4>Live agent feedback</h4>
              </EuiTitle>
              <EuiSpacer size="s" />
              {result ? (
                <>
                  <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
                    <EuiFlexItem grow={false}>
                      <EuiBadge color={result.executionMode === 'llm-assisted' ? 'success' : 'hollow'}>
                        Execution mode: {result.executionMode}
                      </EuiBadge>
                    </EuiFlexItem>
                    <EuiFlexItem grow={false}>
                      <EuiBadge color={result.llmProviderUsed ? 'success' : 'warning'}>
                        LLM provider used: {result.llmProviderUsed ? 'yes' : 'no'}
                      </EuiBadge>
                    </EuiFlexItem>
                  </EuiFlexGroup>
                  <EuiSpacer size="s" />
                </>
              ) : null}

              <EuiTitle size="xxs">
                <h5>Workflow graph</h5>
              </EuiTitle>
              <EuiSpacer size="s" />
              <EuiFlexGroup gutterSize="s" wrap>
                {WORKFLOW_NODES.map((node) => {
                  const isSelected = selectedWorkflowPhase === node.id;
                  return (
                    <EuiFlexItem key={node.id} grow={false}>
                      <EuiButton
                        size="s"
                        fill={isSelected}
                        color={isSelected ? 'primary' : 'text'}
                        onClick={() => setSelectedWorkflowPhase((current) => (current === node.id ? '' : node.id))}
                      >
                        {node.label}
                      </EuiButton>
                    </EuiFlexItem>
                  );
                })}
              </EuiFlexGroup>

              <EuiSpacer size="s" />
              <EuiText size="s">
                {selectedWorkflowPhase
                  ? `Showing logs for phase: ${selectedWorkflowPhase}`
                  : 'Showing logs for all phases.'}
              </EuiText>

              {selectedScript ? (
                <>
                  <EuiSpacer size="s" />
                  <EuiCallOut size="s" title={`${selectedScript.name} script: ${selectedScript.toolName}`}>
                    <p>{selectedScript.purpose}</p>
                    <p>{selectedScript.instructions}</p>
                  </EuiCallOut>
                </>
              ) : null}

              <EuiSpacer size="s" />
              {livePhases.length > 0 ? (
                <EuiFlexGroup gutterSize="s" wrap>
                  {livePhases.map((phase) => (
                    <EuiBadge key={phase}>{phase}</EuiBadge>
                  ))}
                </EuiFlexGroup>
              ) : (
                <EuiText size="s">No live events yet.</EuiText>
              )}

              <EuiSpacer size="s" />
              <EuiCodeBlock language="json" isCopyable>
                {JSON.stringify(displayedLogs, null, 2)}
              </EuiCodeBlock>
            </EuiPanel>

            {result ? (
              <>
                <EuiHorizontalRule />
                <EuiTitle size="s">
                  <h3>Investigation result</h3>
                </EuiTitle>
                <EuiSpacer size="s" />
                <EuiCodeBlock language="json" isCopyable>
                  {JSON.stringify(result, null, 2)}
                </EuiCodeBlock>
              </>
            ) : plan ? (
              <>
                <EuiHorizontalRule />
                <EuiTitle size="s">
                  <h3>Investigation preview plan</h3>
                </EuiTitle>
                <EuiSpacer size="s" />
                <EuiCodeBlock language="json" isCopyable>
                  {JSON.stringify(plan, null, 2)}
                </EuiCodeBlock>
              </>
            ) : null}
          </>
        ) : null}

        {activeTab === 'configuration' ? (
          <EuiPanel paddingSize="m">
            <EuiTitle size="s">
              <h3>OpenAI-compatible provider settings</h3>
            </EuiTitle>
            <EuiSpacer size="s" />
            <EuiFormRow label="Provider">
              <EuiSelect
                options={[
                  { value: 'nvidia', text: 'NVIDIA' },
                  { value: 'groq', text: 'Groq' },
                  { value: 'custom', text: 'Custom OpenAI-compatible URL' },
                ]}
                value={providerPreset}
                onChange={(event) => onProviderPresetChange(event.target.value)}
              />
            </EuiFormRow>
            <EuiFormRow label="Base URL">
              <EuiFieldText value={providerUrl} onChange={(event) => setProviderUrl(event.target.value)} />
            </EuiFormRow>
            <EuiFormRow label="Model">
              <EuiFieldText value={providerModel} onChange={(event) => setProviderModel(event.target.value)} />
            </EuiFormRow>
            <EuiFormRow label="API key (input-only)">
              <EuiFieldPassword
                value={providerApiKey}
                onChange={(event) => setProviderApiKey(event.target.value)}
                type="dual"
                placeholder="Enter provider API key"
              />
            </EuiFormRow>
            <EuiCallOut size="s" color="warning" title="API key visibility policy">
              API keys are treated as input-only in this MVP flow and are never displayed back in generated plans.
            </EuiCallOut>
            <EuiSpacer size="m" />
            <EuiButton fill onClick={saveProviderSettings} isLoading={providerSaveLoading}>
              Save
            </EuiButton>
          </EuiPanel>
        ) : null}

        {activeTab === 'dataQuality' ? (
          <EuiPanel paddingSize="m">
            <EuiFlexGroup alignItems="center" justifyContent="spaceBetween">
              <EuiFlexItem grow={false}>
                <EuiTitle size="s">
                  <h3>Index profiling and inferred technologies</h3>
                </EuiTitle>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButton onClick={() => loadIndexProfile(true)} isLoading={dataQualityLoading}>
                  Refresh index profile
                </EuiButton>
              </EuiFlexItem>
            </EuiFlexGroup>

            <EuiSpacer size="s" />
            <EuiText size="s">Last profile run: {lastDataProfileAt ? lastDataProfileAt : 'not available yet'}</EuiText>

            <EuiSpacer size="m" />
            <EuiTitle size="xs">
              <h4>Inferred technologies</h4>
            </EuiTitle>
            <EuiSpacer size="s" />
            <EuiFlexGroup gutterSize="s" wrap>
              {technologies.length > 0 ? (
                technologies.map((tech) => <EuiBadge key={tech}>{tech}</EuiBadge>)
              ) : (
                <EuiText size="s">No technologies inferred yet.</EuiText>
              )}
            </EuiFlexGroup>

            <EuiSpacer size="m" />
            <EuiTitle size="xs">
              <h4>Available indices (sample)</h4>
            </EuiTitle>
            <EuiSpacer size="s" />
            <EuiText size="s">Discovered indices: {indexRows.length}</EuiText>
            <EuiSpacer size="s" />
            <EuiCodeBlock language="json" isCopyable>
              {JSON.stringify(indexRows.slice(0, 200), null, 2)}
            </EuiCodeBlock>
          </EuiPanel>
        ) : null}
      </EuiPageBody>
    </EuiPage>
  );
};
