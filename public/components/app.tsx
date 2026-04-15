import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  EuiBadge,
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiCodeBlock,
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
  EuiStat,
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

type AppTabId = 'strategy' | 'investigation' | 'history';

const DEFAULT_GOAL = 'Inspect Docker-related logs for signs of exploitation, daemon abuse, or post-compromise behavior.';

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
    try {
      setSuggestingGoals(true);
      const response = await http.post('/api/xdr_sentry/propose_goals', {
        body: JSON.stringify(requestBody),
      });
      setSuggestedGoals(response?.goals ?? []);
      setResearchSignals(response?.signals ?? []);
      setLandscape(response?.landscape ?? null);
      if ((response?.goals ?? []).length > 0) {
        setSelectedGoalId(response.goals[0].id);
      }
    } catch (error: any) {
      notifications.toasts.addDanger(`Failed to suggest goals: ${error?.message ?? 'unknown error'}`);
    } finally {
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
              <p className="xdrSentryHero__subtitle">
                The interface is structured like an investigation pipeline: mission setup on the left, execution canvas in the center,
                and evidence-backed details on the right. The graph is designed to feel closer to GitHub workflow runs than a generic dashboard.
              </p>
            </div>
            <div className="xdrSentryHero__stats">
              <EuiStat title={formatCount(profileCards.length)} description="Profiled index families" titleSize="m" />
              <EuiStat title={formatCount(branchCards.length)} description="Active investigation branches" titleSize="m" />
              <EuiStat title={formatCount(result?.evidenceCards?.length)} description="Evidence cards" titleSize="m" />
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

                <EuiSpacer size="m" />
                <EuiTitle size="xs">
                  <h4>Scope compiler</h4>
                </EuiTitle>
                <EuiSpacer size="s" />
                <EuiFormRow label="Include index patterns (comma separated)">
                  <EuiFieldText value={includePatterns} onChange={(event) => setIncludePatterns(event.target.value)} />
                </EuiFormRow>
                <EuiFormRow label="Exclude index patterns (comma separated)">
                  <EuiFieldText value={excludePatterns} onChange={(event) => setExcludePatterns(event.target.value)} />
                </EuiFormRow>
                <EuiFlexGroup gutterSize="s">
                  <EuiFlexItem>
                    <EuiFormRow label="Time from">
                      <EuiFieldText value={timeFrom} onChange={(event) => setTimeFrom(event.target.value)} />
                    </EuiFormRow>
                  </EuiFlexItem>
                  <EuiFlexItem>
                    <EuiFormRow label="Time to">
                      <EuiFieldText value={timeTo} onChange={(event) => setTimeTo(event.target.value)} />
                    </EuiFormRow>
                  </EuiFlexItem>
                </EuiFlexGroup>
                <EuiFormRow label="Query filter">
                  <EuiFieldText value={queryText} onChange={(event) => setQueryText(event.target.value)} />
                </EuiFormRow>
                <EuiFlexGroup gutterSize="s">
                  <EuiFlexItem>
                    <EuiFormRow label="Max profiles">
                      <EuiFieldText value={maxProfiles} onChange={(event) => setMaxProfiles(event.target.value)} />
                    </EuiFormRow>
                  </EuiFlexItem>
                  <EuiFlexItem>
                    <EuiFormRow label="Max evidence per index">
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
                {sourcePresets.map((preset) => (
                  <div className="xdrSentrySourceRow" key={preset.id}>
                    <div>
                      <strong>{preset.name}</strong>
                      <div>{preset.type} | trust {preset.trustLevel}</div>
                    </div>
                    <EuiSwitch
                      compressed
                      showLabel={false}
                      label={preset.name}
                      checked={enabledSourceIds.includes(preset.id)}
                      onChange={(event) => toggleSourcePreset(preset.id, event.target.checked)}
                    />
                  </div>
                ))}

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
                    <EuiButton onClick={() => refreshLandscape(true)} isLoading={profiling}>Refresh index understanding</EuiButton>
                    <EuiButton onClick={suggestGoals} isLoading={suggestingGoals}>Suggest goals</EuiButton>
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
      </EuiPageBody>
    </EuiPage>
  );
};
