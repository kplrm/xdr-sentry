import { AppMountParameters, CoreSetup, CoreStart, Plugin } from '../../OpenSearch-Dashboards/src/core/public';
import { PLUGIN_CATEGORY, PLUGIN_ID, PLUGIN_NAME } from '../common';

type XdrSentrySetupContract = Record<string, never>;
type XdrSentryStartContract = Record<string, never>;
type XdrSentrySetupDeps = Record<string, never>;
type XdrSentryStartDeps = Record<string, never>;

export class XdrSentryPlugin implements Plugin<
  XdrSentrySetupContract,
  XdrSentryStartContract,
  XdrSentrySetupDeps,
  XdrSentryStartDeps
> {
  public setup(core: CoreSetup) {
    core.application.register({
      id: PLUGIN_ID,
      title: PLUGIN_NAME,
      order: 3,
      category: PLUGIN_CATEGORY,
      async mount(params: AppMountParameters) {
        const { renderApp } = await import('./application');
        const [coreStart] = await core.getStartServices();
        return renderApp(coreStart, params);
      },
    });
    return {};
  }

  public start(_core: CoreStart) {
    return {};
  }

  public stop() {}
}
