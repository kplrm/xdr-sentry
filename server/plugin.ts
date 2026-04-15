import { registerSentryRoutes } from './routes';
import { PROVIDER_CONFIG_SAVED_OBJECT_TYPE } from '../common';

export class XdrSentryServerPlugin {
  public setup(core: any) {
    core.savedObjects.registerType({
      name: PROVIDER_CONFIG_SAVED_OBJECT_TYPE,
      hidden: false,
      namespaceType: 'single',
      mappings: {
        properties: {
          preset: { type: 'keyword' },
          baseUrl: { type: 'keyword' },
          model: { type: 'keyword' },
          apiKey: { type: 'keyword' },
          updatedAt: { type: 'date' },
        },
      },
    });

    const router = core.http.createRouter();
    registerSentryRoutes(router);
    return {};
  }

  public start() {
    return {};
  }

  public stop() {}
}
