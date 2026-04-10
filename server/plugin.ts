import { registerSentryRoutes } from './routes';

export class XdrSentryServerPlugin {
  public setup(core: any) {
    const router = core.http.createRouter();
    registerSentryRoutes(router);
    return {};
  }

  public start() {
    return {};
  }

  public stop() {}
}
