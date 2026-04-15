import {
  getAgentRoles,
  getBootstrap,
  getIndexProfile,
  getProviderConfig,
  getSourcePresets,
  listInvestigations,
  previewInvestigation,
  proposeGoals,
  runInvestigation,
  updateProviderConfig,
} from '../investigation_engine';

export function registerSentryRoutes(router: any): void {
  router.get(
    {
      path: '/api/xdr_sentry/bootstrap',
      validate: false,
    },
    async (_context: any, _request: any, response: any) => response.ok({ body: getBootstrap() })
  );

  router.get(
    {
      path: '/api/xdr_sentry/source_presets',
      validate: false,
    },
    async (_context: any, _request: any, response: any) => {
      return response.ok({ body: { presets: getSourcePresets() } });
    }
  );

  router.get(
    {
      path: '/api/xdr_sentry/agent_scripts',
      validate: false,
    },
    async (_context: any, _request: any, response: any) => {
      return response.ok({ body: { scripts: getAgentRoles() } });
    }
  );

  router.post(
    {
      path: '/api/xdr_sentry/index_profile',
      validate: {
        body: (value: any) => value,
      },
    },
    async (context: any, request: any, response: any) => {
      try {
        const result = await getIndexProfile(context, request.body);
        return response.ok({ body: result });
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
      return response.ok({
        body: {
          provider: updateProviderConfig(request.body),
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
          provider: getProviderConfig(),
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
      try {
        const result = await proposeGoals(context, request.body);
        return response.ok({ body: result });
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
    async (context: any, request: any, response: any) => {
      try {
        const result = await previewInvestigation(context, request.body);
        return response.ok({ body: result });
      } catch (error: any) {
        return response.customError({
          statusCode: 500,
          body: { message: `Failed to build investigation plan: ${error?.message ?? 'unknown error'}` },
        });
      }
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
        const result = await runInvestigation(context, request.body);
        return response.ok({ body: { result } });
      } catch (error: any) {
        const message = error?.message ?? 'unknown error';
        return response.customError({
          statusCode: /required|invalid|missing/i.test(String(message)) ? 400 : 500,
          body: { message: `Failed to run investigation: ${message}` },
        });
      }
    }
  );

  router.get(
    {
      path: '/api/xdr_sentry/investigations',
      validate: false,
    },
    async (_context: any, _request: any, response: any) => response.ok({ body: { investigations: listInvestigations() } })
  );
}
