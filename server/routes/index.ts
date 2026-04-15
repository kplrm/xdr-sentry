import {
  getAgentRoles,
  getBootstrap,
  getIndexProfile,
  getProviderAvailability,
  getProviderConfig,
  getSourcePresets,
  listInvestigations,
  previewInvestigation,
  proposeGoals,
  runInvestigation,
  testProviderConnection,
  updateProviderConfig,
} from '../investigation_engine';
import { schema } from '@osd/config-schema';

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
        body: schema.any(),
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
        body: schema.any(),
      },
    },
    async (context: any, request: any, response: any) => {
      try {
        const provider = await updateProviderConfig(context, request.body);
        return response.ok({
          body: {
            provider,
          },
        });
      } catch (error: any) {
        const message = String(error?.message ?? 'unknown error');
        return response.customError({
          statusCode: /invalid|required|must/i.test(message) ? 400 : 500,
          body: { message: `Failed to save provider config: ${message}` },
        });
      }
    }
  );

  router.get(
    {
      path: '/api/xdr_sentry/provider_config',
      validate: false,
    },
    async (context: any, _request: any, response: any) => {
      try {
        const provider = await getProviderConfig(context);
        return response.ok({
          body: {
            provider,
          },
        });
      } catch (error: any) {
        return response.customError({
          statusCode: 500,
          body: { message: `Failed to load provider config: ${String(error?.message ?? 'unknown error')}` },
        });
      }
    }
  );

  router.get(
    {
      path: '/api/xdr_sentry/provider_availability',
      validate: false,
    },
    async (context: any, _request: any, response: any) => {
      try {
        const result = await getProviderAvailability(context);
        return response.ok({ body: result });
      } catch (error: any) {
        return response.customError({
          statusCode: 500,
          body: { message: `Failed to check provider availability: ${String(error?.message ?? 'unknown error')}` },
        });
      }
    }
  );

  router.post(
    {
      path: '/api/xdr_sentry/test_provider',
      validate: {
        body: schema.any(),
      },
    },
    async (context: any, request: any, response: any) => {
      try {
        const result = await testProviderConnection(context, request.body);
        return response.ok({ body: result });
      } catch (error: any) {
        const message = String(error?.message ?? 'unknown error');
        return response.customError({
          statusCode: /invalid|required|must/i.test(message) ? 400 : 500,
          body: { message: `Failed to test provider connection: ${message}` },
        });
      }
    }
  );

  router.post(
    {
      path: '/api/xdr_sentry/propose_goals',
      validate: {
        body: schema.any(),
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
        body: schema.any(),
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
        body: schema.any(),
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
