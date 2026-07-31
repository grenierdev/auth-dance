import { AuthApi, type AuthApiOptions } from "./api.ts";
import app from "./app.ts";
import { generateSpecs } from "hono-openapi";

export * from "./identity.ts";
export * from "./error.ts";
export { choice, component, sequence } from "./choreography.ts";

export interface ChoreoAuth {
	api: AuthApi;
	fetch: (request: Request) => Response | Promise<Response>;
	generateOpenAPISchema: () => ReturnType<typeof generateSpecs>;
}

export default function choreoAuth(options: AuthApiOptions): ChoreoAuth {
	const api = new AuthApi(options);
	return {
		api,
		// The edge's per-address buckets are configured on the app's bindings; `advanced` is the single place a
		// consumer configures anything, so they are forwarded from there rather than passed a second way.
		fetch: (request) => app.fetch(request, { api, rate_limit: options.advanced?.address_rate_limit }),
		generateOpenAPISchema: () => generateSpecs(app, { documentation: { info: { title: "GrenierAI Auth API", version: "1.0.0" } } }),
	} satisfies ChoreoAuth;
}
