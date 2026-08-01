import type { OpenAPIV3_1 } from "openapi-types";
import { type AuthDanceApi, type AuthDanceApiOptions, createAuthDanceApi } from "./api.ts";
import { type AuthDanceApp, type AuthDanceAppOptions, createAuthDanceApp } from "./app.ts";
import { generateSpecs } from "hono-openapi";

export * from "./api.ts";
export * from "./app.ts";
export * from "./channel.ts";
export * from "./choreography.ts";
export * from "./component.ts";
export * from "./error.ts";
export * from "./identity.ts";
export * from "./message.ts";
export * from "./otp.ts";
export * from "./prompt.ts";
export * from "./provider.ts";
export * from "./response.ts";
export * from "./session.ts";
export * from "./state.ts";
export * from "./storage.ts";

export interface AuthDanceOptions {
	api: AuthDanceApiOptions;
	app?: AuthDanceAppOptions;
	info?: OpenAPIV3_1.InfoObject | undefined;
}

export interface AuthDance {
	api: AuthDanceApi;
	app: AuthDanceApp;
	fetch: (request: Request) => Response | Promise<Response>;
	generateOpenAPISchema: () => ReturnType<typeof generateSpecs>;
}

export function createAuthDance(options: AuthDanceOptions): AuthDance {
	const api = createAuthDanceApi(options.api);
	const app = createAuthDanceApp(options.app);

	return {
		api,
		app,
		fetch: (request) => app.fetch(request, { api, rate_limit: options.api.advanced?.address_rate_limit }),
		generateOpenAPISchema: () => generateSpecs(app, { documentation: { info: options.info } }),
	} satisfies AuthDance;
}
