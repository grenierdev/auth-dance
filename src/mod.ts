/**
 * @module
 *
 * Auth Dance declares authentication as a choreography: a tree of component, choice and sequence nodes. The library
 * walks that one tree for the sign-in, the sign-up and the recover flow. It also reads the tree before an unenroll, so
 * an identity keeps at least one complete path. This module is the entry point, and it adds `createAuthDance`.
 */

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

/** The options of `createAuthDance`: `api` for the state machine, `app` for the HTTP layer, `info` for the OpenAPI document. */
export interface AuthDanceOptions {
	/** The state machine configuration. The required keys are `channels`, `choreography`, `components`, `secret` and `storage`. */
	api: AuthDanceApiOptions;
	/** The HTTP layer configuration. Pass `basePath` to prefix every route. @defaultValue Every route sits at the root. */
	app?: AuthDanceAppOptions;
	/**
	 * The `info` block of the generated OpenAPI document, for example the title and the version.
	 *
	 * @defaultValue The `hono-openapi` placeholder: title `Hono Documentation`, version `0.0.0`.
	 */
	info?: OpenAPIV3_1.InfoObject | undefined;
}

/** One configured Auth Dance instance: the programmatic surface, the HTTP surface and the OpenAPI generator. */
export interface AuthDance {
	/** The state machine that runs every flow. Use its methods to perform the dance in process, without HTTP. */
	api: AuthDanceApi;
	/** The Hono instance behind `fetch`. Mount it in your own app, and supply the `api` binding. `rate_limit` is optional. */
	app: AuthDanceApp;
	/** The HTTP surface. Hand it to a server, for example `Deno.serve(auth.fetch)`. It supplies both bindings. */
	fetch: (request: Request) => Response | Promise<Response>;
	/**
	 * Builds the OpenAPI document of the routes. Its 429 and 500 responses list every code of the `Errors` registry.
	 * @returns A promise that resolves with the generated OpenAPI document.
	 */
	generateOpenAPISchema: () => ReturnType<typeof generateSpecs>;
}

/**
 * Builds one Auth Dance instance: the state machine, the HTTP layer and the OpenAPI generator together. Use
 * `createAuthDanceApi` and `createAuthDanceApp` to build them one at a time.
 *
 * @throws The error `jose` raises when `options.api.secret` is not valid base64url. This call decodes the secret one
 * time, so a bad key fails here and not on the first request.
 *
 * @example
 * ```ts
 * const auth = createAuthDance({
 * 	api: { channels, choreography: sequence("email", "password"), components, secret, storage },
 * 	info: { title: "Auth API", version: "1.0.0" },
 * });
 *
 * Deno.serve(auth.fetch);
 * ```
 */
export function createAuthDance(options: AuthDanceOptions): AuthDance {
	const api = createAuthDanceApi(options.api);
	const app = createAuthDanceApp(options.app);

	return {
		api,
		app,
		fetch: (request) => app.fetch(request, { api, rate_limit: options.api.limits?.address }),
		generateOpenAPISchema: () => generateSpecs(app, { documentation: { info: options.info } }),
	} satisfies AuthDance;
}
