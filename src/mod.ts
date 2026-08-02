/**
 * @module
 *
 * Auth Dance declares authentication as a choreography: a tree of component, choice and sequence nodes. The
 * declaration is inert data. The library walks that one tree for the sign-in, the sign-up and the recover flow.
 * It also reads the tree before an unenroll, so an identity keeps at least one complete path. The state machine
 * covers nine flows: sign-in, sign-up, enroll, unenroll, rotate, recover, subscribe, unsubscribe and delete.
 *
 * This module is the package entry point. It re-exports the whole library, and it adds `createAuthDance`.
 * That function builds the state machine, the HTTP layer and the OpenAPI generator from one set of options.
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

/**
 * The options of `createAuthDance`, in three groups. `api` configures the state machine. `app` configures the
 * HTTP layer. `info` fills the `info` block of the generated OpenAPI document.
 */
export interface AuthDanceOptions {
	/**
	 * The state machine configuration. The five required keys are `channels`, `choreography`, `components`,
	 * `secret` and `storage`. The optional keys tune the durations, the rate limit buckets and the token issuer.
	 */
	api: AuthDanceApiOptions;
	/**
	 * The HTTP layer configuration. Pass `basePath` to prefix every route.
	 *
	 * @defaultValue Every route sits at the root.
	 */
	app?: AuthDanceAppOptions;
	/**
	 * The `info` block of the generated OpenAPI document, for example the title and the version. Nothing else
	 * reads it. `hono-openapi` keeps its own placeholder for every key you do not set.
	 *
	 * @defaultValue The whole placeholder of `hono-openapi`: the title `Hono Documentation`, the description
	 * `Development documentation` and the version `0.0.0`.
	 */
	info?: OpenAPIV3_1.InfoObject | undefined;
}

/** One configured Auth Dance instance. It carries the programmatic surface, the HTTP surface and the OpenAPI generator. */
export interface AuthDance {
	/** The state machine that runs every flow. Use its methods to perform the dance in process, without HTTP. */
	api: AuthDanceApi;
	/**
	 * The Hono instance behind `fetch`. Use it to mount the routes inside an app of your own. Its handlers read the
	 * `api` binding from the environment, so your own mount must supply it. The `rate_limit` binding is optional.
	 * Without it the app applies its own per-address defaults.
	 */
	app: AuthDanceApp;
	/**
	 * The HTTP surface. Hand it to a server, for example `Deno.serve(auth.fetch)`.
	 *
	 * It calls `app` with the `api` binding, and with the per-address rate limit buckets that `createAuthDance`
	 * received in `api.limits.address`.
	 */
	fetch: (request: Request) => Response | Promise<Response>;
	/**
	 * Builds the OpenAPI document of the routes. The document carries the `info` block you pass to
	 * `createAuthDance`. Its 429 and 500 responses list every code of the `Errors` registry.
	 *
	 * @returns A promise that resolves with the generated OpenAPI document.
	 */
	generateOpenAPISchema: () => ReturnType<typeof generateSpecs>;
}

/**
 * Builds one Auth Dance instance. This one call builds the state machine, the HTTP layer and the OpenAPI
 * generator together. `createAuthDanceApi` and `createAuthDanceApp` build them one at a time.
 *
 * The call creates the state machine from `options.api` and the Hono app from `options.app`. The returned `fetch`
 * then gives every request the `api` binding and the per-address rate limit buckets of `options.api.limits.address`.
 *
 * @throws The error `jose` raises when `options.api.secret` is not valid base64url. The `AuthDanceApi` constructor
 * decodes that secret one time, so a bad key fails this call and not the first request.
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
