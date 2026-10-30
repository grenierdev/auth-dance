/**
 * @module
 *
 * Auth Dance as an OAuth 2.0 authorization server. Third-party clients get access to an identity through the standard
 * OAuth 2.0 flows, and the owner signs in with the dance of the core module. This module adds `createAuthDanceOauth2`.
 */

import { generateSpecs } from "hono-openapi";
import type { OpenAPIV3_1 } from "openapi-types";
import { type AuthDanceOauth2Api, type AuthDanceOauth2ApiOptions, createAuthDanceOauth2Api } from "./oauth2/api.ts";
import { type AuthDanceOauth2App, type AuthDanceOauth2AppOptions, createAuthDanceOauth2App } from "./oauth2/app.ts";

export * from "./oauth2/api.ts";
export * from "./oauth2/app.ts";
export * from "./oauth2/client.ts";
export * from "./oauth2/error.ts";
export * from "./oauth2/storage.ts";

/** The options of `createAuthDanceOauth2`: `oauth2` for the protocol logic, `app` for the HTTP layer, `info` for the OpenAPI document. */
export interface AuthDanceOauth2Options {
	/** The authorization server configuration. The required keys are `api`, `clients`, `issuer` and `ui`. */
	oauth2: AuthDanceOauth2ApiOptions;
	/** The HTTP layer configuration. Pass `basePath` to prefix every route but the metadata document. */
	app?: AuthDanceOauth2AppOptions;
	/** The `info` block of the generated OpenAPI document. @defaultValue The `hono-openapi` placeholder. */
	info?: OpenAPIV3_1.InfoObject | undefined;
}

/** One configured authorization server: the protocol logic, the HTTP surface and the OpenAPI generator. */
export interface AuthDanceOauth2 {
	/** The protocol logic. Use its methods in process, without HTTP. */
	oauth2: AuthDanceOauth2Api;
	/** The Hono instance behind `fetch`. Mount it in your own app, and supply the `oauth2` binding. `rate_limit` is optional. */
	app: AuthDanceOauth2App;
	/** The HTTP surface. Hand it to a server. It supplies both bindings. */
	fetch: (request: Request) => Response | Promise<Response>;
	/**
	 * Builds the OpenAPI document of the routes.
	 * @returns A promise that resolves with the generated OpenAPI document.
	 */
	generateOpenAPISchema: () => ReturnType<typeof generateSpecs>;
}

/**
 * Builds one authorization server: the protocol logic, the HTTP layer and the OpenAPI generator together. Use
 * `createAuthDanceOauth2Api` and `createAuthDanceOauth2App` to build them one at a time.
 *
 * @throws {TypeError} For the options `AuthDanceOauth2Api` refuses.
 *
 * @example
 * ```ts
 * const auth = createAuthDance({
 * 	api: { …, tokens: { issuer: "https://auth.example.com", scopes: { profile: { description: "Your name", claims: ["name"] } } } },
 * });
 * const idp = createAuthDanceOauth2({
 * 	oauth2: {
 * 		api: auth.api,
 * 		clients: createAuthDanceMemoryOauth2ClientStorage(),
 * 		issuer: "https://auth.example.com",
 * 		ui: { login: "https://auth.example.com/login", consent: "https://auth.example.com/consent" },
 * 	},
 * 	app: { basePath: "/oauth2" },
 * });
 * ```
 */
export function createAuthDanceOauth2(options: AuthDanceOauth2Options): AuthDanceOauth2 {
	const oauth2 = createAuthDanceOauth2Api(options.oauth2);
	const app = createAuthDanceOauth2App(options.app);

	return {
		oauth2,
		app,
		fetch: (request) => app.fetch(request, { oauth2, rate_limit: options.oauth2.limits?.address }),
		// `hono-openapi` leaves out a path with a dot in its last segment as a static file. `/jwks.json` is a route.
		generateOpenAPISchema: () => generateSpecs(app, { documentation: { info: options.info }, excludeStaticFile: false }),
	} satisfies AuthDanceOauth2;
}
