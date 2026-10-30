import { type Context, Hono } from "hono";
import { describeRoute, resolver } from "hono-openapi";
import * as v from "valibot";
import type { AuthDanceRateLimit } from "../api.ts";
import { type AuthDanceAppOptions, cloudflareAddress, forwardedAddress } from "../app.ts";
import { RateLimitedError } from "../error.ts";
import { AuthDanceTokenResponse } from "../response.ts";
import { AuthDanceSession } from "../session.ts";
import type { AuthDanceOauth2AddressRateLimits, AuthDanceOauth2Api } from "./api.ts";
import { type AuthDanceOauth2Client, isPublic } from "./client.ts";
import { authenticateClient, readClientCredentials } from "./client-auth.ts";
import {
	AccessDeniedError,
	AuthDanceOauth2Error,
	InsufficientScopeError,
	InvalidClientMetadataError,
	InvalidRequestError,
	InvalidTokenError,
} from "./error.ts";
import { readParams } from "./params.ts";

type AuthDanceOauth2Env = { Bindings: { oauth2: AuthDanceOauth2Api; rate_limit?: AuthDanceOauth2AddressRateLimits } };

/**
 * The Hono app that serves the OAuth 2.0 routes, with the bindings every handler needs.
 *
 * A handler reads the `oauth2` binding on each `fetch` call, and the optional per-address buckets as `rate_limit`.
 */
export type AuthDanceOauth2App = Hono<AuthDanceOauth2Env>;

/** What `createAuthDanceOauth2App` needs before it mounts the routes: the options of the core app, and `admin`. */
export interface AuthDanceOauth2AppOptions extends AuthDanceAppOptions {
	/**
	 * Mounts the challenge API under `/admin`, for a login or a consent page that runs in another process.
	 * `authorize` decides, for each request, whether it may use these routes. A refusal answers 403. Without this
	 * option the routes do not exist.
	 */
	admin?: { authorize: (c: Context) => boolean | Promise<boolean> };
}

// The schemas below describe what goes over the wire. They never validate anything.
const MetadataResponse = v.pipe(
	v.looseObject({
		issuer: v.string(),
		authorization_endpoint: v.string(),
		token_endpoint: v.string(),
		jwks_uri: v.string(),
		scopes_supported: v.array(v.string()),
		response_types_supported: v.array(v.string()),
		response_modes_supported: v.array(v.string()),
		grant_types_supported: v.array(v.string()),
		token_endpoint_auth_methods_supported: v.array(v.string()),
		code_challenge_methods_supported: v.array(v.string()),
		authorization_response_iss_parameter_supported: v.boolean(),
		introspection_endpoint: v.string(),
		introspection_endpoint_auth_methods_supported: v.array(v.string()),
		revocation_endpoint: v.string(),
		revocation_endpoint_auth_methods_supported: v.array(v.string()),
		registration_endpoint: v.optional(v.string()),
		device_authorization_endpoint: v.optional(v.string()),
	}),
	v.title("AuthDanceOauth2Metadata"),
	v.description("The authorization server metadata (RFC 8414 §2)"),
);

const JwksResponse = v.pipe(
	v.object({ keys: v.array(v.looseObject({ kty: v.string(), kid: v.string(), alg: v.string(), use: v.literal("sig") })) }),
	v.title("AuthDanceOauth2Jwks"),
	v.description("The public keys that verify the tokens, a JWK Set (RFC 7517 §5)"),
);

// The same response as a dance: the tokens of one work wherever the tokens of the other do.
const TokenResponse = AuthDanceTokenResponse;

const IntrospectionResponse = v.pipe(
	v.looseObject({
		active: v.boolean(),
		scope: v.optional(v.string()),
		client_id: v.optional(v.string()),
		username: v.optional(v.string()),
		token_type: v.optional(v.picklist(["Bearer", "refresh_token"])),
		exp: v.optional(v.number()),
		iat: v.optional(v.number()),
		sub: v.optional(v.string()),
		aud: v.optional(v.union([v.string(), v.array(v.string())])),
		iss: v.optional(v.string()),
		jti: v.optional(v.string()),
		auth_time: v.optional(v.number()),
		sid: v.optional(v.string()),
	}),
	v.title("AuthDanceOauth2Introspection"),
	v.description("The introspection response (RFC 7662 §2.2). An active access token also carries the claims of the claims mapper."),
);

const RegistrationResponse = v.pipe(
	v.looseObject({
		client_id: v.string(),
		client_secret: v.optional(v.string()),
		client_id_issued_at: v.number(),
		client_secret_expires_at: v.optional(v.number()),
		redirect_uris: v.array(v.string()),
		token_endpoint_auth_method: v.string(),
		grant_types: v.array(v.string()),
		response_types: v.array(v.string()),
		scope: v.string(),
		client_name: v.optional(v.string()),
	}),
	v.title("AuthDanceOauth2ClientRegistration"),
	v.description(
		"The registered client (RFC 7591 §3.2.1). Each value of another language is a member of its own, `client_name#fr-CA` for example.",
	),
);

const DeviceAuthorizationResponse = v.pipe(
	v.object({
		device_code: v.string(),
		user_code: v.string(),
		verification_uri: v.string(),
		verification_uri_complete: v.string(),
		expires_in: v.number(),
		interval: v.number(),
	}),
	v.title("AuthDanceOauth2DeviceAuthorization"),
	v.description("The device authorization response (RFC 8628 §3.2)"),
);

const ClientResponse = v.looseObject({ client_id: v.string(), client_name: v.optional(v.string()), redirect_uris: v.array(v.string()) });

const LoginRequestResponse = v.pipe(
	v.object({
		challenge: v.string(),
		client: ClientResponse,
		requested_scope: v.array(v.string()),
		request_url: v.string(),
		user_code: v.optional(v.string()),
	}),
	v.title("AuthDanceOauth2LoginRequest"),
	v.description("The authorization request behind a login challenge"),
);

const ConsentRequestResponse = v.pipe(
	v.object({
		challenge: v.string(),
		client: ClientResponse,
		requested_scope: v.array(v.string()),
		subject: v.string(),
		skip: v.boolean(),
		user_code: v.optional(v.string()),
	}),
	v.title("AuthDanceOauth2ConsentRequest"),
	v.description("The authorization request behind a consent challenge"),
);

const GrantsResponse = v.pipe(
	v.object({
		grants: v.array(
			v.pipe(
				v.intersect([AuthDanceSession, v.object({ client: v.optional(ClientResponse) })]),
				v.title("AuthDanceOauth2Grant"),
				v.description("The session of a consent, with the public record of the client that holds it"),
			),
		),
	}),
	v.title("AuthDanceOauth2Grants"),
	v.description("The grants of the owner, oldest first: the clients that have access to the account"),
);

const DeviceRequestResponse = v.pipe(
	v.object({ challenge: v.string(), user_code: v.optional(v.string()) }),
	v.title("AuthDanceOauth2DeviceRequest"),
	v.description("A visit to the verification URI, with the user code of `verification_uri_complete` when it carried one"),
);

const RedirectResponse = v.pipe(
	v.object({ redirect_to: v.string() }),
	v.title("AuthDanceOauth2Redirect"),
	v.description("Where the page sends the browser next"),
);

const ErrorResponse = v.pipe(
	v.object({ error: v.string(), error_description: v.optional(v.string()) }),
	v.title("AuthDanceOauth2ErrorResponse"),
	v.description("An RFC 6749 §5.2 error"),
);

// These schemas validate the body of an admin route.
const AcceptLoginBody = v.object({ access_token: v.string() });
const AcceptConsentBody = v.object({ grant_scope: v.array(v.string()), remember: v.optional(v.boolean()) });
const RejectBody = v.object({ error: v.string(), error_description: v.optional(v.string()) });
const AcceptDeviceBody = v.object({ user_code: v.string() });

function errorResponse(description: string) {
	return { description, content: { "application/json": { schema: resolver(ErrorResponse) } } };
}

function withErrorResponses() {
	return {
		429: errorResponse("Too Many Requests. A rate-limit bucket is exhausted; `Retry-After` carries the wait in seconds when known."),
		500: errorResponse("The request could not be carried out."),
	};
}

function jsonResponse(description: string, schema: Parameters<typeof resolver>[0]) {
	return { description, content: { "application/json": { schema: resolver(schema) } } };
}

// RFC 8414 §3.1 puts this segment between the host and the path of the issuer.
const METADATA_PATH = "/.well-known/oauth-authorization-server";

const lastForwardedAddress = forwardedAddress(1);

// `cf-connecting-ip`, then the last entry of `x-forwarded-for`, as in the core app.
function defaultAddress(c: Context): string | undefined {
	return cloudflareAddress(c) ?? lastForwardedAddress(c);
}

/** The default per-address buckets of the oauth2 app. */
const AddressRateLimits: Required<AuthDanceOauth2AddressRateLimits> = {
	request: { limit: 300, window: 60 },
	token: { limit: 60, window: 60 },
	client_auth: { limit: 100, window: 300 },
	introspect: { limit: 300, window: 60 },
	revoke: { limit: 60, window: 60 },
	register: { limit: 10, window: 3600 },
	device_authorization: { limit: 60, window: 60 },
	device: { limit: 30, window: 60 },
};

const HTML_ESCAPES: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

function escapeHtml(value: string): string {
	return value.replace(/[&<>"']/g, (character) => HTML_ESCAPES[character]);
}

// The page for an error the server cannot send to the client. No frame can hold it, RFC 9700 §4.16.
function errorPage(c: Context, error: AuthDanceOauth2Error): Response {
	const description = error.description ? `<p>${escapeHtml(error.description)}</p>` : "";
	return c.html(
		`<!doctype html><html lang="en"><meta charset="utf-8"><title>Authorization error</title><h1>Authorization error</h1><p><code>${escapeHtml(error.error)}</code></p>${description}</html>`,
		error.status,
		{
			"cache-control": "no-store",
			"content-security-policy": "default-src 'none'; frame-ancestors 'none'",
			"x-frame-options": "DENY",
		},
	);
}

// RFC 6749 §3.2: the token endpoint takes `application/x-www-form-urlencoded` only.
async function formParams(c: Context): Promise<[string, string][]> {
	const mediaType = c.req.header("content-type")?.split(";")[0].trim().toLowerCase();
	if (mediaType !== "application/x-www-form-urlencoded") {
		throw new InvalidRequestError("the body must be application/x-www-form-urlencoded");
	}
	return [...new URLSearchParams(await c.req.text())];
}

function queryParam(c: Context, name: string): string {
	const value = c.req.query(name);
	if (!value) {
		throw new InvalidRequestError(`${name} is missing`);
	}
	return value;
}

async function jsonBody<TSchema extends v.GenericSchema>(c: Context, schema: TSchema): Promise<v.InferOutput<TSchema>> {
	const result = v.safeParse(schema, await c.req.json().catch(() => undefined));
	if (!result.success) {
		throw new InvalidRequestError("the body does not match the schema of the route");
	}
	return result.output;
}

/**
 * Builds the Hono app that serves the OAuth 2.0 authorization server over HTTP.
 *
 * - `GET /.well-known/oauth-authorization-server` serves the metadata, RFC 8414. The route sits where RFC 8414 §3.1
 *   puts it: at the root of the host, followed by the path of the issuer. `options.basePath` does not move it. Each
 *   endpoint URL in the document is the origin of the issuer, then `options.basePath`, then the route.
 * - `GET /jwks.json` serves the public keys.
 * - `GET /authorize` and `POST /authorize` run `AuthDanceOauth2Api.authorize`, and answer with a 303. They set no
 *   cookie. An error the server cannot send to the client shows an HTML page that no frame can hold.
 * - `POST /token` runs `AuthDanceOauth2Api.token`. A public client may call it from the origin of one of its
 *   redirect URIs, CORS.
 * - When `ui.device` opens the device authorization grant, RFC 8628: `POST /device_authorization` runs
 *   `AuthDanceOauth2Api.deviceAuthorization`, and `GET /device`, the verification URI, sends the browser to the device
 *   page with a 303. Otherwise both answer 404.
 * - `GET /grants` runs `AuthDanceOauth2Api.listOwnGrants`, and `DELETE /grants/{id}` runs
 *   `AuthDanceOauth2Api.revokeOwnGrant`, for an account page. The access token of the owner goes in
 *   `Authorization: Bearer`, and it must hold `account`.
 * - With `options.admin`, the challenge API under `/admin`.
 *
 * An `AuthDanceOauth2Error` answers its `status` with `{ error, error_description }`, and a 401 adds
 * `WWW-Authenticate: Basic` when the request used Basic, RFC 6749 §5.2. A `RateLimitedError` answers 429 with
 * `temporarily_unavailable`, and adds `Retry-After` when the rate limiter adapter reports the delay. Anything else
 * answers 500 with `server_error`. Every JSON answer carries `Cache-Control: no-store` and `Pragma: no-cache`,
 * RFC 6749 §5.1.
 *
 * A middleware consumes the per-address `request` bucket before any route runs, keyed on the address
 * `options.address` reads. `/token` also consumes `token`, and `client_auth` when the request carries a secret. A
 * request with no address goes to one shared `unknown` bucket. `/device_authorization` consumes
 * `device_authorization`, and `/device` consumes `device`, which bounds how fast one address can guess user codes.
 */
export function createAuthDanceOauth2App(options?: AuthDanceOauth2AppOptions): AuthDanceOauth2App {
	const resolveAddress = options?.address ?? defaultAddress;
	const basePath = (options?.basePath ?? "").replace(/\/+$/, "");
	const app = new Hono<AuthDanceOauth2Env>();

	app.onError((err, c) => {
		if (err instanceof RateLimitedError) {
			return c.json(
				{ error: "temporarily_unavailable", error_description: "too many requests" },
				429,
				err.retryAfter === undefined ? {} : { "retry-after": `${err.retryAfter}` },
			);
		}
		if (err instanceof AuthDanceOauth2Error) {
			const body = err.description === undefined ? { error: err.error } : { error: err.error, error_description: err.description };
			// RFC 6750 §3 for a bearer token, RFC 6749 §5.2 for a client that used Basic.
			if (err instanceof InvalidTokenError || err instanceof InsufficientScopeError) {
				return c.json(body, err.status, { "www-authenticate": `Bearer error="${err.error}"` });
			}
			const basic = err.status === 401 && /^basic\s/i.test(c.req.header("authorization") ?? "");
			return c.json(body, err.status, basic ? { "www-authenticate": 'Basic realm="oauth2"' } : {});
		}
		return c.json({ error: "server_error" }, 500);
	});

	app.use(async (c, next) => {
		await next();
		if (c.res.headers.get("content-type")?.startsWith("application/json")) {
			c.res.headers.set("cache-control", "no-store");
			c.res.headers.set("pragma", "no-cache");
		}
	});

	async function consume(c: Context<AuthDanceOauth2Env>, bucket: string, { limit, window }: AuthDanceRateLimit): Promise<void> {
		const address = resolveAddress(c) ?? "unknown";
		const { allowed, retryAfter } = await c.env.oauth2.storage.consumeRateLimit(`address:${bucket}:${address}`, limit, window * 1000);
		if (!allowed) {
			throw new RateLimitedError(retryAfter);
		}
	}

	app.use(async (c, next) => {
		await consume(c, "oauth2:request", c.env.rate_limit?.request ?? AddressRateLimits.request);
		await next();
	});

	const endpointOf = (c: Context<AuthDanceOauth2Env>) => `${new URL(c.env.oauth2.issuer).origin}${basePath}`;

	// The access token of the owner, from `Authorization: Bearer`, RFC 6750 §2.1.
	const ownerToken = (c: Context<AuthDanceOauth2Env>): string => {
		const token = c.req.header("authorization")?.match(/^Bearer +(\S+)$/i)?.[1];
		if (!token) {
			throw new InvalidTokenError("the access token is missing");
		}
		return token;
	};

	// The issuer is known only at request time, so one handler serves every path under the segment and answers 404
	// for every path but the one of the issuer.
	const metadata = (c: Context<AuthDanceOauth2Env>) => {
		const issuer = new URL(c.env.oauth2.issuer);
		if (c.req.path !== `${METADATA_PATH}${issuer.pathname.replace(/\/+$/, "")}`) {
			return c.notFound();
		}
		return c.json(c.env.oauth2.metadata(endpointOf(c)));
	};

	app.get(
		METADATA_PATH,
		describeRoute({
			summary: "Read the authorization server metadata",
			description:
				"Returns the RFC 8414 metadata document: the issuer, the endpoints, the scopes, and what the server supports. For an issuer with a path, the document sits at this path followed by the path of the issuer.",
			tags: ["OAuth 2.0"],
			responses: { 200: jsonResponse("The metadata document", MetadataResponse), ...withErrorResponses() },
		}),
		metadata,
	);
	app.get(`${METADATA_PATH}/*`, metadata);

	const routes = basePath ? app.basePath(basePath) : app;

	routes.get(
		"/jwks.json",
		describeRoute({
			summary: "Read the signing keys",
			description:
				"Returns the public JWK Set of the keys that sign the tokens. A resource server verifies a token with the key its `kid` header names.",
			tags: ["OAuth 2.0"],
			responses: { 200: jsonResponse("The public JWK Set", JwksResponse), ...withErrorResponses() },
		}),
		(c) => c.json(c.env.oauth2.jwks()),
	);

	const authorize = async (c: Context<AuthDanceOauth2Env>) => {
		try {
			const params = c.req.method === "POST" ? await formParams(c) : [...new URL(c.req.url).searchParams];
			const result = await c.env.oauth2.authorize({ params, endpoint: `${endpointOf(c)}/authorize` });
			// RFC 9700 §4.12: a 303 makes the browser follow with a GET, so a POST body never goes to the next page.
			return c.redirect(result.location, 303);
		} catch (error) {
			if (error instanceof AuthDanceOauth2Error) {
				return errorPage(c, error);
			}
			throw error;
		}
	};

	const authorizeRoute = describeRoute({
		summary: "Authorize a client",
		description:
			"The authorization endpoint (RFC 6749 §4.1.1). A new request goes to the login page with a login challenge; the `login_verifier` and `consent_verifier` the pages hand back continue it. The answer is always a 303: to the login page, to the consent page, or to the client with a code or an error, `state` and `iss` (RFC 9207). An error the server cannot send to the client shows an HTML page.",
		tags: ["OAuth 2.0"],
		responses: {
			303: { description: "The next page of the request" },
			400: { description: "An error the server cannot send to the client, as an HTML page" },
			...withErrorResponses(),
		},
	});
	routes.get("/authorize", authorizeRoute, authorize);
	routes.post("/authorize", authorizeRoute, authorize);

	// The response of a public client is readable from the origin of one of its redirect URIs, so a browser app can call
	// the endpoint. A confidential client never needs it.
	async function allowPublicOrigin(c: Context<AuthDanceOauth2Env>, params: [string, string][]): Promise<void> {
		const origin = c.req.header("origin");
		const clientId = params.find(([name]) => name === "client_id")?.[1];
		if (!origin || origin === "null" || !clientId) {
			return;
		}
		c.header("vary", "Origin");
		const client = await c.env.oauth2.clients.getClient(clientId);
		if (client && isPublic(client) && client.redirect_uris.some((uri) => URL.parse(uri)?.origin === origin)) {
			c.header("access-control-allow-origin", origin);
		}
	}

	// Whether one public client has a redirect URI on the origin. A preflight carries no body and so names no client, so
	// this reads every client, one page at a time. A browser keeps the answer for `Access-Control-Max-Age`.
	async function isPublicOrigin(c: Context<AuthDanceOauth2Env>, origin: string): Promise<boolean> {
		const page = 100;
		let cursor: string | undefined;
		for (;;) {
			const clients = await c.env.oauth2.clients.listClients(cursor, page + 1);
			if (
				clients.slice(0, page).some((client) => isPublic(client) && client.redirect_uris.some((uri) => URL.parse(uri)?.origin === origin))
			) {
				return true;
			}
			if (clients.length <= page) {
				return false;
			}
			cursor = clients[page].client_id;
		}
	}

	// The CORS preflight of the two routes a browser app calls, RFC 7009 §5. It allows the origin of a public client
	// only, and only the `Content-Type` header.
	const preflight = async (c: Context<AuthDanceOauth2Env>) => {
		const origin = c.req.header("origin");
		if (!origin || origin === "null" || !(await isPublicOrigin(c, origin))) {
			return c.body(null, 204, { vary: "Origin" });
		}
		return c.body(null, 204, {
			vary: "Origin",
			"access-control-allow-origin": origin,
			"access-control-allow-methods": "POST",
			"access-control-allow-headers": "Content-Type",
			"access-control-max-age": "600",
		});
	};
	routes.options("/token", preflight);
	routes.options("/revoke", preflight);

	// A rate limiter adapter cannot read a bucket without a hit, so every check of a secret counts, not only a failure.
	// Counting failures only would still tell a right guess apart from a wrong one.
	async function countSecretCheck(c: Context<AuthDanceOauth2Env>, params: [string, string][]): Promise<void> {
		if (/^basic\s/i.test(c.req.header("authorization") ?? "") || params.some(([name]) => name === "client_secret")) {
			await consume(c, "client-auth", c.env.rate_limit?.client_auth ?? AddressRateLimits.client_auth);
		}
	}

	// Reads the form body and authenticates its client, RFC 6749 §2.3, for a route that takes no grant.
	async function authenticate(
		c: Context<AuthDanceOauth2Env>,
		entries: [string, string][],
	): Promise<{ client: AuthDanceOauth2Client; params: Map<string, string> }> {
		const { params, repeated } = readParams(entries);
		if (repeated.length > 0) {
			throw new InvalidRequestError(`${repeated[0]} appears more than once`);
		}
		await countSecretCheck(c, entries);
		const client = await authenticateClient(c.env.oauth2.clients, readClientCredentials(c.req.header("authorization"), params));
		return { client, params };
	}

	routes.post(
		"/token",
		describeRoute({
			summary: "Exchange a grant for tokens",
			description:
				"The token endpoint (RFC 6749 §3.2). It takes `application/x-www-form-urlencoded` only. The client authenticates with `client_secret_basic`, `client_secret_post`, or `none` for a public client. `grant_type` is `authorization_code` with PKCE S256 (RFC 7636), `refresh_token`, which gives a new refresh token while the old one stays valid until its session ends, `client_credentials`, or `urn:ietf:params:oauth:grant-type:device_code` with `device_code` (RFC 8628 §3.4) when the server opens the device grant.",
			tags: ["OAuth 2.0"],
			responses: {
				200: jsonResponse("The tokens", TokenResponse),
				400: errorResponse(
					"An RFC 6749 §5.2 error: invalid_request, invalid_grant, unauthorized_client, unsupported_grant_type or invalid_scope. A device that polls gets authorization_pending, slow_down, access_denied or expired_token (RFC 8628 §3.5).",
				),
				401: errorResponse("invalid_client. `WWW-Authenticate: Basic` when the request used Basic."),
				...withErrorResponses(),
			},
		}),
		async (c) => {
			await consume(c, "oauth2:token", c.env.rate_limit?.token ?? AddressRateLimits.token);
			const params = await formParams(c);
			await allowPublicOrigin(c, params);
			await countSecretCheck(c, params);
			return c.json(await c.env.oauth2.token({ params, authorization: c.req.header("authorization") }));
		},
	);

	routes.post(
		"/introspect",
		describeRoute({
			summary: "Introspect a token",
			description:
				'The introspection endpoint (RFC 7662). A confidential client asks whether an access token or a refresh token is active, and what it carries. A token is active while its signature and `exp` pass and its session exists, or, for client credentials, while its client exists. The tokens of a dance carry the issuer as `client_id`. A client sees its own tokens; a client the server marks with `introspect: true` sees every token. A token the client may not see answers `{ "active": false }`, like a token that is not valid. `token_type_hint` only sets which lookup runs first.',
			tags: ["OAuth 2.0"],
			responses: {
				200: jsonResponse("Whether the token is active, and what it carries", IntrospectionResponse),
				400: errorResponse("invalid_request: `token` is missing, or a parameter appears twice."),
				401: errorResponse("invalid_client. `WWW-Authenticate: Basic` when the request used Basic."),
				...withErrorResponses(),
			},
		}),
		async (c) => {
			await consume(c, "oauth2:introspect", c.env.rate_limit?.introspect ?? AddressRateLimits.introspect);
			const { client, params } = await authenticate(c, await formParams(c));
			const token = params.get("token");
			if (token === undefined) {
				throw new InvalidRequestError("token is missing");
			}
			return c.json(await c.env.oauth2.introspect(client, token, params.get("token_type_hint")));
		},
	);

	routes.post(
		"/revoke",
		describeRoute({
			summary: "Revoke a token",
			description:
				"The revocation endpoint (RFC 7009). A client revokes one of its access tokens or refresh tokens; either one ends the whole session of the grant. A token of client credentials has no session, and stays valid until `exp`. A public client authenticates with its `client_id` alone. The answer is 200 with an empty body, also for a token that is not valid, of another client, or already revoked. `token_type_hint` only sets which lookup runs first.",
			tags: ["OAuth 2.0"],
			responses: {
				200: { description: "The session of the token is revoked, or nothing was to revoke" },
				400: errorResponse("invalid_request: `token` is missing, or a parameter appears twice."),
				401: errorResponse("invalid_client. `WWW-Authenticate: Basic` when the request used Basic."),
				...withErrorResponses(),
			},
		}),
		async (c) => {
			await consume(c, "oauth2:revoke", c.env.rate_limit?.revoke ?? AddressRateLimits.revoke);
			const entries = await formParams(c);
			await allowPublicOrigin(c, entries);
			const { client, params } = await authenticate(c, entries);
			const token = params.get("token");
			if (token === undefined) {
				throw new InvalidRequestError("token is missing");
			}
			await c.env.oauth2.revoke(client, token, params.get("token_type_hint"));
			return c.body(null, 200);
		},
	);

	routes.get(
		"/grants",
		describeRoute({
			summary: "List the grants of the owner",
			description:
				"Lists the grants of the owner, oldest first, for an account page: the clients that have access to the account, each with its public record, the scopes it holds and the moment its grant ends. The access token of the owner goes in `Authorization: Bearer`. It must hold `account` and a session that still exists: the token of a dance, or of a client the owner gave `account` to. A sign-out in the core leaves every grant; the owner revokes one with `DELETE /grants/{id}`.",
			tags: ["OAuth 2.0"],
			security: [{ bearerAuth: [] }],
			responses: {
				200: jsonResponse("The grants", GrantsResponse),
				401: errorResponse(
					'invalid_token: the access token is missing, not valid, or its session ended. `WWW-Authenticate: Bearer error="invalid_token"`.',
				),
				403: errorResponse(
					'insufficient_scope: the access token does not hold `account`. `WWW-Authenticate: Bearer error="insufficient_scope"`.',
				),
				...withErrorResponses(),
			},
		}),
		async (c) => c.json({ grants: await c.env.oauth2.listOwnGrants(ownerToken(c)) }),
	);

	routes.delete(
		"/grants/:id",
		describeRoute({
			summary: "Revoke a grant of the owner",
			description:
				"Revokes one grant of the owner, for an account page: the client loses its access token and its refresh token at once, and its next request asks for consent again. `id` is the `id` of the grant in the list of `GET /grants`. The access token of the owner goes in `Authorization: Bearer`, with the same rule as the list. The answer is 204 with no body, also for an id that names no grant of the owner, so the route says nothing about the grants of anyone else. A resource server that only checks the signature still accepts an access token of the grant until `exp`.",
			tags: ["OAuth 2.0"],
			security: [{ bearerAuth: [] }],
			responses: {
				204: { description: "The grant is revoked, or the owner held no grant with this id" },
				401: errorResponse(
					'invalid_token: the access token is missing, not valid, or its session ended. `WWW-Authenticate: Bearer error="invalid_token"`.',
				),
				403: errorResponse(
					'insufficient_scope: the access token does not hold `account`. `WWW-Authenticate: Bearer error="insufficient_scope"`.',
				),
				...withErrorResponses(),
			},
		}),
		async (c) => {
			await c.env.oauth2.revokeOwnGrant(ownerToken(c), c.req.param("id"));
			return c.body(null, 204);
		},
	);

	routes.post(
		"/register",
		describeRoute({
			summary: "Register a client",
			description:
				"The registration endpoint (RFC 7591). It exists only when the server opens registration; otherwise it answers 404. The body is the client metadata, as JSON. The server applies the defaults of RFC 7591 §2, narrows `scope` to what it allows, refuses `jwks`, `jwks_uri` and software statements, and ignores a member it does not know. The answer holds every registered field, and the secret of a confidential client, which is readable this one time.",
			tags: ["OAuth 2.0"],
			responses: {
				201: jsonResponse("The registered client", RegistrationResponse),
				400: errorResponse(
					"invalid_client_metadata, invalid_redirect_uri, invalid_software_statement or unapproved_software_statement (RFC 7591 §3.2.2).",
				),
				401: errorResponse(
					'invalid_token: the initial access token is missing or refused. `WWW-Authenticate: Bearer error="invalid_token"`.',
				),
				404: { description: "The server does not open registration." },
				...withErrorResponses(),
			},
		}),
		async (c) => {
			const registration = c.env.oauth2.registration;
			if (!registration) {
				return c.notFound();
			}
			await consume(c, "oauth2:register", c.env.rate_limit?.register ?? AddressRateLimits.register);
			if (registration.authorize) {
				const token = c.req.header("authorization")?.match(/^Bearer +(\S+)$/i)?.[1];
				if (!token || !(await registration.authorize(token, c))) {
					throw new InvalidTokenError("the initial access token is missing or refused");
				}
			}
			const mediaType = c.req.header("content-type")?.split(";")[0].trim().toLowerCase();
			const body = mediaType === "application/json" ? await c.req.json().catch(() => undefined) : undefined;
			if (body === undefined) {
				throw new InvalidClientMetadataError("the body must be a JSON object");
			}
			return c.json(await c.env.oauth2.registerClient(body, { registered_by: "dynamic" }), 201);
		},
	);

	routes.post(
		"/device_authorization",
		describeRoute({
			summary: "Start a device authorization",
			description:
				"The device authorization endpoint (RFC 8628 §3.1). It exists only when the server opens the device grant; otherwise it answers 404. It takes `application/x-www-form-urlencoded` only. The client authenticates as at the token endpoint: a public client sends its `client_id` alone. The answer holds the device code the device polls the token endpoint with, and the user code the owner types at the verification URI.",
			tags: ["OAuth 2.0"],
			responses: {
				200: jsonResponse("The device and the user code", DeviceAuthorizationResponse),
				400: errorResponse("invalid_request, unauthorized_client or invalid_scope."),
				401: errorResponse("invalid_client. `WWW-Authenticate: Basic` when the request used Basic."),
				404: { description: "The server does not open the device grant." },
				...withErrorResponses(),
			},
		}),
		async (c) => {
			if (!c.env.oauth2.device) {
				return c.notFound();
			}
			await consume(c, "oauth2:device_authorization", c.env.rate_limit?.device_authorization ?? AddressRateLimits.device_authorization);
			const params = await formParams(c);
			await countSecretCheck(c, params);
			return c.json(
				await c.env.oauth2.deviceAuthorization({
					params,
					authorization: c.req.header("authorization"),
					verification_uri: `${endpointOf(c)}/device`,
				}),
			);
		},
	);

	routes.get(
		"/device",
		describeRoute({
			summary: "Open the verification URI",
			description:
				"The verification URI of the device grant (RFC 8628 §3.3). It exists only when the server opens the device grant; otherwise it answers 404. It sends the browser to the device page with a `device_challenge`, where the owner types the user code. A `user_code` in the query, from `verification_uri_complete`, fills in the page.",
			tags: ["OAuth 2.0"],
			responses: {
				303: { description: "The device page" },
				404: { description: "The server does not open the device grant." },
				...withErrorResponses(),
			},
		}),
		async (c) => {
			if (!c.env.oauth2.device) {
				return c.notFound();
			}
			await consume(c, "oauth2:device", c.env.rate_limit?.device ?? AddressRateLimits.device);
			const { location } = await c.env.oauth2.startDeviceVerification({
				params: [...new URL(c.req.url).searchParams],
				endpoint: `${endpointOf(c)}/authorize`,
				verification_uri: `${endpointOf(c)}/device`,
			});
			return c.redirect(location, 303);
		},
	);

	if (options?.admin) {
		const { authorize: allow } = options.admin;
		routes.use("/admin/*", async (c, next) => {
			if (!(await allow(c))) {
				throw new AccessDeniedError("the admin routes refuse this request");
			}
			await next();
		});
		const adminRoute = (summary: string, schema: Parameters<typeof resolver>[0]) =>
			describeRoute({
				summary,
				tags: ["OAuth 2.0 admin"],
				responses: {
					200: jsonResponse(summary, schema),
					400: errorResponse("invalid_request: the challenge is unknown, expired or already answered, or the body is not valid."),
					403: errorResponse("access_denied: `admin.authorize` refused the request."),
					...withErrorResponses(),
				},
			});
		routes.get("/admin/login", adminRoute("Read a login request", LoginRequestResponse), async (c) =>
			c.json(await c.env.oauth2.getLoginRequest(queryParam(c, "login_challenge"))),
		);
		routes.put("/admin/login/accept", adminRoute("Accept a login", RedirectResponse), async (c) =>
			c.json(await c.env.oauth2.acceptLoginRequest(queryParam(c, "login_challenge"), await jsonBody(c, AcceptLoginBody))),
		);
		routes.put("/admin/login/reject", adminRoute("Reject a login", RedirectResponse), async (c) =>
			c.json(await c.env.oauth2.rejectLoginRequest(queryParam(c, "login_challenge"), await jsonBody(c, RejectBody))),
		);
		routes.get("/admin/consent", adminRoute("Read a consent request", ConsentRequestResponse), async (c) =>
			c.json(await c.env.oauth2.getConsentRequest(queryParam(c, "consent_challenge"))),
		);
		routes.put("/admin/consent/accept", adminRoute("Accept a consent", RedirectResponse), async (c) =>
			c.json(await c.env.oauth2.acceptConsentRequest(queryParam(c, "consent_challenge"), await jsonBody(c, AcceptConsentBody))),
		);
		routes.put("/admin/consent/reject", adminRoute("Reject a consent", RedirectResponse), async (c) =>
			c.json(await c.env.oauth2.rejectConsentRequest(queryParam(c, "consent_challenge"), await jsonBody(c, RejectBody))),
		);
		routes.get("/admin/device", adminRoute("Read a device request", DeviceRequestResponse), async (c) =>
			c.json(await c.env.oauth2.getDeviceRequest(queryParam(c, "device_challenge"))),
		);
		routes.put("/admin/device/accept", adminRoute("Accept a user code", RedirectResponse), async (c) =>
			c.json(await c.env.oauth2.acceptDeviceRequest(queryParam(c, "device_challenge"), await jsonBody(c, AcceptDeviceBody))),
		);
	}

	return app;
}
