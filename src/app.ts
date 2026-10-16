import { type Context, Hono } from "hono";
import { describeRoute, resolver, validator } from "hono-openapi";
import * as v from "valibot";
import type { AuthDanceAddressRateLimits, AuthDanceApi, AuthDanceRateLimit } from "./api.ts";
import { AuthDanceError, Errors, InvalidAccessTokenError, RateLimitedError } from "./error.ts";
import type { AuthDanceIdentityComponent, AuthDanceIdentityComponentPublic } from "./identity.ts";
import { AuthDancePromptInput } from "./prompt.ts";
import { AuthDanceResponseComponents, AuthDanceResponseResult, AuthDanceResponseSessions, AuthDanceResponseTokens } from "./response.ts";

// This schema states one level of a choice prompt. Do not replace it with the recursive schema of `prompt.ts`. The
// `v.lazy` of that schema makes a dangling `$ref` in the generated document.
const PromptChoiceResponse = v.pipe(
	v.object({
		kind: v.literal("choice"),
		components: v.array(AuthDancePromptInput),
	}),
	v.title("PromptChoice"),
	v.description("A choice between prompt components, any one of which satisfies the current step"),
);

const PromptResponse = v.pipe(
	v.union([AuthDancePromptInput, PromptChoiceResponse]),
	v.title("Prompt"),
	v.description("A prompt, which can be a component or a choice"),
);

// The schemas below describe what goes over the wire. They never validate anything.
const StateResponse = v.pipe(
	v.object({
		state: v.string(),
		prompt: PromptResponse,
		expireAt: v.pipe(v.string(), v.isoTimestamp()),
	}),
	v.title("AuthDanceResponseState"),
	v.description("The prompt to answer next, with the opaque state to echo back and the moment it stops being valid"),
);

const TokensResponse = AuthDanceResponseTokens;
const ResultResponse = AuthDanceResponseResult;
const SessionsResponse = AuthDanceResponseSessions;
const ComponentsResponse = AuthDanceResponseComponents;

const AnyResponse = v.pipe(
	v.union([StateResponse, TokensResponse, ResultResponse]),
	v.title("AuthDanceResponse"),
	v.description("The next prompt, the tokens minted by a completed authentication, or a bare success for a completed management flow"),
);

const ErrorResponse = v.pipe(
	v.object({ error: v.picklist(Object.keys(Errors) as (keyof typeof Errors)[]) }),
	v.title("AuthDanceErrorResponse"),
	v.description("An auth failure, identified by its code. Codes never carry internal detail."),
);

const BadRequestResponse = v.pipe(
	v.object({ error: v.literal("BAD_REQUEST") }),
	v.title("BadRequestResponse"),
	v.description("The request body is missing or does not match the schema"),
);

function withErrorResponses() {
	return {
		400: {
			description: "Bad Request. Usually due to missing parameters, or invalid parameters.",
			content: { "application/json": { schema: resolver(BadRequestResponse) } },
		},
		429: {
			description: "Too Many Requests. A rate-limit bucket is exhausted; `Retry-After` carries the wait in seconds when known.",
			content: { "application/json": { schema: resolver(ErrorResponse) } },
		},
		500: {
			description: "The request could not be carried out. The code identifies why.",
			content: { "application/json": { schema: resolver(ErrorResponse) } },
		},
	};
}

function badRequest(result: { success: boolean }, c: Context) {
	if (!result.success) {
		return c.json({ error: "BAD_REQUEST" } as const, 400);
	}
}

function bearer(c: Context): string {
	const token = c.req.header("authorization")?.match(/^Bearer +(\S+)$/i)?.[1];
	if (!token) {
		throw new InvalidAccessTokenError();
	}
	return token;
}

// `data` holds the private value of a component, for example a password hash. This function drops the whole field.
function withoutComponentData(component: AuthDanceIdentityComponent): AuthDanceIdentityComponentPublic {
	const { data: _data, ...rest } = component;
	return rest;
}

function localeOf(c: Context, fromBody?: string): string {
	return fromBody ?? c.req.header("accept-language")?.split(",")[0]?.split(";")[0]?.trim() ?? "en";
}

/**
 * Reads the address of the caller from `cf-connecting-ip`. Cloudflare sets this header and drops a value the client
 * sends. Use it only behind Cloudflare: anywhere else the client writes the header.
 */
export function cloudflareAddress(c: Context): string | undefined {
	return c.req.header("cf-connecting-ip")?.trim() || undefined;
}

/**
 * Builds a resolver that reads the address of the caller from `x-forwarded-for`, the entry `hops` positions from the
 * right. Each proxy appends the address it saw, so behind `hops` trusted proxies that entry is the first one the
 * client cannot write. A header with fewer entries gives no address.
 *
 * @param hops The number of trusted proxies in front of the app. @defaultValue `1`
 * @throws {RangeError} When `hops` is not a positive integer.
 */
export function forwardedAddress(hops: number = 1): (c: Context) => string | undefined {
	if (!Number.isInteger(hops) || hops < 1) {
		throw new RangeError("hops must be a positive integer");
	}
	return (c) => {
		const entries = (c.req.header("x-forwarded-for") ?? "")
			.split(",")
			.map((entry) => entry.trim())
			.filter((entry) => entry !== "");
		return entries.length >= hops ? entries[entries.length - hops] : undefined;
	};
}

const lastForwardedAddress = forwardedAddress(1);

// `cf-connecting-ip`, then the last entry of `x-forwarded-for`.
function defaultAddress(c: Context): string | undefined {
	return cloudflareAddress(c) ?? lastForwardedAddress(c);
}

// The bucket key of a request with no address. One shared bucket throttles a misconfiguration, or a client that
// bypasses the proxy.
const UNKNOWN_ADDRESS = "unknown";

/** The default per-address rate limit buckets. */
const AddressRateLimits: Required<AuthDanceAddressRateLimits> = {
	request: { limit: 300, window: 60 },
	send: { limit: 60, window: 60 },
};

/**
 * The Hono app that serves the AuthDance routes, with the bindings every handler needs.
 *
 * A handler reads the `api` binding on each `fetch` call, and the optional per-address buckets as `rate_limit`.
 */
export type AuthDanceApp = Hono<{ Bindings: { api: AuthDanceApi; rate_limit?: AuthDanceAddressRateLimits } }>;

/** What `createAuthDanceApp` needs before it mounts the routes. */
export interface AuthDanceAppOptions {
	/** The prefix for every route, for example `/auth`. Without it the routes sit at the root. */
	basePath?: string;
	/**
	 * Reads the address of the caller from a request. The per-address buckets key on it, and a session records it.
	 *
	 * Pass the resolver that matches the deployment. Behind Cloudflare, pass `cloudflareAddress`. Behind a chain of
	 * proxies, pass `forwardedAddress(hops)`. With no proxy at all, no header can be trusted: on Node.js pass
	 * `(c) => getConnInfo(c).remote.address` from `@hono/node-server/conninfo`.
	 *
	 * @defaultValue `cf-connecting-ip`, then the last entry of `x-forwarded-for`. Off Cloudflare, the client writes
	 * `cf-connecting-ip`, so pass a resolver there.
	 */
	address?: (c: Context) => string | undefined;
}

/**
 * Builds the Hono app that serves AuthDance over HTTP.
 *
 * Every route is a POST, and `options.basePath` prefixes all 15 of them. Each handler calls the matching
 * `AuthDanceApi` method on `c.env.api`. The nine routes that act on an already authenticated identity take the access
 * token from the `Authorization: Bearer` header.
 *
 * A body that does not match the route schema answers 400 with `{ error: "BAD_REQUEST" }`. A `RateLimitedError`
 * answers 429, and adds `Retry-After` in seconds when the rate limiter adapter reports the delay. Every other
 * `AuthDanceError` answers 500 with its own code. Anything else answers 500 with `UNKNOWN`.
 *
 * The app reads the caller address with `options.address`. By default it reads `cf-connecting-ip`, then the last
 * entry of `x-forwarded-for`. It reads the locale from the `locale` field of the body first, then from the first entry
 * of `accept-language`, then uses `en`.
 *
 * A middleware consumes the per-address buckets before anything parses a body. `/send-prompt` consumes a second,
 * tighter bucket. A request with no caller address goes to one shared `unknown` bucket.
 */
export function createAuthDanceApp(options?: AuthDanceAppOptions): AuthDanceApp {
	const resolveAddress = options?.address ?? defaultAddress;

	// The address and the user agent always come from the request, never from the body.
	function callerOf(c: Context): { address?: string; userAgent?: string } {
		return {
			address: resolveAddress(c),
			userAgent: c.req.header("user-agent"),
		};
	}

	let app = new Hono<{ Bindings: { api: AuthDanceApi; rate_limit?: AuthDanceAddressRateLimits } }>();

	if (options?.basePath) {
		app = app.basePath(options.basePath);
	}

	app.onError((err, c) => {
		if (err instanceof RateLimitedError) {
			return c.json({ error: err.code }, 429, err.retryAfter === undefined ? {} : { "retry-after": `${err.retryAfter}` });
		}
		return c.json({ error: err instanceof AuthDanceError ? err.code : "UNKNOWN" }, 500);
	});

	// These buckets stop one caller address from repeating the same abuse across many identities. With a correct
	// resolver, every request has an address. A request without one is a misconfiguration or a client that bypasses
	// the proxy, and all such requests share one bucket.
	app.use(async (c, next) => {
		const address = callerOf(c).address ?? UNKNOWN_ADDRESS;
		await consumeAddressRateLimit(c, `request:${address}`, c.env.rate_limit?.request ?? AddressRateLimits.request);
		await next();
	});

	app.use("/send-prompt", async (c, next) => {
		const address = callerOf(c).address ?? UNKNOWN_ADDRESS;
		await consumeAddressRateLimit(c, `send:${address}`, c.env.rate_limit?.send ?? AddressRateLimits.send);
		await next();
	});

	async function consumeAddressRateLimit(
		c: Context<{ Bindings: { api: AuthDanceApi } }>,
		key: string,
		{ limit, window }: AuthDanceRateLimit,
	): Promise<void> {
		const { allowed, retryAfter } = await c.env.api.storage.consumeRateLimit(`address:${key}`, limit, window * 1000);
		if (!allowed) {
			throw new RateLimitedError(retryAfter);
		}
	}

	app.post(
		"/sign-in",
		describeRoute({
			summary: "Start an authentication",
			description:
				"Begins an authentication flow and returns the first prompt the choreography requires, along with an opaque state to echo back to every subsequent step.",
			tags: ["Auth"],
			responses: {
				200: {
					description: "The first prompt of the authentication",
					content: { "application/json": { schema: resolver(StateResponse) } },
				},
				...withErrorResponses(),
			},
		}),
		async (c) => c.json(await c.env.api.signIn()),
	);

	app.post(
		"/sign-up",
		describeRoute({
			summary: "Start a registration",
			description:
				"Begins a registration flow and returns the first prompt the choreography requires, along with an opaque state to echo back to every subsequent step.",
			tags: ["Auth"],
			responses: {
				200: {
					description: "The first prompt of the registration",
					content: { "application/json": { schema: resolver(StateResponse) } },
				},
				...withErrorResponses(),
			},
		}),
		async (c) => c.json(await c.env.api.signUp()),
	);

	app.post(
		"/sign-out",
		describeRoute({
			summary: "Sign out",
			description: "Destroys current session.",
			tags: ["Auth"],
			security: [{ bearerAuth: [] }],
			responses: {
				200: {
					description: "The session has been destroyed",
					content: { "application/json": { schema: resolver(ResultResponse) } },
				},
				...withErrorResponses(),
			},
		}),
		validator("json", v.object({ others: v.optional(v.boolean()) }), badRequest),
		async (c) => c.json(await c.env.api.signOut(bearer(c), c.req.valid("json").others ?? false)),
	);

	app.post(
		"/list-sessions",
		describeRoute({
			summary: "List sessions",
			description:
				"Lists every session currently open on the authenticated identity — exactly what signing out with `others` would destroy — oldest first, with the address and user agent each was opened from. `current` names the session the call was made with.",
			tags: ["Auth"],
			security: [{ bearerAuth: [] }],
			responses: {
				200: {
					description: "The list of active sessions",
					content: { "application/json": { schema: resolver(SessionsResponse) } },
				},
				...withErrorResponses(),
			},
		}),
		// The sort by id keeps the order independent of the enumeration order of a KV provider. `localeCompare` orders
		// by collation, not by the base62 value of the id, so two ids from different seconds can come out unsorted.
		async (c) => {
			const { identityId, sessionId } = await c.env.api.verifyAccessToken(bearer(c), { session: true });
			const sessions = await c.env.api.storage.listSession(identityId);
			return c.json({ sessions: sessions.sort((a, b) => a.id.localeCompare(b.id)), current: sessionId });
		},
	);

	app.post(
		"/list-components",
		describeRoute({
			summary: "List components",
			description:
				"Lists every component enrolled on the authenticated identity — its identifications, its challenges and its channels — as the names the management routes (`enroll`, `rotate`, `unsubscribe`, …) take. The value a component holds is never returned: only whether it is enrolled and whether control of it has been confirmed.",
			tags: ["Auth"],
			security: [{ bearerAuth: [] }],
			responses: {
				200: {
					description: "The list of enrolled components",
					content: { "application/json": { schema: resolver(ComponentsResponse) } },
				},
				...withErrorResponses(),
			},
		}),
		async (c) => {
			const { identityId } = await c.env.api.verifyAccessToken(bearer(c), { session: true });
			const identity = await c.env.api.storage.getIdentity(identityId);
			if (!identity) {
				throw new InvalidAccessTokenError();
			}
			return c.json({ components: identity.components.map(withoutComponentData) });
		},
	);

	app.post(
		"/refresh-token",
		describeRoute({
			summary: "Refresh the tokens",
			description:
				"Exchanges a refresh token for a freshly minted set of access, id and refresh tokens on the same session. A refresh token works one time. A second exchange of an old token ends the session, because two parties hold it.",
			tags: ["Auth"],
			responses: {
				200: {
					description: "A new set of tokens",
					content: { "application/json": { schema: resolver(TokensResponse) } },
				},
				...withErrorResponses(),
			},
		}),
		validator("json", v.object({ refresh_token: v.string() }), badRequest),
		async (c) => c.json(await c.env.api.refreshToken(c.req.valid("json").refresh_token)),
	);

	app.post(
		"/enroll",
		describeRoute({
			summary: "Enroll a component",
			description:
				"Adds a component to the authenticated identity. The value is collected first, then validated when the component can verify itself — the one-time code goes to the value being enrolled, not to what the identity already has.",
			tags: ["Auth"],
			security: [{ bearerAuth: [] }],
			responses: {
				200: {
					description: "The prompt collecting the value to enroll",
					content: { "application/json": { schema: resolver(StateResponse) } },
				},
				...withErrorResponses(),
			},
		}),
		validator("json", v.object({ name: v.string() }), badRequest),
		async (c) => c.json(await c.env.api.enroll({ name: c.req.valid("json").name, access_token: bearer(c) })),
	);

	app.post(
		"/unenroll",
		describeRoute({
			summary: "Unenroll a component",
			description:
				"Removes a component from the authenticated identity, behind an explicit confirmation. The removal takes the records that name the component in their linkedTo with it, together with every other component those records name. Refused with WOULD_LOCK_OUT when no path through the choreography would still be fully covered by the surviving components.",
			tags: ["Auth"],
			security: [{ bearerAuth: [] }],
			responses: {
				200: {
					description: "The confirmation prompt gating the removal",
					content: { "application/json": { schema: resolver(StateResponse) } },
				},
				...withErrorResponses(),
			},
		}),
		validator("json", v.object({ name: v.string() }), badRequest),
		async (c) => c.json(await c.env.api.unenroll({ name: c.req.valid("json").name, access_token: bearer(c) })),
	);

	app.post(
		"/rotate",
		describeRoute({
			summary: "Rotate a component",
			description:
				"Replaces the value of an already enrolled component. Control of the current value is proven first, but only for components that can verify themselves: receiving a one-time code at the current address proves something, whereas re-typing a password proves nothing the access token has not already established, so such components go straight to the replacement. A completed rotation signs out every other session of the identity.",
			tags: ["Auth"],
			security: [{ bearerAuth: [] }],
			responses: {
				200: {
					description: "The prompt proving control of the current value, or collecting the replacement",
					content: { "application/json": { schema: resolver(StateResponse) } },
				},
				...withErrorResponses(),
			},
		}),
		validator("json", v.object({ name: v.string() }), badRequest),
		async (c) => c.json(await c.env.api.rotate({ name: c.req.valid("json").name, access_token: bearer(c) })),
	);

	app.post(
		"/recover",
		describeRoute({
			summary: "Start a recovery",
			description:
				"The one flow open to a caller with no session at all. `name` is the component the owner can no longer provide. The owner first performs the recovery choreography of that component: a sign-in without it, through every complete path that holds it, or the choreography the deployment declared for it. An address in that dance counts only after its one-time code. The library then collects the replacement, and signs out every session of the identity. A component with no recovery choreography is refused with COMPONENT_NOT_RECOVERABLE.",
			tags: ["Auth"],
			responses: {
				200: {
					description: "The first prompt of the recovery choreography. Nothing about the identity is disclosed yet.",
					content: { "application/json": { schema: resolver(StateResponse) } },
				},
				...withErrorResponses(),
			},
		}),
		validator("json", v.object({ name: v.string() }), badRequest),
		async (c) => c.json(await c.env.api.recover({ name: c.req.valid("json").name })),
	);

	app.post(
		"/subscribe",
		describeRoute({
			summary: "Subscribe a channel",
			description:
				"Attaches a channel to the authenticated identity. The recipient is collected first, then confirmed with a one-time code delivered over the new channel itself — subscribing SMS sends the code to the submitted phone number — so control of the recipient is what gets proven.",
			tags: ["Auth"],
			security: [{ bearerAuth: [] }],
			responses: {
				200: {
					description: "The prompt collecting the recipient",
					content: { "application/json": { schema: resolver(StateResponse) } },
				},
				...withErrorResponses(),
			},
		}),
		validator("json", v.object({ name: v.string() }), badRequest),
		async (c) => c.json(await c.env.api.subscribe({ name: c.req.valid("json").name, access_token: bearer(c) })),
	);

	app.post(
		"/unsubscribe",
		describeRoute({
			summary: "Unsubscribe a channel",
			description:
				"Detaches a channel from the authenticated identity, behind an explicit confirmation. The removal takes the components the channel names in its linkedTo with it, together with every record linked to those. Refused with WOULD_LOCK_OUT when no path through the choreography would still be fully covered by the surviving components.",
			tags: ["Auth"],
			security: [{ bearerAuth: [] }],
			responses: {
				200: {
					description: "The confirmation prompt gating the removal",
					content: { "application/json": { schema: resolver(StateResponse) } },
				},
				...withErrorResponses(),
			},
		}),
		validator("json", v.object({ name: v.string() }), badRequest),
		async (c) => c.json(await c.env.api.unsubscribe({ name: c.req.valid("json").name, access_token: bearer(c) })),
	);

	app.post(
		"/delete",
		describeRoute({
			summary: "Delete the identity",
			description:
				"Deletes the authenticated identity outright, behind an explicit confirmation. Every session open on it goes with it, so no token outlives the identity it was minted for. Requires a recent sign-in, like every other destructive flow.",
			tags: ["Auth"],
			security: [{ bearerAuth: [] }],
			responses: {
				200: {
					description: "The confirmation prompt gating the deletion",
					content: { "application/json": { schema: resolver(StateResponse) } },
				},
				...withErrorResponses(),
			},
		}),
		async (c) => c.json(await c.env.api.delete({ access_token: bearer(c) })),
	);

	app.post(
		"/send-prompt",
		describeRoute({
			summary: "Send the current prompt",
			description:
				"Delivers the current prompt over its channel, for the components that can be sent rather than typed — mailing a one-time code, for instance. The state names the phase, so one route delivers both the prompt of a step and the validation that proves control of a value the flow already collected. `locale` falls back to the Accept-Language header. `name` selects which component to send when the current step is a choice.",
			tags: ["Auth"],
			responses: {
				200: {
					description: "The prompt has been sent",
					content: { "application/json": { schema: resolver(ResultResponse) } },
				},
				...withErrorResponses(),
			},
		}),
		validator("json", v.object({ name: v.string(), locale: v.optional(v.string()), state: v.string() }), badRequest),
		async (c) => {
			const { name, locale, state } = c.req.valid("json");
			return c.json(await c.env.api.sendPrompt({ name, locale: localeOf(c, locale), state }));
		},
	);

	app.post(
		"/submit-prompt",
		describeRoute({
			summary: "Submit the current prompt",
			description:
				"Answers the current prompt and advances the flow. The state names the phase, so one route answers both a prompt that collects a value and a validation that proves control of a value the flow already collected. Returns the next prompt, the tokens once an authentication completes, or a bare success once a management flow completes. `name` selects which component is being answered when the current step is a choice.",
			tags: ["Auth"],
			responses: {
				200: {
					description: "The next prompt, the minted tokens, or a bare success",
					content: { "application/json": { schema: resolver(AnyResponse) } },
				},
				...withErrorResponses(),
			},
		}),
		validator("json", v.object({ name: v.string(), value: v.unknown(), state: v.string() }), badRequest),
		async (c) => {
			const { name, value, state } = c.req.valid("json");
			return c.json(await c.env.api.submitPrompt({ name, value, state, ...callerOf(c) }));
		},
	);

	return app;
}
