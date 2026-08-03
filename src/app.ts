import { type Context, Hono } from "hono";
import { describeRoute, resolver, validator } from "hono-openapi";
import * as v from "valibot";
import type { AuthDanceAddressRateLimits, AuthDanceApi, AuthDanceRateLimit } from "./api.ts";
import { AuthDanceError, Errors, InvalidAccessTokenError, RateLimitedError } from "./error.ts";
import type { AuthDanceIdentityComponent, AuthDanceIdentityComponentPublic } from "./identity.ts";
import { AuthDancePromptInput } from "./prompt.ts";
import { AuthDanceResponseComponents, AuthDanceResponseResult, AuthDanceResponseSessions, AuthDanceResponseTokens } from "./response.ts";

// `AuthDanceComponent.getPrompt` and `AuthDanceChannel.getPrompt` both return an `AuthDancePromptInput`, and a
// `choice()` node accepts components only. A choice prompt therefore holds input prompts and nothing else, so the
// recursion in the `AuthDancePromptChoice` of `prompt.ts` is unreachable. This schema states that one level
// explicitly. It does not reuse the recursive schema, which keeps the generated document self-contained. `v.lazy`
// becomes a `$defs` entry. hono-openapi rewrites that entry into a `#/components/schemas/…` reference, and it
// never registers the target, so the document keeps a dangling `$ref`.
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

// The schemas below describe what goes over the wire. They never validate anything. They exist because
// `AuthDanceResponseState.expireAt` is a `Date`. The domain works with that type, but the client never sees it,
// because `c.json` serializes the date to an ISO string. `v.date()` also has no JSON Schema representation, so
// this module cannot pass the domain schema to `resolver()` as it is.
const StateResponse = v.pipe(
	v.object({
		state: v.string(),
		prompt: PromptResponse,
		expireAt: v.pipe(v.string(), v.isoTimestamp()),
	}),
	v.title("AuthDanceResponseState"),
	v.description("The prompt to answer next, with the opaque state to echo back and the moment it stops being valid"),
);

// These four carry no dates, because `AuthDanceSession.expireAt` is already the ISO string the client sees. This
// module therefore reuses the domain schemas as they are.
const TokensResponse = AuthDanceResponseTokens;
const ResultResponse = AuthDanceResponseResult;
const SessionsResponse = AuthDanceResponseSessions;
const ComponentsResponse = AuthDanceResponseComponents;

const AnyResponse = v.pipe(
	v.union([StateResponse, TokensResponse, ResultResponse]),
	v.title("AuthDanceResponse"),
	v.description("The next prompt, the tokens minted by a completed authentication, or a bare success for a completed management flow"),
);

// This schema reads the documented codes from the `Errors` registry instead of a list of its own. A new
// `AuthDanceError` subclass therefore appears in the generated document as soon as the registry names it.
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

// Every validation failure answers in the same `{ error }` shape as an `AuthDanceError`. The surface therefore
// carries one error format only, and it never leaks the issue list of @hono/standard-validator.
function badRequest(result: { success: boolean }, c: Context) {
	if (!result.success) {
		return c.json({ error: "BAD_REQUEST" } as const, 400);
	}
}

// This function reports a missing header and a malformed header with the code a rejected token produces. From
// the side of the caller both mean "this request carried no usable access token". A more exact answer would only
// help someone who probes the surface.
function bearer(c: Context): string {
	const token = c.req.header("authorization")?.match(/^Bearer +(\S+)$/i)?.[1];
	if (!token) {
		throw new InvalidAccessTokenError();
	}
	return token;
}

// `data` is the private store of the component. `PasswordAuthDanceComponent` keeps the password hash under
// `data.hash`, and `EmailAuthDanceComponent` keeps the address under `data.email`. No component declares which of
// its keys are safe to disclose, so this function drops the whole field rather than some of its keys. A client
// needs two facts from this list: which components exist, and whether each one is confirmed. It never needs the
// value a component holds.
//
// The return type is the `…Public` half of the pair that identity.ts declares. The documented response schema
// comes from that same type, so the two cannot describe different shapes.
function withoutComponentData(component: AuthDanceIdentityComponent): AuthDanceIdentityComponentPublic {
	const { data: _data, ...rest } = component;
	return rest;
}

function localeOf(c: Context, fromBody?: string): string {
	return fromBody ?? c.req.header("accept-language")?.split(",")[0]?.split(";")[0]?.trim() ?? "en";
}

// The address and the user agent describe the caller, not the request. This function therefore reads both from
// the headers, never from the body. A client must not choose what the library records against its own session.
function callerOf(c: Context): { address?: string; userAgent?: string } {
	return {
		address: c.req.header("cf-connecting-ip") ?? c.req.header("x-forwarded-for")?.split(",")[0]?.trim(),
		userAgent: c.req.header("user-agent"),
	};
}

/** Generous on purpose: a whole NATed network shares one address, so these limits fit a crowd. */
const AddressRateLimits: Required<AuthDanceAddressRateLimits> = {
	request: { limit: 300, window: 60 },
	send: { limit: 60, window: 60 },
};

/**
 * The two routes that put a message on a channel. Each call has a cost, so these routes get a bucket of their own.
 *
 * The middleware compares the whole request path against these two entries. A `basePath` prefixes that path, so the
 * match then fails and the route consumes the `request` bucket only.
 */
const sendRoutes = ["/send-prompt", "/send-validation"];

/**
 * The Hono app that serves the AuthDance routes, with the bindings every handler needs.
 *
 * A handler never holds an `AuthDanceApi` of its own. The caller passes one as `api` on each `fetch` call, together with
 * the optional per-address buckets as `rate_limit`. When you do not want the ready-made `fetch` handler, mount this app
 * inside an app of your own.
 */
export type AuthDanceApp = Hono<{ Bindings: { api: AuthDanceApi; rate_limit?: AuthDanceAddressRateLimits } }>;

/** What `createAuthDanceApp` needs before it mounts the routes. */
export interface AuthDanceAppOptions {
	/** The prefix for every route, for example `/auth`. Without it the routes sit at the root. */
	basePath?: string;
}

/**
 * Builds the Hono app that serves AuthDance over HTTP.
 *
 * Every route is a POST. The app mounts `/sign-in`, `/sign-up`, `/sign-out`, `/list-sessions`, `/list-components` and
 * `/refresh-token`. It then mounts `/enroll`, `/unenroll`, `/rotate`, `/recover`, `/subscribe`, `/unsubscribe` and
 * `/delete`. It ends with `/send-prompt`, `/submit-prompt`, `/send-validation` and `/submit-validation`.
 * `options.basePath` prefixes all 17 of them. Each handler calls the matching `AuthDanceApi` method on `c.env.api` and
 * answers with its JSON.
 *
 * `/list-sessions` and `/list-components` have no such method. Both resolve the identity with `accessTokenIdentity`, then
 * read the list themselves. `/list-sessions` sorts by session id. `/list-components` drops the private data each
 * component holds. The nine routes that act on an already authenticated identity take the access token from the
 * `Authorization: Bearer` header. Each route carries its own OpenAPI description, which hono-openapi reads.
 *
 * The app maps a failure to a status code in three places. A body that does not match the route schema answers 400 with
 * `{ error: "BAD_REQUEST" }`, the same one-key shape as every other failure. A `RateLimitedError` answers 429, and adds
 * `Retry-After` in seconds when the rate limiter adapter reports the delay. Every other `AuthDanceError` answers 500 with
 * its own code, and anything else answers 500 with `UNKNOWN`.
 *
 * The app reads the caller address from `cf-connecting-ip`, or from the first entry of `x-forwarded-for`. It reads the
 * locale from the `locale` field of the body first, then from the first entry of `accept-language`. It uses `en` when
 * neither is present. The address and the user agent always come from the headers, never from the body. A client must
 * not choose what the library records against its own session.
 *
 * A middleware consumes the per-address buckets before anything parses a body, so a flood costs nothing but the counter.
 * `/send-prompt` and `/send-validation` consume a second, tighter bucket on top of that, because they put a message on a
 * channel. That second bucket matches the whole request path, so an `options.basePath` keeps it out of reach. The
 * middleware leaves a request with no caller address unbucketed.
 */
export function createAuthDanceApp(options?: AuthDanceAppOptions): AuthDanceApp {
	let app = new Hono<{ Bindings: { api: AuthDanceApi; rate_limit?: AuthDanceAddressRateLimits } }>();

	if (options?.basePath) {
		app = app.basePath(options.basePath);
	}

	// `AuthDanceApi` wraps everything that is not an `AuthDanceError` in an `AuthDanceUnknownError`, and `"UNKNOWN"`
	// is the code that wrapper carries. Every failure from the state machine therefore lands in one of the two
	// branches below. The `"UNKNOWN"` fallback also covers a failure that the HTTP layer itself throws. A rate limit
	// is the one failure that is neither the fault of the caller nor the fault of the server, so it is the only one
	// worth an answer other than a 500.
	app.onError((err, c) => {
		if (err instanceof RateLimitedError) {
			return c.json({ error: err.code }, 429, err.retryAfter === undefined ? {} : { "retry-after": `${err.retryAfter}` });
		}
		return c.json({ error: err instanceof AuthDanceError ? err.code : "UNKNOWN" }, 500);
	});

	// This middleware is the per-address counterpart to the per-identity buckets `AuthDanceApi` consumes. Those
	// buckets stop a flood against one identity. These ones stop one caller address from repeating the same abuse across
	// many identities. An example is a probe for valid addresses through sign-in, or an endless stream of sign-ups. The
	// middleware runs before the app parses a body, so a flood costs nothing but the counter.
	//
	// The middleware leaves a request with no caller address unbucketed. It does not group such requests under a
	// shared "unknown" key, because one caller could then block every such request for everybody.
	app.use(async (c, next) => {
		const { address } = callerOf(c);
		if (address) {
			const limits = c.env.rate_limit;
			await consumeAddressRateLimit(c, `request:${address}`, limits?.request ?? AddressRateLimits.request);
			if (sendRoutes.includes(c.req.path)) {
				await consumeAddressRateLimit(c, `send:${address}`, limits?.send ?? AddressRateLimits.send);
			}
		}
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
		// The handler sorts by id, so the answer does not depend on the order a KV provider enumerates in. A session
		// id is a ksuid, and its leading characters carry the creation second, so the list follows creation order
		// closely. `localeCompare` orders by locale collation, not by the base62 value of the id, so two ids from
		// different seconds can still appear in the wrong order. The order stays stable for the same set of sessions.
		async (c) => {
			const { session } = await c.env.api.accessTokenIdentity(bearer(c));
			const sessions = await c.env.api.storage.listSession(session.identityId);
			return c.json({ sessions: sessions.sort((a, b) => a.id.localeCompare(b.id)), current: session.id });
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
			const { identity } = await c.env.api.accessTokenIdentity(bearer(c));
			return c.json({ components: identity.components.map(withoutComponentData) });
		},
	);

	app.post(
		"/refresh-token",
		describeRoute({
			summary: "Refresh the tokens",
			description: "Exchanges a refresh token for a freshly minted set of access, id and refresh tokens on the same session.",
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
				"Removes a component from the authenticated identity, behind an explicit confirmation. Refused with WOULD_LOCK_OUT when no path through the choreography would still be fully covered by the surviving components.",
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
				"Replaces the value of an already enrolled component. Control of the current value is proven first, but only for components that can verify themselves: receiving a one-time code at the current address proves something, whereas re-typing a password proves nothing the access token has not already established, so such components go straight to the replacement.",
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
				"The one flow open to a caller with no session at all. `name` is the component the caller can no longer provide. The answer offers every component of the choreography that can identify the caller and prove control on its own — the recovered one excluded — and the caller proves control of one of them before the library resets what they named. With no such component left the request is refused with COMPONENT_NOT_RECOVERABLE.",
			tags: ["Auth"],
			responses: {
				200: {
					description: "The choice of components to identify through. Nothing about the identity is disclosed yet.",
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
				"Attaches a channel to the authenticated identity. The recipient is collected first, then confirmed through a channel the identity already trusts — subscribing SMS is confirmed by mail, for instance — so an identity with no other confirmed channel is refused with NO_VERIFICATION_CHANNEL.",
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
				"Detaches a channel from the authenticated identity, behind an explicit confirmation. Refused with CHANNEL_IN_USE while an enrolled component still links to it.",
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
				"Delivers the current prompt over its channel, for the components that can be sent rather than typed — mailing a one-time code, for instance. `locale` falls back to the Accept-Language header. `name` selects which component to send when the current step is a choice.",
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
				"Answers the current prompt and advances the flow. Returns the next prompt, the tokens once an authentication completes, or a bare success once a management flow completes. `name` selects which component is being answered when the current step is a choice.",
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

	app.post(
		"/send-validation",
		describeRoute({
			summary: "Send the current validation",
			description:
				"Delivers the validation prompt that confirms a value already collected — the one-time code proving control of the address just given. `locale` falls back to the Accept-Language header.",
			tags: ["Auth"],
			responses: {
				200: {
					description: "The validation has been sent",
					content: { "application/json": { schema: resolver(ResultResponse) } },
				},
				...withErrorResponses(),
			},
		}),
		validator("json", v.object({ name: v.string(), locale: v.optional(v.string()), state: v.string() }), badRequest),
		async (c) => {
			const { name, locale, state } = c.req.valid("json");
			return c.json(await c.env.api.sendValidation({ name, locale: localeOf(c, locale), state }));
		},
	);

	app.post(
		"/submit-validation",
		describeRoute({
			summary: "Submit the current validation",
			description:
				"Answers the validation prompt, confirming the value it covers and advancing the flow. Returns the next prompt, the tokens once an authentication completes, or a bare success once a management flow completes.",
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
			return c.json(await c.env.api.submitValidation({ name, value, state, ...callerOf(c) }));
		},
	);

	return app;
}
