import { type Context, Hono } from "hono";
import { describeRoute, resolver, validator } from "hono-openapi";
import * as v from "valibot";
import type { AuthDanceAddressRateLimits, AuthDanceApi, AuthDanceRateLimit } from "./api.ts";
import { AuthDanceError, Errors, InvalidAccessTokenError, RateLimitedError } from "./error.ts";
import type { IdentityComponent, IdentityComponentPublic } from "./identity.ts";
import { AuthDancePromptInput } from "./prompt.ts";
import { AuthDanceResponseComponents, AuthDanceResponseResult, AuthDanceResponseSessions, AuthDanceResponseTokens } from "./response.ts";

// `AuthDanceComponent.getPrompt` and `AuthDanceChannel.getPrompt` both return an `AuthDancePromptInput`, and the
// members of a `choice()` are constrained to components — so a choice prompt can only ever hold
// input prompts and the recursion in `prompt.ts`'s `AuthDancePromptChoice` is unreachable. Describing
// that one level explicitly instead of reusing the recursive schema keeps the generated document
// self-contained: `v.lazy` becomes a `$defs` entry that hono-openapi rewrites into a
// `#/components/schemas/…` reference it never registers, leaving a dangling `$ref`.
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

// The schemas below describe what goes over the wire; they never validate anything. They exist
// because `AuthDanceResponseState.expireAt` is a `Date` — the type the domain works with, but not the
// one the client sees, since `c.json` serialises it to an ISO string — and `v.date()` has no JSON
// Schema representation at all, so the domain schema cannot be handed to `resolver()` as-is.
const StateResponse = v.pipe(
	v.object({
		state: v.string(),
		prompt: PromptResponse,
		expireAt: v.pipe(v.string(), v.isoTimestamp()),
	}),
	v.title("AuthDanceResponseState"),
	v.description("The prompt to answer next, with the opaque state to echo back and the moment it stops being valid"),
);

// These four carry no dates — `AuthDanceSession.expireAt` is already the ISO string the client sees — and
// are reused verbatim from the domain.
const TokensResponse = AuthDanceResponseTokens;
const ResultResponse = AuthDanceResponseResult;
const SessionsResponse = AuthDanceResponseSessions;
const ComponentsResponse = AuthDanceResponseComponents;

const AnyResponse = v.pipe(
	v.union([StateResponse, TokensResponse, ResultResponse]),
	v.title("AuthDanceResponse"),
	v.description("The next prompt, the tokens minted by a completed authentication, or a bare success for a completed management flow"),
);

// The documented codes stay derived from the `Errors` registry rather than restated, so a new
// `AuthDanceError` subclass shows up in the specification the moment it is registered.
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

// Every validation failure answers in the same `{ error }` shape as an `AuthDanceError`, so the surface
// has exactly one error format instead of also leaking @hono/standard-validator's issue list.
function badRequest(result: { success: boolean }, c: Context) {
	if (!result.success) {
		return c.json({ error: "BAD_REQUEST" } as const, 400);
	}
}

// A missing or malformed header is reported with the same code a rejected token would produce: from
// the caller's side both mean "this request carried no usable access token", and saying which would
// only help someone probing.
function bearer(c: Context): string {
	const token = c.req.header("authorization")?.match(/^Bearer +(\S+)$/i)?.[1];
	if (!token) {
		throw new InvalidAccessTokenError();
	}
	return token;
}

// `data` is the component's own private store — PasswordAuthDanceComponent keeps the hash there, OTP its
// pending code — and no component declares which of its keys would be safe to disclose. It is therefore
// dropped wholesale rather than filtered: what a client needs from this list is which components exist
// and whether each is confirmed, never what they hold. The return type is the `…Public` half of the pair
// declared in identity.ts, which is also what the documented response schema is built from, so the two
// cannot describe different shapes.
function withoutComponentData(component: IdentityComponent): IdentityComponentPublic {
	const { data: _data, ...rest } = component;
	return rest;
}

function localeOf(c: Context, fromBody?: string): string {
	return fromBody ?? c.req.header("accept-language")?.split(",")[0]?.split(";")[0]?.trim() ?? "en";
}

// Both describe the caller rather than the request, so they are read from the connection and never
// from the body — a client must not be able to choose what gets recorded against its own session.
function callerOf(c: Context): { address?: string; userAgent?: string } {
	return {
		address: c.req.header("cf-connecting-ip") ?? c.req.header("x-forwarded-for")?.split(",")[0]?.trim(),
		userAgent: c.req.header("user-agent"),
	};
}

/** Generous on purpose: a whole NATed network shares one address, so these are sized for a crowd. */
const AddressRateLimits: Required<AuthDanceAddressRateLimits> = {
	request: { limit: 300, window: 60 },
	send: { limit: 60, window: 60 },
};

/** The two routes that put a message on a channel; they carry a cost per call, so they get a bucket of their own. */
const sendRoutes = ["/send-prompt", "/send-validation"];

const app = new Hono<{ Bindings: { api: AuthDanceApi; rate_limit?: AuthDanceAddressRateLimits } }>();

// `AuthDanceApi`'s own guard has already wrapped everything that is not an `AuthDanceError` into an
// `AuthDanceUnknownError`, so there are only two cases here — and `"UNKNOWN"` is precisely the code that
// wrapper carries. A rate limit is the one failure that is neither the caller's fault nor a server
// fault, and the only one worth answering with something other than a 500.
app.onError((err, c) => {
	if (err instanceof RateLimitedError) {
		return c.json({ error: err.code }, 429, err.retryAfter === undefined ? {} : { "retry-after": `${err.retryAfter}` });
	}
	return c.json({ error: err instanceof AuthDanceError ? err.code : "UNKNOWN" }, 500);
});

// The per-address counterpart to the per-identity buckets `AuthDanceApi` consumes: those stop one identity
// from being hammered, this one stops one origin from spreading the same abuse across many identities —
// enumerating addresses through sign-in, or starting an endless stream of sign-ups. It runs before
// anything is parsed, so a flood costs nothing but the counter.
//
// An address the connection did not give us is not bucketed rather than lumped into a shared "unknown"
// key, which would let any one caller lock every such request out for everybody.
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
	// Sorted by id so the answer does not depend on the order a KV provider happens to enumerate in. Session
	// ids are ksuids, whose sortable prefix has one-second resolution: that puts the list in creation order
	// down to the second, and settles the rest arbitrarily but stably.
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
			"The one flow open to a caller with no session at all. The caller proves control of a single component the choreography can start with, then resets whatever the choreography still requires after it — precisely the components the caller could not provide. The component must therefore both resolve an identity and prove control of it, or the request is refused with COMPONENT_NOT_RECOVERABLE.",
		tags: ["Auth"],
		responses: {
			200: {
				description: "The component's own prompt. Nothing about the identity is disclosed yet.",
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

export default app;
