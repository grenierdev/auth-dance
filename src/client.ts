/**
 * @module
 *
 * The client half of the dance. `AuthDanceClient` speaks to the routes `createAuthDanceApp` mounts, and
 * `AuthDanceClientChoreography` drives one flow from its first prompt to its last answer.
 *
 * The library keeps nothing between two calls. Each answer carries the opaque state forward, and the dance holds that
 * state for the owner. A flow ends with the tokens of a new session, or with a bare success.
 *
 * This module imports no HTTP layer, so it runs in a browser. Give it the `fetch` of the page, or the `fetch` of an
 * `AuthDance` instance to dance in process.
 *
 * @example
 * ```ts
 * const client = new AuthDanceClient({ baseUrl: "https://auth.example.com" });
 * using choreography = await client.signIn();
 * await choreography.submitPrompt("john.doe@example.com");
 * await choreography.submitPrompt("hunter2");
 * console.log(client.identity?.id);
 * ```
 */

import { decodeJwt } from "jose/jwt/decode";
import { type GenericSchema, parse } from "valibot";
import { type AuthDanceError, Errors, RateLimitedError } from "./error.ts";
import type { AuthDanceIdentityComponentPublic } from "./identity.ts";
import type { AuthDancePrompt, AuthDancePromptInput } from "./prompt.ts";
import {
	AuthDanceResponse,
	AuthDanceResponseComponents,
	AuthDanceResponseResult,
	AuthDanceResponseSessions,
	AuthDanceResponseState,
	AuthDanceResponseTokens,
} from "./response.ts";
import type { AuthDanceSession } from "./session.ts";

// The shapes the routes answer with. A page imports them from here, so the client half needs no entry point that
// carries the HTTP layer with it.
export type {
	AuthDanceIdentityChallengePublic,
	AuthDanceIdentityChannelPublic,
	AuthDanceIdentityComponentPublic,
	AuthDanceIdentityIdentificationPublic,
} from "./identity.ts";
export type { AuthDancePrompt, AuthDancePromptChoice, AuthDancePromptInput } from "./prompt.ts";
export type {
	AuthDanceResponse,
	AuthDanceResponseResult,
	AuthDanceResponseSessions,
	AuthDanceResponseState,
	AuthDanceResponseTokens,
} from "./response.ts";
export type { AuthDanceSession } from "./session.ts";

/**
 * The base class for every failure this module raises on its own. A failure the library reports keeps its own class,
 * out of the `Errors` registry.
 */
export abstract class AuthDanceClientError extends Error {
	/**
	 * Makes the error.
	 *
	 * @param message What went wrong, for the owner and for the log.
	 * @param options The standard error options. Put the failure this one wraps in `cause`.
	 */
	constructor(message?: string, options?: ErrorOptions) {
		super(message, options);
		Object.defineProperty(this, "name", { value: new.target.name, enumerable: false, configurable: true });
	}
}

/**
 * A route answered with something this module cannot map to the `Errors` registry: a body that does not parse, or a code
 * the registry does not hold.
 */
export class AuthDanceResponseError extends AuthDanceClientError {
	/** The status the call answered with. */
	readonly status: number;
	/** The code the body named, or `UNKNOWN` when the body named none. */
	readonly code: string;

	/**
	 * Makes the error.
	 *
	 * @param status The status the call answered with.
	 * @param code The code the body named.
	 * @param options The standard error options. Put the failure this one wraps in `cause`.
	 */
	constructor(status: number, code: string, options?: ErrorOptions) {
		super(`${code} · HTTP ${status}`, options);
		this.status = status;
		this.code = code;
	}
}

/** A route that carries a bearer token was called, and the client holds no tokens. */
export class AuthDanceNotAuthenticatedError extends AuthDanceClientError {}

/** The dance holds no prompt to answer: it is over, it expired, or the step is a choice with no branch picked. */
export class AuthDanceClientChoreographyStateError extends AuthDanceClientError {}

/** The name given to `choose`, to `sendPrompt` or to `submitPrompt` is not a branch of the current step. */
export class AuthDanceClientChoreographyPromptError extends AuthDanceClientError {}

/** What one flow needs before it starts. */
export interface AuthDanceFlowDefinition {
	/** The route that starts the flow. */
	path: string;
	/** Whether the start carries a bearer token. Every authenticated flow also needs a recent sign-in. */
	authenticated: boolean;
	/** What the body names: nothing, a component of `api.components`, or a channel of `api.channels`. */
	argument: "none" | "component" | "channel";
}

/**
 * The nine flows, under the name each route uses.
 *
 * The six authenticated flows check the elevated window first. Past `durations.elevated` they answer
 * `FRESH_SIGN_IN_REQUIRED`.
 */
export const AuthDanceFlows = {
	"sign-in": { path: "/sign-in", authenticated: false, argument: "none" },
	"sign-up": { path: "/sign-up", authenticated: false, argument: "none" },
	"recover": { path: "/recover", authenticated: false, argument: "component" },
	"enroll": { path: "/enroll", authenticated: true, argument: "component" },
	"unenroll": { path: "/unenroll", authenticated: true, argument: "component" },
	"rotate": { path: "/rotate", authenticated: true, argument: "component" },
	"subscribe": { path: "/subscribe", authenticated: true, argument: "channel" },
	"unsubscribe": { path: "/unsubscribe", authenticated: true, argument: "channel" },
	"delete": { path: "/delete", authenticated: true, argument: "none" },
} as const satisfies Record<string, AuthDanceFlowDefinition>;

/** The name of a flow, and the key of {@link AuthDanceFlows}. */
export type AuthDanceFlow = keyof typeof AuthDanceFlows;

/** One step of a dance: the prompt the owner answers, and the state that carries it to the next call. */
export interface AuthDanceClientChoreographyStep {
	/** The in-progress dance, as the library encrypted it. Every later call echoes it back. */
	state: string;
	/** What the owner answers: one input, or a choice between the branches of the choreography. */
	prompt: AuthDancePrompt;
	/** The moment the flow expires, as an ISO 8601 string. An answer to a prompt never extends it. */
	expireAt: string;
}

/** Everything a dance holds, in a shape `JSON.stringify` takes. A page that reloads reads one of these back. */
export interface AuthDanceClientChoreographySnapshot {
	/** The flow that is running. */
	flow: AuthDanceFlow;
	/** The component or the channel the flow acts on. A flow that takes no argument carries none. */
	name?: string;
	/** Every step so far, oldest first. The last one is the step the owner answers. */
	steps: AuthDanceClientChoreographyStep[];
	/** The branch of the current choice the owner picked, by name. */
	selected?: string;
	/** The names answered so far in this flow, oldest first. */
	trail: string[];
}

/**
 * Where a dance keeps its progress, so a page that reloads goes on from the same step.
 *
 * Each method may answer at once or with a promise. {@link webStorageStore} builds one over `localStorage`.
 */
export interface AuthDanceClientChoreographyStore {
	/** Reads the stored snapshot, or `null` when the store holds none. */
	get(): AuthDanceClientChoreographySnapshot | null | Promise<AuthDanceClientChoreographySnapshot | null>;
	/** Writes the snapshot over whatever the store held. */
	set(snapshot: AuthDanceClientChoreographySnapshot): void | Promise<void>;
	/** Drops the stored snapshot. */
	delete(): void | Promise<void>;
}

/**
 * Where the client keeps the tokens of the session, so a page that reloads stays signed in.
 *
 * Each method may answer at once or with a promise. {@link webStorageStore} builds one over `localStorage`.
 */
export interface AuthDanceTokenStore {
	/** Reads the stored tokens, or `null` when the store holds none. */
	get(): AuthDanceResponseTokens | null | Promise<AuthDanceResponseTokens | null>;
	/** Writes the tokens over whatever the store held. */
	set(tokens: AuthDanceResponseTokens): void | Promise<void>;
	/** Drops the stored tokens. */
	delete(): void | Promise<void>;
}

/** The three methods {@link webStorageStore} needs. Both `localStorage` and `sessionStorage` hold them. */
export interface AuthDanceWebStorage {
	/** Reads one entry, or `null` when the storage holds none under that key. */
	getItem(key: string): string | null;
	/** Writes one entry. */
	setItem(key: string, value: string): void;
	/** Drops one entry. */
	removeItem(key: string): void;
}

/**
 * Builds a store over a web storage. The value travels as JSON, and an entry that does not parse reads as empty.
 *
 * The result satisfies both {@link AuthDanceClientChoreographyStore} and {@link AuthDanceTokenStore}.
 *
 * @typeParam T What the store holds.
 * @param key The key of the entry.
 * @param storage Where the entry goes. `localStorage` outlives the tab, and `sessionStorage` goes with it.
 * @returns A store that reads and writes that one entry.
 *
 * @example
 * ```ts
 * const client = new AuthDanceClient({ baseUrl: "/auth", store: webStorageStore("auth-dance.tokens", localStorage) });
 * ```
 */
export function webStorageStore<T>(key: string, storage: AuthDanceWebStorage): {
	/** Reads the entry, or `null` when it is absent or does not parse. */
	get(): T | null;
	/** Writes the entry as JSON. */
	set(value: T): void;
	/** Drops the entry. */
	delete(): void;
} {
	return {
		get: (): T | null => {
			const raw = storage.getItem(key);
			if (raw === null) {
				return null;
			}
			try {
				return JSON.parse(raw) as T;
			} catch {
				return null;
			}
		},
		set: (value: T): void => storage.setItem(key, JSON.stringify(value)),
		delete: (): void => storage.removeItem(key),
	};
}

/** Everything `AuthDanceClient` needs before it calls a route. */
export interface AuthDanceClientOptions {
	/**
	 * What every route path hangs off, `https://auth.example.com` or `/auth` for example. A trailing slash goes away.
	 */
	baseUrl: string | URL;
	/**
	 * What carries a request. Hand it the `fetch` of an `AuthDance` instance to dance in process, and leave it out to
	 * use the `fetch` of the platform.
	 * @defaultValue `globalThis.fetch`
	 */
	fetch?: (request: Request) => Response | Promise<Response>;
	/** The tokens of a session the client already holds, from a server pass for example. */
	tokens?: AuthDanceResponseTokens;
	/** Where the tokens live between two page loads. Without one the client keeps them in memory alone. */
	store?: AuthDanceTokenStore;
	/**
	 * The language of every message the library delivers. It travels as the `accept-language` header, and
	 * `sendPrompt` takes one of its own for a single call.
	 * @defaultValue "en"
	 */
	locale?: string;
	/**
	 * Extra headers on every request, `user-agent` for example. A header this record names wins over the ones the
	 * client writes, the `authorization` header excepted.
	 */
	headers?: Record<string, string>;
	/**
	 * How long an access token must still be valid for the client to use it, in seconds. Under this the client
	 * exchanges the refresh token first.
	 * @defaultValue 10
	 */
	refreshSkew?: number;
}

/** What one call to {@link AuthDanceClient.request} needs. */
export interface AuthDanceRequestOptions {
	/** What the body carries. A route that takes no body takes none here either. */
	body?: unknown;
	/** Whether the call carries a bearer token. The client exchanges the refresh token first when the access token is about to expire. */
	authenticated?: boolean;
	/** The language of this one call, over the `locale` of the client. */
	locale?: string;
	/** Extra headers on this one call, over the `headers` of the client. */
	headers?: Record<string, string>;
	/** Drops the call. */
	signal?: AbortSignal;
}

/** What one flow needs when it starts. */
export interface AuthDanceClientChoreographyOptions {
	/** Where the dance keeps its progress. A snapshot of the same flow resumes instead of starting a new one. */
	store?: AuthDanceClientChoreographyStore;
	/** Drops the call that starts the flow. */
	signal?: AbortSignal;
}

// A listener that throws never fails the flow, the way an api hook never does.
class Listeners<T> {
	#handlers = new Set<(value: T) => void>();

	on(handler: (value: T) => void): Disposable {
		this.#handlers.add(handler);
		return {
			[Symbol.dispose]: (): void => {
				this.#handlers.delete(handler);
			},
		};
	}

	emit(value: T): void {
		for (const handler of this.#handlers) {
			try {
				handler(value);
			} catch {
				// Nowhere left to report to.
			}
		}
	}

	clear(): void {
		this.#handlers.clear();
	}
}

// The `Errors` registry maps a code to its class. Every one of them builds with no argument, but their signatures
// differ, so the union of constructors cannot be called as it stands.
const errorsByCode = Errors as unknown as Record<string, new () => AuthDanceError>;

// The library reports a failure as a single `{ error: CODE }`, whatever the status.
function toError(status: number, body: unknown, retryAfter: string | null): Error {
	const code = (body as { error?: unknown } | null | undefined)?.error;
	if (typeof code !== "string") {
		return new AuthDanceResponseError(status, "UNKNOWN");
	}
	if (code === "RATE_LIMITED") {
		const seconds = retryAfter === null ? Number.NaN : Number(retryAfter);
		return new RateLimitedError(Number.isFinite(seconds) ? seconds : undefined);
	}
	const constructor = errorsByCode[code];
	return constructor ? new constructor() : new AuthDanceResponseError(status, code);
}

// `expireAt` is a `Date` in the schemas and an ISO 8601 string on the wire.
function revive(body: unknown): unknown {
	if (body !== null && typeof body === "object" && typeof (body as { expireAt?: unknown }).expireAt === "string") {
		return { ...body, expireAt: new Date((body as { expireAt: string }).expireAt) };
	}
	return body;
}

function parseBody<T>(schema: GenericSchema<T>, body: unknown): T {
	try {
		return parse(schema, revive(body));
	} catch (cause) {
		throw new AuthDanceResponseError(200, "UNKNOWN", { cause });
	}
}

/**
 * The client of the dance. It calls the routes, it keeps the tokens of the session, and it hands a
 * {@link AuthDanceClientChoreography} to whoever runs a flow.
 *
 * Every method that carries a bearer token exchanges the refresh token first when the access token is about to expire.
 * A completed sign-in, a completed sign-up and every exchange write their tokens back into the client, and into the
 * store when there is one.
 *
 * @example
 * ```ts
 * const client = new AuthDanceClient({ baseUrl: "https://auth.example.com" });
 * using choreography = await client.signIn();
 * await choreography.submitPrompt("john.doe@example.com");
 * await choreography.submitPrompt("hunter2");
 * ```
 */
export class AuthDanceClient {
	#baseUrl: string;
	#fetch: (request: Request) => Response | Promise<Response>;
	#tokens: AuthDanceResponseTokens | undefined;
	#store: AuthDanceTokenStore | undefined;
	#locale: string;
	#headers: Record<string, string>;
	#refreshSkew: number;
	#listeners = new Listeners<AuthDanceResponseTokens | undefined>();
	#restoring: Promise<void> | undefined;
	#refreshing: Promise<AuthDanceResponseTokens> | undefined;

	/**
	 * Builds the client from a policy. It calls nothing here, and it reads the store on the first call that needs the
	 * tokens. Call {@link restore} to read the store up front.
	 *
	 * @param options Where the routes live, what carries a request, and where the tokens go.
	 */
	constructor(options: AuthDanceClientOptions) {
		this.#baseUrl = String(options.baseUrl).replace(/\/+$/, "");
		this.#fetch = options.fetch ?? ((request) => globalThis.fetch(request));
		this.#tokens = options.tokens;
		this.#store = options.store;
		this.#locale = options.locale ?? "en";
		this.#headers = options.headers ?? {};
		this.#refreshSkew = options.refreshSkew ?? 10;
	}

	/** The whole answer of the last sign-in, sign-up or exchange, or nothing while the client holds no session. */
	get credentials(): AuthDanceResponseTokens | undefined {
		return this.#tokens;
	}

	/** The three tokens of the session, or nothing while the client holds no session. */
	get tokens(): AuthDanceResponseTokens["tokens"] | undefined {
		return this.#tokens?.tokens;
	}

	/** The session record the tokens belong to, or nothing while the client holds no session. */
	get session(): AuthDanceSession | undefined {
		return this.#tokens?.session;
	}

	/** Who the tokens belong to, with the identity data the scopes of the session allow. */
	get identity(): AuthDanceResponseTokens["identity"] | undefined {
		return this.#tokens?.identity;
	}

	/**
	 * Registers a listener the client calls every time the tokens change. A listener that throws never fails the call.
	 *
	 * @param handler What to call with the new tokens, or with nothing once the client drops them.
	 * @returns A `Disposable` that drops the listener.
	 */
	onTokensChange(handler: (tokens: AuthDanceResponseTokens | undefined) => void): Disposable {
		return this.#listeners.on(handler);
	}

	/**
	 * Reads the tokens out of the store. It runs one time, and every call that needs the tokens awaits it first.
	 *
	 * @returns A promise that resolves once the store answered.
	 */
	restore(): Promise<void> {
		this.#restoring ??= (async (): Promise<void> => {
			if (!this.#store || this.#tokens) {
				return;
			}
			const stored = await this.#store.get();
			this.#tokens ??= stored ?? undefined;
		})();
		return this.#restoring;
	}

	/**
	 * Takes a set of tokens as the session of this client, and writes them to the store.
	 *
	 * @param tokens What a sign-in, a sign-up or an exchange answered with.
	 */
	async setTokens(tokens: AuthDanceResponseTokens): Promise<void> {
		this.#tokens = tokens;
		this.#restoring ??= Promise.resolve();
		await this.#store?.set(tokens);
		this.#listeners.emit(tokens);
	}

	/**
	 * Drops the tokens of this client, and the ones in the store. It calls no route, so the session stays open on the
	 * server. Use {@link signOut} to destroy it.
	 */
	async clearTokens(): Promise<void> {
		this.#tokens = undefined;
		this.#restoring ??= Promise.resolve();
		await this.#store?.delete();
		this.#listeners.emit(undefined);
	}

	/**
	 * Calls one route and answers with the body it parsed.
	 *
	 * Every route of the library is a POST that answers JSON. A status other than 200 raises the class of the code the
	 * body named, out of the `Errors` registry, or an {@link AuthDanceResponseError} for anything else.
	 *
	 * @param path The route, `/sign-in` for example.
	 * @param options What the body carries, whether the call takes a bearer token, and the language of the message.
	 * @returns The parsed body.
	 * @throws AuthDanceNotAuthenticatedError when the call takes a bearer token and the client holds none.
	 * @throws AuthDanceResponseError when the body names a code the `Errors` registry does not hold.
	 */
	async request(path: string, options?: AuthDanceRequestOptions): Promise<unknown> {
		const headers: Record<string, string> = {
			"content-type": "application/json",
			"accept-language": options?.locale ?? this.#locale,
			...this.#headers,
			...options?.headers,
		};
		if (options?.authenticated) {
			headers.authorization = `Bearer ${await this.#accessToken(options.signal)}`;
		}
		const response = await this.#fetch(
			new Request(`${this.#baseUrl}${path}`, {
				method: "POST",
				headers,
				body: options?.body === undefined ? undefined : JSON.stringify(options.body),
				signal: options?.signal,
			}),
		);
		const body = await response.json().catch(() => undefined);
		if (response.status !== 200) {
			throw toError(response.status, body, response.headers.get("retry-after"));
		}
		return body;
	}

	/**
	 * Exchanges the refresh token for a fresh set of tokens on the same session.
	 *
	 * The new tokens keep the `aat` of the sign-in, so an exchange never re-opens the elevated window. Two calls at once
	 * share one exchange, and a refused exchange is not kept, so the next call tries again.
	 *
	 * @param signal Drops the call.
	 * @returns The new tokens, the session and the scoped identity data.
	 * @throws AuthDanceNotAuthenticatedError when the client holds no refresh token.
	 * @throws InvalidRefreshTokenError when the token is tampered with, expired, or missing a claim.
	 */
	refreshTokens(signal?: AbortSignal): Promise<AuthDanceResponseTokens> {
		this.#refreshing ??= this.#refreshTokens(signal).finally(() => {
			this.#refreshing = undefined;
		});
		return this.#refreshing;
	}

	async #refreshTokens(signal?: AbortSignal): Promise<AuthDanceResponseTokens> {
		await this.restore();
		const refresh_token = this.#tokens?.tokens.refresh_token;
		if (!refresh_token) {
			throw new AuthDanceNotAuthenticatedError("the client holds no refresh token");
		}
		const body = await this.request("/refresh-token", { body: { refresh_token }, signal });
		const result = parseBody(AuthDanceResponseTokens, body);
		await this.setTokens(result);
		return result;
	}

	/**
	 * Destroys the session of this client, and drops the tokens it holds.
	 *
	 * A refused call still drops the tokens, because the owner asked to leave.
	 *
	 * @param options `others` destroys every session of the identity, this one included. `signal` drops the call.
	 */
	async signOut(options?: { others?: boolean; signal?: AbortSignal }): Promise<void> {
		await this.restore();
		if (!this.#tokens) {
			return;
		}
		await this.request("/sign-out", {
			body: { others: options?.others ?? false },
			authenticated: true,
			signal: options?.signal,
		}).catch(() => undefined);
		await this.clearTokens();
	}

	/**
	 * Lists every session open on the identity, oldest first, with the address and the user agent each one was opened
	 * from. A sign-out with `others` destroys exactly these.
	 *
	 * @param signal Drops the call.
	 * @returns The open sessions, and the id of the one that asked.
	 * @throws AuthDanceNotAuthenticatedError when the client holds no tokens.
	 */
	async listSessions(signal?: AbortSignal): Promise<AuthDanceResponseSessions> {
		const body = await this.request("/list-sessions", { authenticated: true, signal });
		return parseBody(AuthDanceResponseSessions, body);
	}

	/**
	 * Lists every component enrolled on the identity: its identifications, its challenges and its channels, under the
	 * names the management flows take. The value a component holds never comes back.
	 *
	 * @param signal Drops the call.
	 * @returns The enrolled components, without the private data of each one.
	 * @throws AuthDanceNotAuthenticatedError when the client holds no tokens.
	 */
	async listComponents(signal?: AbortSignal): Promise<AuthDanceIdentityComponentPublic[]> {
		const body = await this.request("/list-components", { authenticated: true, signal });
		return parseBody(AuthDanceResponseComponents, body).components;
	}

	/**
	 * Answers the current prompt of a flow and moves the dance one step. {@link AuthDanceClientChoreography.submitPrompt} calls
	 * it for you, and it holds the state and the name of the step.
	 *
	 * The client takes the tokens of a completed sign-in or sign-up as its own session.
	 *
	 * @param options `name` is the component the answer belongs to. `value` is what the owner gave. `state` is the
	 * opaque string the previous call returned.
	 * @returns The next prompt, the minted tokens, or a bare success.
	 */
	async submitPrompt(
		options: { name: string; value: unknown; state: string; signal?: AbortSignal },
	): Promise<AuthDanceResponse> {
		const body = await this.request("/submit-prompt", {
			body: { name: options.name, value: options.value, state: options.state },
			signal: options.signal,
		});
		const result = parseBody(AuthDanceResponse, body);
		if ("tokens" in result) {
			await this.setTokens(result);
		}
		return result;
	}

	/**
	 * Delivers the current prompt of a flow over its channel, a one-time code for example.
	 * {@link AuthDanceClientChoreography.sendPrompt} calls it for you, and it holds the state and the name of the step.
	 *
	 * @param options `name` is the component to deliver. `locale` picks the language of the message, over the one of
	 * the client. `state` is the opaque string the previous call returned.
	 * @throws ComponentNotSendableError when the component delivers nothing over a channel.
	 */
	async sendPrompt(options: { name: string; state: string; locale?: string; signal?: AbortSignal }): Promise<void> {
		const body = await this.request("/send-prompt", {
			body: { name: options.name, locale: options.locale ?? this.#locale, state: options.state },
			locale: options.locale,
			signal: options.signal,
		});
		parseBody(AuthDanceResponseResult, body);
	}

	/**
	 * Starts an authentication.
	 *
	 * @param options Where the dance keeps its progress, and what drops the call.
	 * @returns The dance in progress, on its first prompt.
	 */
	signIn(options?: AuthDanceClientChoreographyOptions): Promise<AuthDanceClientChoreography> {
		return AuthDanceClientChoreography.start(this, "sign-in", options);
	}

	/**
	 * Starts a registration.
	 *
	 * @param options Where the dance keeps its progress, and what drops the call.
	 * @returns The dance in progress, on its first prompt.
	 */
	signUp(options?: AuthDanceClientChoreographyOptions): Promise<AuthDanceClientChoreography> {
		return AuthDanceClientChoreography.start(this, "sign-up", options);
	}

	/**
	 * Starts the recovery of one component, for an owner who can no longer provide it. This flow needs no session.
	 *
	 * The first prompt is a choice between every component of the choreography that both resolves an identity and
	 * proves control of it, the recovered one excepted. It names components and never values, so it discloses nothing.
	 *
	 * @param name The component the recovery resets.
	 * @param options Where the dance keeps its progress, and what drops the call.
	 * @returns The dance in progress, on its first prompt.
	 * @throws ComponentNotRecoverableError when nothing is left to identify the owner through.
	 */
	recover(name: string, options?: AuthDanceClientChoreographyOptions): Promise<AuthDanceClientChoreography> {
		return AuthDanceClientChoreography.start(this, "recover", { ...options, name });
	}

	/**
	 * Starts the enrollment of a new component on the identity of this client. It needs a recent sign-in.
	 *
	 * @param name The component to enroll.
	 * @param options Where the dance keeps its progress, and what drops the call.
	 * @returns The dance in progress, on the prompt that collects the new value.
	 * @throws ComponentAlreadyEnrolledError when the identity already carries that component.
	 * @throws FreshSignInRequiredError when the sign-in is older than the elevated window.
	 */
	enroll(name: string, options?: AuthDanceClientChoreographyOptions): Promise<AuthDanceClientChoreography> {
		return AuthDanceClientChoreography.start(this, "enroll", { ...options, name });
	}

	/**
	 * Starts the removal of a component from the identity of this client. It needs a recent sign-in.
	 *
	 * The removal takes the linked records with it. Answer the confirmation with {@link AuthDanceClientChoreography.confirm}.
	 *
	 * @param name The component to remove.
	 * @param options Where the dance keeps its progress, and what drops the call.
	 * @returns The dance in progress, on its confirmation prompt.
	 * @throws WouldLockOutError when no path through the choreography stays completable without that whole set.
	 */
	unenroll(name: string, options?: AuthDanceClientChoreographyOptions): Promise<AuthDanceClientChoreography> {
		return AuthDanceClientChoreography.start(this, "unenroll", { ...options, name });
	}

	/**
	 * Starts the replacement of an enrolled component on the identity of this client. It needs a recent sign-in.
	 *
	 * A component that can verify itself proves control of the current value first, so the flow answers two rounds. A
	 * component that cannot collects the replacement at once.
	 *
	 * @param name The component to replace.
	 * @param options Where the dance keeps its progress, and what drops the call.
	 * @returns The dance in progress, on its first prompt.
	 * @throws ComponentNotEnrolledError when the identity carries no such component.
	 */
	rotate(name: string, options?: AuthDanceClientChoreographyOptions): Promise<AuthDanceClientChoreography> {
		return AuthDanceClientChoreography.start(this, "rotate", { ...options, name });
	}

	/**
	 * Starts the subscription of a channel for the identity of this client. It needs a recent sign-in.
	 *
	 * The prompt collects the recipient. The library then delivers a one-time code over the new channel itself, so the
	 * validation proves control of that recipient.
	 *
	 * @param name The channel to subscribe.
	 * @param options Where the dance keeps its progress, and what drops the call.
	 * @returns The dance in progress, on the prompt that collects the recipient.
	 * @throws ChannelAlreadySubscribedError when the identity already carries that channel.
	 */
	subscribe(name: string, options?: AuthDanceClientChoreographyOptions): Promise<AuthDanceClientChoreography> {
		return AuthDanceClientChoreography.start(this, "subscribe", { ...options, name });
	}

	/**
	 * Starts the removal of a channel from the identity of this client. It needs a recent sign-in.
	 *
	 * The removal takes every component the channel links to with it. Answer the confirmation with
	 * {@link AuthDanceClientChoreography.confirm}.
	 *
	 * @param name The channel to remove.
	 * @param options Where the dance keeps its progress, and what drops the call.
	 * @returns The dance in progress, on its confirmation prompt.
	 * @throws WouldLockOutError when no path through the choreography stays completable without that whole set.
	 */
	unsubscribe(name: string, options?: AuthDanceClientChoreographyOptions): Promise<AuthDanceClientChoreography> {
		return AuthDanceClientChoreography.start(this, "unsubscribe", { ...options, name });
	}

	/**
	 * Starts the deletion of the identity of this client. It needs a recent sign-in.
	 *
	 * Every session of the identity goes with it, so the dance drops the tokens of this client once the owner
	 * confirms. Answer the confirmation with {@link AuthDanceClientChoreography.confirm}.
	 *
	 * @param options Where the dance keeps its progress, and what drops the call.
	 * @returns The dance in progress, on its confirmation prompt.
	 * @throws FreshSignInRequiredError when the sign-in is older than the elevated window.
	 */
	delete(options?: AuthDanceClientChoreographyOptions): Promise<AuthDanceClientChoreography> {
		return AuthDanceClientChoreography.start(this, "delete", options);
	}

	/**
	 * Rebuilds the dance a store holds, whatever flow it carries. It calls no route, so the dance goes on from the
	 * step the snapshot names.
	 *
	 * @param store Where the dance kept its progress.
	 * @returns The dance, or nothing when the store holds no snapshot.
	 */
	async resume(store: AuthDanceClientChoreographyStore): Promise<AuthDanceClientChoreography | undefined> {
		const snapshot = await store.get();
		return snapshot ? new AuthDanceClientChoreography(this, snapshot, store) : undefined;
	}

	async #accessToken(signal?: AbortSignal): Promise<string> {
		await this.restore();
		const tokens = this.#tokens;
		if (!tokens) {
			throw new AuthDanceNotAuthenticatedError("this route needs an access token");
		}
		if (expiresWithin(tokens.tokens.access_token, this.#refreshSkew)) {
			await this.refreshTokens(signal);
		}
		return this.#tokens!.tokens.access_token;
	}
}

// A token this client cannot read is a token it must exchange. Nothing here verifies a signature: the server does that.
function expiresWithin(token: string, seconds: number): boolean {
	try {
		const { exp } = decodeJwt(token);
		return exp === undefined || exp - Date.now() / 1000 < seconds;
	} catch {
		return true;
	}
}

/**
 * One flow in progress. It holds the opaque state, the prompt the owner answers, and the branch the owner picked.
 *
 * A flow ends when an answer carries the tokens of a new session, or a bare success. {@link done} says so, and
 * {@link current} answers `null` from then on.
 *
 * The dance arms a timer on the moment the flow expires. Dispose it, or answer a prompt, to disarm the timer.
 *
 * @example
 * ```ts
 * using choreography = await client.rotate("password");
 * await choreography.submitPrompt("a new password");
 * console.log(choreography.done);
 * ```
 */
export class AuthDanceClientChoreography implements Disposable {
	#client: AuthDanceClient;
	#flow: AuthDanceFlow;
	#name: string | undefined;
	#steps: AuthDanceClientChoreographyStep[];
	#selected: string | undefined;
	#trail: string[];
	#store: AuthDanceClientChoreographyStore | undefined;
	#done: boolean;
	#timer: ReturnType<typeof setTimeout> | undefined;
	#listeners = new Listeners<AuthDanceClientChoreography>();

	/**
	 * Starts one flow, or takes back the one the store holds.
	 *
	 * A snapshot of the same flow, on the same component or channel, resumes without a call. Any other snapshot goes
	 * away, and the flow starts fresh. {@link AuthDanceClient.signIn} and the eight methods beside it call this one.
	 *
	 * @param client Who calls the routes and keeps the tokens.
	 * @param flow The flow to start, under the name its route uses.
	 * @param options `name` is the component or the channel the flow acts on. `store` is where the progress goes.
	 * @returns The dance, on the prompt the owner answers next.
	 */
	static async start(
		client: AuthDanceClient,
		flow: AuthDanceFlow,
		options?: AuthDanceClientChoreographyOptions & { name?: string },
	): Promise<AuthDanceClientChoreography> {
		const definition = AuthDanceFlows[flow];
		if (definition.argument !== "none" && options?.name === undefined) {
			throw new TypeError(`the ${flow} flow names the ${definition.argument} it acts on`);
		}
		const stored = await options?.store?.get();
		if (stored && stored.flow === flow && stored.name === options?.name && stored.steps.length > 0) {
			return new AuthDanceClientChoreography(client, stored, options?.store);
		}
		const step = await requestStep(client, definition, options?.name, options?.signal);
		const choreography = new AuthDanceClientChoreography(
			client,
			{ flow, name: options?.name, steps: [step], trail: [] },
			options?.store,
		);
		// A snapshot of another flow must not outlive the dance it belonged to.
		await choreography.#save();
		return choreography;
	}

	/**
	 * Builds the dance over a snapshot. {@link AuthDanceClientChoreography.start} and {@link AuthDanceClient.resume} call it
	 * for you.
	 *
	 * @param client Who calls the routes and keeps the tokens.
	 * @param snapshot The flow, the steps so far, the branch the owner picked and the names answered.
	 * @param store Where the progress goes on every change.
	 */
	constructor(client: AuthDanceClient, snapshot: AuthDanceClientChoreographySnapshot, store?: AuthDanceClientChoreographyStore) {
		this.#client = client;
		this.#flow = snapshot.flow;
		this.#name = snapshot.name;
		this.#steps = [...snapshot.steps];
		this.#selected = snapshot.selected;
		this.#trail = [...snapshot.trail];
		this.#store = store;
		this.#done = snapshot.steps.length === 0;
		this.#arm();
	}

	/** Disarms the timer of the expiry and drops every listener. It keeps the snapshot in the store. */
	[Symbol.dispose](): void {
		clearTimeout(this.#timer);
		this.#timer = undefined;
		this.#listeners.clear();
	}

	/** The flow that is running. */
	get flow(): AuthDanceFlow {
		return this.#flow;
	}

	/** The component or the channel the flow acts on. A flow that takes no argument carries none. */
	get name(): string | undefined {
		return this.#name;
	}

	/** The in-progress dance, as the library encrypted it, or nothing once the flow is over. */
	get state(): string | undefined {
		return this.#steps.at(-1)?.state;
	}

	/** What the owner answers next: one input, or a choice between branches. It is `null` once the flow is over. */
	get prompt(): AuthDancePrompt | null {
		return this.#steps.at(-1)?.prompt ?? null;
	}

	/** The branches of the current step, or an empty array when the step holds one input. */
	get choices(): AuthDancePromptInput[] {
		const prompt = this.prompt;
		if (!prompt || prompt.kind !== "choice") {
			return [];
		}
		return prompt.components.filter((branch): branch is AuthDancePromptInput => branch.kind === "input");
	}

	/** The branch the owner picked, by name. A step that holds one input carries none. */
	get selected(): string | undefined {
		return this.#selected;
	}

	/**
	 * The one input the owner answers now. It is `null` once the flow is over, and `null` while the step is a choice
	 * and no branch is picked.
	 */
	get current(): AuthDancePromptInput | null {
		const prompt = this.prompt;
		if (!prompt) {
			return null;
		}
		if (prompt.kind === "input") {
			return prompt;
		}
		return this.choices.find((branch) => branch.name === this.#selected) ?? null;
	}

	/** The names answered so far in this flow, oldest first. */
	get trail(): string[] {
		return [...this.#trail];
	}

	/** The moment the flow expires. An answer to a prompt never moves it. It is `null` once the flow is over. */
	get expireAt(): Date | null {
		const step = this.#steps.at(-1);
		return step ? new Date(step.expireAt) : null;
	}

	/** Whether the flow expired. The library refuses the state from then on, so start the flow again. */
	get expired(): boolean {
		const expireAt = this.expireAt;
		return !this.#done && expireAt !== null && expireAt.getTime() <= Date.now();
	}

	/** Whether the flow is over: an answer carried the tokens or a bare success, or {@link abandon} dropped it. */
	get done(): boolean {
		return this.#done;
	}

	/** Whether {@link sendPrompt} has something to deliver: the current input takes a value the library delivers. */
	get sendable(): boolean {
		return this.current?.sendable === true;
	}

	/** The snapshot of this dance, in a shape `JSON.stringify` takes. */
	toSnapshot(): AuthDanceClientChoreographySnapshot {
		return { flow: this.#flow, name: this.#name, steps: [...this.#steps], selected: this.#selected, trail: [...this.#trail] };
	}

	/**
	 * Registers a listener the dance calls every time it moves: a new step, a branch picked, an expiry, or the end
	 * of the flow. A listener that throws never fails the flow.
	 *
	 * @param handler What to call with the dance itself. Read what changed off its properties.
	 * @returns A `Disposable` that drops the listener.
	 */
	onChange(handler: (choreography: AuthDanceClientChoreography) => void): Disposable {
		return this.#listeners.on(handler);
	}

	/**
	 * Picks one branch of a choice, by name. {@link current} answers with that branch from then on.
	 *
	 * @param name The name of the branch, as {@link choices} carries it.
	 * @throws AuthDanceClientChoreographyPromptError when the current step offers no branch of that name.
	 */
	async choose(name: string): Promise<void> {
		if (!this.choices.some((branch) => branch.name === name)) {
			throw new AuthDanceClientChoreographyPromptError(`${name} is not a branch of this step`);
		}
		this.#selected = name;
		await this.#save();
		this.#listeners.emit(this);
	}

	/**
	 * Goes back one step. The library keeps nothing between two calls, so the state of the previous step is still the
	 * state of that step. It does nothing on the first step.
	 *
	 * A step that already collected a value answers `COMPONENT_ALREADY_COLLECTED` when the owner answers it a second
	 * time. Use {@link restart} to take the flow from the top.
	 */
	async prev(): Promise<void> {
		if (this.#steps.length > 1 && !this.#done) {
			this.#steps = this.#steps.slice(0, -1);
			this.#trail = this.#trail.slice(0, -1);
			this.#selected = undefined;
			this.#arm();
			await this.#save();
			this.#listeners.emit(this);
		}
	}

	/**
	 * Takes the flow from the top. It calls the route that started the flow again, so the library hands out a fresh
	 * state.
	 *
	 * @param signal Drops the call.
	 */
	async restart(signal?: AbortSignal): Promise<void> {
		const step = await requestStep(this.#client, AuthDanceFlows[this.#flow], this.#name, signal);
		this.#steps = [step];
		this.#trail = [];
		this.#selected = undefined;
		this.#done = false;
		this.#arm();
		await this.#save();
		this.#listeners.emit(this);
	}

	/**
	 * Drops the flow. It calls no route: the library keeps nothing, so the state simply expires.
	 */
	async abandon(): Promise<void> {
		this.#steps = [];
		this.#trail = [];
		this.#selected = undefined;
		this.#done = true;
		this.#arm();
		await this.#save();
		this.#listeners.emit(this);
	}

	/**
	 * Asks the library to deliver the current prompt over its channel, a one-time code for example.
	 *
	 * @param options `name` picks the branch to deliver, over the one {@link choose} picked. `locale` picks the
	 * language of the message. `signal` drops the call.
	 * @throws AuthDanceClientChoreographyStateError when the flow is over, or the step is a choice with no branch picked.
	 * @throws ComponentNotSendableError when the component delivers nothing over a channel.
	 */
	async sendPrompt(options?: { name?: string; locale?: string; signal?: AbortSignal }): Promise<void> {
		const target = this.#target(options?.name);
		await this.#client.sendPrompt({
			name: target.name,
			state: this.state!,
			locale: options?.locale,
			signal: options?.signal,
		});
	}

	/**
	 * Answers the current prompt and moves the dance one step.
	 *
	 * The answer holds the next prompt, the tokens of a completed sign-in or sign-up, or a bare success. The tokens go
	 * to the client. A completed delete drops the tokens the client held, because every session went with the identity.
	 *
	 * @param value What the owner gave.
	 * @param options `name` picks the branch to answer, over the one {@link choose} picked. `signal` drops the call.
	 * @returns The next prompt, the minted tokens, or a bare success.
	 * @throws AuthDanceClientChoreographyStateError when the flow is over, or the step is a choice with no branch picked.
	 * @throws InvalidPromptValueError when a sign-in step rejects the value.
	 * @throws InvalidValidationValueError when a validation rejects the value.
	 */
	async submitPrompt(value: unknown, options?: { name?: string; signal?: AbortSignal }): Promise<AuthDanceResponse> {
		const target = this.#target(options?.name);
		const result = await this.#client.submitPrompt({
			name: target.name,
			value,
			state: this.state!,
			signal: options?.signal,
		});
		this.#trail = [...this.#trail, target.name];
		this.#selected = undefined;
		if ("state" in result) {
			this.#steps = [...this.#steps, { state: result.state, prompt: result.prompt, expireAt: result.expireAt.toISOString() }];
		} else {
			this.#steps = [];
			this.#done = true;
			if (this.#flow === "delete") {
				await this.#client.clearTokens();
			}
		}
		this.#arm();
		await this.#save();
		this.#listeners.emit(this);
		return result;
	}

	/**
	 * Answers a confirmation prompt with the boolean `true`. An unenroll, an unsubscribe and a delete each end on one.
	 *
	 * @param options `signal` drops the call.
	 * @returns A bare success, or the next prompt when the flow holds one.
	 * @throws ConfirmationRequiredError when the flow takes no confirmation here.
	 */
	confirm(options?: { signal?: AbortSignal }): Promise<AuthDanceResponse> {
		return this.submitPrompt(true, options);
	}

	// The one input an answer belongs to. A choice needs a branch, from this call or from `choose`.
	#target(name?: string): AuthDancePromptInput {
		if (this.#done) {
			throw new AuthDanceClientChoreographyStateError("the flow is over");
		}
		if (this.expired) {
			throw new AuthDanceClientChoreographyStateError("the flow expired");
		}
		const prompt = this.prompt;
		if (!prompt) {
			throw new AuthDanceClientChoreographyStateError("the flow holds no prompt");
		}
		if (prompt.kind === "input") {
			if (name !== undefined && name !== prompt.name) {
				throw new AuthDanceClientChoreographyPromptError(`${name} is not the input of this step`);
			}
			return prompt;
		}
		const wanted = name ?? this.#selected;
		if (wanted === undefined) {
			throw new AuthDanceClientChoreographyStateError("the step is a choice, and no branch is picked");
		}
		const branch = this.choices.find((candidate) => candidate.name === wanted);
		if (!branch) {
			throw new AuthDanceClientChoreographyPromptError(`${wanted} is not a branch of this step`);
		}
		return branch;
	}

	async #save(): Promise<void> {
		if (!this.#store) {
			return;
		}
		if (this.#steps.length === 0) {
			await this.#store.delete();
			return;
		}
		await this.#store.set(this.toSnapshot());
	}

	// One timer for the current step. A flow that already expired arms nothing: `expired` answers on the clock.
	#arm(): void {
		clearTimeout(this.#timer);
		this.#timer = undefined;
		const expireAt = this.expireAt;
		if (this.#done || expireAt === null) {
			return;
		}
		const delay = expireAt.getTime() - Date.now();
		if (delay <= 0) {
			return;
		}
		this.#timer = setTimeout(() => {
			this.#timer = undefined;
			this.#listeners.emit(this);
		}, Math.min(delay, 2 ** 31 - 1));
	}
}

// The body of a start route names the component or the channel, and nothing else.
async function requestStep(
	client: AuthDanceClient,
	definition: AuthDanceFlowDefinition,
	name: string | undefined,
	signal: AbortSignal | undefined,
): Promise<AuthDanceClientChoreographyStep> {
	const body = await client.request(definition.path, {
		body: definition.argument === "none" ? undefined : { name },
		authenticated: definition.authenticated,
		signal,
	});
	const result = parseBody(AuthDanceResponseState, body);
	return { state: result.state, prompt: result.prompt, expireAt: result.expireAt.toISOString() };
}
