import { ksuid } from "./id.ts";
import type { AuthDanceChannel } from "./channel.ts";
import { OtpAuthDanceComponent } from "./components/otp.ts";
import {
	type AuthDanceChoreography,
	type AuthDanceChoreographyChoice,
	type AuthDanceChoreographyComponent,
	choice,
	component,
	peek,
	simplify,
	walk,
} from "./choreography.ts";
import type { AuthDanceComponent, AuthDanceComponentContext } from "./component.ts";
import type {
	AuthDanceIdentity,
	AuthDanceIdentityChallenge,
	AuthDanceIdentityChannel,
	AuthDanceIdentityComponent,
	AuthDanceIdentityIdentification,
} from "./identity.ts";
import type { AuthDanceMessage } from "./message.ts";
import {
	AuthDanceState,
	type AuthDanceStateDelete,
	type AuthDanceStateEnroll,
	type AuthDanceStateRecover,
	type AuthDanceStateRotate,
	type AuthDanceStateSignIn,
	type AuthDanceStateSignUp,
	type AuthDanceStateSubscribe,
	type AuthDanceStateUnenroll,
	type AuthDanceStateUnsubscribe,
} from "./state.ts";
import type { AuthDancePrompt } from "./prompt.ts";
import { decode } from "jose/base64url";
import { EncryptJWT } from "jose/jwt/encrypt";
import { jwtDecrypt } from "jose/jwt/decrypt";
import { SignJWT } from "jose/jwt/sign";
import { jwtVerify } from "jose/jwt/verify";
import { parse } from "valibot";
import type { AuthDanceResponse, AuthDanceResponseResult, AuthDanceResponseState, AuthDanceResponseTokens } from "./response.ts";
import type { AuthDanceSession } from "./session.ts";
import type { AuthDanceStorage } from "./storage.ts";
import {
	AuthDanceError,
	AuthDanceUnknownError,
	ChannelAlreadySubscribedError,
	ChannelNotSubscribedError,
	ChoreographyEmptyError,
	ComponentAlreadyCollectedError,
	ComponentAlreadyEnrolledError,
	ComponentNotCollectedError,
	ComponentNotEnrolledError,
	ComponentNotInChoreographyError,
	ComponentNotRecoverableError,
	ComponentNotSendableError,
	ComponentNotVerifiableError,
	ConfirmationRequiredError,
	FreshSignInRequiredError,
	IdentityMismatchError,
	IdentityNotFoundError,
	IdentityNotResolvedError,
	InvalidAccessTokenError,
	InvalidPromptValueError,
	InvalidRefreshTokenError,
	InvalidStateError,
	InvalidStateForFlowError,
	InvalidValidationValueError,
	RateLimitedError,
	RecoveryNotIdentifiedError,
	SessionNotFoundError,
	UnknownChannelError,
	UnknownComponentError,
	WouldLockOutError,
} from "./error.ts";

export type AuthDanceClaimJson =
	| string
	| number
	| boolean
	| null;
// | { [key: string]: AuthDanceClaimJson }
// | AuthDanceClaimJson[];

export type AuthDanceClaims = Record<string, AuthDanceClaimJson>;

/** One fixed-window rate limit bucket. It allows `limit` hits in each `window`. */
export interface AuthDanceRateLimit {
	/** How many hits the bucket allows in one window. */
	limit: number;
	/** How long one window lasts, in seconds. */
	window: number;
}

/** The buckets `AuthDanceApi` consumes. `AuthDanceApi` keys each one on the identity or the session a call belongs to. */
export interface AuthDanceIdentityRateLimits {
	/** Each answer to a prompt or to a validation. @defaultValue `{ limit: 10, window: 300 }` */
	verify?: AuthDanceRateLimit;
	/** Each prompt or validation the library delivers over a channel. @defaultValue `{ limit: 5, window: 300 }` */
	send?: AuthDanceRateLimit;
	/**
	 * Each start of a management flow, such as enroll, rotate or subscribe. A sign-out consumes this bucket too.
	 * @defaultValue `{ limit: 20, window: 300 }`
	 */
	manage?: AuthDanceRateLimit;
	/** Each exchange of a refresh token. @defaultValue `{ limit: 60, window: 300 }` */
	refresh?: AuthDanceRateLimit;
}

/** The buckets the HTTP layer consumes. The HTTP layer keys each one on the address of the caller. */
export interface AuthDanceAddressRateLimits {
	/** Every request, whatever the route. @defaultValue `{ limit: 300, window: 60 }` */
	request?: AuthDanceRateLimit;
	/**
	 * The two routes that deliver a message over a channel. The HTTP layer consumes this bucket on top of `request`.
	 * @defaultValue `{ limit: 60, window: 60 }`
	 */
	send?: AuthDanceRateLimit;
}

/** The flows that change an identity. Each one reports the change to one of the three identity hooks. */
export type AuthDanceIdentityEventFlow =
	| "sign-up"
	| "enroll"
	| "unenroll"
	| "rotate"
	| "recover"
	| "subscribe"
	| "unsubscribe"
	| "delete";

/**
 * What the library hands an identity hook.
 * @typeParam TFlow The flows the hook that reads this event reports.
 */
export interface AuthDanceIdentityEvent<TFlow extends AuthDanceIdentityEventFlow = AuthDanceIdentityEventFlow> {
	/** Which flow changed the identity. */
	flow: TFlow;
	/**
	 * The identity the change produced, exactly as the library saved it. `onIdentityDeleted` gets the identity
	 * as it stood one moment before the library removed it.
	 */
	identity: AuthDanceIdentity;
	/**
	 * The component or the channel the flow acts on, under the name `options.components` or `options.channels`
	 * declares it. A recovery names the component it reset. `onIdentityCreated` and `onIdentityDeleted` name nothing.
	 */
	name?: string;
}

/** The flows that create, renew or delete a session. Each one reports the change to one of the three session hooks. */
export type AuthDanceSessionEventFlow = "sign-in" | "sign-up" | "refresh" | "sign-out" | "delete";

/**
 * What the library hands a session hook. The event carries no token.
 * @typeParam TFlow The flows the hook that reads this event reports.
 */
export interface AuthDanceSessionEvent<TFlow extends AuthDanceSessionEventFlow = AuthDanceSessionEventFlow> {
	/** Which flow created, renewed or deleted the session. */
	flow: TFlow;
	/** The session the flow acts on. A refresh reports the record the sign-in created. */
	session: AuthDanceSession;
	/** The identity the session signs in. */
	identity: AuthDanceIdentity;
}

/** What the library hands `onError` when another hook rejects. */
export interface AuthDanceHookErrorEvent {
	/** Which hook rejected. */
	hook: Exclude<keyof AuthDanceApiHooks, "onError">;
	/** What that hook rejected with. */
	cause: unknown;
}

/**
 * The listeners the library calls after it changes an identity or a session. The library calls a hook after the
 * write. A hook that rejects never fails the flow, and `onError` gets every rejection. The library awaits each
 * hook. Return at once, and do the long work outside the flow.
 */
export interface AuthDanceApiHooks {
	/** A sign-up completed and the store now holds a new identity. The session hook follows for the same flow. */
	onIdentityCreated?(event: AuthDanceIdentityEvent<"sign-up">): void | Promise<void>;
	/** A flow changed the components of an identity that already existed, and the store holds the change. */
	onIdentityUpdated?(event: AuthDanceIdentityEvent<Exclude<AuthDanceIdentityEventFlow, "sign-up" | "delete">>): void | Promise<void>;
	/** A delete flow removed an identity. `onSessionDeleted` reported each session of that identity before this hook. */
	onIdentityDeleted?(event: AuthDanceIdentityEvent<"delete">): void | Promise<void>;
	/** A sign-in or a sign-up minted a session, together with the first pair of tokens on it. */
	onSessionCreated?(event: AuthDanceSessionEvent<"sign-in" | "sign-up">): void | Promise<void>;
	/** A refresh minted a new pair of tokens on a session that already existed. It keeps `aat` unchanged. */
	onSessionRefreshed?(event: AuthDanceSessionEvent<"refresh">): void | Promise<void>;
	/** The library deleted a session. A sign-out or a delete flow fires this hook one time for each session it takes. */
	onSessionDeleted?(event: AuthDanceSessionEvent<"sign-out" | "delete">): void | Promise<void>;
	/** Another hook rejected. The library drops a rejection from this hook. */
	onError?(event: AuthDanceHookErrorEvent): void | Promise<void>;
}

/** Everything `AuthDanceApi` needs to run the dance. */
export interface AuthDanceApiOptions {
	/** Where the library delivers a message, keyed by the channel name a component asks for. */
	channels: Record<string, AuthDanceChannel>;
	/** The declaration the sign-in, the sign-up, the recover and the unenroll flow read. */
	choreography: AuthDanceChoreography;
	/** What each step does, keyed by the name the choreography and the prompts use. */
	components: Record<string, AuthDanceComponent>;
	/** The base64url key. It signs every minted token and it encrypts the state. Keep it in a secret store. */
	secret: string;
	/** Where identities, sessions, one-time codes and rate limit counters live. */
	storage: AuthDanceStorage;
	/** How long a flow, a token and the elevated window last, in seconds. */
	durations?: {
		/** How long a sign-in state stays valid. @defaultValue 300 */
		sign_in?: number;
		/** How long a sign-up state stays valid. @defaultValue 300 */
		sign_up?: number;
		/** How long an enroll state stays valid. @defaultValue 300 */
		enroll?: number;
		/** How long an unenroll confirmation stays valid. @defaultValue 300 */
		unenroll?: number;
		/** How long a rotate state stays valid, across both of its validation rounds. @defaultValue 300 */
		rotate?: number;
		/** How long a recover state stays valid, across the whole reset. @defaultValue 300 */
		recover?: number;
		/** How long a subscribe state stays valid. @defaultValue 300 */
		subscribe?: number;
		/** How long an unsubscribe confirmation stays valid. @defaultValue 300 */
		unsubscribe?: number;
		/** How long a delete confirmation stays valid. @defaultValue 300 */
		delete?: number;
		/** How long an access token stays valid. @defaultValue 300 */
		access?: number;
		/** How long a refresh token stays valid. @defaultValue 86400 */
		refresh?: number;
		/**
		 * The window after a sign-in in which a session may still run a sensitive flow. Past this window `enroll`,
		 * `unenroll`, `rotate`, `subscribe`, `unsubscribe` and `delete` raise `FreshSignInRequiredError`. A sign-out
		 * needs no fresh sign-in. A refresh keeps `aat` unchanged and never re-opens the window.
		 * @defaultValue 300
		 */
		elevated?: number;
	};
	/** The rate limit buckets. Any bucket you omit keeps its default. */
	limits?: {
		/** The per-identity buckets `AuthDanceApi` consumes. */
		identity?: AuthDanceIdentityRateLimits;
		/** The per-address buckets the HTTP layer consumes. `AuthDanceApi` never reads them. */
		address?: AuthDanceAddressRateLimits;
	};
	/** How the minted tokens present themselves. */
	tokens?: {
		/**
		 * The `iss` claim of every minted token. The encrypted state carries the same claim, and the library checks
		 * that claim every time it reads a state back. If you omit this option, the state carries no issuer.
		 * @defaultValue "acme"
		 */
		issuer?: string;
	};
	/**
	 * The listeners the library calls after it changes an identity or a session. Any hook you omit reports nothing.
	 * @defaultValue No listener.
	 */
	hooks?: AuthDanceApiHooks;
}

/** The buckets `AuthDanceApi` uses when `limits.identity` omits one. */
export const IdentityRateLimits: Required<AuthDanceIdentityRateLimits> = {
	verify: { limit: 10, window: 5 * 60 },
	send: { limit: 5, window: 5 * 60 },
	manage: { limit: 20, window: 5 * 60 },
	refresh: { limit: 60, window: 5 * 60 },
};

interface AuthDanceAdvance {
	state: AuthDanceState;
	path: string[];
	identity: AuthDanceIdentity;
	expireAt: Date;
	flow: string;
	name?: string;
	persist?: boolean;
	address?: string;
	userAgent?: string;
}

/**
 * The state machine of the library. It performs the dance the choreography declares. It covers nine flows:
 * sign-in, sign-up, enroll, unenroll, rotate, recover, subscribe, unsubscribe and delete.
 *
 * A flow method returns the first prompt together with the state. The state is a JWE the client keeps and returns
 * with every later call. The client then calls `submitPrompt` until the answer carries the tokens or a plain
 * success result.
 *
 * Each method raises an `AuthDanceError` for a failure the caller can act on. Any other failure escapes as
 * `AuthDanceUnknownError` and carries the original failure in `cause`. `accessTokenIdentity` lets an unexpected
 * failure escape as it stands.
 *
 * @example
 * ```ts
 * const started = await api.signIn();
 * const next = await api.submitPrompt({ name: "email", value: "john.doe@example.com", state: started.state });
 * ```
 */
export class AuthDanceApi {
	#options: AuthDanceApiOptions;
	#decodedSecret: Uint8Array;

	/** Builds the state machine from a policy. It decodes `options.secret` one time and keeps the raw key. */
	constructor(options: AuthDanceApiOptions) {
		this.#options = options;
		this.#decodedSecret = decode(this.#options.secret);
	}

	/** The storage this instance reads and writes. */
	get storage(): AuthDanceStorage {
		return this.#options.storage;
	}

	// An AuthDanceError passes through. Any other failure becomes an AuthDanceUnknownError.
	async #guard<T>(method: string, fn: () => Promise<T>): Promise<T> {
		try {
			return await fn();
		} catch (cause) {
			if (cause instanceof AuthDanceError) {
				throw cause;
			}
			throw new AuthDanceUnknownError(`${method} failed`, { cause });
		}
	}

	async #emit<TKey extends Exclude<keyof AuthDanceApiHooks, "onError">>(
		hook: TKey,
		event: Parameters<NonNullable<AuthDanceApiHooks[TKey]>>[0],
	): Promise<void> {
		const listener = this.#options.hooks?.[hook] as ((event: unknown) => void | Promise<void>) | undefined;
		if (!listener) {
			return;
		}
		try {
			await listener(event);
		} catch (cause) {
			try {
				await this.#options.hooks?.onError?.({ hook, cause });
			} catch {
				// Nowhere left to report to.
			}
		}
	}

	#sendMessage(message: AuthDanceMessage): Promise<void> {
		const ch = this.#options.channels[message.recipient.component];
		if (!ch) {
			throw new UnknownChannelError(message.recipient.component);
		}
		return ch.sendMessage(message);
	}

	/**
	 * Sends a message to one identity over a channel it subscribes to.
	 *
	 * @param identityId The id of the identity to reach.
	 * @param channel The name of the channel, as `options.channels` declares it.
	 * @param message The subject and the content. The method itself adds the recipient.
	 * @throws IdentityNotFoundError when storage holds no identity under `identityId`.
	 * @throws ChannelNotSubscribedError when the identity carries no channel component of that name.
	 * @throws UnknownChannelError when `options.channels` declares no channel of that name.
	 */
	sendMessageTo(
		identityId: string,
		channel: string,
		message: Omit<AuthDanceMessage, "recipient">,
	): Promise<AuthDanceResponseResult> {
		return this.#guard("sendMessageTo", async () => {
			const identity = await this.#options.storage.getIdentity(identityId);
			if (!identity) {
				throw new IdentityNotFoundError(identityId);
			}
			const identityChannel = identity.components
				.find((c): c is AuthDanceIdentityChannel => c.kind === "channel" && c.component === channel);
			if (!identityChannel) {
				throw new ChannelNotSubscribedError(channel);
			}
			await this.#sendMessage({
				...message,
				recipient: identityChannel,
			});
			return { success: true };
		});
	}

	/**
	 * Sends a message that already names its recipient. The recipient is a channel component.
	 *
	 * @throws UnknownChannelError when `options.channels` declares no channel the recipient names.
	 */
	sendMessage(message: AuthDanceMessage): Promise<AuthDanceResponseResult> {
		return this.#guard("sendMessage", async () => {
			await this.#sendMessage(message);
			return { success: true };
		});
	}

	// `aat` comes from the first pair and stays unchanged through every refresh. See #requireFreshSignIn.
	async #generateTokens(
		options: { identity: AuthDanceIdentity; scopes: string[]; session: AuthDanceSession; authTime?: number },
	): Promise<AuthDanceResponseTokens> {
		const authTime = options.authTime ?? Math.floor(Date.now() / 1000);

		const claims = Object.entries(options.identity.data ?? {}).reduce((acc, [key, value]) => {
			if (options.scopes.includes(key)) {
				acc[key] = value as AuthDanceClaimJson;
			}
			return acc;
		}, {} as AuthDanceClaims);

		const access_token = await new SignJWT({ id: options.identity.id, claims, aat: authTime })
			.setProtectedHeader({ alg: "HS256" })
			.setIssuer(this.#options.tokens?.issuer ?? "acme")
			.setIssuedAt()
			.setExpirationTime(new Date(Date.now() + (this.#options.durations?.access ?? 5 * 60) * 1000))
			.setSubject(options.session.id)
			.setJti(ksuid())
			.sign(this.#decodedSecret);

		const refresh_token = await new SignJWT({ aat: authTime, scopes: options.scopes })
			.setProtectedHeader({ alg: "HS256" })
			.setIssuer(this.#options.tokens?.issuer ?? "acme")
			.setIssuedAt()
			.setExpirationTime(new Date(Date.now() + (this.#options.durations?.refresh ?? 24 * 60 * 60) * 1000))
			.setSubject(options.session.id)
			.setJti(ksuid())
			.sign(this.#decodedSecret);

		const id_token = await new SignJWT({ claims })
			.setProtectedHeader({ alg: "HS256" })
			.setIssuer(this.#options.tokens?.issuer ?? "acme")
			.setIssuedAt()
			.setSubject(options.identity.id)
			.sign(this.#decodedSecret);

		return {
			tokens: { access_token, id_token, refresh_token },
			session: options.session,
			identity: { id: options.identity.id, data: claims },
		};
	}

	// Every failure reads the same to the caller. Every token this class mints carries `sub` and `aat`,
	// so a token that misses either one is invalid.
	async #verifiedClaims(token: string, invalid: () => AuthDanceError): Promise<{ sub: string; authTime: number }> {
		const payload = await jwtVerify(token, this.#decodedSecret, {
			issuer: this.#options.tokens?.issuer ?? "acme",
		}).then(({ payload }) => payload, () => undefined);
		if (!payload?.sub || typeof payload.aat !== "number") {
			throw invalid();
		}
		return { sub: payload.sub, authTime: payload.aat };
	}

	// A valid session is not enough for a management action. A refresh carries `aat` forward unchanged,
	// so it cannot extend this window.
	#requireFreshSignIn(authTime: number): void {
		const elevated = (this.#options.durations?.elevated ?? 5 * 60) * 1000;
		if (Date.now() - authTime * 1000 > elevated) {
			throw new FreshSignInRequiredError();
		}
	}

	// A bucket keys on the subject of the call: the session behind an access token, or the identity the state
	// resolved. A call with neither one keys on nothing here. The per-address buckets at the edge cover it.
	async #consumeRateLimit(bucket: keyof AuthDanceIdentityRateLimits, subject: string | undefined): Promise<void> {
		if (!subject) {
			return;
		}
		const { limit, window } = this.#options.limits?.identity?.[bucket] ?? IdentityRateLimits[bucket];
		const { allowed, retryAfter } = await this.#options.storage.consumeRateLimit(`${bucket}:${subject}`, limit, window * 1000);
		if (!allowed) {
			throw new RateLimitedError(retryAfter);
		}
	}

	// The subject of a state. A sign-up has none, because it mints its own identity id.
	#stateSubject(state: AuthDanceState): string | undefined {
		if (state.kind === "sign-in" || state.kind === "recover") {
			return state.identityId && `identity:${state.identityId}`;
		}
		if (state.kind === "sign-up") {
			return undefined;
		}
		return `session:${state.sessionId}`;
	}

	// The phase the flow waits in. Both step methods dispatch on it. A state that holds an unproven value takes
	// the validation branch. Every other state takes the prompt branch. A sign-in has no validation phase, and
	// a confirmation-only flow — unenroll, unsubscribe, delete — has none either.
	#awaitsValidation(state: AuthDanceState): boolean {
		switch (state.kind) {
			case "sign-up":
				return this.#signUpStepPending(state);
			case "enroll":
				return this.#isPending(state.components, state.component);
			case "rotate":
				// Two rounds: control of the enrolled value, then the replacement it collects once control is proven.
				return !state.verified || this.#isPending(state.components, state.component);
			case "recover":
				// The same two rounds, behind the choice of the component the owner identifies through. Until that
				// choice is answered there is nothing to prove control of.
				return state.identification !== undefined && (!state.verified || this.#isPending(state.components, state.component));
			case "subscribe":
				return state.validating;
			default:
				return false;
		}
	}

	// The record a validation covers: the identification or challenge the flow names, collected and unproven.
	// One component can contribute more than one record, so the name has to match. A replayed state of a
	// finished flow stays on the collect branch and answers COMPONENT_ALREADY_COLLECTED.
	#isPending(components: AuthDanceIdentityComponent[], name: string): boolean {
		return components.some((c) => c.kind !== "channel" && c.component === name && !c.confirmed);
	}

	// #signUpPath counts confirmed components only. The walk stays on the same step until the proof lands.
	#signUpStepPending(state: AuthDanceStateSignUp): boolean {
		const nextMove = peek(this.#options.choreography, this.#signUpPath(state));
		if (nextMove === null) {
			return false;
		}
		const offered = nextMove.kind === "component" ? [nextMove.component] : nextMove.components.map((c) => c.component);
		return offered.some((name) => this.#isPending(state.components, name));
	}

	/**
	 * Exchanges a refresh token for a new set of tokens on the same session.
	 *
	 * The new tokens keep the `aat` of the sign-in. A refresh needs no fresh sign-in and re-opens no window.
	 * A completed exchange fires `onSessionRefreshed`.
	 *
	 * @returns A new access token, id token and refresh token, plus the session and the scoped identity data.
	 * @throws InvalidRefreshTokenError when the token is tampered with, expired, or missing a claim.
	 * @throws RateLimitedError when the `refresh` bucket of the session is empty.
	 * @throws SessionNotFoundError when the session the token names has expired or was signed out.
	 * @throws IdentityNotFoundError when storage holds no identity for that session.
	 */
	refreshToken(refresh_token: string): Promise<AuthDanceResponseTokens> {
		return this.#guard("refreshToken", async () => {
			const { sub, authTime } = await this.#verifiedClaims(refresh_token, () => new InvalidRefreshTokenError());
			await this.#consumeRateLimit("refresh", `session:${sub}`);
			const session = await this.#options.storage.getSession(sub);
			if (!session) {
				throw new SessionNotFoundError(sub);
			}
			const identity = await this.#options.storage.getIdentity(session.identityId);
			if (!identity) {
				throw new IdentityNotFoundError(session.identityId);
			}
			const tokens = await this.#generateTokens({ identity, scopes: session.scopes, session, authTime });
			await this.#emit("onSessionRefreshed", { flow: "refresh", session, identity });
			return tokens;
		});
	}

	/**
	 * Destroys the session the access token names, or every session of its identity.
	 *
	 * A sign-out needs no fresh sign-in. It fires `onSessionDeleted` one time for each session it destroys.
	 *
	 * @param access_token The access token of the session to destroy.
	 * @param others Pass `true` to destroy every session of the identity, this one included.
	 * @defaultValue `others` is `false`
	 * @throws InvalidAccessTokenError when the token is tampered with, expired, or missing a claim.
	 * @throws RateLimitedError when the `manage` bucket of the session is empty.
	 * @throws SessionNotFoundError when the session has already expired or was signed out.
	 * @throws IdentityNotFoundError when storage holds no identity for that session.
	 */
	signOut(access_token: string, others: boolean = false): Promise<AuthDanceResponseResult> {
		return this.#guard("signOut", async () => {
			try {
				const { session, identity } = await this.#unrollAccessToken(access_token);
				await this.#consumeRateLimit("manage", `session:${session.id}`);
				const deleted = others ? await this.#options.storage.listSession(session.identityId) : [session];
				await Promise.all(deleted.map((s) => this.#options.storage.deleteSession(s.id)));
				for (const s of deleted) {
					await this.#emit("onSessionDeleted", { flow: "sign-out", session: s, identity });
				}
			} catch (cause) {
				if (!(cause instanceof InvalidAccessTokenError)) {
					throw cause;
				}
			}
			return { success: true };
		});
	}

	async #getPromptFromChoreography(options: {
		choreography: AuthDanceChoreographyComponent | AuthDanceChoreographyChoice<AuthDanceChoreographyComponent>;
		stateId: string;
		flow: string;
		identity: AuthDanceIdentity | undefined;
	}): Promise<AuthDancePrompt> {
		const components = "component" in options.choreography ? [options.choreography] : options.choreography.components;
		const prompts = await Promise.all(components.map((component) => {
			const authComponent = this.#options.components[component.component];
			if (!authComponent) {
				throw new UnknownComponentError(component.component);
			}
			return authComponent.getPrompt({
				storage: this.#options.storage,
				stateId: options.stateId,
				name: component.component,
				flow: options.flow,
				identity: options.identity,
			});
		}));

		return prompts.length === 1 ? prompts[0] : { kind: "choice", components: prompts };
	}

	#expireAt(duration: number | undefined): Date {
		return new Date(Date.now() + (duration ?? 5 * 60) * 1000);
	}

	async #promptResponse(
		state: AuthDanceState,
		nextMove: AuthDanceChoreographyComponent | AuthDanceChoreographyChoice<AuthDanceChoreographyComponent>,
		expireAt: Date,
		flow: string,
	): Promise<AuthDanceResponseState> {
		const prompt = await this.#getPromptFromChoreography({
			choreography: nextMove,
			stateId: state.id,
			flow,
			identity: undefined,
		});
		return { state: await this.#encryptState(state, expireAt), prompt, expireAt };
	}

	async #issueTokens(
		identity: AuthDanceIdentity,
		options: { expireAt: Date; address?: string; userAgent?: string },
	): Promise<AuthDanceResponseTokens> {
		const scopes = Object.keys(identity.data ?? {});
		const session = await this.#options.storage.createSession({
			identityId: identity.id,
			scopes,
			expireAt: options.expireAt,
			address: options.address,
			userAgent: options.userAgent,
		});
		return this.#generateTokens({ identity, scopes, session });
	}

	async #advance(options: AuthDanceAdvance): Promise<AuthDanceResponse> {
		const authFlow = options.flow === "sign-in" || options.flow === "sign-up";
		const nextMove = authFlow ? peek(this.#options.choreography, options.path) : null;
		if (nextMove === null) {
			if (options.persist) {
				await this.#options.storage.setIdentity(options.identity);
				if (options.flow === "sign-up") {
					await this.#emit("onIdentityCreated", { flow: options.flow, identity: options.identity });
				} else {
					await this.#emit("onIdentityUpdated", {
						flow: options.flow as Exclude<AuthDanceIdentityEventFlow, "sign-up" | "delete">,
						identity: options.identity,
						name: options.name,
					});
				}
			}
			if (authFlow) {
				const issued = await this.#issueTokens(
					options.identity,
					{
						...options,
						expireAt: new Date(Date.now() + (this.#options.durations?.refresh ?? 24 * 60 * 60) * 1000),
					},
				);
				await this.#emit("onSessionCreated", {
					flow: options.flow === "sign-up" ? "sign-up" : "sign-in",
					session: issued.session,
					identity: options.identity,
				});
				return issued;
			}
			return { success: true };
		}
		return this.#promptResponse(options.state, nextMove, options.expireAt, options.flow);
	}

	#resolveStep(
		path: string[],
		componentName?: string,
	): { choreographyComponent: AuthDanceChoreographyComponent; authComponent: AuthDanceComponent } {
		const nextMove = peek(this.#options.choreography, path)!;
		const choreographyComponent = nextMove.kind === "component" ? nextMove : nextMove.components.find((c) => c.component === componentName);
		if (!choreographyComponent) {
			throw new ComponentNotInChoreographyError(componentName);
		}
		const authComponent = this.#options.components[choreographyComponent.component];
		if (!authComponent) {
			throw new UnknownComponentError(choreographyComponent.component);
		}
		return { choreographyComponent, authComponent };
	}

	#signUpPath(state: AuthDanceStateSignUp): string[] {
		return state.components
			.filter((c): c is AuthDanceIdentityIdentification | AuthDanceIdentityChallenge => c.confirmed && c.kind !== "channel")
			.map((c) => c.component);
	}

	#signInContext(state: AuthDanceStateSignIn, component: string, identity: AuthDanceIdentity | undefined): AuthDanceComponentContext {
		return {
			storage: this.#options.storage,
			name: component,
			stateId: state.id,
			flow: "sign-in",
			identity,
		};
	}

	#signUpContext(state: AuthDanceStateSignUp, component: string): AuthDanceComponentContext {
		return {
			storage: this.#options.storage,
			name: component,
			stateId: state.id,
			flow: "sign-up",
			identity: {
				id: state.identityId,
				data: {},
				components: state.components,
			},
		};
	}

	/**
	 * Verify an access token and return the identity id, the session id, the claims and the `aat` it carries.
	 *
	 * @param access_token The access token to verify.
	 * @returns The identity id, the session id, the claims and the `aat` the token carries.
	 * @throws InvalidAccessTokenError when the token is tampered with, expired, or missing a claim.
	 */
	async verifyAccessToken(
		access_token: string,
	): Promise<{ identityId: string; sessionId: string; claims: AuthDanceClaims; authTime: number }> {
		const payload = await jwtVerify(access_token, this.#decodedSecret, {
			issuer: this.#options.tokens?.issuer ?? "acme",
		}).then(({ payload }) => payload, () => undefined);
		const identityId = payload?.id;
		const sessionId = payload?.sub;
		const authTime = payload?.aat;
		const claims = (payload?.claims as AuthDanceClaims | undefined) ?? {};
		if (!sessionId || typeof identityId !== "string" || typeof authTime !== "number") {
			throw new InvalidAccessTokenError();
		}
		return { identityId, sessionId, claims, authTime };
	}

	async #unrollAccessToken(access_token: string): Promise<{ session: AuthDanceSession; identity: AuthDanceIdentity; authTime: number }> {
		const { sub, authTime } = await this.#verifiedClaims(access_token, () => new InvalidAccessTokenError());
		return { ...await this.#getSessionAndIdentity(sub), authTime };
	}

	async #getSessionAndIdentity(sessionId: string): Promise<{ session: AuthDanceSession; identity: AuthDanceIdentity }> {
		const session = await this.#options.storage.getSession(sessionId);
		if (!session) {
			throw new SessionNotFoundError(sessionId);
		}
		const identity = await this.#options.storage.getIdentity(session.identityId);
		if (!identity) {
			throw new IdentityNotFoundError(session.identityId);
		}
		return { session, identity };
	}

	// The pending channel comes before the components of the identity. The one-time code goes to the new recipient.
	#subscribeContext(state: AuthDanceStateSubscribe, identity: AuthDanceIdentity): AuthDanceComponentContext {
		return {
			storage: this.#options.storage,
			name: state.channel.component,
			stateId: state.id,
			flow: "subscribe",
			identity: { ...identity, components: [state.channel, ...identity.components] },
		};
	}

	// The components this enrollment collected come first. The verification targets the new value.
	#enrollContext(state: AuthDanceStateEnroll, identity: AuthDanceIdentity): AuthDanceComponentContext {
		return {
			storage: this.#options.storage,
			name: state.component,
			stateId: state.id,
			flow: "enroll",
			identity: { ...identity, components: [...state.components, ...identity.components] },
		};
	}

	async #resolveEnrollVerification(state: AuthDanceStateEnroll): Promise<{
		identity: AuthDanceIdentity;
		identityComponent: AuthDanceIdentityIdentification | AuthDanceIdentityChallenge;
		ctx: AuthDanceComponentContext;
		verificationAuthDanceComponent: AuthDanceComponent;
	}> {
		const { identity } = await this.#getSessionAndIdentity(state.sessionId);
		const authComponent = this.#options.components[state.component];
		if (!authComponent) {
			throw new UnknownComponentError(state.component);
		}
		if (!authComponent.verificationComponent) {
			throw new ComponentNotVerifiableError(state.component);
		}
		const identityComponent = this.#collectedIdentityComponent(state.components, state.component);
		const ctx = this.#enrollContext(state, identity);
		const verificationAuthDanceComponent = await authComponent.verificationComponent(ctx);
		return { identity, identityComponent, ctx, verificationAuthDanceComponent };
	}

	// The subject is the identification or the challenge the component produced, never a channel it also yields.
	#collectedIdentityComponent(
		components: AuthDanceIdentityComponent[],
		component: string,
	): AuthDanceIdentityIdentification | AuthDanceIdentityChallenge {
		const identityComponent = components.find((c): c is AuthDanceIdentityIdentification | AuthDanceIdentityChallenge =>
			c.kind !== "channel" && c.component === component
		);
		if (!identityComponent) {
			throw new ComponentNotCollectedError(component);
		}
		return identityComponent;
	}

	// The replacement shadows the enrolled value, so the verification targets the new value.
	#rotateContext(state: AuthDanceStateRotate, identity: AuthDanceIdentity): AuthDanceComponentContext {
		return {
			storage: this.#options.storage,
			name: state.component,
			stateId: state.id,
			flow: "rotate",
			identity: { ...identity, components: [...state.components, ...identity.components] },
		};
	}

	async #resolveRotateVerification(state: AuthDanceStateRotate): Promise<{
		identity: AuthDanceIdentity;
		ctx: AuthDanceComponentContext;
		authComponent: AuthDanceComponent;
		verificationAuthDanceComponent: AuthDanceComponent;
	}> {
		const { identity } = await this.#getSessionAndIdentity(state.sessionId);
		const authComponent = this.#options.components[state.component];
		if (!authComponent) {
			throw new UnknownComponentError(state.component);
		}
		if (!authComponent.verificationComponent) {
			throw new ComponentNotVerifiableError(state.component);
		}
		const ctx = this.#rotateContext(state, identity);
		const verificationAuthDanceComponent = await authComponent.verificationComponent(ctx);
		return { identity, ctx, authComponent, verificationAuthDanceComponent };
	}

	// A rotation and a recovery replace a component by name. A channel the component emits again supersedes the
	// previous entry and keeps the links that entry held. Replacement by name is idempotent.
	#applyReplacement(identity: AuthDanceIdentity, components: AuthDanceIdentityComponent[]): void {
		const replaced = new Set(components.filter((c) => c.kind !== "channel").map((c) => c.component));
		identity.components = identity.components.filter((previous) => {
			if (previous.kind !== "channel") {
				return !replaced.has(previous.component);
			}
			const replacement = components
				.find((c): c is AuthDanceIdentityChannel => c.kind === "channel" && c.component === previous.component);
			if (!replacement) {
				return true;
			}
			replacement.linkedTo = [...new Set([...(previous.linkedTo ?? []), ...(replacement.linkedTo ?? [])])];
			return false;
		});
		identity.components.push(...components);
	}

	// A recovery is proven through a verifiable identification, never through the component under recovery.
	#recoverIdentifications(recovering: string): string[] {
		const names: string[] = [];
		for (const { component } of walk(this.#options.choreography)) {
			if (!component || component.component === recovering || names.includes(component.component)) {
				continue;
			}
			const authComponent = this.#options.components[component.component];
			if (authComponent?.kind === "identification" && authComponent.verifiable) {
				names.push(component.component);
			}
		}
		return names;
	}

	#isChoreographyComponent(component: string): boolean {
		for (const { component: step } of walk(this.#options.choreography)) {
			if (step?.component === component) {
				return true;
			}
		}
		return false;
	}

	// A replacement collected in the reset shadows the value it replaces. The identity is unknown before that.
	#recoverContext(state: AuthDanceStateRecover, component: string, identity: AuthDanceIdentity | undefined): AuthDanceComponentContext {
		return {
			storage: this.#options.storage,
			name: component,
			stateId: state.id,
			flow: "recover",
			identity: identity && { ...identity, components: [...state.components, ...identity.components] },
		};
	}

	async #recoverIdentity(state: AuthDanceStateRecover): Promise<AuthDanceIdentity> {
		if (!state.identityId) {
			throw new RecoveryNotIdentifiedError(state.component);
		}
		const identity = await this.#options.storage.getIdentity(state.identityId);
		if (!identity) {
			throw new IdentityNotFoundError(state.identityId);
		}
		return identity;
	}

	// First phase: prove control of the component the owner picked to identify with.
	async #resolveRecoverControl(state: AuthDanceStateRecover, identity: AuthDanceIdentity): Promise<{
		ctx: AuthDanceComponentContext;
		verificationAuthDanceComponent: AuthDanceComponent;
	}> {
		if (!state.identification) {
			throw new RecoveryNotIdentifiedError(state.component);
		}
		const authComponent = this.#options.components[state.identification];
		if (!authComponent) {
			throw new UnknownComponentError(state.identification);
		}
		if (!authComponent.verificationComponent) {
			throw new ComponentNotVerifiableError(state.identification);
		}
		const ctx = this.#recoverContext(state, state.identification, identity);
		return { ctx, verificationAuthDanceComponent: await authComponent.verificationComponent(ctx) };
	}

	// Second phase: the recovered component collects the replacement.
	#resolveRecoverReset(
		state: AuthDanceStateRecover,
		identity: AuthDanceIdentity,
	): { authComponent: AuthDanceComponent; ctx: AuthDanceComponentContext } {
		const authComponent = this.#options.components[state.component];
		if (!authComponent) {
			throw new UnknownComponentError(state.component);
		}
		return { authComponent, ctx: this.#recoverContext(state, state.component, identity) };
	}

	// Second phase: validate the replacement.
	async #resolveRecoverResetVerification(state: AuthDanceStateRecover, identity: AuthDanceIdentity): Promise<{
		identityComponent: AuthDanceIdentityIdentification | AuthDanceIdentityChallenge;
		ctx: AuthDanceComponentContext;
		verificationAuthDanceComponent: AuthDanceComponent;
	}> {
		const { authComponent, ctx } = this.#resolveRecoverReset(state, identity);
		if (!authComponent.verificationComponent) {
			throw new ComponentNotVerifiableError(state.component);
		}
		return {
			identityComponent: this.#collectedIdentityComponent(state.components, state.component),
			ctx,
			verificationAuthDanceComponent: await authComponent.verificationComponent(ctx),
		};
	}

	// What a removal takes down, beyond the record the flow names. The removal follows the `linkedTo` links both
	// ways, until nothing new joins. A component and a channel of the same name are two records, and a `linkedTo`
	// entry always names a component.
	#removalCollateral(
		identity: AuthDanceIdentity,
		name: string,
		namespace: "component" | "channel",
	): { components: Set<string>; channels: Set<string> } {
		const components = new Set<string>(namespace === "channel" ? [] : [name]);
		const channels = new Set<string>(namespace === "channel" ? [name] : []);
		for (let grew = true; grew;) {
			grew = false;
			for (const c of identity.components) {
				const claimed = c.kind === "channel" ? channels : components;
				// The seed channel of an unsubscribe joins through the second half alone.
				if (!claimed.has(c.component)) {
					if (!(c.linkedTo ?? []).some((linked) => components.has(linked))) {
						continue;
					}
					claimed.add(c.component);
					grew = true;
				}
				for (const linked of c.linkedTo ?? []) {
					if (!components.has(linked)) {
						components.add(linked);
						grew = true;
					}
				}
			}
		}
		return { components, channels };
	}

	// A removal must not lock the identity out. Pass the whole collateral set of #removalCollateral, never one name.
	#isChoreographyCompletableWithout(identity: AuthDanceIdentity, removed: ReadonlySet<string>): boolean {
		const surviving = identity.components
			.filter((c): c is AuthDanceIdentityIdentification | AuthDanceIdentityChallenge =>
				c.kind !== "channel" && c.confirmed && !removed.has(c.component)
			)
			.map((c) => c.component);
		for (const { component: nextMove, path } of walk(this.#options.choreography)) {
			if (nextMove === null && path.every((p) => surviving.includes(p.component))) {
				return true;
			}
		}
		return false;
	}

	async #resolveVerification(state: AuthDanceStateSignUp, componentName?: string): Promise<{
		path: string[];
		choreographyComponent: AuthDanceChoreographyComponent;
		identityComponent: AuthDanceIdentityComponent;
		ctx: AuthDanceComponentContext;
		verificationAuthDanceComponent: AuthDanceComponent;
	}> {
		const path = this.#signUpPath(state);
		const { choreographyComponent, authComponent } = this.#resolveStep(path, componentName);
		const identityComponent = state.components.find((c) => c.kind !== "channel" && c.component === choreographyComponent.component);
		if (!identityComponent) {
			throw new ComponentNotCollectedError(choreographyComponent.component);
		}
		const ctx = this.#signUpContext(state, choreographyComponent.component);
		if (!authComponent.verificationComponent) {
			throw new ComponentNotVerifiableError(choreographyComponent.component);
		}
		const verificationAuthDanceComponent = await authComponent.verificationComponent(ctx);
		return { path, choreographyComponent, identityComponent, ctx, verificationAuthDanceComponent };
	}

	// The issuer must travel as the `iss` claim. #decryptState checks that claim.
	#encryptState(state: AuthDanceState, expireAt: Date): Promise<string> {
		const issuer = this.#options.tokens?.issuer;
		const jwt = new EncryptJWT({ state })
			.setProtectedHeader({ alg: "dir", enc: "A256GCM" })
			.setIssuedAt()
			.setExpirationTime(expireAt);
		return (issuer === undefined ? jwt : jwt.setIssuer(issuer)).encrypt(this.#decodedSecret);
	}

	async #decryptState(value: string): Promise<{ state: AuthDanceState; expireAt: Date }> {
		const payload = await jwtDecrypt(value, this.#decodedSecret, { issuer: this.#options.tokens?.issuer })
			.then(({ payload }) => payload, () => undefined);
		if (!payload?.exp) {
			throw new InvalidStateError();
		}
		try {
			return { state: parse(AuthDanceState, payload.state), expireAt: new Date(payload.exp * 1000) };
		} catch (cause) {
			throw new InvalidStateError("state payload does not match the schema", { cause });
		}
	}

	/**
	 * Starts an authentication and returns the first prompt of the choreography.
	 *
	 * This flow needs no access token and no fresh sign-in. No per-identity bucket guards it.
	 *
	 * @returns The encrypted state, the first prompt, and the moment the state expires.
	 * @throws ChoreographyEmptyError when the choreography is already over at its first step.
	 * @throws UnknownComponentError when the first step names a component `options.components` does not declare.
	 */
	signIn(): Promise<AuthDanceResponseState> {
		return this.#guard("signIn", () => {
			const expireAt = this.#expireAt(this.#options.durations?.sign_in);
			const state: AuthDanceStateSignIn = {
				kind: "sign-in",
				id: ksuid("st_"),
				path: [],
			};
			const nextMove = peek(this.#options.choreography, []);
			if (nextMove === null) {
				throw new ChoreographyEmptyError();
			}
			return this.#promptResponse(state, nextMove, expireAt, "sign-in");
		});
	}

	/**
	 * Starts a registration and returns the first prompt of the choreography.
	 *
	 * The state carries the new identity id from the start. Storage keeps nothing until the choreography
	 * completes. This flow needs no access token and no fresh sign-in, and no per-identity bucket guards it.
	 *
	 * @returns The encrypted state, the first prompt, and the moment the state expires.
	 * @throws ChoreographyEmptyError when the choreography is already over at its first step.
	 * @throws UnknownComponentError when the first step names a component `options.components` does not declare.
	 */
	signUp(): Promise<AuthDanceResponseState> {
		return this.#guard("signUp", () => {
			const expireAt = this.#expireAt(this.#options.durations?.sign_up);
			const state: AuthDanceStateSignUp = {
				kind: "sign-up",
				id: ksuid("st_"),
				identityId: ksuid("id_"),
				components: [],
			};
			const nextMove = peek(this.#options.choreography, []);
			if (nextMove === null) {
				throw new ChoreographyEmptyError();
			}
			return this.#promptResponse(state, nextMove, expireAt, "sign-up");
		});
	}

	/**
	 * Starts the enrollment of a new component on the identity behind the access token.
	 *
	 * The prompt collects the new value. A validation targets the new value, never a value the identity already
	 * carries. Answer that validation with `sendPrompt` and `submitPrompt`.
	 *
	 * @param options `name` is the component to enroll, as `options.components` declares it.
	 * @returns The encrypted state, the prompt of the component, and the moment the state expires.
	 * @throws InvalidAccessTokenError, SessionNotFoundError or IdentityNotFoundError when the token resolves to nothing.
	 * @throws RateLimitedError when the `manage` bucket of the session is empty.
	 * @throws ComponentAlreadyEnrolledError when the identity already carries that component.
	 * @throws UnknownComponentError when `options.components` declares no component of that name.
	 * @throws FreshSignInRequiredError when the sign-in is older than the elevated window.
	 */
	enroll(options: { name: string; access_token: string }): Promise<AuthDanceResponseState> {
		return this.#guard("enroll", async () => {
			const { session, identity, authTime } = await this.#unrollAccessToken(options.access_token);
			await this.#consumeRateLimit("manage", `session:${session.id}`);
			if (identity.components.some((c) => c.kind !== "channel" && c.component === options.name)) {
				throw new ComponentAlreadyEnrolledError(options.name);
			}
			const authComponent = this.#options.components[options.name];
			if (!authComponent) {
				throw new UnknownComponentError(options.name);
			}
			this.#requireFreshSignIn(authTime);
			const expireAt = this.#expireAt(this.#options.durations?.enroll);
			const state: AuthDanceStateEnroll = {
				id: ksuid("st_"),
				kind: "enroll",
				sessionId: session.id,
				component: options.name,
				components: [],
			};
			const prompt = await authComponent.getPrompt(this.#enrollContext(state, identity));
			return { state: await this.#encryptState(state, expireAt), prompt, expireAt };
		});
	}

	/**
	 * Starts the removal of a component from the identity behind the access token.
	 *
	 * The removal takes the linked records with it. A channel that names the component in its `linkedTo` goes
	 * too, and so does every other component that channel names. The library removes the whole set at the
	 * confirmation, and it refuses a removal that leaves no completable path through the choreography. Submit
	 * the boolean `true` to the confirmation prompt through `submitPrompt`.
	 *
	 * @param options `name` is the component to remove.
	 * @returns The encrypted state, a confirmation prompt, and the moment the state expires.
	 * @throws InvalidAccessTokenError, SessionNotFoundError or IdentityNotFoundError when the token resolves to nothing.
	 * @throws RateLimitedError when the `manage` bucket of the session is empty.
	 * @throws ComponentNotEnrolledError when the identity carries no such component.
	 * @throws UnknownComponentError when `options.components` declares no component of that name.
	 * @throws FreshSignInRequiredError when the sign-in is older than the elevated window.
	 * @throws WouldLockOutError when no path through the choreography stays completable without that whole set.
	 */
	unenroll(options: { name: string; access_token: string }): Promise<AuthDanceResponseState> {
		return this.#guard("unenroll", async () => {
			const { session, identity, authTime } = await this.#unrollAccessToken(options.access_token);
			await this.#consumeRateLimit("manage", `session:${session.id}`);
			if (!identity.components.some((c) => c.kind !== "channel" && c.component === options.name)) {
				throw new ComponentNotEnrolledError(options.name);
			}
			if (!this.#options.components[options.name]) {
				throw new UnknownComponentError(options.name);
			}
			this.#requireFreshSignIn(authTime);
			if (!this.#isChoreographyCompletableWithout(identity, this.#removalCollateral(identity, options.name, "component").components)) {
				throw new WouldLockOutError(options.name);
			}
			const expireAt = this.#expireAt(this.#options.durations?.unenroll);
			const state: AuthDanceStateUnenroll = {
				id: ksuid("st_"),
				kind: "unenroll",
				sessionId: session.id,
				component: options.name,
			};
			return {
				state: await this.#encryptState(state, expireAt),
				prompt: { kind: "input", name: options.name, type: "confirmation", sendable: false } as const,
				expireAt,
			};
		});
	}

	/**
	 * Starts the replacement of an enrolled component on the identity behind the access token.
	 *
	 * A component that can verify itself proves control of the current value first, so the flow has two
	 * validation rounds. A component that cannot is proven from the start and collects the replacement at once.
	 *
	 * @param options `name` is the component to replace.
	 * @returns The encrypted state, the first prompt, and the moment the state expires.
	 * @throws InvalidAccessTokenError, SessionNotFoundError or IdentityNotFoundError when the token resolves to nothing.
	 * @throws RateLimitedError when the `manage` bucket of the session is empty.
	 * @throws ComponentNotEnrolledError when the identity carries no such component.
	 * @throws UnknownComponentError when `options.components` declares no component of that name.
	 * @throws FreshSignInRequiredError when the sign-in is older than the elevated window.
	 */
	rotate(options: { name: string; access_token: string }): Promise<AuthDanceResponseState> {
		return this.#guard("rotate", async () => {
			const { session, identity, authTime } = await this.#unrollAccessToken(options.access_token);
			await this.#consumeRateLimit("manage", `session:${session.id}`);
			if (!identity.components.some((c) => c.kind !== "channel" && c.component === options.name)) {
				throw new ComponentNotEnrolledError(options.name);
			}
			const authComponent = this.#options.components[options.name];
			if (!authComponent) {
				throw new UnknownComponentError(options.name);
			}
			this.#requireFreshSignIn(authTime);
			const expireAt = this.#expireAt(this.#options.durations?.rotate);
			const state: AuthDanceStateRotate = {
				id: ksuid("st_"),
				kind: "rotate",
				sessionId: session.id,
				component: options.name,
				// A component with no verification component starts out proven and goes to the replacement.
				verified: !authComponent.verificationComponent,
				components: [],
			};
			const ctx = this.#rotateContext(state, identity);
			const promptWith = authComponent.verificationComponent ? await authComponent.verificationComponent(ctx) : authComponent;
			const prompt = await promptWith.getPrompt(ctx);
			return { state: await this.#encryptState(state, expireAt), prompt, expireAt };
		});
	}

	/**
	 * Starts the recovery of one component, for an owner who can no longer provide it.
	 *
	 * This flow needs no access token and no fresh sign-in. The owner identifies themselves through another
	 * component that both resolves an identity and proves control of it. The first prompt is a choice between
	 * every such component of the choreography, or the prompt of that component when only one qualifies. The
	 * choice names components, never values, so the response discloses nothing about the identity. The flow then
	 * collects the replacement and validates it. It completes with a success result, never with tokens.
	 *
	 * @param options `name` is the component the recovery resets.
	 * @returns The encrypted state, the choice of components to identify with, and the moment the state expires.
	 * @throws UnknownComponentError when `options.components` declares no component of that name.
	 * @throws ComponentNotRecoverableError when no step of the choreography carries that name, or when no other
	 * step of it both resolves an identity and proves control of it.
	 */
	recover(options: { name: string }): Promise<AuthDanceResponseState> {
		return this.#guard("recover", async () => {
			if (!this.#options.components[options.name]) {
				throw new UnknownComponentError(options.name);
			}
			const identifications = this.#recoverIdentifications(options.name);
			if (!this.#isChoreographyComponent(options.name) || identifications.length === 0) {
				throw new ComponentNotRecoverableError(options.name);
			}
			const expireAt = this.#expireAt(this.#options.durations?.recover);
			const state: AuthDanceStateRecover = {
				id: ksuid("st_"),
				kind: "recover",
				component: options.name,
				verified: false,
				components: [],
			};
			const prompt = await this.#getPromptFromChoreography({
				choreography: simplify(choice(...identifications.map(component))) as
					| AuthDanceChoreographyComponent
					| AuthDanceChoreographyChoice<AuthDanceChoreographyComponent>,
				stateId: state.id,
				flow: "recover",
				identity: undefined,
			});
			return { state: await this.#encryptState(state, expireAt), prompt, expireAt };
		});
	}

	/**
	 * Starts the subscription of a channel for the identity behind the access token.
	 *
	 * This flow needs a fresh sign-in. Past the elevated window it raises `FreshSignInRequiredError`.
	 *
	 * The prompt collects the recipient, a phone number for example. The library then confirms the new channel
	 * with a one-time code. It delivers that code over the channel being subscribed, to the recipient it just
	 * collected, so the validation proves control of that recipient.
	 *
	 * @param options `name` is the channel to subscribe, as `options.channels` declares it.
	 * @returns The encrypted state, the prompt of the channel, and the moment the state expires.
	 * @throws InvalidAccessTokenError, SessionNotFoundError or IdentityNotFoundError when the token resolves to nothing.
	 * @throws RateLimitedError when the `manage` bucket of the session is empty.
	 * @throws ChannelAlreadySubscribedError when the identity already carries that channel.
	 * @throws UnknownChannelError when `options.channels` declares no channel of that name.
	 * @throws FreshSignInRequiredError when the sign-in is older than the elevated window.
	 */
	subscribe(options: { name: string; access_token: string }): Promise<AuthDanceResponseState> {
		return this.#guard("subscribe", async () => {
			const { session, identity, authTime } = await this.#unrollAccessToken(options.access_token);
			await this.#consumeRateLimit("manage", `session:${session.id}`);
			if (identity.components.some((c) => c.kind === "channel" && c.component === options.name)) {
				throw new ChannelAlreadySubscribedError(options.name);
			}
			const channel = this.#options.channels[options.name];
			if (!channel) {
				throw new UnknownChannelError(options.name);
			}
			this.#requireFreshSignIn(authTime);
			const expireAt = this.#expireAt(this.#options.durations?.subscribe);
			const state: AuthDanceStateSubscribe = {
				id: ksuid("st_"),
				kind: "subscribe",
				sessionId: session.id,
				channel: { kind: "channel", component: options.name, confirmed: false, data: {} },
				validating: false,
			};
			const prompt = await channel.getPrompt({
				storage: this.#options.storage,
				stateId: state.id,
				name: options.name,
				flow: "subscribe",
				identity,
			});
			return { state: await this.#encryptState(state, expireAt), prompt, expireAt };
		});
	}

	/**
	 * Starts the removal of a channel from the identity behind the access token.
	 *
	 * This flow needs a fresh sign-in.
	 *
	 * The removal also deletes every component the channel names in its `linkedTo`, and every record linked to
	 * those. The library refuses a removal that leaves no completable path through the choreography. It counts the
	 * whole set, not the one channel the caller named.
	 *
	 * Submit the boolean `true` to the confirmation prompt through `submitPrompt`.
	 *
	 * @param options `name` is the channel to remove.
	 * @returns The encrypted state, a confirmation prompt, and the moment the state expires.
	 * @throws InvalidAccessTokenError, SessionNotFoundError or IdentityNotFoundError when the token resolves to nothing.
	 * @throws RateLimitedError when the `manage` bucket of the session is empty.
	 * @throws ChannelNotSubscribedError when the identity carries no such channel.
	 * @throws UnknownChannelError when `options.channels` declares no channel of that name.
	 * @throws FreshSignInRequiredError when the sign-in is older than the elevated window.
	 * @throws WouldLockOutError when no path through the choreography stays completable without the channel and
	 * the linked records that go with it.
	 */
	unsubscribe(options: { name: string; access_token: string }): Promise<AuthDanceResponseState> {
		return this.#guard("unsubscribe", async () => {
			const { session, identity, authTime } = await this.#unrollAccessToken(options.access_token);
			await this.#consumeRateLimit("manage", `session:${session.id}`);
			if (!identity.components.some((c) => c.kind === "channel" && c.component === options.name)) {
				throw new ChannelNotSubscribedError(options.name);
			}
			if (!this.#options.channels[options.name]) {
				throw new UnknownChannelError(options.name);
			}
			this.#requireFreshSignIn(authTime);
			if (!this.#isChoreographyCompletableWithout(identity, this.#removalCollateral(identity, options.name, "channel").components)) {
				throw new WouldLockOutError(options.name);
			}
			const expireAt = this.#expireAt(this.#options.durations?.unsubscribe);
			const state: AuthDanceStateUnsubscribe = {
				id: ksuid("st_"),
				kind: "unsubscribe",
				sessionId: session.id,
				channel: options.name,
			};
			return {
				state: await this.#encryptState(state, expireAt),
				prompt: { kind: "input", name: options.name, type: "confirmation", sendable: false } as const,
				expireAt,
			};
		});
	}

	/**
	 * Starts the deletion of the identity behind the access token.
	 *
	 * This flow needs a fresh sign-in. There is no lock-out check.
	 *
	 * `submitPrompt` takes the confirmation. It then deletes every session of the identity together with the
	 * identity itself, so no token outlives it.
	 *
	 * @returns The encrypted state, a confirmation prompt, and the moment the state expires.
	 * @throws InvalidAccessTokenError, SessionNotFoundError or IdentityNotFoundError when the token resolves to nothing.
	 * @throws RateLimitedError when the `manage` bucket of the session is empty.
	 * @throws FreshSignInRequiredError when the sign-in is older than the elevated window.
	 */
	delete(options: { access_token: string }): Promise<AuthDanceResponseState> {
		return this.#guard("delete", async () => {
			const { session, authTime } = await this.#unrollAccessToken(options.access_token);
			await this.#consumeRateLimit("manage", `session:${session.id}`);
			this.#requireFreshSignIn(authTime);
			const expireAt = this.#expireAt(this.#options.durations?.delete);
			const state: AuthDanceStateDelete = {
				id: ksuid("st_"),
				kind: "delete",
				sessionId: session.id,
			};
			return {
				state: await this.#encryptState(state, expireAt),
				prompt: { kind: "input", name: "identity", type: "confirmation", sendable: false } as const,
				expireAt,
			};
		});
	}

	/**
	 * Delivers the current prompt over its channel, for a component the owner cannot type — a one-time code, for
	 * example.
	 *
	 * A sign-in and a sign-up deliver the prompt of the step itself. A sign-up, an enroll, a rotate, a recover and
	 * a subscribe deliver the validation that proves control of a value the flow already collected. A rotate and a
	 * recover deliver one in each of their two rounds: first the current value, then the replacement.
	 *
	 * A subscribe and a recover name the component themselves, so `name` selects nothing there. This method needs
	 * no access token and no fresh sign-in.
	 *
	 * @param options `name` selects which component to deliver when the current step is a choice. `locale` picks
	 * the language of the message. `state` is the opaque string the previous call returned.
	 * @throws InvalidStateError when the state does not decrypt, carries no expiry, or no longer matches the schema.
	 * @throws RateLimitedError when the `send` bucket of the subject is empty.
	 * @throws InvalidStateForFlowError when the flow holds nothing to deliver, for example a delete waiting on its
	 * confirmation, or an enroll that has not collected its value yet.
	 * @throws ComponentNotInChoreographyError when `name` is not a component the current step offers.
	 * @throws UnknownComponentError when `options.components` declares no component of that name.
	 * @throws ComponentNotVerifiableError when the component offers no verification.
	 * @throws ComponentNotCollectedError when a subscribe has not collected its recipient yet.
	 * @throws ComponentNotSendableError when the component delivers nothing over a channel.
	 * @throws RecoveryNotIdentifiedError when a recovery has not resolved its identity yet.
	 * @throws SessionNotFoundError or IdentityNotFoundError when the session or the identity the state names is gone.
	 * @throws UnknownChannelError when `options.channels` declares no channel the message names.
	 */
	sendPrompt(options: { name: string; locale: string; state: string }): Promise<AuthDanceResponseResult> {
		return this.#guard("sendPrompt", () => this.#sendPrompt(options));
	}

	async #sendPrompt(options: { name: string; locale: string; state: string }): Promise<AuthDanceResponseResult> {
		const { state } = await this.#decryptState(options.state);
		await this.#consumeRateLimit("send", this.#stateSubject(state));
		const { authComponent, ctx } = this.#awaitsValidation(state)
			? await this.#resolveValidationSend(state, options.name)
			: await this.#resolvePromptSend(state, options.name);
		if (!authComponent.sendPrompt) {
			throw new ComponentNotSendableError(options.name);
		}
		const message = await authComponent.sendPrompt(options.locale, ctx);
		if (!message) {
			throw new ComponentNotSendableError(options.name);
		}
		await this.#sendMessage(message);
		return { success: true };
	}

	// The prompt of the step itself. Only a sign-in and a sign-up hold one the library can deliver.
	async #resolvePromptSend(
		state: AuthDanceState,
		name: string,
	): Promise<{ authComponent: AuthDanceComponent; ctx: AuthDanceComponentContext }> {
		if (state.kind === "sign-in") {
			const { choreographyComponent, authComponent } = this.#resolveStep(state.path, name);
			const identity = state.identityId ? await this.#options.storage.getIdentity(state.identityId) : undefined;
			return { authComponent, ctx: this.#signInContext(state, choreographyComponent.component, identity!) };
		}
		if (state.kind === "sign-up") {
			const path = this.#signUpPath(state);
			const { choreographyComponent, authComponent } = this.#resolveStep(path, name);
			return { authComponent, ctx: this.#signUpContext(state, choreographyComponent.component) };
		}
		if (state.kind === "subscribe") {
			throw new ComponentNotCollectedError(state.channel.component);
		}
		if (state.kind === "recover") {
			throw new RecoveryNotIdentifiedError(state.component);
		}
		throw new InvalidStateForFlowError(state.kind);
	}

	/**
	 * Answers the current prompt of any flow and moves the dance one step.
	 *
	 * This one method serves all nine flows. A sign-in verifies the value against the choreography. A sign-up, an
	 * enroll and a rotate collect the value. A recover answers the choice of components to identify with, and later
	 * collects the replacement of the component it resets. An unenroll, an unsubscribe and a delete take the boolean
	 * `true` as their confirmation. A subscribe stores the recipient and moves to its one-time code.
	 *
	 * When the collected value still needs proof of control, the answer is a validation prompt. Answer that prompt
	 * with this same method. On success the value becomes confirmed. A rotate and a recover answer twice, the first
	 * time for the current value and the second for the replacement.
	 *
	 * This method does not check the elevated window, and it needs no access token.
	 *
	 * A step that completes a flow reports it to `options.hooks`. A sign-in fires `onSessionCreated`. A sign-up
	 * fires `onIdentityCreated` and then `onSessionCreated`. A delete fires `onSessionDeleted` for each session and
	 * then `onIdentityDeleted`. Any other flow fires `onIdentityUpdated`.
	 *
	 * @param options `name` selects which component to answer when the current step is a choice. `value` is what
	 * the client collected. `state` is the opaque string the previous call returned. The library stores `address`
	 * and `userAgent` on the session a completed sign-in or sign-up mints.
	 * @returns The next state and prompt. A completed sign-in or sign-up returns the tokens instead. A completed
	 * management flow or recovery returns a plain success result.
	 * @throws InvalidStateError when the state does not decrypt, carries no expiry, or no longer matches the schema.
	 * @throws RateLimitedError when the `verify` bucket of the subject is empty. The method consumes the bucket
	 * before it reads the value, so a wrong password costs a slot.
	 * @throws InvalidStateForFlowError when the state carries a `kind` the schema does not know about.
	 * @throws ComponentNotInChoreographyError or UnknownComponentError when `name` is not the step the flow expects.
	 * @throws InvalidPromptValueError when a sign-in step rejects the value.
	 * @throws InvalidValidationValueError when a verification rejects the value.
	 * @throws IdentityNotResolvedError when no step has resolved an identity and the value resolves none either.
	 * @throws IdentityMismatchError when two components of one dance resolve two different identities.
	 * @throws ComponentAlreadyCollectedError when the step already holds a confirmed value.
	 * @throws ComponentNotCollectedError when the component yields no identification and no challenge.
	 * @throws ComponentNotVerifiableError when the component the flow validates through offers no verification.
	 * @throws ConfirmationRequiredError when an unenroll, an unsubscribe or a delete gets a value other than `true`.
	 * @throws RecoveryNotIdentifiedError when a recovery has not resolved its identity yet.
	 * @throws WouldLockOutError when the unenroll or the unsubscribe leaves no completable path through the choreography.
	 * @throws SessionNotFoundError or IdentityNotFoundError when the session or the identity the state names is gone.
	 */
	submitPrompt(
		options: { name: string; value: unknown; state: string; address?: string; userAgent?: string },
	): Promise<AuthDanceResponse> {
		return this.#guard("submitPrompt", () => this.#submitPrompt(options));
	}

	async #submitPrompt(
		options: { name: string; value: unknown; state: string; address?: string; userAgent?: string },
	): Promise<AuthDanceResponse> {
		const { state, expireAt } = await this.#decryptState(options.state);
		// The method consumes the bucket before it reads the value, so a wrong value costs a slot.
		await this.#consumeRateLimit("verify", this.#stateSubject(state));
		return this.#awaitsValidation(state)
			? this.#submitValidationStep(state, expireAt, options)
			: this.#submitPromptStep(state, expireAt, options);
	}

	// The bag both branches hand to #advance. Each branch overrides the keys its own flow decides.
	#advanceBag(
		state: AuthDanceState,
		expireAt: Date,
		options: { address?: string; userAgent?: string },
	): AuthDanceAdvance {
		return {
			state,
			path: [],
			identity: void 0 as unknown as AuthDanceIdentity,
			expireAt,
			flow: "",
			name: undefined,
			persist: undefined,
			address: options.address,
			userAgent: options.userAgent,
		};
	}

	// The value answers the prompt of the step. It collects what the flow asked for, or it confirms a removal.
	async #submitPromptStep(
		state: AuthDanceState,
		expireAt: Date,
		options: { name: string; value: unknown; address?: string; userAgent?: string },
	): Promise<AuthDanceResponse> {
		let advanceOptions = this.#advanceBag(state, expireAt, options);
		if (state.kind === "sign-in") {
			const { choreographyComponent, authComponent } = this.#resolveStep(state.path, options.name);
			let identity = state.identityId ? await this.#options.storage.getIdentity(state.identityId) : undefined;
			const ctx = this.#signInContext(state, choreographyComponent.component, identity!);
			const identityId = await authComponent.verifyPrompt(options.value, ctx);
			// Verification failed. Keep this check on its own. The guard below no longer fires once an earlier step
			// put an identityId in the state, and a rejected value would walk straight to the tokens.
			if (identityId === false) {
				throw new InvalidPromptValueError(choreographyComponent.component);
			}
			if (!identity && identityId === true) {
				throw new IdentityNotResolvedError(choreographyComponent.component);
			}
			if (identity && typeof identityId === "string" && identityId !== identity.id) {
				throw new IdentityMismatchError(choreographyComponent.component);
			}
			if (typeof identityId === "string") {
				state.identityId = identityId;
			}
			identity ??= await this.#options.storage.getIdentity(state.identityId!);
			state.path.push(choreographyComponent.component);
			advanceOptions = {
				...advanceOptions,
				identity: identity!,
				flow: "sign-in",
				path: state.path,
			};
		} else if (state.kind === "sign-up") {
			const path = this.#signUpPath(state);
			const { choreographyComponent, authComponent } = this.#resolveStep(path, options.name);
			const ctx = this.#signUpContext(state, choreographyComponent.component);
			if (state.components.find((c) => c.kind !== "channel" && c.component === choreographyComponent.component)) {
				throw new ComponentAlreadyCollectedError(choreographyComponent.component);
			}
			state.components.push(
				...await authComponent.getIdentityComponent(choreographyComponent.component, options.value, false, ctx),
			);
			const identityComponent = state.components.find((c): c is AuthDanceIdentityIdentification | AuthDanceIdentityChallenge =>
				c.kind !== "channel" && c.component === choreographyComponent.component
			);
			if (!identityComponent) {
				throw new ComponentNotCollectedError(choreographyComponent.component);
			}
			if (!identityComponent.confirmed && authComponent.verificationComponent) {
				const verificationAuthDanceComponent = await authComponent.verificationComponent(ctx);
				const nextPrompt = await verificationAuthDanceComponent?.getPrompt(ctx);
				const encrypted = await this.#encryptState(state, expireAt);
				return {
					state: encrypted,
					prompt: nextPrompt,
					expireAt,
				};
			}
			identityComponent.confirmed = true;
			advanceOptions = {
				...advanceOptions,
				identity: ctx.identity!,
				flow: "sign-up",
				path: [...path, choreographyComponent.component],
				persist: true,
			};
		} else if (state.kind === "enroll") {
			// The enrolled value is collected exactly once. A value here means a replay of a finished enrollment.
			if (state.components.length > 0) {
				throw new ComponentAlreadyCollectedError(state.component);
			}
			const { identity } = await this.#getSessionAndIdentity(state.sessionId);
			const authComponent = this.#options.components[state.component];
			if (!authComponent) {
				throw new UnknownComponentError(state.component);
			}
			// #enrollContext snapshots state.components. Build the verification context below only after the
			// collection, so the verification targets the new value.
			state.components.push(
				...await authComponent.getIdentityComponent(state.component, options.value, false, this.#enrollContext(state, identity)),
			);
			const identityComponent = this.#collectedIdentityComponent(state.components, state.component);
			if (!identityComponent.confirmed && authComponent.verificationComponent) {
				const ctx = this.#enrollContext(state, identity);
				const verificationAuthDanceComponent = await authComponent.verificationComponent(ctx);
				const nextPrompt = await verificationAuthDanceComponent.getPrompt(ctx);
				return { state: await this.#encryptState(state, expireAt), prompt: nextPrompt, expireAt };
			}
			identityComponent.confirmed = true;
			identity.components.push(...state.components);
			advanceOptions = {
				...advanceOptions,
				identity,
				flow: "enroll",
				name: state.component,
				persist: true,
			};
		} else if (state.kind === "rotate") {
			// Only the replacement value is collected here, exactly once. The validation branch proves control of
			// the current value.
			if (state.components.length > 0) {
				throw new ComponentAlreadyCollectedError(state.component);
			}
			const { identity } = await this.#getSessionAndIdentity(state.sessionId);
			const authComponent = this.#options.components[state.component];
			if (!authComponent) {
				throw new UnknownComponentError(state.component);
			}
			// The collection sees the identity as it stands, so a component can refuse a value identical to the
			// current one.
			state.components.push(
				...await authComponent.getIdentityComponent(state.component, options.value, false, this.#rotateContext(state, identity)),
			);
			const identityComponent = this.#collectedIdentityComponent(state.components, state.component);
			if (!identityComponent.confirmed && authComponent.verificationComponent) {
				const ctx = this.#rotateContext(state, identity);
				const verificationAuthDanceComponent = await authComponent.verificationComponent(ctx);
				const nextPrompt = await verificationAuthDanceComponent.getPrompt(ctx);
				return { state: await this.#encryptState(state, expireAt), prompt: nextPrompt, expireAt };
			}
			identityComponent.confirmed = true;
			this.#applyReplacement(identity, state.components);
			advanceOptions = {
				...advanceOptions,
				identity,
				flow: "rotate",
				name: state.component,
				persist: true,
			};
		} else if (state.kind === "recover") {
			if (!state.identification) {
				// This step, and only this step, resolves which identity the recovery acts on.
				if (!this.#recoverIdentifications(state.component).includes(options.name)) {
					throw new ComponentNotInChoreographyError(options.name);
				}
				const authComponent = this.#options.components[options.name];
				if (!authComponent) {
					throw new UnknownComponentError(options.name);
				}
				const ctx = this.#recoverContext(state, options.name, undefined);
				const identityId = await authComponent.verifyPrompt(options.value, ctx);
				if (typeof identityId !== "string") {
					throw new IdentityNotResolvedError(options.name);
				}
				state.identification = options.name;
				state.identityId = identityId;
				const control = await this.#resolveRecoverControl(state, await this.#recoverIdentity(state));
				return {
					state: await this.#encryptState(state, expireAt),
					prompt: await control.verificationAuthDanceComponent.getPrompt(control.ctx),
					expireAt,
				};
			}
			// A recovery reaches this line only after the validation branch marked the state verified.
			const identity = await this.#recoverIdentity(state);
			// The replacement is collected exactly once.
			if (state.components.length > 0) {
				throw new ComponentAlreadyCollectedError(state.component);
			}
			const { authComponent } = this.#resolveRecoverReset(state, identity);
			state.components.push(
				...await authComponent.getIdentityComponent(
					state.component,
					options.value,
					false,
					this.#recoverContext(state, state.component, identity),
				),
			);
			const identityComponent = this.#collectedIdentityComponent(state.components, state.component);
			if (!identityComponent.confirmed && authComponent.verificationComponent) {
				const ctx = this.#recoverContext(state, state.component, identity);
				const verificationAuthDanceComponent = await authComponent.verificationComponent(ctx);
				return { state: await this.#encryptState(state, expireAt), prompt: await verificationAuthDanceComponent.getPrompt(ctx), expireAt };
			}
			identityComponent.confirmed = true;
			this.#applyReplacement(identity, state.components);
			advanceOptions = {
				...advanceOptions,
				identity,
				flow: "recover",
				// The component the recovery reset, not the one the owner proved control through.
				name: state.component,
				persist: true,
			};
		} else if (state.kind === "unenroll") {
			if (options.value !== true) {
				throw new ConfirmationRequiredError(state.component);
			}
			const { identity } = await this.#getSessionAndIdentity(state.sessionId);
			// Resolve the collateral again against the identity as it stands now. Another flow can change the
			// identity while the confirmation is outstanding.
			const collateral = this.#removalCollateral(identity, state.component, "component");
			if (!this.#isChoreographyCompletableWithout(identity, collateral.components)) {
				throw new WouldLockOutError(state.component);
			}
			identity.components = identity.components.filter((c) =>
				c.kind === "channel" ? !collateral.channels.has(c.component) : !collateral.components.has(c.component)
			);
			advanceOptions = {
				...advanceOptions,
				identity,
				flow: "unenroll",
				name: state.component,
				persist: true,
			};
		} else if (state.kind === "subscribe") {
			// Only the recipient is collected here. The one-time code that confirms it goes to the validation
			// branch.
			const { identity } = await this.#getSessionAndIdentity(state.sessionId);
			state.channel.data = { ...(state.channel.data ?? {}), [state.channel.component]: options.value };
			state.validating = true;
			const prompt = await new OtpAuthDanceComponent({ channel: state.channel.component }).getPrompt(
				this.#subscribeContext(state, identity),
			);
			return { state: await this.#encryptState(state, expireAt), prompt, expireAt };
		} else if (state.kind === "unsubscribe") {
			if (options.value !== true) {
				throw new ConfirmationRequiredError(state.channel);
			}
			const { identity } = await this.#getSessionAndIdentity(state.sessionId);
			// Resolve the collateral again against the identity as it stands now, the same way the unenroll branch
			// above does.
			const collateral = this.#removalCollateral(identity, state.channel, "channel");
			if (!this.#isChoreographyCompletableWithout(identity, collateral.components)) {
				throw new WouldLockOutError(state.channel);
			}
			identity.components = identity.components.filter((c) =>
				c.kind === "channel" ? !collateral.channels.has(c.component) : !collateral.components.has(c.component)
			);
			advanceOptions = {
				...advanceOptions,
				identity,
				flow: "unsubscribe",
				name: state.channel,
				persist: true,
			};
		} else if (state.kind === "delete") {
			// This flow returns here and never calls #advance. Never write the deleted identity back.
			if (options.value !== true) {
				throw new ConfirmationRequiredError("identity");
			}
			const { identity } = await this.#getSessionAndIdentity(state.sessionId);
			const sessions = await this.#options.storage.listSession(identity.id);
			await Promise.all(sessions.map((s) => this.#options.storage.deleteSession(s.id)));
			await this.#options.storage.deleteIdentity(identity.id);
			// A hook gets the identity as it stood before the delete. The store no longer holds it.
			for (const session of sessions) {
				await this.#emit("onSessionDeleted", { flow: "delete", session, identity });
			}
			await this.#emit("onIdentityDeleted", { flow: "delete", identity });
			return { success: true };
		} else {
			// A runtime guard. The state comes from the client and can carry a kind the schema does not know.
			throw new InvalidStateForFlowError((state as AuthDanceState).kind);
		}
		return this.#advance(advanceOptions);
	}

	// The verification that proves control of a value the flow already collected — the one-time code that confirms
	// the address the owner just gave, for example.
	async #resolveValidationSend(
		state: AuthDanceState,
		name: string,
	): Promise<{ authComponent: AuthDanceComponent; ctx: AuthDanceComponentContext }> {
		if (state.kind === "sign-up") {
			const { ctx, verificationAuthDanceComponent } = await this.#resolveVerification(state, name);
			return { authComponent: verificationAuthDanceComponent, ctx };
		}
		if (state.kind === "enroll") {
			const { ctx, verificationAuthDanceComponent } = await this.#resolveEnrollVerification(state);
			return { authComponent: verificationAuthDanceComponent, ctx };
		}
		if (state.kind === "rotate") {
			// Serves both rounds: the enrolled value before the collection of the replacement, then the replacement.
			const { ctx, verificationAuthDanceComponent } = await this.#resolveRotateVerification(state);
			return { authComponent: verificationAuthDanceComponent, ctx };
		}
		if (state.kind === "recover") {
			// Serves both rounds: the component the owner identified with, then the replacement.
			const identity = await this.#recoverIdentity(state);
			const { ctx, verificationAuthDanceComponent } = state.verified
				? await this.#resolveRecoverResetVerification(state, identity)
				: await this.#resolveRecoverControl(state, identity);
			return { authComponent: verificationAuthDanceComponent, ctx };
		}
		if (state.kind === "subscribe") {
			const { identity } = await this.#getSessionAndIdentity(state.sessionId);
			return {
				authComponent: new OtpAuthDanceComponent({ channel: state.channel.component }),
				ctx: this.#subscribeContext(state, identity),
			};
		}
		// A runtime guard for a kind #awaitsValidation does not accept.
		throw new InvalidStateForFlowError((state as AuthDanceState).kind);
	}

	// The value answers the validation the flow asked for. On success the collected value becomes confirmed. A
	// rotate and a recover reply with the prompt that collects the replacement. Every other flow advances.
	async #submitValidationStep(
		state: AuthDanceState,
		expireAt: Date,
		options: { name: string; value: unknown; address?: string; userAgent?: string },
	): Promise<AuthDanceResponse> {
		let advanceOptions = this.#advanceBag(state, expireAt, options);
		if (state.kind === "sign-up") {
			const { path, choreographyComponent, identityComponent, ctx, verificationAuthDanceComponent } = await this.#resolveVerification(
				state,
				options.name,
			);
			const identityId = await verificationAuthDanceComponent.verifyPrompt(options.value, ctx);
			if (identityId !== true) {
				throw new InvalidValidationValueError(choreographyComponent.component);
			}
			identityComponent.confirmed = true;
			advanceOptions = {
				...advanceOptions,
				identity: ctx.identity!,
				flow: "sign-up",
				path: [...path, choreographyComponent.component],
				persist: true,
			};
		} else if (state.kind === "enroll") {
			const { identity, identityComponent, ctx, verificationAuthDanceComponent } = await this.#resolveEnrollVerification(state);
			const verified = await verificationAuthDanceComponent.verifyPrompt(options.value, ctx);
			if (verified !== true) {
				throw new InvalidValidationValueError(state.component);
			}
			identityComponent.confirmed = true;
			identity.components.push(...state.components);
			advanceOptions = {
				...advanceOptions,
				identity,
				flow: "enroll",
				name: state.component,
				persist: true,
			};
		} else if (state.kind === "rotate") {
			const { identity, ctx, authComponent, verificationAuthDanceComponent } = await this.#resolveRotateVerification(state);
			const verified = await verificationAuthDanceComponent.verifyPrompt(options.value, ctx);
			if (verified !== true) {
				throw new InvalidValidationValueError(state.component);
			}
			if (!state.verified) {
				state.verified = true;
				return { state: await this.#encryptState(state, expireAt), prompt: await authComponent.getPrompt(ctx), expireAt };
			}
			const identityComponent = this.#collectedIdentityComponent(state.components, state.component);
			identityComponent.confirmed = true;
			this.#applyReplacement(identity, state.components);
			advanceOptions = {
				...advanceOptions,
				identity,
				flow: "rotate",
				name: state.component,
				persist: true,
			};
		} else if (state.kind === "recover") {
			const identity = await this.#recoverIdentity(state);
			if (!state.verified) {
				const { ctx, verificationAuthDanceComponent } = await this.#resolveRecoverControl(state, identity);
				const verified = await verificationAuthDanceComponent.verifyPrompt(options.value, ctx);
				if (verified !== true) {
					throw new InvalidValidationValueError(state.identification!);
				}
				state.verified = true;
				const { authComponent, ctx: resetCtx } = this.#resolveRecoverReset(state, identity);
				return { state: await this.#encryptState(state, expireAt), prompt: await authComponent.getPrompt(resetCtx), expireAt };
			}
			const { identityComponent, ctx, verificationAuthDanceComponent } = await this.#resolveRecoverResetVerification(state, identity);
			const verified = await verificationAuthDanceComponent.verifyPrompt(options.value, ctx);
			if (verified !== true) {
				throw new InvalidValidationValueError(state.component);
			}
			identityComponent.confirmed = true;
			this.#applyReplacement(identity, state.components);
			advanceOptions = {
				...advanceOptions,
				identity,
				flow: "recover",
				name: state.component,
				persist: true,
			};
		} else if (state.kind === "subscribe") {
			const { identity } = await this.#getSessionAndIdentity(state.sessionId);
			const verified = await new OtpAuthDanceComponent({ channel: state.channel.component }).verifyPrompt(
				options.value,
				this.#subscribeContext(state, identity),
			);
			if (verified !== true) {
				throw new InvalidValidationValueError(state.channel.component);
			}
			state.channel.confirmed = true;
			identity.components.push(state.channel);
			advanceOptions = {
				...advanceOptions,
				identity,
				flow: "subscribe",
				name: state.channel.component,
				persist: true,
			};
		} else {
			// A runtime guard for a kind #awaitsValidation does not accept.
			throw new InvalidStateForFlowError((state as AuthDanceState).kind);
		}
		return this.#advance(advanceOptions);
	}
}

/**
 * Builds an `AuthDanceApi` from a policy.
 *
 * Call it directly when you want the state machine without the HTTP layer.
 */
export function createAuthDanceApi(options: AuthDanceApiOptions): AuthDanceApi {
	return new AuthDanceApi(options);
}
