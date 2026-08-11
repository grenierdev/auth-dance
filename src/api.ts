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
	ChannelInUseError,
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
	ControlNotProvenError,
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
	NoVerificationChannelError,
	RateLimitedError,
	RecoveryNotIdentifiedError,
	SessionNotFoundError,
	UnknownChannelError,
	UnknownComponentError,
	WouldLockOutError,
} from "./error.ts";

/**
 * One fixed-window rate limit bucket. It allows `limit` hits in each `window`.
 *
 * Every duration in this library is a number of seconds, and `window` keeps that rule.
 */
export interface AuthDanceRateLimit {
	/** How many hits the bucket allows in one window. */
	limit: number;
	/** How long one window lasts, in seconds. */
	window: number;
}

/**
 * The buckets `AuthDanceApi` consumes. `AuthDanceApi` keys each one on the identity or the session a call belongs to.
 *
 * These buckets guard one identity against repeated attacks, for example a brute-force attack on its password,
 * or many calls that drain its one-time code quota. They are tight on purpose. The per-address buckets of the
 * HTTP layer handle a caller that spreads the same abuse over many identities.
 */
export interface AuthDanceIdentityRateLimits {
	/**
	 * Each answer to a prompt or to a validation. Every attempt to prove something costs one slot.
	 * @defaultValue `{ limit: 10, window: 300 }`
	 */
	verify?: AuthDanceRateLimit;
	/**
	 * Each prompt or validation the library delivers over a channel. These calls cost real money.
	 * @defaultValue `{ limit: 5, window: 300 }`
	 */
	send?: AuthDanceRateLimit;
	/**
	 * Each start of a management flow, such as enroll, rotate or subscribe. A sign-out consumes this bucket too.
	 * @defaultValue `{ limit: 20, window: 300 }`
	 */
	manage?: AuthDanceRateLimit;
	/**
	 * Each exchange of a refresh token. A legitimate client does this often, so this bucket is the loosest of the four.
	 * @defaultValue `{ limit: 60, window: 300 }`
	 */
	refresh?: AuthDanceRateLimit;
}

/**
 * The buckets the HTTP layer consumes. The HTTP layer keys each one on the address of the caller.
 *
 * These buckets guard against abuse from one address that probes many identities. They are generous on
 * purpose. A whole NATed campus shares one address, so a limit tuned for a single client blocks everybody
 * behind that address.
 */
export interface AuthDanceAddressRateLimits {
	/**
	 * Every request, whatever the route.
	 * @defaultValue `{ limit: 300, window: 60 }`
	 */
	request?: AuthDanceRateLimit;
	/**
	 * The two routes that deliver a message over a channel. The HTTP layer consumes this bucket on top of `request`.
	 * @defaultValue `{ limit: 60, window: 60 }`
	 */
	send?: AuthDanceRateLimit;
}

/**
 * The flows that change an identity. Each one reports the change to one of the three identity hooks.
 *
 * A sign-in is absent from the list. It reads an identity and it changes nothing on it.
 */
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
 *
 * @typeParam TFlow The flows the hook that reads this event reports.
 */
export interface AuthDanceIdentityEvent<TFlow extends AuthDanceIdentityEventFlow = AuthDanceIdentityEventFlow> {
	/** Which flow changed the identity. */
	flow: TFlow;
	/**
	 * The identity the change produced, exactly as the library saved it.
	 *
	 * `onIdentityDeleted` is the one hook that reads an identity the store no longer holds. It gets the identity
	 * as it stood one moment before the library removed it, because a hook that reports a delete has nothing left
	 * to read.
	 */
	identity: AuthDanceIdentity;
	/**
	 * The component or the channel the flow acts on, under the name `options.components` or `options.channels`
	 * declares it. A recovery names the component it reset, never the component it was proven through.
	 *
	 * The type marks it optional, but every flow `onIdentityUpdated` reports names one. A sign-up and a delete
	 * act on the whole identity, so `onIdentityCreated` and `onIdentityDeleted` name nothing.
	 */
	name?: string;
}

/** The flows that create, renew or delete a session. Each one reports the change to one of the three session hooks. */
export type AuthDanceSessionEventFlow = "sign-in" | "sign-up" | "refresh" | "sign-out" | "delete";

/**
 * What the library hands a session hook.
 *
 * The event carries no token. A hook records what happened, and a token that reaches a log or a queue is a
 * credential in the wrong place.
 *
 * @typeParam TFlow The flows the hook that reads this event reports.
 */
export interface AuthDanceSessionEvent<TFlow extends AuthDanceSessionEventFlow = AuthDanceSessionEventFlow> {
	/** Which flow created, renewed or deleted the session. */
	flow: TFlow;
	/**
	 * The session the flow acts on. A refresh mints a new pair of tokens on the session it already holds, so the
	 * record it reports is the one the sign-in created.
	 */
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
 * The listeners the library calls after it changes an identity or a session. A deployment reacts to a change
 * here: it publishes an event, it writes an audit record, or it warns the owner that an account changed.
 *
 * A hook reports a change, it never decides one. The library calls it after the write, and a hook that rejects
 * never fails the flow. The tokens of a completed sign-in are already minted, and the identity of a completed
 * delete is already gone, so a listener cannot undo what it reads. `onError` gets every rejection.
 *
 * The library awaits each hook, so a hook that publishes an event finishes before the caller reads the answer. A
 * slow hook therefore slows the call that fires it. Return at once, and do the long work outside the flow.
 */
export interface AuthDanceApiHooks {
	/** A sign-up completed and the store now holds a new identity. The session hook follows for the same flow. */
	onIdentityCreated?(event: AuthDanceIdentityEvent<"sign-up">): void | Promise<void>;
	/**
	 * A flow changed the components of an identity that already existed, and the store holds the change.
	 *
	 * One flow reports one change, whatever it moved. A recovery therefore fires this hook one time, for the
	 * component it reset.
	 */
	onIdentityUpdated?(event: AuthDanceIdentityEvent<Exclude<AuthDanceIdentityEventFlow, "sign-up" | "delete">>): void | Promise<void>;
	/**
	 * A delete flow removed an identity. Every session of that identity is already gone, and `onSessionDeleted`
	 * reported each one before this hook.
	 */
	onIdentityDeleted?(event: AuthDanceIdentityEvent<"delete">): void | Promise<void>;
	/** A sign-in or a sign-up minted a session, together with the first pair of tokens on it. */
	onSessionCreated?(event: AuthDanceSessionEvent<"sign-in" | "sign-up">): void | Promise<void>;
	/**
	 * A refresh minted a new pair of tokens on a session that already existed.
	 *
	 * The hook reports the exchange alone. It does not report a new sign-in, because a refresh carries the
	 * `auth_time` of the original sign-in unchanged.
	 */
	onSessionRefreshed?(event: AuthDanceSessionEvent<"refresh">): void | Promise<void>;
	/**
	 * The library deleted a session. A sign-out that takes every session of the identity fires this hook one time
	 * for each one, and a delete flow does the same before it removes the identity.
	 */
	onSessionDeleted?(event: AuthDanceSessionEvent<"sign-out" | "delete">): void | Promise<void>;
	/**
	 * Another hook rejected. This is the one place a deployment sees a listener that is down, because the library
	 * keeps that rejection away from the flow.
	 *
	 * A rejection from this hook has nowhere left to go, and the library drops it.
	 */
	onError?(event: AuthDanceHookErrorEvent): void | Promise<void>;
}

/**
 * Everything `AuthDanceApi` needs to run the dance.
 *
 * The five required options declare the policy. The four optional groups tune the durations, the rate limits,
 * the token issuer and the lifecycle hooks.
 */
export interface AuthDanceApiOptions {
	/** Where the library delivers a message, keyed by the channel name a component asks for. */
	channels: Record<string, AuthDanceChannel>;
	/** The one declaration the sign-in, the sign-up, the recover and the unenroll flow read. `peek` picks the next step from it. */
	choreography: AuthDanceChoreography;
	/** What each step does, keyed by the name the choreography and the prompts use. */
	components: Record<string, AuthDanceComponent>;
	/** The base64url key. It signs every minted token and it encrypts the state. Keep it in a secret store. */
	secret: string;
	/** Where identities, sessions, one-time codes and rate limit counters live. */
	storage: AuthDanceStorage;
	/**
	 * How long a flow, a token and the elevated window last, in seconds.
	 *
	 * There is one key per flow. A recovery can get more room than a sign-in, and a confirmation-only flow such
	 * as `unenroll` can get less.
	 */
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
		 * needs no fresh sign-in. A refresh keeps `auth_time` unchanged, so it never re-opens the window either.
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
		 * The `iss` claim of every minted token. The encrypted state carries the same claim, and the library
		 * checks that claim every time it reads a state back.
		 *
		 * The default applies to the minted tokens only. Omit this option and the state carries no issuer, and
		 * the library checks none.
		 * @defaultValue "acme"
		 */
		issuer?: string;
	};
	/**
	 * The listeners the library calls after it changes an identity or a session. Any hook you omit reports nothing.
	 *
	 * @defaultValue No listener. The library changes an identity and a session exactly the same way without them.
	 */
	hooks?: AuthDanceApiHooks;
}

/**
 * The buckets `AuthDanceApi` uses when `limits.identity` omits one. They are tight, because each one applies
 * to a single identity or to a single session.
 */
export const IdentityRateLimits: Required<AuthDanceIdentityRateLimits> = {
	verify: { limit: 10, window: 5 * 60 },
	send: { limit: 5, window: 5 * 60 },
	manage: { limit: 20, window: 5 * 60 },
	refresh: { limit: 60, window: 5 * 60 },
};

/**
 * The state machine of the library. It performs the dance the choreography declares.
 *
 * It covers nine flows: sign-in, sign-up, enroll, unenroll, rotate, recover, subscribe, unsubscribe and delete.
 * A flow method returns the first prompt together with the state. The state is a JWE the client keeps and
 * returns with every later call. The client then calls `submitPrompt` until the answer carries the tokens or a
 * plain success result. When the library asks for proof of control, the client calls `submitValidation` instead.
 *
 * Each method raises an `AuthDanceError` for a failure the caller can act on. Any other failure escapes as
 * `AuthDanceUnknownError` and carries the original failure in `cause`. `accessTokenIdentity` is the one
 * exception, because it lets an unexpected failure escape as it stands.
 *
 * A flow that changes an identity or a session reports the change to `options.hooks` after it saves it. A hook
 * that rejects never fails the flow. Read `AuthDanceApiHooks` about what each one reports.
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

	/**
	 * Builds the state machine from a policy. It decodes `options.secret` one time and keeps the raw key.
	 *
	 * `createAuthDanceApi` calls this constructor. `createAuthDance` reaches it through `createAuthDanceApi`.
	 */
	constructor(options: AuthDanceApiOptions) {
		this.#options = options;
		this.#decodedSecret = decode(this.#options.secret);
	}

	/**
	 * The storage this instance reads and writes.
	 *
	 * The HTTP layer needs it for the read-only routes that follow `accessTokenIdentity`, and for the
	 * per-address rate limit counters it keeps.
	 */
	get storage(): AuthDanceStorage {
		return this.#options.storage;
	}

	// The single boundary between "this failed in a way the caller was told about" and "this should never
	// have happened". Internals — including every private helper below — signal failure by throwing an
	// AuthDanceError, which passes through untouched. Anything else (jose, valibot, a storage provider, a bug)
	// is wrapped in AuthDanceUnknownError, so an unhandled case can never masquerade as a business rule.
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

	// The deliberate hole in #guard above. A hook reports a write that has already happened, so a listener that
	// rejects must not turn a completed flow into a failure: a sign-in whose audit queue is down still signed in,
	// and surfacing that as UNKNOWN would tell the caller their tokens are worthless when they are not. The
	// rejection goes to onError instead, the one place a deployment sees a broken listener. A rejecting onError
	// has nowhere left to report to.
	async #emit<TKey extends Exclude<keyof AuthDanceApiHooks, "onError">>(
		hook: TKey,
		event: Parameters<NonNullable<AuthDanceApiHooks[TKey]>>[0],
	): Promise<void> {
		// One key of a union of listener types, each narrower than the union of their events — hence the cast.
		// The generic keeps every call site honest, which is where it matters.
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
	 * No flow calls this. It serves the deployment around the library, which knows the identity it wants to
	 * reach but not the recipient data the channel needs. This method resolves that recipient.
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
	 * Sends a message that already names its recipient.
	 *
	 * The recipient is a channel component. A caller that already holds one, from a previous
	 * `accessTokenIdentity` read for example, skips the identity lookup `sendMessageTo` does.
	 *
	 * @throws UnknownChannelError when `options.channels` declares no channel the recipient names.
	 */
	sendMessage(message: AuthDanceMessage): Promise<AuthDanceResponseResult> {
		return this.#guard("sendMessage", async () => {
			await this.#sendMessage(message);
			return { success: true };
		});
	}

	// `auth_time` (OIDC's claim for "when the sign-in itself happened") is minted with the very first
	// pair and then carried verbatim through every refresh: refreshing extends how long the session may
	// be used, never how recently its holder proved who they are. Sensitive actions gate on it — see
	// #requireFreshSignIn.
	async #generateTokens(
		options: { identity: AuthDanceIdentity; scopes: string[]; session: AuthDanceSession; authTime?: number },
	): Promise<AuthDanceResponseTokens> {
		const authTime = options.authTime ?? Math.floor(Date.now() / 1000);

		const access_token = await new SignJWT({ auth_time: authTime })
			.setProtectedHeader({ alg: "HS256" })
			.setIssuer(this.#options.tokens?.issuer ?? "acme")
			.setIssuedAt()
			.setExpirationTime(new Date(Date.now() + (this.#options.durations?.access ?? 5 * 60) * 1000))
			.setSubject(options.session.id)
			.setJti(ksuid())
			.sign(this.#decodedSecret);

		const refresh_token = await new SignJWT({ auth_time: authTime })
			.setProtectedHeader({ alg: "HS256", scopes: options.scopes })
			.setIssuer(this.#options.tokens?.issuer ?? "acme")
			.setIssuedAt()
			.setExpirationTime(new Date(Date.now() + (this.#options.durations?.refresh ?? 24 * 60 * 60) * 1000))
			.setSubject(options.session.id)
			.setJti(ksuid())
			.sign(this.#decodedSecret);

		const claims = Object.entries(options.identity.data ?? {}).reduce((acc, [key, value]) => {
			if (options.scopes.includes(key)) {
				acc[key] = value;
			}
			return acc;
		}, {} as Record<string, unknown>);
		const id_token = await new SignJWT({})
			.setProtectedHeader({ ...claims, alg: "HS256" })
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

	// A tampered, expired, subject-less or auth_time-less token all mean the same thing to the caller, and
	// saying which would only help someone probing. jose's own failure is therefore expected here, not
	// unknown. Every token this class mints carries both claims, so a token missing either is not one of ours.
	async #verifiedClaims(token: string, invalid: () => AuthDanceError): Promise<{ sub: string; authTime: number }> {
		const payload = await jwtVerify(token, this.#decodedSecret, {
			issuer: this.#options.tokens?.issuer ?? "acme",
		}).then(({ payload }) => payload, () => undefined);
		if (!payload?.sub || typeof payload.auth_time !== "number") {
			throw invalid();
		}
		return { sub: payload.sub, authTime: payload.auth_time };
	}

	// Sensitive management actions (enroll, rotate, unsubscribe, …) are not satisfied by a merely valid
	// session: the caller must have proven who they are recently. A refresh carries auth_time forward
	// untouched, so it can never be used to walk out of this window.
	#requireFreshSignIn(authTime: number): void {
		const elevated = (this.#options.durations?.elevated ?? 5 * 60) * 1000;
		if (Date.now() - authTime * 1000 > elevated) {
			throw new FreshSignInRequiredError();
		}
	}

	// Buckets are keyed on the subject a call is attributable to, never on the request: the session behind
	// an access token, or the identity a flow's state has already resolved. A call attributable to neither
	// — signing in before the identification has been answered, starting a sign-up or a recovery — is left
	// to the per-address buckets at the edge, the only layer that can bucket it at all.
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

	// Which subject a state is attributable to. Sign-up is the one flow with none: it mints its own identity
	// id and a caller can always start another, so there is nothing durable to bucket on.
	#stateSubject(state: AuthDanceState): string | undefined {
		if (state.kind === "sign-in" || state.kind === "recover") {
			return state.identityId && `identity:${state.identityId}`;
		}
		if (state.kind === "sign-up") {
			return undefined;
		}
		return `session:${state.sessionId}`;
	}

	/**
	 * Exchanges a refresh token for a new set of tokens on the same session.
	 *
	 * The new tokens carry the `auth_time` of the original sign-in unchanged. A refresh therefore extends how
	 * long the client may use the session, and never how recently its holder proved who they are. It cannot
	 * re-open the elevated window, so it needs no fresh sign-in and grants none.
	 *
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
	 * A sign-out needs no fresh sign-in. It only removes access, so an old session is enough to ask for it.
	 *
	 * The call fires `onSessionDeleted` one time for each session it destroys.
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
			const { session, identity } = await this.accessTokenIdentity(access_token);
			await this.#consumeRateLimit("manage", `session:${session.id}`);
			// The hook fires one time for each session the call destroyed, and only after the store agrees it is
			// gone. A sign-out that takes them all reports each one rather than the sweep, so a listener sees the
			// same event whichever way a session ended.
			const deleted = others ? await this.#options.storage.listSession(session.identityId) : [session];
			await Promise.all(deleted.map((s) => this.#options.storage.deleteSession(s.id)));
			for (const s of deleted) {
				await this.#emit("onSessionDeleted", { flow: "sign-out", session: s, identity });
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

	async #advance(options: {
		state: AuthDanceState;
		path: string[];
		identity: AuthDanceIdentity;
		expireAt: Date;
		flow: string;
		name?: string;
		persist?: boolean;
		address?: string;
		userAgent?: string;
	}): Promise<AuthDanceResponse> {
		// Only the authentication flows walk the choreography and mint tokens; every other flow — a recovery
		// included — acts on the one component it names and completes with a plain success result. Proving
		// control of a single component is not a sign-in.
		const authFlow = options.flow === "sign-in" || options.flow === "sign-up";
		const nextMove = authFlow ? peek(this.#options.choreography, options.path) : null;
		if (nextMove === null) {
			// Every identity hook fires from this one place, so a hook reports a change the store already holds and
			// never one a later step could still reject.
			if (options.persist) {
				await this.#options.storage.setIdentity(options.identity);
				if (options.flow === "sign-up") {
					await this.#emit("onIdentityCreated", { flow: options.flow, identity: options.identity });
				} else {
					// A flow reaches this line only through a branch of #submitPrompt or #submitValidation, and each
					// one of those sets a flow AuthDanceIdentityEventFlow names. The bag they share types it as a
					// plain string, hence the cast.
					await this.#emit("onIdentityUpdated", {
						flow: options.flow as Exclude<AuthDanceIdentityEventFlow, "sign-up" | "delete">,
						identity: options.identity,
						name: options.name,
					});
				}
			}
			if (authFlow) {
				const issued = await this.#issueTokens(options.identity, options);
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

	async #sessionIdentity(sessionId: string): Promise<{ session: AuthDanceSession; identity: AuthDanceIdentity }> {
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

	/**
	 * Resolves the session and the identity of an access token, and returns its `auth_time`.
	 *
	 * An already authenticated caller runs a management flow such as enroll or subscribe. Such a flow starts
	 * from the access token, not from a step through the choreography.
	 *
	 * This method is public because the read-only routes — list the sessions, list the components — are this
	 * call plus one storage read. A method here for each of them adds a layer that decides nothing.
	 *
	 * @returns The session, the identity behind it, and the `auth_time` claim of the token in seconds.
	 * @throws InvalidAccessTokenError when the token is tampered with, expired, or missing a claim.
	 * @throws SessionNotFoundError when the session has already expired or was signed out.
	 * @throws IdentityNotFoundError when storage holds no identity for that session.
	 */
	async accessTokenIdentity(access_token: string): Promise<{ session: AuthDanceSession; identity: AuthDanceIdentity; authTime: number }> {
		const { sub, authTime } = await this.#verifiedClaims(access_token, () => new InvalidAccessTokenError());
		return { ...await this.#sessionIdentity(sub), authTime };
	}

	// Confirming a new channel is authorised through an already-trusted channel: pick the first
	// confirmed channel that is not the one being subscribed to (e.g. send the OTP to email while
	// subscribing SMS).
	#subscribeSendChannel(identity: AuthDanceIdentity, subscribing: string): AuthDanceIdentityChannel {
		const channel = identity.components
			.find((c): c is AuthDanceIdentityChannel => c.kind === "channel" && c.confirmed && c.component !== subscribing);
		if (!channel) {
			throw new NoVerificationChannelError(subscribing);
		}
		return channel;
	}

	#subscribeContext(state: AuthDanceStateSubscribe, identity: AuthDanceIdentity): AuthDanceComponentContext {
		return {
			storage: this.#options.storage,
			name: state.channel.component,
			stateId: state.id,
			flow: "subscribe",
			identity,
		};
	}

	// Like #signUpContext, the component sees the components collected during this enrollment first,
	// so its verification targets the value being enrolled (e.g. the OTP goes to the new email
	// address) while the identity's existing components stay available as a fallback.
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
		const { identity } = await this.#sessionIdentity(state.sessionId);
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

	// The component being enrolled, rotated or reset is the identification/challenge it produced; any channel
	// it also yielded (e.g. the email address it can be reached at) rides along but is not the subject.
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

	// Same layering as #enrollContext: the replacement value shadows the currently enrolled one, so its
	// verification targets the new value (e.g. the OTP goes to the new email address). While the
	// replacement has not been collected yet, state.components is empty and the identity is seen as it
	// stands, which is exactly what proving control of the enrolled component needs.
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
		const { identity } = await this.#sessionIdentity(state.sessionId);
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

	// Rotation and recovery both swap components in place: the previously enrolled identification/challenge
	// is dropped in favour of the freshly validated one carrying the same name. Channels are keyed by name,
	// so a channel a component re-emits ("email" now pointing at the new address) supersedes the previous
	// entry instead of duplicating it — while keeping the links other components hold on that channel.
	// Replacing by name makes this idempotent, so a flow that collects several components can re-apply the
	// whole set on every step.
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

	// Which components of the choreography a recovery can be proven through: one that resolves an identity on
	// its own, as an identification does, and proves control of it, as a verification does. The component being
	// recovered is never one of them — the value the caller no longer has cannot be the value they prove.
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

	// Same layering as #rotateContext: a replacement collected during the reset shadows the value it replaces,
	// so its verification targets the new one. While control of the picked component is still being proven
	// nothing has been collected and the identity is seen as it stands — which is what proving control needs.
	// The identity itself is unknown until the identification has been submitted.
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

	// First phase: prove control of the component the caller picked to identify with.
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

	// Second phase: the component being recovered. It collects the replacement, exactly as an enroll does.
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

	// Second phase again: validate the replacement the recovered component asked to prove control of.
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

	// What an unenroll takes down, beyond the component the caller named. A channel exists for the components its
	// linkedTo names — the email component lists itself on the channel it contributes — so removing one of them
	// orphans the channel, and removing the channel leaves every other component that channel carries with no way
	// to reach its owner. That second state is exactly the one unsubscribe refuses to create (ChannelInUseError),
	// so an unenroll must not create it either. The removal therefore follows the links both ways — component to
	// the channels that name it, channel back to the components it names — until nothing new joins.
	// The two sets stay apart because the names live in two namespaces: the email component contributes an "email"
	// channel beside its "email" identification, and those are not the same record.
	#unenrollCollateral(identity: AuthDanceIdentity, component: string): { components: Set<string>; channels: Set<string> } {
		const components = new Set([component]);
		const channels = new Set<string>();
		// Each pass that changes anything claims at least one more channel, and an identity holds a finite number
		// of them, so the walk reaches its fixed point.
		for (let grew = true; grew;) {
			grew = false;
			for (const c of identity.components) {
				if (c.kind !== "channel" || channels.has(c.component) || !(c.linkedTo ?? []).some((name) => components.has(name))) {
					continue;
				}
				channels.add(c.component);
				for (const name of c.linkedTo ?? []) {
					components.add(name);
				}
				grew = true;
			}
		}
		return { components, channels };
	}

	// Unenrolling must not lock the identity out of its own account: walk the choreography and keep the
	// removal only if at least one path to an end is still fully covered by the surviving confirmed
	// components. With choice(sequence("email", "password"), "facebook"), dropping "facebook" is fine
	// because the email + password path survives; dropping "password" would not be. `removed` is the whole
	// collateral #unenrollCollateral produced, never the single name the caller gave: a component that falls
	// with a channel stops covering the paths it used to cover, and the check has to see that.
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

	// The issuer travels as the `iss` claim, the way the minted tokens carry it. #decryptState hands the
	// configured issuer to jose, and jose checks it against the claim: an issuer in the protected header instead
	// left that claim unset, so every state of a deployment that configured one failed to decrypt.
	#encryptState(state: AuthDanceState, expireAt: Date): Promise<string> {
		const issuer = this.#options.tokens?.issuer;
		const jwt = new EncryptJWT({ state })
			.setProtectedHeader({ alg: "dir", enc: "A256GCM" })
			.setIssuedAt()
			.setExpirationTime(expireAt);
		return (issuer === undefined ? jwt : jwt.setIssuer(issuer)).encrypt(this.#decodedSecret);
	}

	// A state that fails to decrypt, carries no expiry, or no longer matches the schema is a stale or forged
	// value coming from the client — expected input, not a server fault. jose and valibot both fail by
	// throwing, so they are converted here rather than escaping as unknown.
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
	 * The state holds no identity yet. A component resolves one during the dance, so no per-identity bucket can
	 * key on anything before that step. Until then, only the per-address buckets of the HTTP layer guard this flow.
	 * This flow needs no access token and no fresh sign-in.
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
			// A choreography that is already over at its first step has nothing to authenticate against.
			if (nextMove === null) {
				throw new ChoreographyEmptyError();
			}
			return this.#promptResponse(state, nextMove, expireAt, "sign-in");
		});
	}

	/**
	 * Starts a registration and returns the first prompt of the choreography.
	 *
	 * Sign-up walks the same steps sign-in verifies, so the two flows cannot differ. The state carries the
	 * new identity id from the start, but storage keeps nothing until the choreography completes.
	 *
	 * Sign-up is the one flow with no per-identity bucket. It mints its own identity id and a caller can always
	 * start another one, so there is nothing durable to key a bucket on. This flow needs no access token and no
	 * fresh sign-in.
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
	 * This flow needs a fresh sign-in. Past the elevated window it raises `FreshSignInRequiredError`.
	 *
	 * The prompt collects the new value. The component sees the values this enrollment collected first, so a
	 * validation targets the new value and not the ones the identity already carries. Answer that validation
	 * with `sendValidation` and `submitValidation`.
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
			const { session, identity, authTime } = await this.accessTokenIdentity(options.access_token);
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
	 * This flow needs a fresh sign-in. Past the elevated window it raises `FreshSignInRequiredError`.
	 *
	 * The removal takes the linked records with it. A channel that names the component in its `linkedTo` goes
	 * too, and so does every other component that channel names, because a component a channel carries has no
	 * way to reach its owner once that channel is gone. The library follows those links to their end, and it
	 * removes the whole set at the confirmation.
	 *
	 * The library then walks the choreography and refuses a removal that leaves no completable path. It counts
	 * that whole set, never the one component the caller named. It answers with a confirmation prompt. Submit
	 * the boolean `true` to it through `submitPrompt`.
	 *
	 * @param options `name` is the component to remove.
	 * @returns The encrypted state, a confirmation prompt, and the moment the state expires.
	 * @throws InvalidAccessTokenError, SessionNotFoundError or IdentityNotFoundError when the token resolves to nothing.
	 * @throws RateLimitedError when the `manage` bucket of the session is empty.
	 * @throws ComponentNotEnrolledError when the identity carries no such component.
	 * @throws UnknownComponentError when `options.components` declares no component of that name.
	 * @throws FreshSignInRequiredError when the sign-in is older than the elevated window.
	 * @throws WouldLockOutError when no path through the choreography stays completable without the component
	 * and the linked records that go with it.
	 */
	unenroll(options: { name: string; access_token: string }): Promise<AuthDanceResponseState> {
		return this.#guard("unenroll", async () => {
			const { session, identity, authTime } = await this.accessTokenIdentity(options.access_token);
			await this.#consumeRateLimit("manage", `session:${session.id}`);
			if (!identity.components.some((c) => c.kind !== "channel" && c.component === options.name)) {
				throw new ComponentNotEnrolledError(options.name);
			}
			if (!this.#options.components[options.name]) {
				throw new UnknownComponentError(options.name);
			}
			this.#requireFreshSignIn(authTime);
			if (!this.#isChoreographyCompletableWithout(identity, this.#unenrollCollateral(identity, options.name).components)) {
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
	 * This flow needs a fresh sign-in. Past the elevated window it raises `FreshSignInRequiredError`.
	 *
	 * A component that can verify itself proves control of the current value first, so the flow has two
	 * validation rounds. A component that cannot, a password for example, is proven from the start. Its first
	 * prompt already collects the replacement.
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
			const { session, identity, authTime } = await this.accessTokenIdentity(options.access_token);
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
				// Proving control of the currently enrolled value is only meaningful for a component that can
				// verify itself: receiving an OTP at the current email address proves something, re-typing a
				// password proves nothing the access token has not already established. Components without a
				// verification component therefore start out proven and go straight to the replacement.
				verified: !authComponent.verificationComponent,
				components: [],
			};
			// Once control is proven, the flow continues exactly like enroll — collect the replacement, then
			// validate it.
			const ctx = this.#rotateContext(state, identity);
			const promptWith = authComponent.verificationComponent ? await authComponent.verificationComponent(ctx) : authComponent;
			const prompt = await promptWith.getPrompt(ctx);
			return { state: await this.#encryptState(state, expireAt), prompt, expireAt };
		});
	}

	/**
	 * Starts the recovery of one component, for a caller who can no longer provide it.
	 *
	 * Apart from a sign-in and a sign-up, this is the only flow a caller with no session can start. The caller
	 * therefore has to identify themselves and prove control through another component, and one component has to do
	 * both jobs on its own. It resolves an identity, as an identification does, and it proves control of that
	 * identity, as a verification does. The first prompt is a choice between every such component of the
	 * choreography, or that component's own prompt when the choreography holds exactly one. This flow needs no
	 * access token and no fresh sign-in.
	 *
	 * The choice is one between components, never between values, so the response discloses nothing about the
	 * identity. Which identity the flow recovers stays unknown until `submitPrompt` answers that choice. Once
	 * control of the picked component is proven, the flow collects the replacement of the recovered component and
	 * validates it, exactly as an enroll does. It completes with a plain success result, never with tokens. Proof
	 * of control of a single component is not a sign-in.
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
			// Which identity is being recovered is unknown until the choice is answered, so every prompt of it is
			// the component's own and nothing about the identity is disclosed.
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
	 * with a one-time code. It delivers that code over a channel the identity has already confirmed. An identity
	 * with no other confirmed channel therefore meets `NoVerificationChannelError` on the next step, not here.
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
			const { session, identity, authTime } = await this.accessTokenIdentity(options.access_token);
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
	 * This flow needs a fresh sign-in. Past the elevated window it raises `FreshSignInRequiredError`.
	 *
	 * A channel another enrolled component links to stays in place. That component needs the channel to reach the
	 * identity. The library answers with a confirmation prompt. Submit the boolean `true` to it through
	 * `submitPrompt`.
	 *
	 * @param options `name` is the channel to remove.
	 * @returns The encrypted state, a confirmation prompt, and the moment the state expires.
	 * @throws InvalidAccessTokenError, SessionNotFoundError or IdentityNotFoundError when the token resolves to nothing.
	 * @throws RateLimitedError when the `manage` bucket of the session is empty.
	 * @throws ChannelNotSubscribedError when the identity carries no such channel.
	 * @throws UnknownChannelError when `options.channels` declares no channel of that name.
	 * @throws FreshSignInRequiredError when the sign-in is older than the elevated window.
	 * @throws ChannelInUseError when an enrolled component still links to the channel.
	 */
	unsubscribe(options: { name: string; access_token: string }): Promise<AuthDanceResponseState> {
		return this.#guard("unsubscribe", async () => {
			const { session, identity, authTime } = await this.accessTokenIdentity(options.access_token);
			await this.#consumeRateLimit("manage", `session:${session.id}`);
			const channel = identity.components.find((c): c is AuthDanceIdentityChannel => c.kind === "channel" && c.component === options.name);
			if (!channel) {
				throw new ChannelNotSubscribedError(options.name);
			}
			if (!this.#options.channels[options.name]) {
				throw new UnknownChannelError(options.name);
			}
			this.#requireFreshSignIn(authTime);
			const linkedTo = channel.linkedTo ?? [];
			if (identity.components.some((c) => c.kind !== "channel" && linkedTo.includes(c.component))) {
				throw new ChannelInUseError(options.name);
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
	 * This flow needs a fresh sign-in. Past the elevated window it raises `FreshSignInRequiredError`.
	 *
	 * A delete is the one management flow with nothing left to protect afterwards. The library gates it exactly
	 * like the other destructive flows — a recent sign-in, then an explicit confirmation — and nothing more.
	 * There is no component to keep the choreography completable with, and no lock-out to avoid. A lock-out of
	 * the identity is exactly what the caller wants.
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
			const { session, authTime } = await this.accessTokenIdentity(options.access_token);
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
	 * Delivers the current prompt over its channel, for a component the caller cannot simply type — a one-time
	 * code, for example.
	 *
	 * Only a sign-in and a sign-up hold a prompt to deliver. Every other flow delivers a validation instead,
	 * through `sendValidation`. This method needs no access token and no fresh sign-in, because the state carries
	 * whatever the flow has established.
	 *
	 * @param options `name` selects which component to deliver when the current step is a choice. `locale` picks
	 * the language of the message. `state` is the opaque string the previous call returned.
	 * @throws InvalidStateError when the state does not decrypt, carries no expiry, or no longer matches the schema.
	 * @throws RateLimitedError when the `send` bucket of the subject is empty.
	 * @throws InvalidStateForFlowError when the state is neither a sign-in nor a sign-up.
	 * @throws ComponentNotInChoreographyError when `name` is not a component the current step offers.
	 * @throws UnknownComponentError when `options.components` declares no component of that name.
	 * @throws ComponentNotSendableError when the component delivers nothing over a channel.
	 * @throws UnknownChannelError when `options.channels` declares no channel the message names.
	 */
	sendPrompt(options: { name: string; locale: string; state: string }): Promise<AuthDanceResponseResult> {
		return this.#guard("sendPrompt", async () => {
			const { state } = await this.#decryptState(options.state);
			await this.#consumeRateLimit("send", this.#stateSubject(state));
			let authComponent: AuthDanceComponent | undefined;
			let ctx: AuthDanceComponentContext | undefined;
			if (state.kind === "sign-in") {
				const { choreographyComponent, authComponent: ac } = this.#resolveStep(state.path, options.name);
				const identity = state.identityId ? await this.#options.storage.getIdentity(state.identityId) : undefined;
				authComponent = ac;
				ctx = this.#signInContext(state, choreographyComponent.component, identity!);
			} else if (state.kind === "sign-up") {
				const path = this.#signUpPath(state);
				const { choreographyComponent, authComponent: ac } = this.#resolveStep(path, options.name);
				authComponent = ac;
				ctx = this.#signUpContext(state, choreographyComponent.component);
			} else {
				throw new InvalidStateForFlowError(state.kind);
			}
			if (!authComponent || !authComponent.sendPrompt || !ctx) {
				throw new ComponentNotSendableError(options.name);
			}
			const message = await authComponent.sendPrompt(options.locale, ctx);
			if (!message) {
				throw new ComponentNotSendableError(options.name);
			}
			await this.#sendMessage(message);
			return { success: true };
		});
	}

	/**
	 * Answers the current prompt of any flow and moves the dance one step.
	 *
	 * The state names the flow, so this one method serves all nine of them. A sign-in verifies the value against
	 * the choreography. A sign-up, an enroll and a rotate collect the value. A recover answers the choice of
	 * components to identify with, and later collects the replacement of the component it resets. An unenroll, an
	 * unsubscribe and a delete take the boolean `true` as their confirmation. A subscribe stores the recipient
	 * and moves to its one-time code.
	 *
	 * When the collected value still needs proof of control, the answer is a validation prompt instead of the
	 * next step. Reply to it with `sendValidation` and `submitValidation`, then the dance continues.
	 *
	 * The library checks the elevated window when a flow starts, so this method does not check it again. It needs no
	 * access token either, because the state carries the session the flow started from.
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
	 * @throws InvalidStateForFlowError when the state has no prompt left to answer, for example a subscribe that
	 * already waits for its one-time code.
	 * @throws ComponentNotInChoreographyError or UnknownComponentError when `name` is not the step the flow expects.
	 * @throws InvalidPromptValueError when a sign-in step rejects the value.
	 * @throws IdentityNotResolvedError when no step has resolved an identity and the value resolves none either.
	 * @throws IdentityMismatchError when two components of one dance resolve two different identities.
	 * @throws ComponentAlreadyCollectedError when the step already holds a value.
	 * @throws ComponentNotCollectedError when the component yields no identification and no challenge.
	 * @throws ControlNotProvenError when a rotate or a recover has not yet proven control of the current value.
	 * @throws ComponentNotVerifiableError when the component a recovery identifies through offers no verification.
	 * @throws ConfirmationRequiredError when an unenroll, an unsubscribe or a delete gets a value other than `true`.
	 * @throws WouldLockOutError when the unenroll leaves no completable path through the choreography.
	 * @throws NoVerificationChannelError when a subscribe has no other confirmed channel to deliver the code over.
	 * @throws SessionNotFoundError or IdentityNotFoundError when the session or the identity the state names is gone.
	 */
	submitPrompt(
		options: { name: string; value: unknown; state: string; address?: string; userAgent?: string },
	): Promise<AuthDanceResponse> {
		return this.#guard("submitPrompt", () => this.#submitPrompt(options));
	}

	// The three long flows below stay in private methods rather than inside the #guard closure: the error
	// boundary reads as one line, and the body keeps signalling failure exactly the way every private helper
	// does — by throwing — instead of being re-indented into a callback.
	async #submitPrompt(
		options: { name: string; value: unknown; state: string; address?: string; userAgent?: string },
	): Promise<AuthDanceResponse> {
		const { state, expireAt } = await this.#decryptState(options.state);
		// Before the value is looked at, so a wrong password costs a bucket slot rather than being free. In a
		// sign-in the subject is whatever an earlier step resolved, which is exactly the step that matters:
		// guessing a password happens once the identification is behind us.
		await this.#consumeRateLimit("verify", this.#stateSubject(state));
		let advanceOptions = {
			state,
			path: [] as string[],
			identity: void 0 as unknown as AuthDanceIdentity,
			expireAt,
			flow: "",
			name: undefined as string | undefined,
			persist: undefined as boolean | undefined,
			address: options.address,
			userAgent: options.userAgent,
		};
		if (state.kind === "sign-in") {
			const { choreographyComponent, authComponent } = this.#resolveStep(state.path, options.name);
			let identity = state.identityId ? await this.#options.storage.getIdentity(state.identityId) : undefined;
			const ctx = this.#signInContext(state, choreographyComponent.component, identity!);
			const identityId = await authComponent.verifyPrompt(options.value, ctx);
			// Verification failed: never advance the choreography. This has to be checked on its own, because
			// once an earlier step has put an identityId in the state the guard below no longer fires and a
			// rejected value (e.g. a wrong password) would otherwise walk straight to the tokens.
			if (identityId === false) {
				throw new InvalidPromptValueError(choreographyComponent.component);
			}
			// Prompt did not yield an identity and state does not have an identityId, so we cannot proceed
			if (!identity && identityId === true) {
				throw new IdentityNotResolvedError(choreographyComponent.component);
			}
			// Prompt yielded an identityId, but state already has an identityId that does not match, so we cannot proceed
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
			// The enrolled value is collected exactly once; anything further belongs to the verification
			// phase (sendValidation/submitValidation).
			if (state.components.length > 0) {
				throw new ComponentAlreadyCollectedError(state.component);
			}
			const { identity } = await this.#sessionIdentity(state.sessionId);
			const authComponent = this.#options.components[state.component];
			if (!authComponent) {
				throw new UnknownComponentError(state.component);
			}
			// Collection sees the identity as it stands; the verification context below is rebuilt after the
			// value has been collected, because #enrollContext snapshots state.components and verification has
			// to target the value being enrolled rather than the one it replaces.
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
			// Control of the enrolled value is proven through sendValidation/submitValidation, which is the
			// prompt rotate() handed out; only the replacement value is collected here, exactly once.
			if (!state.verified) {
				throw new ControlNotProvenError(state.component);
			}
			if (state.components.length > 0) {
				throw new ComponentAlreadyCollectedError(state.component);
			}
			const { identity } = await this.#sessionIdentity(state.sessionId);
			const authComponent = this.#options.components[state.component];
			if (!authComponent) {
				throw new UnknownComponentError(state.component);
			}
			// Same layering as enroll: the replacement is collected against the identity as it stands, which is
			// what lets a component refuse a value identical to the one being replaced.
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
				// Which identity is being recovered is established here and only here: the caller picks one of the
				// components that can identify them, that component resolves the submitted value to an identity,
				// then its verification takes over to prove control of it.
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
			// Nothing is reset before control of the picked component has been proven, which is what
			// sendValidation/submitValidation did with the prompt handed out above.
			if (!state.verified) {
				throw new ControlNotProvenError(state.identification);
			}
			const identity = await this.#recoverIdentity(state);
			// The replacement is collected exactly once; anything further belongs to its validation round.
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
				// The component the recovery reset, which is what a listener acts on. Which component the caller
				// proved control through is not what changed.
				name: state.component,
				persist: true,
			};
		} else if (state.kind === "unenroll") {
			if (options.value !== true) {
				throw new ConfirmationRequiredError(state.component);
			}
			const { identity } = await this.#sessionIdentity(state.sessionId);
			// The collateral is resolved again here, against the identity as it stands now: another flow may have
			// moved a component or a channel while this confirmation was outstanding, and the set that survives the
			// removal is what the lock-out check has to run against.
			const collateral = this.#unenrollCollateral(identity, state.component);
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
			// The recipient (e.g. phone number) has already been collected once we reach the validating phase.
			if (state.validating) {
				throw new InvalidStateForFlowError(state.kind);
			}
			const { identity } = await this.#sessionIdentity(state.sessionId);
			// Stash the submitted recipient on the pending channel, keyed by the channel name (mirrors how the
			// email component stores its address), then move to OTP validation.
			state.channel.data = { ...(state.channel.data ?? {}), [state.channel.component]: options.value };
			state.validating = true;
			const sendChannel = this.#subscribeSendChannel(identity, state.channel.component);
			const prompt = await new OtpAuthDanceComponent({ channel: sendChannel.component }).getPrompt(this.#subscribeContext(state, identity));
			return { state: await this.#encryptState(state, expireAt), prompt, expireAt };
		} else if (state.kind === "unsubscribe") {
			// A single confirmation gate: the authenticated caller must explicitly confirm (value === true)
			// before the channel is detached.
			if (options.value !== true) {
				throw new ConfirmationRequiredError(state.channel);
			}
			const { identity } = await this.#sessionIdentity(state.sessionId);
			identity.components = identity.components.filter((c) => !(c.kind === "channel" && c.component === state.channel));
			advanceOptions = {
				...advanceOptions,
				identity,
				flow: "unsubscribe",
				name: state.channel,
				persist: true,
			};
		} else if (state.kind === "delete") {
			// Same confirmation gate as unenroll and unsubscribe, but the flow returns here instead of going
			// through #advance: persisting is what every other flow ends with, and the identity being gone is the
			// one outcome that must not be written back. Its sessions go with it, so no token outlives the
			// identity it was minted for and resolves to a session pointing at nothing.
			if (options.value !== true) {
				throw new ConfirmationRequiredError("identity");
			}
			const { identity } = await this.#sessionIdentity(state.sessionId);
			const sessions = await this.#options.storage.listSession(identity.id);
			await Promise.all(sessions.map((s) => this.#options.storage.deleteSession(s.id)));
			await this.#options.storage.deleteIdentity(identity.id);
			// The hooks follow the same order as the two writes above, so a listener never reads an identity that
			// still holds a session the store already dropped. This is also the one identity a hook receives that
			// the store no longer holds: the event carries it as it stood one moment before the delete.
			for (const session of sessions) {
				await this.#emit("onSessionDeleted", { flow: "delete", session, identity });
			}
			await this.#emit("onIdentityDeleted", { flow: "delete", identity });
			return { success: true };
		} else {
			// Every AuthDanceState kind is handled above, so `state` narrows to `never` here — hence the cast. The
			// branch is kept as a runtime guard: the state comes from the client, and a kind the schema does
			// not know about should fail loudly rather than fall through to #advance with an empty flow.
			throw new InvalidStateForFlowError((state as AuthDanceState).kind);
		}
		return this.#advance(advanceOptions);
	}

	/**
	 * Delivers the validation that proves control of a value the flow already collected. One example is the
	 * one-time code that confirms the address the caller just gave.
	 *
	 * A sign-up, an enroll, a rotate, a recover and a subscribe all validate a value. A sign-in has no validation
	 * phase, and a confirmation-only flow has none either. A rotate and a recover use this method in both of
	 * their phases. Before the flow collects the replacement, the message proves control of the current value — of
	 * the component the caller identified through, for a recovery. Afterwards it validates the replacement.
	 *
	 * For a subscribe the library picks the first confirmed channel other than the channel the flow subscribes
	 * to, so `name` does not select it. A recovery names one component in each of its phases, so `name` does not
	 * select there either. This method needs no access token and no fresh sign-in.
	 *
	 * @param options `name` selects which component to validate when the sign-up step is a choice. `locale` picks
	 * the language of the message. `state` is the opaque string the previous call returned.
	 * @throws InvalidStateError when the state does not decrypt, carries no expiry, or no longer matches the schema.
	 * @throws RateLimitedError when the `send` bucket of the subject is empty.
	 * @throws InvalidStateForFlowError when the flow has no validation to deliver.
	 * @throws ComponentNotInChoreographyError or UnknownComponentError when `name` is not the step the flow expects.
	 * @throws ComponentNotVerifiableError when the component offers no verification.
	 * @throws ComponentNotCollectedError when the flow has collected no value to validate yet.
	 * @throws ComponentNotSendableError when the verification delivers nothing over a channel.
	 * @throws NoVerificationChannelError when a subscribe has no other confirmed channel to deliver the code over.
	 * @throws RecoveryNotIdentifiedError when a recovery has not resolved its identity yet.
	 * @throws SessionNotFoundError or IdentityNotFoundError when the session or the identity the state names is gone.
	 * @throws UnknownChannelError when `options.channels` declares no channel the message names.
	 */
	sendValidation(options: { name: string; locale: string; state: string }): Promise<AuthDanceResponseResult> {
		return this.#guard("sendValidation", () => this.#sendValidation(options));
	}

	async #sendValidation(options: { name: string; locale: string; state: string }): Promise<AuthDanceResponseResult> {
		const { state } = await this.#decryptState(options.state);
		await this.#consumeRateLimit("send", this.#stateSubject(state));
		let authComponent: AuthDanceComponent | undefined;
		let ctx: AuthDanceComponentContext | undefined;
		if (state.kind === "sign-up") {
			const { ctx: c, verificationAuthDanceComponent: ac } = await this.#resolveVerification(state, options.name);
			authComponent = ac;
			ctx = c;
		} else if (state.kind === "enroll") {
			const { ctx: c, verificationAuthDanceComponent: ac } = await this.#resolveEnrollVerification(state);
			authComponent = ac;
			ctx = c;
		} else if (state.kind === "rotate") {
			// Serves both phases: before the replacement is collected the context still resolves to the
			// enrolled value (proving control), afterwards it resolves to the replacement (validating it).
			const { ctx: c, verificationAuthDanceComponent: ac } = await this.#resolveRotateVerification(state);
			authComponent = ac;
			ctx = c;
		} else if (state.kind === "recover") {
			// Serves both phases too: proving control of the component the caller picked to identify with, then
			// validating the replacement collected for the recovered component.
			const identity = await this.#recoverIdentity(state);
			const { ctx: c, verificationAuthDanceComponent: ac } = state.verified
				? await this.#resolveRecoverResetVerification(state, identity)
				: await this.#resolveRecoverControl(state, identity);
			authComponent = ac;
			ctx = c;
		} else if (state.kind === "subscribe") {
			const { identity } = await this.#sessionIdentity(state.sessionId);
			authComponent = new OtpAuthDanceComponent({ channel: this.#subscribeSendChannel(identity, state.channel.component).component });
			ctx = this.#subscribeContext(state, identity);
		} else {
			throw new InvalidStateForFlowError(state.kind);
		}
		if (!authComponent || !authComponent.sendPrompt || !ctx) {
			throw new ComponentNotSendableError(options.name);
		}
		const message = await authComponent.sendPrompt(options.locale, ctx);
		if (!message) {
			throw new ComponentNotSendableError(options.name);
		}
		await this.#sendMessage(message);
		return { success: true };
	}

	/**
	 * Answers the validation prompt and proves control of the value the flow collected.
	 *
	 * On success the value becomes confirmed and the dance continues. A rotate and a recover use this method
	 * twice. The first answer proves control of the current value, and the library replies with the prompt that
	 * collects the replacement. The second answer validates that replacement.
	 *
	 * A sign-up that completes here mints the tokens, exactly as `submitPrompt` does. A management flow and a
	 * recovery complete with a plain success result. Either way the completed flow reports itself to
	 * `options.hooks`, the same way `submitPrompt` does.
	 *
	 * The library checks the elevated window when a flow starts, so this method does not check it again. It needs no
	 * access token either, because the state carries the session the flow started from.
	 *
	 * @param options `name` selects which component to validate when the step is a choice. `value` is the proof the
	 * client collected. `state` is the opaque string the previous call returned. The library stores `address` and
	 * `userAgent` on the session a completed sign-up mints.
	 * @returns The next state and prompt. A completed sign-up returns the tokens instead. A completed management
	 * flow or recovery returns a plain success result.
	 * @throws InvalidStateError when the state does not decrypt, carries no expiry, or no longer matches the schema.
	 * @throws RateLimitedError when the `verify` bucket of the subject is empty.
	 * @throws InvalidStateForFlowError when the flow has no validation to answer.
	 * @throws InvalidValidationValueError when the verification rejects the value.
	 * @throws ComponentNotInChoreographyError or UnknownComponentError when `name` is not the step the flow expects.
	 * @throws ComponentNotVerifiableError when the component offers no verification.
	 * @throws ComponentNotCollectedError when the flow has collected no value to validate yet.
	 * @throws NoVerificationChannelError when a subscribe has no other confirmed channel to check the code against.
	 * @throws RecoveryNotIdentifiedError when a recovery has not resolved its identity yet.
	 * @throws SessionNotFoundError or IdentityNotFoundError when the session or the identity the state names is gone.
	 */
	submitValidation(
		options: { name: string; value: unknown; state: string; address?: string; userAgent?: string },
	): Promise<AuthDanceResponse> {
		return this.#guard("submitValidation", () => this.#submitValidation(options));
	}

	async #submitValidation(
		options: { name: string; value: unknown; state: string; address?: string; userAgent?: string },
	): Promise<AuthDanceResponse> {
		const { state, expireAt } = await this.#decryptState(options.state);
		await this.#consumeRateLimit("verify", this.#stateSubject(state));
		let advanceOptions = {
			state,
			path: [] as string[],
			identity: void 0 as unknown as AuthDanceIdentity,
			expireAt,
			flow: "",
			name: undefined as string | undefined,
			persist: undefined as boolean | undefined,
			address: options.address,
			userAgent: options.userAgent,
		};
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
				// Control established, now collect the replacement value.
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
				// Control established, now collect the replacement of the recovered component — the same second
				// phase a rotation reaches once the current value is proven.
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
			const { identity } = await this.#sessionIdentity(state.sessionId);
			const sendChannel = this.#subscribeSendChannel(identity, state.channel.component);
			const verified = await new OtpAuthDanceComponent({ channel: sendChannel.component }).verifyPrompt(
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
			throw new InvalidStateForFlowError(state.kind);
		}
		return this.#advance(advanceOptions);
	}
}

/**
 * Builds an `AuthDanceApi` from a policy.
 *
 * `createAuthDance` calls this with its own `api` option group and returns the result as `api`. Call it directly
 * when you want the state machine without the HTTP layer around it.
 */
export function createAuthDanceApi(options: AuthDanceApiOptions): AuthDanceApi {
	return new AuthDanceApi(options);
}
