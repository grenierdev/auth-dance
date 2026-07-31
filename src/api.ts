import { ksuid } from "./id.ts";
import type { AuthChannel } from "./channel.ts";
import OtpAuthComponent from "./components/otp.ts";
import { type AuthChoreography, type AuthChoreographyChoice, type AuthChoreographyComponent, peek, walk } from "./choreography.ts";
import type { AuthComponent, AuthComponentContext } from "./component.ts";
import type { Identity, IdentityChallenge, IdentityChannel, IdentityComponent, IdentityIdentification } from "./identity.ts";
import type { AuthMessage } from "./message.ts";
import {
	AuthState,
	type AuthStateDelete,
	type AuthStateEnroll,
	type AuthStateRecover,
	type AuthStateRotate,
	type AuthStateSignIn,
	type AuthStateSignUp,
	type AuthStateSubscribe,
	type AuthStateUnenroll,
	type AuthStateUnsubscribe,
} from "./state.ts";
import type { AuthPrompt } from "./prompt.ts";
import { decode } from "jose/base64url";
import { EncryptJWT } from "jose/jwt/encrypt";
import { jwtDecrypt } from "jose/jwt/decrypt";
import { SignJWT } from "jose/jwt/sign";
import { jwtVerify } from "jose/jwt/verify";
import { parse } from "valibot";
import type { AuthResponse, AuthResponseResult, AuthResponseState, AuthResponseTokens } from "./response.ts";
import type { AuthSession } from "./session.ts";
import type { AuthStorage } from "./storage.ts";
import {
	AuthError,
	AuthUnknownError,
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

/** A single fixed-window bucket: `limit` calls per `window`, the window expressed in seconds like every other duration here. */
export interface AuthRateLimit {
	limit: number;
	window: number;
}

/**
 * The buckets `AuthApi` consumes, keyed on the identity or session a call is attributable to. They guard
 * one identity against being hammered — brute-forcing its password, draining its OTP quota — so they are
 * deliberately tight; a caller spreading the same abuse over many identities is what the per-address
 * buckets at the edge are for.
 */
export interface AuthIdentityRateLimits {
	/** Answering a prompt or a validation, i.e. every attempt at proving something. */
	verify?: AuthRateLimit;
	/** Delivering a prompt or a validation over a channel — the buckets that cost real money. */
	send?: AuthRateLimit;
	/** Starting a management flow (enroll, rotate, subscribe, …) or signing out. */
	manage?: AuthRateLimit;
	/** Exchanging a refresh token. Legitimate clients do this often, so it is the loosest of the four. */
	refresh?: AuthRateLimit;
}

/**
 * The buckets the Hono edge consumes, keyed on the caller's address. They guard against distributed
 * abuse — many identities probed from one place — and are generous on purpose: a whole NATed campus
 * shares one address, so a limit tuned for a single client would lock out everybody behind it.
 */
export interface AuthAddressRateLimits {
	/** Every request, whatever it is.  */
	request?: AuthRateLimit;
	/** The two routes that put a message on a channel, on top of the `request` bucket. */
	send?: AuthRateLimit;
}

export interface AuthApiOptions {
	channels: Record<string, AuthChannel>;
	choreography: AuthChoreography;
	components: Record<string, AuthComponent>;
	secret: string;
	storage: AuthStorage;
	advanced?: {
		// How long an in-progress flow's state stays valid, in seconds — one key per flow, each defaulting to
		// 5 minutes. Recovering an account may reasonably be given more room than signing in, and a
		// confirmation-only flow such as unenroll less.
		sign_in_duration?: number;
		sign_up_duration?: number;
		enroll_duration?: number;
		unenroll_duration?: number;
		rotate_duration?: number;
		recover_duration?: number;
		subscribe_duration?: number;
		unsubscribe_duration?: number;
		delete_duration?: number;
		access_duration?: number;
		refresh_duration?: number;
		/** How long after signing in a session may still perform sensitive actions (enroll, rotate, …), in seconds. */
		elevated_duration?: number;
		/** Per-identity buckets, each defaulting to `IdentityRateLimits`. */
		identity_rate_limit?: AuthIdentityRateLimits;
		/** Per-address buckets, each defaulting to `AddressRateLimits`. Consumed at the edge, not here — `choreoAuth` forwards them to the app's bindings. */
		address_rate_limit?: AuthAddressRateLimits;
		issuer?: string;
	};
}

/** Tight, because they apply to one identity at a time. */
export const IdentityRateLimits: Required<AuthIdentityRateLimits> = {
	verify: { limit: 10, window: 5 * 60 },
	send: { limit: 5, window: 5 * 60 },
	manage: { limit: 20, window: 5 * 60 },
	refresh: { limit: 60, window: 5 * 60 },
};

export class AuthApi {
	#options: AuthApiOptions;
	#decodedSecret: Uint8Array;

	constructor(options: AuthApiOptions) {
		this.#options = options;
		this.#decodedSecret = decode(this.#options.secret);
	}

	get storage(): AuthStorage {
		return this.#options.storage;
	}

	// The single boundary between "this failed in a way the caller was told about" and "this should never
	// have happened". Internals — including every private helper below — signal failure by throwing an
	// AuthError, which passes through untouched. Anything else (jose, valibot, a storage provider, a bug)
	// is wrapped in AuthUnknownError, so an unhandled case can never masquerade as a business rule.
	async #guard<T>(method: string, fn: () => Promise<T>): Promise<T> {
		try {
			return await fn();
		} catch (cause) {
			if (cause instanceof AuthError) {
				throw cause;
			}
			throw new AuthUnknownError(`${method} failed`, { cause });
		}
	}

	#sendMessage(message: AuthMessage): Promise<void> {
		const ch = this.#options.channels[message.recipient.channel];
		if (!ch) {
			throw new UnknownChannelError(message.recipient.channel);
		}
		return ch.sendMessage(message);
	}

	sendMessageTo(
		identityId: string,
		channel: string,
		message: Omit<AuthMessage, "recipient">,
	): Promise<AuthResponseResult> {
		return this.#guard("sendMessageTo", async () => {
			const identity = await this.#options.storage.getIdentity(identityId);
			if (!identity) {
				throw new IdentityNotFoundError(identityId);
			}
			const identityChannel = identity.components
				.find((c): c is IdentityChannel => c.kind === "channel" && c.channel === channel);
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

	sendMessage(message: AuthMessage): Promise<AuthResponseResult> {
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
		options: { identity: Identity; scopes: string[]; session: AuthSession; authTime?: number },
	): Promise<AuthResponseTokens> {
		const authTime = options.authTime ?? Math.floor(Date.now() / 1000);

		const access_token = await new SignJWT({ auth_time: authTime })
			.setProtectedHeader({ alg: "HS256" })
			.setIssuer(this.#options.advanced?.issuer ?? "acme")
			.setIssuedAt()
			.setExpirationTime(new Date(Date.now() + (this.#options.advanced?.access_duration ?? 5 * 60) * 1000))
			.setSubject(options.session.id)
			.setJti(ksuid())
			.sign(this.#decodedSecret);

		const refresh_token = await new SignJWT({ auth_time: authTime })
			.setProtectedHeader({ alg: "HS256", scopes: options.scopes })
			.setIssuer(this.#options.advanced?.issuer ?? "acme")
			.setIssuedAt()
			.setExpirationTime(new Date(Date.now() + (this.#options.advanced?.refresh_duration ?? 24 * 60 * 60) * 1000))
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
			.setIssuer(this.#options.advanced?.issuer ?? "acme")
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
	async #verifiedClaims(token: string, invalid: () => AuthError): Promise<{ sub: string; authTime: number }> {
		const payload = await jwtVerify(token, this.#decodedSecret, {
			issuer: this.#options.advanced?.issuer ?? "acme",
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
		const elevated = (this.#options.advanced?.elevated_duration ?? 5 * 60) * 1000;
		if (Date.now() - authTime * 1000 > elevated) {
			throw new FreshSignInRequiredError();
		}
	}

	// Buckets are keyed on the subject a call is attributable to, never on the request: the session behind
	// an access token, or the identity a flow's state has already resolved. A call attributable to neither
	// — signing in before the identification has been answered, starting a sign-up or a recovery — is left
	// to the per-address buckets at the edge, the only layer that can bucket it at all.
	async #consumeRateLimit(bucket: keyof AuthIdentityRateLimits, subject: string | undefined): Promise<void> {
		if (!subject) {
			return;
		}
		const { limit, window } = this.#options.advanced?.identity_rate_limit?.[bucket] ?? IdentityRateLimits[bucket];
		const { allowed, retryAfter } = await this.#options.storage.consumeRateLimit(`${bucket}:${subject}`, limit, window * 1000);
		if (!allowed) {
			throw new RateLimitedError(retryAfter);
		}
	}

	// Which subject a state is attributable to. Sign-up is the one flow with none: it mints its own identity
	// id and a caller can always start another, so there is nothing durable to bucket on.
	#stateSubject(state: AuthState): string | undefined {
		if (state.kind === "sign-in" || state.kind === "recover") {
			return state.identityId && `identity:${state.identityId}`;
		}
		if (state.kind === "sign-up") {
			return undefined;
		}
		return `session:${state.sessionId}`;
	}

	refreshToken(refresh_token: string): Promise<AuthResponseTokens> {
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
			return this.#generateTokens({ identity, scopes: session.scopes, session, authTime });
		});
	}

	signOut(access_token: string, others: boolean = false): Promise<AuthResponseResult> {
		return this.#guard("signOut", async () => {
			const { session } = await this.accessTokenIdentity(access_token);
			await this.#consumeRateLimit("manage", `session:${session.id}`);
			if (!others) {
				await this.#options.storage.deleteSession(session.id);
			} else {
				const sessions = await this.#options.storage.listSession(session.identityId);
				await Promise.all(sessions.map((s) => this.#options.storage.deleteSession(s.id)));
			}
			return { success: true };
		});
	}

	async #getPromptFromChoreography(options: {
		choreography: AuthChoreographyComponent | AuthChoreographyChoice<AuthChoreographyComponent>;
		stateId: string;
		flow: string;
		identity: Identity | undefined;
	}): Promise<AuthPrompt> {
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
		state: AuthState,
		nextMove: AuthChoreographyComponent | AuthChoreographyChoice<AuthChoreographyComponent>,
		expireAt: Date,
		flow: string,
	): Promise<AuthResponseState> {
		const prompt = await this.#getPromptFromChoreography({
			choreography: nextMove,
			stateId: state.id,
			flow,
			identity: undefined,
		});
		return { state: await this.#encryptState(state, expireAt), prompt, expireAt };
	}

	async #issueTokens(identity: Identity, options: { expireAt: Date; address?: string; userAgent?: string }): Promise<AuthResponseTokens> {
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
		state: AuthState;
		path: string[];
		identity: Identity;
		expireAt: Date;
		flow: string;
		persist?: boolean;
		address?: string;
		userAgent?: string;
	}): Promise<AuthResponse> {
		// Only the authentication flows mint tokens; management flows (subscribe, …) have no further steps
		// and complete with a plain success result. Recovery is in between: it walks the choreography like an
		// authentication flow — resetting whatever it still requires after the recovered component — but
		// proving control of a single component is not a sign-in, so it completes without tokens.
		const authFlow = options.flow === "sign-in" || options.flow === "sign-up";
		const nextMove = authFlow || options.flow === "recover" ? peek(this.#options.choreography, options.path) : null;
		if (nextMove === null) {
			if (options.persist) {
				await this.#options.storage.setIdentity(options.identity);
			}
			if (authFlow) {
				return this.#issueTokens(options.identity, options);
			}
			return { success: true };
		}
		return this.#promptResponse(options.state, nextMove, options.expireAt, options.flow);
	}

	#resolveStep(
		path: string[],
		componentName?: string,
	): { choreographyComponent: AuthChoreographyComponent; authComponent: AuthComponent } {
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

	#signUpPath(state: AuthStateSignUp): string[] {
		return state.components
			.filter((c): c is IdentityIdentification | IdentityChallenge => c.confirmed && c.kind !== "channel")
			.map((c) => c.component);
	}

	#signInContext(state: AuthStateSignIn, component: string, identity: Identity | undefined): AuthComponentContext {
		return {
			storage: this.#options.storage,
			name: component,
			stateId: state.id,
			flow: "sign-in",
			identity,
		};
	}

	#signUpContext(state: AuthStateSignUp, component: string): AuthComponentContext {
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

	async #sessionIdentity(sessionId: string): Promise<{ session: AuthSession; identity: Identity }> {
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
	 * Resolves the session and identity an access token was minted for, along with its `auth_time`.
	 *
	 * Management flows (enroll, subscribe, …) are performed by an already authenticated caller: they start
	 * from the access token instead of stepping through the choreography. Public because the read-only
	 * routes — listing sessions, listing components — are nothing but this call followed by a storage read,
	 * and wrapping each of them in a method here would add a layer that decides nothing.
	 */
	async accessTokenIdentity(access_token: string): Promise<{ session: AuthSession; identity: Identity; authTime: number }> {
		const { sub, authTime } = await this.#verifiedClaims(access_token, () => new InvalidAccessTokenError());
		return { ...await this.#sessionIdentity(sub), authTime };
	}

	// Confirming a new channel is authorised through an already-trusted channel: pick the first
	// confirmed channel that is not the one being subscribed to (e.g. send the OTP to email while
	// subscribing SMS).
	#subscribeSendChannel(identity: Identity, subscribing: string): IdentityChannel {
		const channel = identity.components
			.find((c): c is IdentityChannel => c.kind === "channel" && c.confirmed && c.channel !== subscribing);
		if (!channel) {
			throw new NoVerificationChannelError(subscribing);
		}
		return channel;
	}

	#subscribeContext(state: AuthStateSubscribe, identity: Identity): AuthComponentContext {
		return {
			storage: this.#options.storage,
			name: state.channel.channel,
			stateId: state.id,
			flow: "subscribe",
			identity,
		};
	}

	// Like #signUpContext, the component sees the components collected during this enrollment first,
	// so its verification targets the value being enrolled (e.g. the OTP goes to the new email
	// address) while the identity's existing components stay available as a fallback.
	#enrollContext(state: AuthStateEnroll, identity: Identity): AuthComponentContext {
		return {
			storage: this.#options.storage,
			name: state.component,
			stateId: state.id,
			flow: "enroll",
			identity: { ...identity, components: [...state.components, ...identity.components] },
		};
	}

	async #resolveEnrollVerification(state: AuthStateEnroll): Promise<{
		identity: Identity;
		identityComponent: IdentityIdentification | IdentityChallenge;
		ctx: AuthComponentContext;
		verificationAuthComponent: AuthComponent;
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
		const verificationAuthComponent = await authComponent.verificationComponent(ctx);
		return { identity, identityComponent, ctx, verificationAuthComponent };
	}

	// The component being enrolled, rotated or reset is the identification/challenge it produced; any channel
	// it also yielded (e.g. the email address it can be reached at) rides along but is not the subject.
	#collectedIdentityComponent(components: IdentityComponent[], component: string): IdentityIdentification | IdentityChallenge {
		const identityComponent = components.find((c): c is IdentityIdentification | IdentityChallenge =>
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
	#rotateContext(state: AuthStateRotate, identity: Identity): AuthComponentContext {
		return {
			storage: this.#options.storage,
			name: state.component,
			stateId: state.id,
			flow: "rotate",
			identity: { ...identity, components: [...state.components, ...identity.components] },
		};
	}

	async #resolveRotateVerification(state: AuthStateRotate): Promise<{
		identity: Identity;
		ctx: AuthComponentContext;
		authComponent: AuthComponent;
		verificationAuthComponent: AuthComponent;
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
		const verificationAuthComponent = await authComponent.verificationComponent(ctx);
		return { identity, ctx, authComponent, verificationAuthComponent };
	}

	// Rotation and recovery both swap components in place: the previously enrolled identification/challenge
	// is dropped in favour of the freshly validated one carrying the same name. Channels are keyed by name,
	// so a channel a component re-emits ("email" now pointing at the new address) supersedes the previous
	// entry instead of duplicating it — while keeping the links other components hold on that channel.
	// Replacing by name makes this idempotent, so a flow that collects several components can re-apply the
	// whole set on every step.
	#applyReplacement(identity: Identity, components: IdentityComponent[]): void {
		const replaced = new Set(components.filter((c) => c.kind !== "channel").map((c) => c.component));
		identity.components = identity.components.filter((previous) => {
			if (previous.kind !== "channel") {
				return !replaced.has(previous.component);
			}
			const replacement = components
				.find((c): c is IdentityChannel => c.kind === "channel" && c.channel === previous.channel);
			if (!replacement) {
				return true;
			}
			replacement.linkedTo = [...new Set([...(previous.linkedTo ?? []), ...(replacement.linkedTo ?? [])])];
			return false;
		});
		identity.components.push(...components);
	}

	// The recovery component is the step control has been proven for, so it opens the path; every component
	// reset since then follows it, exactly like #signUpPath tracks what sign-up has collected so far.
	#recoverPath(state: AuthStateRecover): string[] {
		return [
			state.component,
			...state.components
				.filter((c): c is IdentityIdentification | IdentityChallenge => c.confirmed && c.kind !== "channel")
				.map((c) => c.component),
		];
	}

	// Same layering as #rotateContext: a replacement collected during the reset shadows the value it replaces,
	// so its verification targets the new one. While control of the recovery component is still being proven
	// nothing has been collected and the identity is seen as it stands — which is what proving control needs.
	// The identity itself is unknown until the identification has been submitted.
	#recoverContext(state: AuthStateRecover, component: string, identity: Identity | undefined): AuthComponentContext {
		return {
			storage: this.#options.storage,
			name: component,
			stateId: state.id,
			flow: "recover",
			identity: identity && { ...identity, components: [...state.components, ...identity.components] },
		};
	}

	async #recoverIdentity(state: AuthStateRecover): Promise<Identity> {
		if (!state.identityId) {
			throw new RecoveryNotIdentifiedError(state.component);
		}
		const identity = await this.#options.storage.getIdentity(state.identityId);
		if (!identity) {
			throw new IdentityNotFoundError(state.identityId);
		}
		return identity;
	}

	// First phase: prove control of the component the recovery started from.
	async #resolveRecoverControl(state: AuthStateRecover, identity: Identity): Promise<{
		ctx: AuthComponentContext;
		verificationAuthComponent: AuthComponent;
	}> {
		const authComponent = this.#options.components[state.component];
		if (!authComponent) {
			throw new UnknownComponentError(state.component);
		}
		if (!authComponent.verificationComponent) {
			throw new ComponentNotVerifiableError(state.component);
		}
		const ctx = this.#recoverContext(state, state.component, identity);
		return { ctx, verificationAuthComponent: await authComponent.verificationComponent(ctx) };
	}

	// Second phase: validate the replacement collected for the component currently being reset.
	async #resolveRecoverReset(state: AuthStateRecover, identity: Identity, componentName?: string): Promise<{
		path: string[];
		choreographyComponent: AuthChoreographyComponent;
		identityComponent: IdentityIdentification | IdentityChallenge;
		ctx: AuthComponentContext;
		verificationAuthComponent: AuthComponent;
	}> {
		const path = this.#recoverPath(state);
		const { choreographyComponent, authComponent } = this.#resolveStep(path, componentName);
		if (!authComponent.verificationComponent) {
			throw new ComponentNotVerifiableError(choreographyComponent.component);
		}
		const identityComponent = this.#collectedIdentityComponent(state.components, choreographyComponent.component);
		const ctx = this.#recoverContext(state, choreographyComponent.component, identity);
		return {
			path,
			choreographyComponent,
			identityComponent,
			ctx,
			verificationAuthComponent: await authComponent.verificationComponent(ctx),
		};
	}

	// The reset walks the choreography from the recovered component, so that component has to be a step the
	// choreography can actually start with — otherwise there is no continuation to reset.
	#isChoreographyFirstMove(component: string): boolean {
		const firstMove = peek(this.#options.choreography, []);
		if (firstMove === null) {
			return false;
		}
		return firstMove.kind === "component" ? firstMove.component === component : firstMove.components.some((c) => c.component === component);
	}

	// Unenrolling must not lock the identity out of its own account: walk the choreography and keep the
	// component only if at least one path to an end is still fully covered by the surviving confirmed
	// components. With choice(sequence("email", "password"), "facebook"), dropping "facebook" is fine
	// because the email + password path survives; dropping "password" would not be.
	#isChoreographyCompletableWithout(identity: Identity, component: string): boolean {
		const surviving = identity.components
			.filter((c): c is IdentityIdentification | IdentityChallenge => c.kind !== "channel" && c.confirmed && c.component !== component)
			.map((c) => c.component);
		for (const { component: nextMove, path } of walk(this.#options.choreography)) {
			if (nextMove === null && path.every((p) => surviving.includes(p.component))) {
				return true;
			}
		}
		return false;
	}

	async #resolveVerification(state: AuthStateSignUp, componentName?: string): Promise<{
		path: string[];
		choreographyComponent: AuthChoreographyComponent;
		identityComponent: IdentityComponent;
		ctx: AuthComponentContext;
		verificationAuthComponent: AuthComponent;
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
		const verificationAuthComponent = await authComponent.verificationComponent(ctx);
		return { path, choreographyComponent, identityComponent, ctx, verificationAuthComponent };
	}

	#encryptState(state: AuthState, expireAt: Date): Promise<string> {
		const jwt = new EncryptJWT({ state })
			.setProtectedHeader({ alg: "dir", enc: "A256GCM", issuer: this.#options.advanced?.issuer })
			.setIssuedAt()
			.setExpirationTime(expireAt)
			.encrypt(this.#decodedSecret);
		return jwt;
	}

	// A state that fails to decrypt, carries no expiry, or no longer matches the schema is a stale or forged
	// value coming from the client — expected input, not a server fault. jose and valibot both fail by
	// throwing, so they are converted here rather than escaping as unknown.
	async #decryptState(value: string): Promise<{ state: AuthState; expireAt: Date }> {
		const payload = await jwtDecrypt(value, this.#decodedSecret, { issuer: this.#options.advanced?.issuer })
			.then(({ payload }) => payload, () => undefined);
		if (!payload?.exp) {
			throw new InvalidStateError();
		}
		try {
			return { state: parse(AuthState, payload.state), expireAt: new Date(payload.exp * 1000) };
		} catch (cause) {
			throw new InvalidStateError("state payload does not match the schema", { cause });
		}
	}

	signIn(): Promise<AuthResponseState> {
		return this.#guard("signIn", () => {
			const expireAt = this.#expireAt(this.#options.advanced?.sign_in_duration);
			const state: AuthStateSignIn = {
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

	signUp(): Promise<AuthResponseState> {
		return this.#guard("signUp", () => {
			const expireAt = this.#expireAt(this.#options.advanced?.sign_up_duration);
			const state: AuthStateSignUp = {
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

	enroll(options: { name: string; access_token: string }): Promise<AuthResponseState> {
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
			const expireAt = this.#expireAt(this.#options.advanced?.enroll_duration);
			const state: AuthStateEnroll = {
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

	unenroll(options: { name: string; access_token: string }): Promise<AuthResponseState> {
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
			if (!this.#isChoreographyCompletableWithout(identity, options.name)) {
				throw new WouldLockOutError(options.name);
			}
			const expireAt = this.#expireAt(this.#options.advanced?.unenroll_duration);
			const state: AuthStateUnenroll = {
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

	rotate(options: { name: string; access_token: string }): Promise<AuthResponseState> {
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
			const expireAt = this.#expireAt(this.#options.advanced?.rotate_duration);
			const state: AuthStateRotate = {
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

	// Recovery is a special case of the choreography: the caller proves control of one of the components the
	// choreography can start with, then resets whatever it still requires after that component — precisely the
	// components the caller could not provide. It is the only flow open to a caller with no session at all,
	// which is why the component it starts from has to do both jobs on its own: resolve an identity (an
	// identification) and prove control of it (a verification).
	recover(options: { name: string }): Promise<AuthResponseState> {
		return this.#guard("recover", async () => {
			const authComponent = this.#options.components[options.name];
			if (!authComponent) {
				throw new UnknownComponentError(options.name);
			}
			if (authComponent.kind !== "identification" || !authComponent.verifiable || !this.#isChoreographyFirstMove(options.name)) {
				throw new ComponentNotRecoverableError(options.name);
			}
			const expireAt = this.#expireAt(this.#options.advanced?.recover_duration);
			const state: AuthStateRecover = {
				id: ksuid("st_"),
				kind: "recover",
				component: options.name,
				verified: false,
				components: [],
			};
			// Which identity is being recovered is unknown until the identification is submitted, so the first
			// prompt is the component's own and nothing about the identity is disclosed.
			const prompt = await authComponent.getPrompt(this.#recoverContext(state, options.name, undefined));
			return { state: await this.#encryptState(state, expireAt), prompt, expireAt };
		});
	}

	subscribe(options: { name: string; access_token: string }): Promise<AuthResponseState> {
		return this.#guard("subscribe", async () => {
			const { session, identity, authTime } = await this.accessTokenIdentity(options.access_token);
			await this.#consumeRateLimit("manage", `session:${session.id}`);
			if (identity.components.some((c) => c.kind === "channel" && c.channel === options.name)) {
				throw new ChannelAlreadySubscribedError(options.name);
			}
			const channel = this.#options.channels[options.name];
			if (!channel) {
				throw new UnknownChannelError(options.name);
			}
			this.#requireFreshSignIn(authTime);
			const expireAt = this.#expireAt(this.#options.advanced?.subscribe_duration);
			const state: AuthStateSubscribe = {
				id: ksuid("st_"),
				kind: "subscribe",
				sessionId: session.id,
				channel: { kind: "channel", channel: options.name, confirmed: false, data: {} },
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

	unsubscribe(options: { name: string; access_token: string }): Promise<AuthResponseState> {
		return this.#guard("unsubscribe", async () => {
			const { session, identity, authTime } = await this.accessTokenIdentity(options.access_token);
			await this.#consumeRateLimit("manage", `session:${session.id}`);
			const channel = identity.components.find((c): c is IdentityChannel => c.kind === "channel" && c.channel === options.name);
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
			const expireAt = this.#expireAt(this.#options.advanced?.unsubscribe_duration);
			const state: AuthStateUnsubscribe = {
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

	// Deleting the identity is the one management flow with nothing left to protect afterwards, so it is
	// gated exactly like the other destructive ones — a recent sign-in, then an explicit confirmation — and
	// nothing more: there is no component to keep the choreography completable with, and no lock-out to
	// avoid, since locking the identity out of itself is precisely what the caller asked for.
	delete(options: { access_token: string }): Promise<AuthResponseState> {
		return this.#guard("delete", async () => {
			const { session, authTime } = await this.accessTokenIdentity(options.access_token);
			await this.#consumeRateLimit("manage", `session:${session.id}`);
			this.#requireFreshSignIn(authTime);
			const expireAt = this.#expireAt(this.#options.advanced?.delete_duration);
			const state: AuthStateDelete = {
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

	sendPrompt(options: { name: string; locale: string; state: string }): Promise<AuthResponseResult> {
		return this.#guard("sendPrompt", async () => {
			const { state } = await this.#decryptState(options.state);
			await this.#consumeRateLimit("send", this.#stateSubject(state));
			let authComponent: AuthComponent | undefined;
			let ctx: AuthComponentContext | undefined;
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

	submitPrompt(
		options: { name: string; value: unknown; state: string; address?: string; userAgent?: string },
	): Promise<AuthResponse> {
		return this.#guard("submitPrompt", () => this.#submitPrompt(options));
	}

	// The three long flows below stay in private methods rather than inside the #guard closure: the error
	// boundary reads as one line, and the body keeps signalling failure exactly the way every private helper
	// does — by throwing — instead of being re-indented into a callback.
	async #submitPrompt(
		options: { name: string; value: unknown; state: string; address?: string; userAgent?: string },
	): Promise<AuthResponse> {
		const { state, expireAt } = await this.#decryptState(options.state);
		// Before the value is looked at, so a wrong password costs a bucket slot rather than being free. In a
		// sign-in the subject is whatever an earlier step resolved, which is exactly the step that matters:
		// guessing a password happens once the identification is behind us.
		await this.#consumeRateLimit("verify", this.#stateSubject(state));
		let advanceOptions = {
			state,
			path: [] as string[],
			identity: void 0 as unknown as Identity,
			expireAt,
			flow: "",
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
				...await authComponent.getIdentityComponent(choreographyComponent.component, options.value, false),
			);
			const identityComponent = state.components.find((c): c is IdentityIdentification | IdentityChallenge =>
				c.kind !== "channel" && c.component === choreographyComponent.component
			);
			if (!identityComponent) {
				throw new ComponentNotCollectedError(choreographyComponent.component);
			}
			if (!identityComponent.confirmed && authComponent.verificationComponent) {
				const verificationAuthComponent = await authComponent.verificationComponent(ctx);
				const nextPrompt = await verificationAuthComponent?.getPrompt(ctx);
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
			state.components.push(...await authComponent.getIdentityComponent(state.component, options.value, false));
			const identityComponent = this.#collectedIdentityComponent(state.components, state.component);
			if (!identityComponent.confirmed && authComponent.verificationComponent) {
				const ctx = this.#enrollContext(state, identity);
				const verificationAuthComponent = await authComponent.verificationComponent(ctx);
				const nextPrompt = await verificationAuthComponent.getPrompt(ctx);
				return { state: await this.#encryptState(state, expireAt), prompt: nextPrompt, expireAt };
			}
			identityComponent.confirmed = true;
			identity.components.push(...state.components);
			advanceOptions = {
				...advanceOptions,
				identity,
				flow: "enroll",
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
			state.components.push(...await authComponent.getIdentityComponent(state.component, options.value, false));
			const identityComponent = this.#collectedIdentityComponent(state.components, state.component);
			if (!identityComponent.confirmed && authComponent.verificationComponent) {
				const ctx = this.#rotateContext(state, identity);
				const verificationAuthComponent = await authComponent.verificationComponent(ctx);
				const nextPrompt = await verificationAuthComponent.getPrompt(ctx);
				return { state: await this.#encryptState(state, expireAt), prompt: nextPrompt, expireAt };
			}
			identityComponent.confirmed = true;
			this.#applyReplacement(identity, state.components);
			advanceOptions = {
				...advanceOptions,
				identity,
				flow: "rotate",
				persist: true,
			};
		} else if (state.kind === "recover") {
			if (!state.identityId) {
				// Which identity is being recovered is established here and only here: the component resolves the
				// submitted value to an identity, then its verification takes over to prove control of it.
				const authComponent = this.#options.components[state.component];
				if (!authComponent) {
					throw new UnknownComponentError(state.component);
				}
				if (!authComponent.verificationComponent) {
					throw new ComponentNotVerifiableError(state.component);
				}
				const ctx = this.#recoverContext(state, state.component, undefined);
				const identityId = await authComponent.verifyPrompt(options.value, ctx);
				if (typeof identityId !== "string") {
					throw new IdentityNotResolvedError(state.component);
				}
				state.identityId = identityId;
				const control = await this.#resolveRecoverControl(state, await this.#recoverIdentity(state));
				return {
					state: await this.#encryptState(state, expireAt),
					prompt: await control.verificationAuthComponent.getPrompt(control.ctx),
					expireAt,
				};
			}
			// Nothing is reset before control of the recovery component has been proven, which is what
			// sendValidation/submitValidation did with the prompt handed out above.
			if (!state.verified) {
				throw new ControlNotProvenError(state.component);
			}
			const identity = await this.#recoverIdentity(state);
			const path = this.#recoverPath(state);
			const { choreographyComponent, authComponent } = this.#resolveStep(path, options.name);
			// Each component the reset walks through is collected exactly once.
			if (state.components.some((c) => c.kind !== "channel" && c.component === choreographyComponent.component)) {
				throw new ComponentAlreadyCollectedError(choreographyComponent.component);
			}
			state.components.push(...await authComponent.getIdentityComponent(choreographyComponent.component, options.value, false));
			const identityComponent = this.#collectedIdentityComponent(state.components, choreographyComponent.component);
			if (!identityComponent.confirmed && authComponent.verificationComponent) {
				const ctx = this.#recoverContext(state, choreographyComponent.component, identity);
				const verificationAuthComponent = await authComponent.verificationComponent(ctx);
				return { state: await this.#encryptState(state, expireAt), prompt: await verificationAuthComponent.getPrompt(ctx), expireAt };
			}
			identityComponent.confirmed = true;
			this.#applyReplacement(identity, state.components);
			advanceOptions = {
				...advanceOptions,
				identity,
				flow: "recover",
				path: [...path, choreographyComponent.component],
				persist: true,
			};
		} else if (state.kind === "unenroll") {
			if (options.value !== true) {
				throw new ConfirmationRequiredError(state.component);
			}
			const { identity } = await this.#sessionIdentity(state.sessionId);
			if (!this.#isChoreographyCompletableWithout(identity, state.component)) {
				throw new WouldLockOutError(state.component);
			}
			identity.components = identity.components.filter((c) => c.kind === "channel" || c.component !== state.component);
			advanceOptions = {
				...advanceOptions,
				identity,
				flow: "unenroll",
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
			state.channel.data = { ...(state.channel.data ?? {}), [state.channel.channel]: options.value };
			state.validating = true;
			const sendChannel = this.#subscribeSendChannel(identity, state.channel.channel);
			const prompt = await new OtpAuthComponent(sendChannel.channel).getPrompt(this.#subscribeContext(state, identity));
			return { state: await this.#encryptState(state, expireAt), prompt, expireAt };
		} else if (state.kind === "unsubscribe") {
			// A single confirmation gate: the authenticated caller must explicitly confirm (value === true)
			// before the channel is detached.
			if (options.value !== true) {
				throw new ConfirmationRequiredError(state.channel);
			}
			const { identity } = await this.#sessionIdentity(state.sessionId);
			identity.components = identity.components.filter((c) => !(c.kind === "channel" && c.channel === state.channel));
			advanceOptions = {
				...advanceOptions,
				identity,
				flow: "unsubscribe",
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
			return { success: true };
		} else {
			// Every AuthState kind is handled above, so `state` narrows to `never` here — hence the cast. The
			// branch is kept as a runtime guard: the state comes from the client, and a kind the schema does
			// not know about should fail loudly rather than fall through to #advance with an empty flow.
			throw new InvalidStateForFlowError((state as AuthState).kind);
		}
		return this.#advance(advanceOptions);
	}

	sendValidation(options: { name: string; locale: string; state: string }): Promise<AuthResponseResult> {
		return this.#guard("sendValidation", () => this.#sendValidation(options));
	}

	async #sendValidation(options: { name: string; locale: string; state: string }): Promise<AuthResponseResult> {
		const { state } = await this.#decryptState(options.state);
		await this.#consumeRateLimit("send", this.#stateSubject(state));
		let authComponent: AuthComponent | undefined;
		let ctx: AuthComponentContext | undefined;
		if (state.kind === "sign-up") {
			const { ctx: c, verificationAuthComponent: ac } = await this.#resolveVerification(state, options.name);
			authComponent = ac;
			ctx = c;
		} else if (state.kind === "enroll") {
			const { ctx: c, verificationAuthComponent: ac } = await this.#resolveEnrollVerification(state);
			authComponent = ac;
			ctx = c;
		} else if (state.kind === "rotate") {
			// Serves both phases: before the replacement is collected the context still resolves to the
			// enrolled value (proving control), afterwards it resolves to the replacement (validating it).
			const { ctx: c, verificationAuthComponent: ac } = await this.#resolveRotateVerification(state);
			authComponent = ac;
			ctx = c;
		} else if (state.kind === "recover") {
			// Serves both phases too: proving control of the component the recovery started from, then validating
			// a replacement collected during the reset.
			const identity = await this.#recoverIdentity(state);
			const { ctx: c, verificationAuthComponent: ac } = state.verified
				? await this.#resolveRecoverReset(state, identity, options.name)
				: await this.#resolveRecoverControl(state, identity);
			authComponent = ac;
			ctx = c;
		} else if (state.kind === "subscribe") {
			const { identity } = await this.#sessionIdentity(state.sessionId);
			authComponent = new OtpAuthComponent(this.#subscribeSendChannel(identity, state.channel.channel).channel);
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

	submitValidation(
		options: { name: string; value: unknown; state: string; address?: string; userAgent?: string },
	): Promise<AuthResponse> {
		return this.#guard("submitValidation", () => this.#submitValidation(options));
	}

	async #submitValidation(
		options: { name: string; value: unknown; state: string; address?: string; userAgent?: string },
	): Promise<AuthResponse> {
		const { state, expireAt } = await this.#decryptState(options.state);
		await this.#consumeRateLimit("verify", this.#stateSubject(state));
		let advanceOptions = {
			state,
			path: [] as string[],
			identity: void 0 as unknown as Identity,
			expireAt,
			flow: "",
			persist: undefined as boolean | undefined,
			address: options.address,
			userAgent: options.userAgent,
		};
		if (state.kind === "sign-up") {
			const { path, choreographyComponent, identityComponent, ctx, verificationAuthComponent } = await this.#resolveVerification(
				state,
				options.name,
			);
			const identityId = await verificationAuthComponent.verifyPrompt(options.value, ctx);
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
			const { identity, identityComponent, ctx, verificationAuthComponent } = await this.#resolveEnrollVerification(state);
			const verified = await verificationAuthComponent.verifyPrompt(options.value, ctx);
			if (verified !== true) {
				throw new InvalidValidationValueError(state.component);
			}
			identityComponent.confirmed = true;
			identity.components.push(...state.components);
			advanceOptions = {
				...advanceOptions,
				identity,
				flow: "enroll",
				persist: true,
			};
		} else if (state.kind === "rotate") {
			const { identity, ctx, authComponent, verificationAuthComponent } = await this.#resolveRotateVerification(state);
			const verified = await verificationAuthComponent.verifyPrompt(options.value, ctx);
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
				persist: true,
			};
		} else if (state.kind === "recover") {
			const identity = await this.#recoverIdentity(state);
			if (!state.verified) {
				const { ctx, verificationAuthComponent } = await this.#resolveRecoverControl(state, identity);
				const verified = await verificationAuthComponent.verifyPrompt(options.value, ctx);
				if (verified !== true) {
					throw new InvalidValidationValueError(state.component);
				}
				state.verified = true;
				// Control established: the reset now walks whatever the choreography still requires after the
				// recovered component, one component at a time.
				advanceOptions = {
					...advanceOptions,
					identity,
					flow: "recover",
					path: this.#recoverPath(state),
				};
			} else {
				const { path, choreographyComponent, identityComponent, ctx, verificationAuthComponent } = await this.#resolveRecoverReset(
					state,
					identity,
					options.name,
				);
				const verified = await verificationAuthComponent.verifyPrompt(options.value, ctx);
				if (verified !== true) {
					throw new InvalidValidationValueError(choreographyComponent.component);
				}
				identityComponent.confirmed = true;
				this.#applyReplacement(identity, state.components);
				advanceOptions = {
					...advanceOptions,
					identity,
					flow: "recover",
					path: [...path, choreographyComponent.component],
					persist: true,
				};
			}
		} else if (state.kind === "subscribe") {
			const { identity } = await this.#sessionIdentity(state.sessionId);
			const sendChannel = this.#subscribeSendChannel(identity, state.channel.channel);
			const verified = await new OtpAuthComponent(sendChannel.channel).verifyPrompt(
				options.value,
				this.#subscribeContext(state, identity),
			);
			if (verified !== true) {
				throw new InvalidValidationValueError(state.channel.channel);
			}
			state.channel.confirmed = true;
			identity.components.push(state.channel);
			advanceOptions = {
				...advanceOptions,
				identity,
				flow: "subscribe",
				persist: true,
			};
		} else {
			throw new InvalidStateForFlowError(state.kind);
		}
		return this.#advance(advanceOptions);
	}
}
