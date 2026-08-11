/**
 * Base class for every failure the library reports with a code. `AuthDanceApi`, the HTTP layer, a
 * component and a storage provider each raise one.
 *
 * `code` is an own enumerable property. `message` and `name` are not, so `JSON.stringify(error)` gives
 * exactly `{"code":"…"}`. `Error` itself keeps `message` non-enumerable, and the constructor below does
 * the same for `name`. Internal detail in the message, such as a component name or a storage failure,
 * therefore never reaches a response.
 */
export abstract class AuthDanceError extends Error {
	/** The stable code the HTTP layer puts in the `{ "error": CODE }` body. Each subclass fixes it to one literal. */
	abstract readonly code: string;

	/**
	 * Sets `name` to the name of the subclass under construction, and defines it as non-enumerable.
	 *
	 * @param message Internal detail for the server log, for example the component that failed. It never reaches the client.
	 */
	constructor(message?: string, options?: ErrorOptions) {
		super(message, options);
		Object.defineProperty(this, "name", { value: new.target.name, enumerable: false, configurable: true });
	}
}

// Token & session
/**
 * The access token does not verify, or it carries no `sub` or no numeric `auth_time`. The HTTP layer also
 * raises it when the `Authorization` header is missing or malformed, because both cases mean the request
 * carried no usable access token.
 */
export class InvalidAccessTokenError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"INVALID_ACCESS_TOKEN"}`. */
	readonly code: "INVALID_ACCESS_TOKEN" = "INVALID_ACCESS_TOKEN";
}
/** The refresh token given to `refreshToken` does not verify, or it carries no `sub` or no numeric `auth_time`. */
export class InvalidRefreshTokenError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"INVALID_REFRESH_TOKEN"}`. */
	readonly code: "INVALID_REFRESH_TOKEN" = "INVALID_REFRESH_TOKEN";
}
/**
 * Storage holds no session under the id a token or a flow state names. The session expired, or a sign-out
 * or an identity delete removed it.
 */
export class SessionNotFoundError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"SESSION_NOT_FOUND"}`. */
	readonly code: "SESSION_NOT_FOUND" = "SESSION_NOT_FOUND";
}
/** Storage holds no identity under the id a session, a recovery state or a `sendMessageTo` call names. */
export class IdentityNotFoundError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"IDENTITY_NOT_FOUND"}`. */
	readonly code: "IDENTITY_NOT_FOUND" = "IDENTITY_NOT_FOUND";
}

// Choreography state
/**
 * The state string does not decrypt, carries no expiry, or no longer matches the `AuthDanceState` schema.
 * The client holds the state, so a stale or a forged value is expected input rather than a server fault.
 */
export class InvalidStateError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"INVALID_STATE"}`. */
	readonly code: "INVALID_STATE" = "INVALID_STATE";
}
/**
 * The step does not accept the flow the state carries. Three cases raise it. `sendPrompt` runs outside a
 * sign-in or a sign-up. `sendValidation` or `submitValidation` runs for a flow with no validation.
 * `submitPrompt` runs on a subscribe state that already collected its recipient. It also guards against a
 * state `kind` the schema does not know about.
 */
export class InvalidStateForFlowError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"INVALID_STATE_FOR_FLOW"}`. */
	readonly code: "INVALID_STATE_FOR_FLOW" = "INVALID_STATE_FOR_FLOW";
}
/**
 * A rotate or a recover flow reached a replacement step before the caller proved control. A rotate proves
 * control of the value it replaces. A recovery proves control of the component it started from.
 * `submitValidation` marks the state as verified, and the flow collects nothing before that.
 */
export class ControlNotProvenError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"CONTROL_NOT_PROVEN"}`. */
	readonly code: "CONTROL_NOT_PROVEN" = "CONTROL_NOT_PROVEN";
}
/**
 * The session is authentic, but its sign-in is older than the elevated window a sensitive action requires.
 * A refresh carries `auth_time` forward unchanged, so a refresh cannot re-open this window.
 */
export class FreshSignInRequiredError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"FRESH_SIGN_IN_REQUIRED"}`. */
	readonly code: "FRESH_SIGN_IN_REQUIRED" = "FRESH_SIGN_IN_REQUIRED";
}

/**
 * A rate limit bucket has no hit left. `AuthDanceApi` consumes the per-identity buckets, and the HTTP
 * layer consumes the per-address buckets.
 *
 * `retryAfter` is not enumerable, so the HTTP layer can copy it into a `Retry-After` header. The
 * `{ "error": … }` body keeps the one shape every other failure has.
 */
export class RateLimitedError extends AuthDanceError {
	/** The app layer answers HTTP 429 with this code, and adds `Retry-After` in seconds when `retryAfter` holds a value. */
	readonly code: "RATE_LIMITED" = "RATE_LIMITED";
	/** How long the caller must wait, in seconds. It is `undefined` when the storage provider reports no delay. */
	readonly retryAfter: number | undefined;

	/**
	 * Sets the message to `rate limit exceeded`, and defines `retryAfter` as a non-enumerable property.
	 *
	 * @param retryAfter Seconds until the bucket accepts a hit again, as the storage provider reports it.
	 */
	constructor(retryAfter?: number, options?: ErrorOptions) {
		super("rate limit exceeded", options);
		Object.defineProperty(this, "retryAfter", { value: retryAfter, enumerable: false, configurable: true });
	}
}

// Configuration — these signal a miswired AuthDanceApiOptions or choreography rather than caller error
/**
 * A flow named a component that `AuthDanceApiOptions.components` does not hold. The choreography names it
 * on a step, or the caller names it in an `enroll`, `unenroll`, `rotate` or `recover` call.
 */
export class UnknownComponentError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"UNKNOWN_COMPONENT"}`. */
	readonly code: "UNKNOWN_COMPONENT" = "UNKNOWN_COMPONENT";
}
/** A flow, or the recipient of a message, named a channel that `AuthDanceApiOptions.channels` does not hold. */
export class UnknownChannelError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"UNKNOWN_CHANNEL"}`. */
	readonly code: "UNKNOWN_CHANNEL" = "UNKNOWN_CHANNEL";
}
/** The caller named a component that the current step of the choreography does not offer. */
export class ComponentNotInChoreographyError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"COMPONENT_NOT_IN_CHOREOGRAPHY"}`. */
	readonly code: "COMPONENT_NOT_IN_CHOREOGRAPHY" = "COMPONENT_NOT_IN_CHOREOGRAPHY";
}
/**
 * The flow needs a second prompt to prove control of a value, but the component declares no
 * `verificationComponent`. Enroll, rotate, recover and the sign-up validation all need one.
 */
export class ComponentNotVerifiableError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"COMPONENT_NOT_VERIFIABLE"}`. */
	readonly code: "COMPONENT_NOT_VERIFIABLE" = "COMPONENT_NOT_VERIFIABLE";
}
/**
 * The caller asked to deliver a prompt or a validation for a component that declares no `sendPrompt`, or
 * whose `sendPrompt` produced no message.
 */
export class ComponentNotSendableError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"COMPONENT_NOT_SENDABLE"}`. */
	readonly code: "COMPONENT_NOT_SENDABLE" = "COMPONENT_NOT_SENDABLE";
}
/**
 * `recover` named a component the flow cannot reset. A step of the choreography must carry that name, and
 * another step of it must both resolve an identity and prove control of it, so the caller has something left
 * to identify themselves through.
 */
export class ComponentNotRecoverableError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"COMPONENT_NOT_RECOVERABLE"}`. */
	readonly code: "COMPONENT_NOT_RECOVERABLE" = "COMPONENT_NOT_RECOVERABLE";
}
/** `signIn` or `signUp` found no first step, so the choreography has nothing to authenticate against. */
export class ChoreographyEmptyError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"CHOREOGRAPHY_EMPTY"}`. */
	readonly code: "CHOREOGRAPHY_EMPTY" = "CHOREOGRAPHY_EMPTY";
}

// Flow
/** `enroll` named a component the identity already holds. */
export class ComponentAlreadyEnrolledError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"COMPONENT_ALREADY_ENROLLED"}`. */
	readonly code: "COMPONENT_ALREADY_ENROLLED" = "COMPONENT_ALREADY_ENROLLED";
}
/** `unenroll` or `rotate` named a component the identity does not hold. */
export class ComponentNotEnrolledError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"COMPONENT_NOT_ENROLLED"}`. */
	readonly code: "COMPONENT_NOT_ENROLLED" = "COMPONENT_NOT_ENROLLED";
}
/**
 * The flow already collected a value for this component. Sign-up, enroll, rotate and recover each collect
 * a component exactly once, and every step after that belongs to the validation.
 */
export class ComponentAlreadyCollectedError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"COMPONENT_ALREADY_COLLECTED"}`. */
	readonly code: "COMPONENT_ALREADY_COLLECTED" = "COMPONENT_ALREADY_COLLECTED";
}
/**
 * The state holds no collected value for the component. The flow reached a validation with nothing to
 * validate, or the component yielded no identification and no challenge under its own name.
 */
export class ComponentNotCollectedError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"COMPONENT_NOT_COLLECTED"}`. */
	readonly code: "COMPONENT_NOT_COLLECTED" = "COMPONENT_NOT_COLLECTED";
}
/**
 * Without the component, no path through the choreography stays completable for the confirmed components
 * that survive. `unenroll` checks this when it starts, and again when the caller confirms. The check counts
 * every component the linked channels take down with the named one, not the named one alone.
 */
export class WouldLockOutError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"WOULD_LOCK_OUT"}`. */
	readonly code: "WOULD_LOCK_OUT" = "WOULD_LOCK_OUT";
}
/** `subscribe` named a channel the identity is already subscribed to. */
export class ChannelAlreadySubscribedError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"CHANNEL_ALREADY_SUBSCRIBED"}`. */
	readonly code: "CHANNEL_ALREADY_SUBSCRIBED" = "CHANNEL_ALREADY_SUBSCRIBED";
}
/** `unsubscribe` or `sendMessageTo` named a channel the identity is not subscribed to. */
export class ChannelNotSubscribedError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"CHANNEL_NOT_SUBSCRIBED"}`. */
	readonly code: "CHANNEL_NOT_SUBSCRIBED" = "CHANNEL_NOT_SUBSCRIBED";
}
/** `unsubscribe` would detach a channel that still names an enrolled component in its `linkedTo` list. */
export class ChannelInUseError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"CHANNEL_IN_USE"}`. */
	readonly code: "CHANNEL_IN_USE" = "CHANNEL_IN_USE";
}
/**
 * The subscribe flow found no other confirmed channel for the code that confirms the new channel. The
 * library confirms a new channel through a channel it already trusts.
 */
export class NoVerificationChannelError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"NO_VERIFICATION_CHANNEL"}`. */
	readonly code: "NO_VERIFICATION_CHANNEL" = "NO_VERIFICATION_CHANNEL";
}
/** `unenroll`, `unsubscribe` and `delete` each end with one explicit confirmation. The caller submitted a value other than `true`. */
export class ConfirmationRequiredError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"CONFIRMATION_REQUIRED"}`. */
	readonly code: "CONFIRMATION_REQUIRED" = "CONFIRMATION_REQUIRED";
}

// Verification
/**
 * A component rejected the submitted value. The choreography never advances after this.
 *
 * A sign-in raises it for a value that does not verify, a wrong password for example. A flow that collects a
 * value raises it for a value the component refuses to store by its own rules. `PasswordAuthDanceComponent`
 * refuses a value that is not a string, an empty one, one that matches the password it replaces, and one that
 * matches the value that identifies its owner.
 */
export class InvalidPromptValueError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"INVALID_PROMPT_VALUE"}`. */
	readonly code: "INVALID_PROMPT_VALUE" = "INVALID_PROMPT_VALUE";
}
/**
 * The validation rejected the submitted value, for example a wrong one-time code. Nothing becomes confirmed
 * and the flow does not advance.
 */
export class InvalidValidationValueError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"INVALID_VALIDATION_VALUE"}`. */
	readonly code: "INVALID_VALIDATION_VALUE" = "INVALID_VALIDATION_VALUE";
}
/**
 * A step needs an identity, but no step resolved one.
 *
 * A sign-in needs an identification to resolve the identity before a challenge can prove a claim against
 * it. The prompt verified, it yielded no identity, and the state holds none either.
 *
 * A recovery identifies through a component that resolves the identity on its own. That component raises this
 * error for a rejected value too, because the step accepts only an identity id.
 */
export class IdentityNotResolvedError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"IDENTITY_NOT_RESOLVED"}`. */
	readonly code: "IDENTITY_NOT_RESOLVED" = "IDENTITY_NOT_RESOLVED";
}
/** A sign-in step resolved one identity, but an earlier step of the same dance already resolved a different one. */
export class IdentityMismatchError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"IDENTITY_MISMATCH"}`. */
	readonly code: "IDENTITY_MISMATCH" = "IDENTITY_MISMATCH";
}
/** A recovery step needs the identity, but the caller has not answered the identification yet. */
export class RecoveryNotIdentifiedError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"RECOVERY_NOT_IDENTIFIED"}`. */
	readonly code: "RECOVERY_NOT_IDENTIFIED" = "RECOVERY_NOT_IDENTIFIED";
}

/**
 * The wrapper for anything raised inside `AuthDanceApi` that is not an `AuthDanceError`: jose, valibot, a
 * storage provider, or a plain bug. `AuthDanceApi` never returns it as a result. The error boundary of
 * each method raises it as an exception, and puts the original failure in `cause` for the server log. A
 * caller that sees this code met a server fault, not a rule it can act on.
 */
export class AuthDanceUnknownError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"UNKNOWN"}`. It answers the same for any error that is not an `AuthDanceError`. */
	readonly code: "UNKNOWN" = "UNKNOWN";
}

/**
 * Every code, mapped to the class that carries it.
 *
 * `createAuthDanceApp` builds the `{ error: CODE }` picklist of its OpenAPI error response from
 * `Object.keys(Errors)`. The documented codes therefore stay derived instead of restated. Register a new
 * subclass here and it reaches the specification. Each entry repeats the code its own class already
 * declares, so no entry needs a comment of its own.
 */
export const Errors = {
	CHANNEL_ALREADY_SUBSCRIBED: ChannelAlreadySubscribedError,
	CHANNEL_IN_USE: ChannelInUseError,
	CHANNEL_NOT_SUBSCRIBED: ChannelNotSubscribedError,
	CHOREOGRAPHY_EMPTY: ChoreographyEmptyError,
	COMPONENT_ALREADY_COLLECTED: ComponentAlreadyCollectedError,
	COMPONENT_ALREADY_ENROLLED: ComponentAlreadyEnrolledError,
	COMPONENT_NOT_COLLECTED: ComponentNotCollectedError,
	COMPONENT_NOT_ENROLLED: ComponentNotEnrolledError,
	COMPONENT_NOT_IN_CHOREOGRAPHY: ComponentNotInChoreographyError,
	COMPONENT_NOT_RECOVERABLE: ComponentNotRecoverableError,
	COMPONENT_NOT_SENDABLE: ComponentNotSendableError,
	COMPONENT_NOT_VERIFIABLE: ComponentNotVerifiableError,
	CONFIRMATION_REQUIRED: ConfirmationRequiredError,
	CONTROL_NOT_PROVEN: ControlNotProvenError,
	FRESH_SIGN_IN_REQUIRED: FreshSignInRequiredError,
	IDENTITY_MISMATCH: IdentityMismatchError,
	IDENTITY_NOT_FOUND: IdentityNotFoundError,
	IDENTITY_NOT_RESOLVED: IdentityNotResolvedError,
	INVALID_ACCESS_TOKEN: InvalidAccessTokenError,
	INVALID_PROMPT_VALUE: InvalidPromptValueError,
	INVALID_REFRESH_TOKEN: InvalidRefreshTokenError,
	INVALID_STATE_FOR_FLOW: InvalidStateForFlowError,
	INVALID_STATE: InvalidStateError,
	INVALID_VALIDATION_VALUE: InvalidValidationValueError,
	NO_VERIFICATION_CHANNEL: NoVerificationChannelError,
	RATE_LIMITED: RateLimitedError,
	RECOVERY_NOT_IDENTIFIED: RecoveryNotIdentifiedError,
	SESSION_NOT_FOUND: SessionNotFoundError,
	UNKNOWN_CHANNEL: UnknownChannelError,
	UNKNOWN_COMPONENT: UnknownComponentError,
	UNKNOWN: AuthDanceUnknownError,
	WOULD_LOCK_OUT: WouldLockOutError,
} as const;
