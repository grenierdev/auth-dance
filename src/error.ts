/**
 * The base class for every failure the library reports with a code.
 *
 * `code` is an own enumerable property. `message` and `name` are not, so `JSON.stringify(error)` gives exactly
 * `{"code":"…"}`. Internal detail in the message never reaches a response.
 */
export abstract class AuthDanceError extends Error {
	/** The stable code the HTTP layer puts in the `{ "error": CODE }` body. */
	abstract readonly code: string;

	/**
	 * Makes the error.
	 *
	 * @param message Internal detail for the server log. It never reaches the client.
	 */
	constructor(message?: string, options?: ErrorOptions) {
		super(message, options);
		Object.defineProperty(this, "name", { value: new.target.name, enumerable: false, configurable: true });
	}
}

// Token & session
/**
 * The access token does not verify, is not an RFC 9068 access token of this issuer, or is for another audience. The
 * HTTP layer also raises it when the `Authorization` header is missing or malformed.
 */
export class InvalidAccessTokenError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"INVALID_ACCESS_TOKEN"}`. */
	readonly code: "INVALID_ACCESS_TOKEN" = "INVALID_ACCESS_TOKEN";
}
/**
 * The refresh token given to `refreshToken` does not verify, is not a refresh token of this issuer, belongs to another
 * client, or asks for a scope it does not hold.
 */
export class InvalidRefreshTokenError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"INVALID_REFRESH_TOKEN"}`. */
	readonly code: "INVALID_REFRESH_TOKEN" = "INVALID_REFRESH_TOKEN";
}
/** The access token is valid, but it does not hold the scope the action needs, `account` for a management route. */
export class InsufficientScopeError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"INSUFFICIENT_SCOPE"}`. */
	readonly code: "INSUFFICIENT_SCOPE" = "INSUFFICIENT_SCOPE";
}
/**
 * The `claims` mapper threw, or its result broke a rule of `AuthDanceClaimsMapper`. `cause` holds what the mapper
 * threw, or a `TypeError` that names the rule.
 */
export class ClaimsMapperError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"CLAIMS_MAPPER_FAILED"}`. */
	readonly code: "CLAIMS_MAPPER_FAILED" = "CLAIMS_MAPPER_FAILED";
}
/** Storage holds no session under the id a token or a flow state names. */
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
/** The state string does not decrypt, carries no expiry, or no longer matches the `AuthDanceState` schema. */
export class InvalidStateError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"INVALID_STATE"}`. */
	readonly code: "INVALID_STATE" = "INVALID_STATE";
}
/**
 * The step does not accept the flow the state carries. `sendPrompt` raises it for a flow that holds nothing to deliver
 * over a channel, such as a confirmation-only unenroll, unsubscribe or delete.
 */
export class InvalidStateForFlowError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"INVALID_STATE_FOR_FLOW"}`. */
	readonly code: "INVALID_STATE_FOR_FLOW" = "INVALID_STATE_FOR_FLOW";
}
/**
 * The sign-in of the session is older than the elevated window a sensitive action requires. A refresh carries
 * `auth_time` forward unchanged, so a refresh cannot re-open the window.
 */
export class FreshSignInRequiredError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"FRESH_SIGN_IN_REQUIRED"}`. */
	readonly code: "FRESH_SIGN_IN_REQUIRED" = "FRESH_SIGN_IN_REQUIRED";
}

/**
 * A rate limit bucket has no hit left. `AuthDanceApi` consumes the per-identity buckets, and the HTTP layer consumes
 * the per-address buckets. `retryAfter` is not enumerable, so it never reaches the `{ "error": … }` body.
 */
export class RateLimitedError extends AuthDanceError {
	/** The app layer answers HTTP 429 with this code, and adds `Retry-After` in seconds when `retryAfter` holds a value. */
	readonly code: "RATE_LIMITED" = "RATE_LIMITED";
	/** How long the caller must wait, in seconds. It is `undefined` when the storage provider reports no delay. */
	readonly retryAfter: number | undefined;

	/**
	 * Makes the error.
	 *
	 * @param retryAfter Seconds until the bucket accepts a hit again, as the storage provider reports it.
	 */
	constructor(retryAfter?: number, options?: ErrorOptions) {
		super("rate limit exceeded", options);
		Object.defineProperty(this, "retryAfter", { value: retryAfter, enumerable: false, configurable: true });
	}
}

// Configuration
/** A flow named a component that `AuthDanceApiOptions.components` does not hold. */
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
 * The flow needs a second prompt to prove control of a value, but the component declares no `verificationComponent`.
 * Enroll, rotate, recover and the sign-up validation all need one.
 */
export class ComponentNotVerifiableError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"COMPONENT_NOT_VERIFIABLE"}`. */
	readonly code: "COMPONENT_NOT_VERIFIABLE" = "COMPONENT_NOT_VERIFIABLE";
}
/** The component declares no `sendPrompt`, or its `sendPrompt` produced no message. */
export class ComponentNotSendableError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"COMPONENT_NOT_SENDABLE"}`. */
	readonly code: "COMPONENT_NOT_SENDABLE" = "COMPONENT_NOT_SENDABLE";
}
/**
 * `recover` named a component the flow cannot reset. The deployment marked the component `false` in
 * `AuthDanceApiOptions.recovery`, or no complete path of the choreography stays a recovery path without it. A
 * recovery path starts with an identification and holds a step that proves control.
 */
export class ComponentNotRecoverableError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"COMPONENT_NOT_RECOVERABLE"}`. */
	readonly code: "COMPONENT_NOT_RECOVERABLE" = "COMPONENT_NOT_RECOVERABLE";
}
/**
 * The choreography, or a recovery choreography, declares a path the library refuses to run. The constructor raises
 * it. A sign-in or a sign-up also raises it before it mints tokens on a path with no step that proves control.
 */
export class InvalidChoreographyError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"INVALID_CHOREOGRAPHY"}`. */
	readonly code: "INVALID_CHOREOGRAPHY" = "INVALID_CHOREOGRAPHY";
}
/** `signIn` or `signUp` found no first step in the choreography. */
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
 * The flow already collected a value for this component. Sign-up, enroll, rotate and recover each collect a component
 * one time. Every step after that belongs to the validation.
 */
export class ComponentAlreadyCollectedError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"COMPONENT_ALREADY_COLLECTED"}`. */
	readonly code: "COMPONENT_ALREADY_COLLECTED" = "COMPONENT_ALREADY_COLLECTED";
}
/** The state holds no collected value for the component. */
export class ComponentNotCollectedError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"COMPONENT_NOT_COLLECTED"}`. */
	readonly code: "COMPONENT_NOT_COLLECTED" = "COMPONENT_NOT_COLLECTED";
}
/**
 * Without the component, no path through the choreography stays completable for the confirmed components that survive.
 * `unenroll` checks this at the start and again at the confirmation. The check counts every component the linked
 * channels take down with the named one.
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
/**
 * A removal would leave an enrolled record that names a component which is gone, and the library cannot take that
 * record down with it. `unenroll` and `unsubscribe` follow `linkedTo` in both directions, so a link they resolve
 * never raises this.
 */
export class ComponentInUseError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"COMPONENT_IN_USE"}`. */
	readonly code: "COMPONENT_IN_USE" = "COMPONENT_IN_USE";
}
/** An identification is already in use by another identity. */
export class IdentificationTakenError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"IDENTIFICATION_TAKEN"}`. */
	readonly code: "IDENTIFICATION_TAKEN" = "IDENTIFICATION_TAKEN";
}
/** `unenroll`, `unsubscribe` and `delete` each end with one explicit confirmation. The owner submitted a value other than `true`. */
export class ConfirmationRequiredError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"CONFIRMATION_REQUIRED"}`. */
	readonly code: "CONFIRMATION_REQUIRED" = "CONFIRMATION_REQUIRED";
}

// Verification
/**
 * A component rejected the submitted value, a wrong password for example. The choreography does not advance. A flow
 * that collects a value also raises it for a value the component refuses to store by its own rules.
 */
export class InvalidPromptValueError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"INVALID_PROMPT_VALUE"}`. */
	readonly code: "INVALID_PROMPT_VALUE" = "INVALID_PROMPT_VALUE";
}
/**
 * The validation rejected the submitted value, a wrong one-time code for example. Nothing becomes confirmed and the
 * flow does not advance.
 */
export class InvalidValidationValueError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"INVALID_VALIDATION_VALUE"}`. */
	readonly code: "INVALID_VALIDATION_VALUE" = "INVALID_VALIDATION_VALUE";
}
/**
 * A step needs an identity, but no step resolved one and the state holds none. A first step that answers `true`
 * instead of an identity id raises it, in a sign-in and in a recovery.
 */
export class IdentityNotResolvedError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"IDENTITY_NOT_RESOLVED"}`. */
	readonly code: "IDENTITY_NOT_RESOLVED" = "IDENTITY_NOT_RESOLVED";
}
/** A sign-in or recovery step resolved one identity, but an earlier step of the same dance already resolved a different one. */
export class IdentityMismatchError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"IDENTITY_MISMATCH"}`. */
	readonly code: "IDENTITY_MISMATCH" = "IDENTITY_MISMATCH";
}
/** A recovery step needs the identity, but the owner has not answered the first step of the recovery yet. */
export class RecoveryNotIdentifiedError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"RECOVERY_NOT_IDENTIFIED"}`. */
	readonly code: "RECOVERY_NOT_IDENTIFIED" = "RECOVERY_NOT_IDENTIFIED";
}

/**
 * The wrapper for anything raised inside `AuthDanceApi` that is not an `AuthDanceError`. The error boundary of each
 * method raises it as an exception, and puts the original failure in `cause` for the server log.
 */
export class AuthDanceUnknownError extends AuthDanceError {
	/** The app layer answers HTTP 500 with `{"error":"UNKNOWN"}`. It answers the same for any error that is not an `AuthDanceError`. */
	readonly code: "UNKNOWN" = "UNKNOWN";
}

/**
 * Every code, mapped to the class that carries it. `createAuthDanceApp` builds the `{ error: CODE }` picklist of its
 * OpenAPI error response from `Object.keys(Errors)`, so register a new subclass here.
 */
export const Errors = {
	CHANNEL_ALREADY_SUBSCRIBED: ChannelAlreadySubscribedError,
	CHANNEL_NOT_SUBSCRIBED: ChannelNotSubscribedError,
	CHOREOGRAPHY_EMPTY: ChoreographyEmptyError,
	CLAIMS_MAPPER_FAILED: ClaimsMapperError,
	COMPONENT_ALREADY_COLLECTED: ComponentAlreadyCollectedError,
	COMPONENT_ALREADY_ENROLLED: ComponentAlreadyEnrolledError,
	COMPONENT_IN_USE: ComponentInUseError,
	COMPONENT_NOT_COLLECTED: ComponentNotCollectedError,
	COMPONENT_NOT_ENROLLED: ComponentNotEnrolledError,
	COMPONENT_NOT_IN_CHOREOGRAPHY: ComponentNotInChoreographyError,
	COMPONENT_NOT_RECOVERABLE: ComponentNotRecoverableError,
	COMPONENT_NOT_SENDABLE: ComponentNotSendableError,
	COMPONENT_NOT_VERIFIABLE: ComponentNotVerifiableError,
	CONFIRMATION_REQUIRED: ConfirmationRequiredError,
	FRESH_SIGN_IN_REQUIRED: FreshSignInRequiredError,
	IDENTITY_MISMATCH: IdentityMismatchError,
	IDENTITY_NOT_FOUND: IdentityNotFoundError,
	IDENTITY_NOT_RESOLVED: IdentityNotResolvedError,
	INSUFFICIENT_SCOPE: InsufficientScopeError,
	INVALID_ACCESS_TOKEN: InvalidAccessTokenError,
	INVALID_CHOREOGRAPHY: InvalidChoreographyError,
	INVALID_PROMPT_VALUE: InvalidPromptValueError,
	INVALID_REFRESH_TOKEN: InvalidRefreshTokenError,
	INVALID_STATE_FOR_FLOW: InvalidStateForFlowError,
	INVALID_STATE: InvalidStateError,
	INVALID_VALIDATION_VALUE: InvalidValidationValueError,
	RATE_LIMITED: RateLimitedError,
	RECOVERY_NOT_IDENTIFIED: RecoveryNotIdentifiedError,
	SESSION_NOT_FOUND: SessionNotFoundError,
	UNKNOWN_CHANNEL: UnknownChannelError,
	UNKNOWN_COMPONENT: UnknownComponentError,
	UNKNOWN: AuthDanceUnknownError,
	WOULD_LOCK_OUT: WouldLockOutError,
} as const;
