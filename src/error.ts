/**
 * Base class for every failure `AuthApi` can produce.
 *
 * `code` is an own enumerable property while `message` and `name` are deliberately not, so
 * `JSON.stringify(error)` yields exactly `{"code":"…"}`. Internal detail put in the message —
 * a component name, a storage failure — can therefore never leak into a response by accident.
 */
export abstract class AuthError extends Error {
	abstract readonly code: string;

	constructor(message?: string, options?: ErrorOptions) {
		super(message, options);
		Object.defineProperty(this, "name", { value: new.target.name, enumerable: false, configurable: true });
	}
}

// Token & session
export class InvalidAccessTokenError extends AuthError {
	readonly code: "INVALID_ACCESS_TOKEN" = "INVALID_ACCESS_TOKEN";
}
export class InvalidRefreshTokenError extends AuthError {
	readonly code: "INVALID_REFRESH_TOKEN" = "INVALID_REFRESH_TOKEN";
}
export class SessionNotFoundError extends AuthError {
	readonly code: "SESSION_NOT_FOUND" = "SESSION_NOT_FOUND";
}
export class IdentityNotFoundError extends AuthError {
	readonly code: "IDENTITY_NOT_FOUND" = "IDENTITY_NOT_FOUND";
}

// Choreography state
export class InvalidStateError extends AuthError {
	readonly code: "INVALID_STATE" = "INVALID_STATE";
}
export class InvalidStateForFlowError extends AuthError {
	readonly code: "INVALID_STATE_FOR_FLOW" = "INVALID_STATE_FOR_FLOW";
}
export class ControlNotProvenError extends AuthError {
	readonly code: "CONTROL_NOT_PROVEN" = "CONTROL_NOT_PROVEN";
}
/** The session is authentic but its sign-in is older than the elevated window a sensitive action requires. */
export class FreshSignInRequiredError extends AuthError {
	readonly code: "FRESH_SIGN_IN_REQUIRED" = "FRESH_SIGN_IN_REQUIRED";
}

/**
 * A rate-limit bucket is exhausted — either the per-identity one `AuthApi` consumes, or the per-address
 * one the edge consumes. `retryAfter` is a number of seconds and is deliberately not enumerable, so it
 * can feed a `Retry-After` header without widening the `{ "error": … }` body every other failure has.
 */
export class RateLimitedError extends AuthError {
	readonly code: "RATE_LIMITED" = "RATE_LIMITED";
	readonly retryAfter: number | undefined;

	constructor(retryAfter?: number, options?: ErrorOptions) {
		super("rate limit exceeded", options);
		Object.defineProperty(this, "retryAfter", { value: retryAfter, enumerable: false, configurable: true });
	}
}

// Configuration — these signal a miswired AuthApiOptions or choreography rather than caller error
export class UnknownComponentError extends AuthError {
	readonly code: "UNKNOWN_COMPONENT" = "UNKNOWN_COMPONENT";
}
export class UnknownChannelError extends AuthError {
	readonly code: "UNKNOWN_CHANNEL" = "UNKNOWN_CHANNEL";
}
export class ComponentNotInChoreographyError extends AuthError {
	readonly code: "COMPONENT_NOT_IN_CHOREOGRAPHY" = "COMPONENT_NOT_IN_CHOREOGRAPHY";
}
export class ComponentNotVerifiableError extends AuthError {
	readonly code: "COMPONENT_NOT_VERIFIABLE" = "COMPONENT_NOT_VERIFIABLE";
}
export class ComponentNotSendableError extends AuthError {
	readonly code: "COMPONENT_NOT_SENDABLE" = "COMPONENT_NOT_SENDABLE";
}
export class ComponentNotRecoverableError extends AuthError {
	readonly code: "COMPONENT_NOT_RECOVERABLE" = "COMPONENT_NOT_RECOVERABLE";
}
export class ChoreographyEmptyError extends AuthError {
	readonly code: "CHOREOGRAPHY_EMPTY" = "CHOREOGRAPHY_EMPTY";
}

// Flow
export class ComponentAlreadyEnrolledError extends AuthError {
	readonly code: "COMPONENT_ALREADY_ENROLLED" = "COMPONENT_ALREADY_ENROLLED";
}
export class ComponentNotEnrolledError extends AuthError {
	readonly code: "COMPONENT_NOT_ENROLLED" = "COMPONENT_NOT_ENROLLED";
}
export class ComponentAlreadyCollectedError extends AuthError {
	readonly code: "COMPONENT_ALREADY_COLLECTED" = "COMPONENT_ALREADY_COLLECTED";
}
export class ComponentNotCollectedError extends AuthError {
	readonly code: "COMPONENT_NOT_COLLECTED" = "COMPONENT_NOT_COLLECTED";
}
export class WouldLockOutError extends AuthError {
	readonly code: "WOULD_LOCK_OUT" = "WOULD_LOCK_OUT";
}
export class ChannelAlreadySubscribedError extends AuthError {
	readonly code: "CHANNEL_ALREADY_SUBSCRIBED" = "CHANNEL_ALREADY_SUBSCRIBED";
}
export class ChannelNotSubscribedError extends AuthError {
	readonly code: "CHANNEL_NOT_SUBSCRIBED" = "CHANNEL_NOT_SUBSCRIBED";
}
export class ChannelInUseError extends AuthError {
	readonly code: "CHANNEL_IN_USE" = "CHANNEL_IN_USE";
}
export class NoVerificationChannelError extends AuthError {
	readonly code: "NO_VERIFICATION_CHANNEL" = "NO_VERIFICATION_CHANNEL";
}
export class ConfirmationRequiredError extends AuthError {
	readonly code: "CONFIRMATION_REQUIRED" = "CONFIRMATION_REQUIRED";
}

// Verification
export class InvalidPromptValueError extends AuthError {
	readonly code: "INVALID_PROMPT_VALUE" = "INVALID_PROMPT_VALUE";
}
export class InvalidValidationValueError extends AuthError {
	readonly code: "INVALID_VALIDATION_VALUE" = "INVALID_VALIDATION_VALUE";
}
export class IdentityNotResolvedError extends AuthError {
	readonly code: "IDENTITY_NOT_RESOLVED" = "IDENTITY_NOT_RESOLVED";
}
export class IdentityMismatchError extends AuthError {
	readonly code: "IDENTITY_MISMATCH" = "IDENTITY_MISMATCH";
}
export class RecoveryNotIdentifiedError extends AuthError {
	readonly code: "RECOVERY_NOT_IDENTIFIED" = "RECOVERY_NOT_IDENTIFIED";
}

/**
 * Anything thrown inside `AuthApi` that is not an `AuthError` — jose, valibot, a storage provider,
 * a plain bug. Never returned in a `Result`: it escapes as an exception, carrying the original in
 * `cause` for the server log. A caller seeing this has hit a 500, not a business rule.
 */
export class AuthUnknownError extends AuthError {
	readonly code: "UNKNOWN" = "UNKNOWN";
}

/** Registry mapping every code to its class, so the per-method unions below stay derived rather than restated. */
export const Errors = {
	INVALID_ACCESS_TOKEN: InvalidAccessTokenError,
	INVALID_REFRESH_TOKEN: InvalidRefreshTokenError,
	SESSION_NOT_FOUND: SessionNotFoundError,
	IDENTITY_NOT_FOUND: IdentityNotFoundError,
	INVALID_STATE: InvalidStateError,
	INVALID_STATE_FOR_FLOW: InvalidStateForFlowError,
	CONTROL_NOT_PROVEN: ControlNotProvenError,
	FRESH_SIGN_IN_REQUIRED: FreshSignInRequiredError,
	RATE_LIMITED: RateLimitedError,
	UNKNOWN_COMPONENT: UnknownComponentError,
	UNKNOWN_CHANNEL: UnknownChannelError,
	COMPONENT_NOT_IN_CHOREOGRAPHY: ComponentNotInChoreographyError,
	COMPONENT_NOT_VERIFIABLE: ComponentNotVerifiableError,
	COMPONENT_NOT_SENDABLE: ComponentNotSendableError,
	COMPONENT_NOT_RECOVERABLE: ComponentNotRecoverableError,
	CHOREOGRAPHY_EMPTY: ChoreographyEmptyError,
	COMPONENT_ALREADY_ENROLLED: ComponentAlreadyEnrolledError,
	COMPONENT_NOT_ENROLLED: ComponentNotEnrolledError,
	COMPONENT_ALREADY_COLLECTED: ComponentAlreadyCollectedError,
	COMPONENT_NOT_COLLECTED: ComponentNotCollectedError,
	WOULD_LOCK_OUT: WouldLockOutError,
	CHANNEL_ALREADY_SUBSCRIBED: ChannelAlreadySubscribedError,
	CHANNEL_NOT_SUBSCRIBED: ChannelNotSubscribedError,
	CHANNEL_IN_USE: ChannelInUseError,
	NO_VERIFICATION_CHANNEL: NoVerificationChannelError,
	CONFIRMATION_REQUIRED: ConfirmationRequiredError,
	INVALID_PROMPT_VALUE: InvalidPromptValueError,
	INVALID_VALIDATION_VALUE: InvalidValidationValueError,
	IDENTITY_NOT_RESOLVED: IdentityNotResolvedError,
	IDENTITY_MISMATCH: IdentityMismatchError,
	RECOVERY_NOT_IDENTIFIED: RecoveryNotIdentifiedError,
	UNKNOWN: AuthUnknownError,
} as const;
