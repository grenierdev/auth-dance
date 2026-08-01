/**
 * Base class for every failure `AuthDanceApi` can produce.
 *
 * `code` is an own enumerable property while `message` and `name` are deliberately not, so
 * `JSON.stringify(error)` yields exactly `{"code":"…"}`. Internal detail put in the message —
 * a component name, a storage failure — can therefore never leak into a response by accident.
 */
export abstract class AuthDanceError extends Error {
	abstract readonly code: string;

	constructor(message?: string, options?: ErrorOptions) {
		super(message, options);
		Object.defineProperty(this, "name", { value: new.target.name, enumerable: false, configurable: true });
	}
}

// Token & session
export class InvalidAccessTokenError extends AuthDanceError {
	readonly code: "INVALID_ACCESS_TOKEN" = "INVALID_ACCESS_TOKEN";
}
export class InvalidRefreshTokenError extends AuthDanceError {
	readonly code: "INVALID_REFRESH_TOKEN" = "INVALID_REFRESH_TOKEN";
}
export class SessionNotFoundError extends AuthDanceError {
	readonly code: "SESSION_NOT_FOUND" = "SESSION_NOT_FOUND";
}
export class IdentityNotFoundError extends AuthDanceError {
	readonly code: "IDENTITY_NOT_FOUND" = "IDENTITY_NOT_FOUND";
}

// KV
export class KVKeyNotFoundError extends AuthDanceError {
	readonly code: "KV_KEY_NOT_FOUND" = "KV_KEY_NOT_FOUND";
}

// Choreography state
export class InvalidStateError extends AuthDanceError {
	readonly code: "INVALID_STATE" = "INVALID_STATE";
}
export class InvalidStateForFlowError extends AuthDanceError {
	readonly code: "INVALID_STATE_FOR_FLOW" = "INVALID_STATE_FOR_FLOW";
}
export class ControlNotProvenError extends AuthDanceError {
	readonly code: "CONTROL_NOT_PROVEN" = "CONTROL_NOT_PROVEN";
}
/** The session is authentic but its sign-in is older than the elevated window a sensitive action requires. */
export class FreshSignInRequiredError extends AuthDanceError {
	readonly code: "FRESH_SIGN_IN_REQUIRED" = "FRESH_SIGN_IN_REQUIRED";
}

/**
 * A rate-limit bucket is exhausted — either the per-identity one `AuthDanceApi` consumes, or the per-address
 * one the edge consumes. `retryAfter` is a number of seconds and is deliberately not enumerable, so it
 * can feed a `Retry-After` header without widening the `{ "error": … }` body every other failure has.
 */
export class RateLimitedError extends AuthDanceError {
	readonly code: "RATE_LIMITED" = "RATE_LIMITED";
	readonly retryAfter: number | undefined;

	constructor(retryAfter?: number, options?: ErrorOptions) {
		super("rate limit exceeded", options);
		Object.defineProperty(this, "retryAfter", { value: retryAfter, enumerable: false, configurable: true });
	}
}

// Configuration — these signal a miswired AuthDanceApiOptions or choreography rather than caller error
export class UnknownComponentError extends AuthDanceError {
	readonly code: "UNKNOWN_COMPONENT" = "UNKNOWN_COMPONENT";
}
export class UnknownChannelError extends AuthDanceError {
	readonly code: "UNKNOWN_CHANNEL" = "UNKNOWN_CHANNEL";
}
export class ComponentNotInChoreographyError extends AuthDanceError {
	readonly code: "COMPONENT_NOT_IN_CHOREOGRAPHY" = "COMPONENT_NOT_IN_CHOREOGRAPHY";
}
export class ComponentNotVerifiableError extends AuthDanceError {
	readonly code: "COMPONENT_NOT_VERIFIABLE" = "COMPONENT_NOT_VERIFIABLE";
}
export class ComponentNotSendableError extends AuthDanceError {
	readonly code: "COMPONENT_NOT_SENDABLE" = "COMPONENT_NOT_SENDABLE";
}
export class ComponentNotRecoverableError extends AuthDanceError {
	readonly code: "COMPONENT_NOT_RECOVERABLE" = "COMPONENT_NOT_RECOVERABLE";
}
export class ChoreographyEmptyError extends AuthDanceError {
	readonly code: "CHOREOGRAPHY_EMPTY" = "CHOREOGRAPHY_EMPTY";
}

// Flow
export class ComponentAlreadyEnrolledError extends AuthDanceError {
	readonly code: "COMPONENT_ALREADY_ENROLLED" = "COMPONENT_ALREADY_ENROLLED";
}
export class ComponentNotEnrolledError extends AuthDanceError {
	readonly code: "COMPONENT_NOT_ENROLLED" = "COMPONENT_NOT_ENROLLED";
}
export class ComponentAlreadyCollectedError extends AuthDanceError {
	readonly code: "COMPONENT_ALREADY_COLLECTED" = "COMPONENT_ALREADY_COLLECTED";
}
export class ComponentNotCollectedError extends AuthDanceError {
	readonly code: "COMPONENT_NOT_COLLECTED" = "COMPONENT_NOT_COLLECTED";
}
export class WouldLockOutError extends AuthDanceError {
	readonly code: "WOULD_LOCK_OUT" = "WOULD_LOCK_OUT";
}
export class ChannelAlreadySubscribedError extends AuthDanceError {
	readonly code: "CHANNEL_ALREADY_SUBSCRIBED" = "CHANNEL_ALREADY_SUBSCRIBED";
}
export class ChannelNotSubscribedError extends AuthDanceError {
	readonly code: "CHANNEL_NOT_SUBSCRIBED" = "CHANNEL_NOT_SUBSCRIBED";
}
export class ChannelInUseError extends AuthDanceError {
	readonly code: "CHANNEL_IN_USE" = "CHANNEL_IN_USE";
}
export class NoVerificationChannelError extends AuthDanceError {
	readonly code: "NO_VERIFICATION_CHANNEL" = "NO_VERIFICATION_CHANNEL";
}
export class ConfirmationRequiredError extends AuthDanceError {
	readonly code: "CONFIRMATION_REQUIRED" = "CONFIRMATION_REQUIRED";
}

// Verification
export class InvalidPromptValueError extends AuthDanceError {
	readonly code: "INVALID_PROMPT_VALUE" = "INVALID_PROMPT_VALUE";
}
export class InvalidValidationValueError extends AuthDanceError {
	readonly code: "INVALID_VALIDATION_VALUE" = "INVALID_VALIDATION_VALUE";
}
export class PolicyViolationError extends AuthDanceError {
	readonly code: "POLICY_VIOLATION" = "POLICY_VIOLATION";
}
export class IdentityNotResolvedError extends AuthDanceError {
	readonly code: "IDENTITY_NOT_RESOLVED" = "IDENTITY_NOT_RESOLVED";
}
export class IdentityMismatchError extends AuthDanceError {
	readonly code: "IDENTITY_MISMATCH" = "IDENTITY_MISMATCH";
}
export class RecoveryNotIdentifiedError extends AuthDanceError {
	readonly code: "RECOVERY_NOT_IDENTIFIED" = "RECOVERY_NOT_IDENTIFIED";
}

/**
 * Anything thrown inside `AuthDanceApi` that is not an `AuthDanceError` — jose, valibot, a storage provider,
 * a plain bug. Never returned in a `Result`: it escapes as an exception, carrying the original in
 * `cause` for the server log. A caller seeing this has hit a 500, not a business rule.
 */
export class AuthDanceUnknownError extends AuthDanceError {
	readonly code: "UNKNOWN" = "UNKNOWN";
}

/** Registry mapping every code to its class, so the per-method unions below stay derived rather than restated. */
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
	KV_KEY_NOT_FOUND: KVKeyNotFoundError,
	NO_VERIFICATION_CHANNEL: NoVerificationChannelError,
	POLICY_VIOLATION: PolicyViolationError,
	RATE_LIMITED: RateLimitedError,
	RECOVERY_NOT_IDENTIFIED: RecoveryNotIdentifiedError,
	SESSION_NOT_FOUND: SessionNotFoundError,
	UNKNOWN_CHANNEL: UnknownChannelError,
	UNKNOWN_COMPONENT: UnknownComponentError,
	UNKNOWN: AuthDanceUnknownError,
	WOULD_LOCK_OUT: WouldLockOutError,
} as const;
