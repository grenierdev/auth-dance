// RFC 6749 §5.2: `error_description` holds only these characters. Any other character drops out.
const DESCRIPTION_CHARACTERS = /[^\x20-\x21\x23-\x5B\x5D-\x7E]/g;

/**
 * The base class for every failure the oauth2 module reports with an RFC error code.
 *
 * The HTTP layer answers `status` with `{ error, error_description }`. `description` goes to the client, so it never
 * holds internal detail. Put internal detail in `cause`.
 */
export abstract class AuthDanceOauth2Error extends Error {
	/** The RFC error code, for example `invalid_request`. */
	abstract readonly error: string;
	/** The HTTP status the app answers with. */
	abstract readonly status: 400 | 401 | 403 | 404 | 500 | 503;
	/** The text the app sends as `error_description`. It holds only the characters RFC 6749 §5.2 allows. */
	readonly description?: string;

	/**
	 * Makes the error.
	 *
	 * @param description The text for the client. It never holds internal detail.
	 * @param options `cause` holds the internal detail, for the server log.
	 */
	constructor(description?: string, options?: ErrorOptions) {
		super(description, options);
		Object.defineProperty(this, "name", { value: new.target.name, enumerable: false, configurable: true });
		if (description !== undefined) {
			this.description = description.replace(DESCRIPTION_CHARACTERS, "");
		}
	}
}

/** The request misses a parameter, repeats one, or holds a value the server cannot read. RFC 6749 §4.1.2.1, §5.2. */
export class InvalidRequestError extends AuthDanceOauth2Error {
	readonly error = "invalid_request";
	readonly status = 400;
}

/**
 * The client authentication failed: an unknown client, a wrong secret, or a method other than the registered one.
 * RFC 6749 §5.2. The app adds `WWW-Authenticate: Basic` when the request used Basic.
 */
export class InvalidClientError extends AuthDanceOauth2Error {
	readonly error = "invalid_client";
	readonly status = 401;
}

/**
 * The code or the refresh token is not valid, has expired, was already used, or belongs to another client.
 * RFC 6749 §5.2.
 */
export class InvalidGrantError extends AuthDanceOauth2Error {
	readonly error = "invalid_grant";
	readonly status = 400;
}

/** The client may not use this grant type or this response type. RFC 6749 §4.1.2.1, §5.2. */
export class UnauthorizedClientError extends AuthDanceOauth2Error {
	readonly error = "unauthorized_client";
	readonly status = 400;
}

/** The server does not support the grant type, the password grant for example. RFC 6749 §5.2. */
export class UnsupportedGrantTypeError extends AuthDanceOauth2Error {
	readonly error = "unsupported_grant_type";
	readonly status = 400;
}

/** The server does not support the response type, the implicit `token` for example. RFC 6749 §4.1.2.1. */
export class UnsupportedResponseTypeError extends AuthDanceOauth2Error {
	readonly error = "unsupported_response_type";
	readonly status = 400;
}

/** The scope is unknown, or outside the scope of the client. RFC 6749 §4.1.2.1, §5.2. */
export class InvalidScopeError extends AuthDanceOauth2Error {
	readonly error = "invalid_scope";
	readonly status = 400;
}

/**
 * The access token is missing, expired, revoked, or not valid for this resource. RFC 6750 §3.1. A resource server
 * answers it with `WWW-Authenticate: Bearer error="invalid_token"`.
 */
export class InvalidTokenError extends AuthDanceOauth2Error {
	readonly error = "invalid_token";
	readonly status = 401;
}

/**
 * The access token is valid, but it does not hold the scope the request needs. RFC 6750 §3.1. The HTTP layer answers
 * it with `WWW-Authenticate: Bearer error="insufficient_scope"`.
 */
export class InsufficientScopeError extends AuthDanceOauth2Error {
	readonly error = "insufficient_scope";
	readonly status = 403;
}

/** The owner or the server refused the request. RFC 6749 §4.1.2.1. */
export class AccessDeniedError extends AuthDanceOauth2Error {
	readonly error = "access_denied";
	readonly status = 403;
}

/** The server failed in a way the client cannot fix. RFC 6749 §4.1.2.1. `cause` holds what failed. */
export class ServerError extends AuthDanceOauth2Error {
	readonly error = "server_error";
	readonly status = 500;
}

/** The server cannot handle the request now, because of a load or a maintenance. RFC 6749 §4.1.2.1. */
export class TemporarilyUnavailableError extends AuthDanceOauth2Error {
	readonly error = "temporarily_unavailable";
	readonly status = 503;
}

/** The server cannot revoke this type of token. RFC 7009 §2.2.1. */
export class UnsupportedTokenTypeError extends AuthDanceOauth2Error {
	readonly error = "unsupported_token_type";
	readonly status = 400;
}

/** A redirect URI of the client metadata is not valid. RFC 7591 §3.2.2. */
export class InvalidRedirectUriError extends AuthDanceOauth2Error {
	readonly error = "invalid_redirect_uri";
	readonly status = 400;
}

/** A field of the client metadata is not valid, or two fields do not agree. RFC 7591 §3.2.2. */
export class InvalidClientMetadataError extends AuthDanceOauth2Error {
	readonly error = "invalid_client_metadata";
	readonly status = 400;
}

/** The software statement is not valid. RFC 7591 §3.2.2. */
export class InvalidSoftwareStatementError extends AuthDanceOauth2Error {
	readonly error = "invalid_software_statement";
	readonly status = 400;
}

/** The server does not accept the software statement. RFC 7591 §3.2.2. */
export class UnapprovedSoftwareStatementError extends AuthDanceOauth2Error {
	readonly error = "unapproved_software_statement";
	readonly status = 400;
}

/** The owner has not finished the device authorization yet, so the device polls again later. RFC 8628 §3.5. */
export class AuthorizationPendingError extends AuthDanceOauth2Error {
	readonly error = "authorization_pending";
	readonly status = 400;
}

/** The device polls faster than the interval. It waits 5 more seconds from now on. RFC 8628 §3.5. */
export class SlowDownError extends AuthDanceOauth2Error {
	readonly error = "slow_down";
	readonly status = 400;
}

/** The device code expired before the owner approved it, so the device starts a new request. RFC 8628 §3.5. */
export class ExpiredTokenError extends AuthDanceOauth2Error {
	readonly error = "expired_token";
	readonly status = 400;
}

/**
 * The owner denied the device authorization, at the token endpoint. RFC 8628 §3.5. It is `access_denied` with the
 * status of a token error, RFC 6749 §5.2, where `AccessDeniedError` answers 403.
 */
export class DeviceAccessDeniedError extends AuthDanceOauth2Error {
	readonly error = "access_denied";
	readonly status = 400;
}

/**
 * The user code the device page sent names no pending device authorization. The page asks the owner again. After too
 * many wrong codes the device challenge ends, and `acceptDeviceRequest` raises `InvalidRequestError` instead.
 */
export class InvalidUserCodeError extends InvalidRequestError {}
