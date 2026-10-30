import { deepEqual } from "node:assert";
import { describe, it } from "vitest";
import {
	AccessDeniedError,
	InsufficientScopeError,
	InvalidClientError,
	InvalidClientMetadataError,
	InvalidGrantError,
	InvalidRedirectUriError,
	InvalidRequestError,
	InvalidScopeError,
	InvalidSoftwareStatementError,
	ServerError,
	TemporarilyUnavailableError,
	UnapprovedSoftwareStatementError,
	UnauthorizedClientError,
	UnsupportedGrantTypeError,
	UnsupportedResponseTypeError,
	UnsupportedTokenTypeError,
} from "./error.ts";

describe("AuthDanceOauth2Error", () => {
	it("should carry the RFC code and the HTTP status of each class", () => {
		deepEqual(
			[
				new InvalidRequestError(),
				new InvalidClientError(),
				new InvalidGrantError(),
				new UnauthorizedClientError(),
				new UnsupportedGrantTypeError(),
				new UnsupportedResponseTypeError(),
				new InvalidScopeError(),
				new AccessDeniedError(),
				new InsufficientScopeError(),
				new ServerError(),
				new TemporarilyUnavailableError(),
				new UnsupportedTokenTypeError(),
				new InvalidRedirectUriError(),
				new InvalidClientMetadataError(),
				new InvalidSoftwareStatementError(),
				new UnapprovedSoftwareStatementError(),
			].map((error) => [error.name, error.error, error.status]),
			[
				["InvalidRequestError", "invalid_request", 400],
				["InvalidClientError", "invalid_client", 401],
				["InvalidGrantError", "invalid_grant", 400],
				["UnauthorizedClientError", "unauthorized_client", 400],
				["UnsupportedGrantTypeError", "unsupported_grant_type", 400],
				["UnsupportedResponseTypeError", "unsupported_response_type", 400],
				["InvalidScopeError", "invalid_scope", 400],
				["AccessDeniedError", "access_denied", 403],
				["InsufficientScopeError", "insufficient_scope", 403],
				["ServerError", "server_error", 500],
				["TemporarilyUnavailableError", "temporarily_unavailable", 503],
				["UnsupportedTokenTypeError", "unsupported_token_type", 400],
				["InvalidRedirectUriError", "invalid_redirect_uri", 400],
				["InvalidClientMetadataError", "invalid_client_metadata", 400],
				["InvalidSoftwareStatementError", "invalid_software_statement", 400],
				["UnapprovedSoftwareStatementError", "unapproved_software_statement", 400],
			],
		);
	});
	it("should keep only the characters RFC 6749 allows in the description", () => {
		deepEqual(new InvalidRequestError('the "scope" parameter\\ is repeated\n é').description, "the scope parameter is repeated ");
		deepEqual(new InvalidRequestError().description, undefined);
	});
});
