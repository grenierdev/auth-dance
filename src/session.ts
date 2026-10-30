import * as v from "valibot";

/**
 * One open session of one identity. A completed sign-in or sign-up mints one for the issuer, and a consent of the
 * oauth2 module mints one for the client that asked: a grant. Every access token and refresh token of the session
 * carries its id as `sid`. A grant stands alone: a sign-out of the session that signed in for the consent leaves it.
 */
export interface AuthDanceSession {
	/** The id of the session, a ksuid with a `ses_` prefix. */
	id: string;
	/** The identity that signed in, a ksuid with an `id_` prefix. It names the `sessions/<identityId>/` key space. */
	identityId: string;
	/** The client the tokens of the session are for, the `client_id` of each token. A dance gives the issuer. */
	client_id: string;
	/** The scopes the session holds. A dance holds every scope the server knows. */
	scopes: string[];
	/** The moment the session ends, as an ISO timestamp. It also sets the time to live of both session records. */
	expireAt: string;
	/** The address of the client that signed in. The HTTP layer reads it from the connection, never from the body. */
	address?: string;
	/** The user agent of the client that signed in. The HTTP layer reads it from the `user-agent` header. */
	userAgent?: string;
}

/**
 * Parses and validates a session at runtime, and checks `expireAt` as an ISO timestamp. A record that does not
 * match the shape fails the read.
 */
export const AuthDanceSession: v.GenericSchema<AuthDanceSession> = v.pipe(
	v.object({
		id: v.string(),
		identityId: v.string(),
		client_id: v.string(),
		scopes: v.array(v.string()),
		expireAt: v.pipe(v.string(), v.isoTimestamp()),
		address: v.optional(v.string()),
		userAgent: v.optional(v.string()),
	}),
	v.title("AuthDanceSession"),
	v.description("A user session"),
);
