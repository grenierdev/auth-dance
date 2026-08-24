import * as v from "valibot";

/**
 * One open session of one identity, which a completed sign-in or sign-up mints. `access_token` and
 * `refresh_token` carry its id as `sub`.
 */
export interface AuthDanceSession {
	/** The id of the session, a ksuid with a `ses_` prefix. */
	id: string;
	/** The identity that signed in, a ksuid with an `id_` prefix. It names the `sessions/<identityId>/` key space. */
	identityId: string;
	/** The keys of the identity data bag this session may disclose. `id_token` carries only these claims. */
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
		scopes: v.array(v.string()),
		expireAt: v.pipe(v.string(), v.isoTimestamp()),
		address: v.optional(v.string()),
		userAgent: v.optional(v.string()),
	}),
	v.title("AuthDanceSession"),
	v.description("A user session"),
);
