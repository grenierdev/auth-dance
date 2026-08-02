import * as v from "valibot";

/**
 * One open session of one identity, which a completed sign-in or sign-up mints.
 *
 * The session is the subject of the tokens. `access_token` and `refresh_token` carry its id as `sub`, and a refresh
 * mints a new set of tokens on the same session. `AuthDanceStorage` keeps the record twice, at `session/<id>` for a
 * read by id and at `sessions/<identityId>/<id>` as the index of one identity.
 */
export interface AuthDanceSession {
	/** The id of the session, a ksuid with a `ses_` prefix. `access_token` and `refresh_token` carry it as `sub`. */
	id: string;
	/**
	 * The identity that signed in, a ksuid with an `id_` prefix. It names the `sessions/<identityId>/` key space
	 * that `/list-sessions` reads, and every refresh reads the identity again with it.
	 */
	identityId: string;
	/**
	 * The keys of the identity data bag this session may disclose. A sign-in and a sign-up fill the list with every
	 * key the bag holds. `id_token` carries only the claims these scopes name, and `refresh_token` repeats the list
	 * in its protected header.
	 */
	scopes: string[];
	/**
	 * The moment the session ends, as an ISO timestamp. It also sets the time to live of both session records, so
	 * the store deletes them on its own. The value is already the string a client sees, which is why the response
	 * schemas reuse this shape as it is.
	 */
	expireAt: string;
	/**
	 * The address of the client that signed in. `/list-sessions` shows it, so the owner recognizes each session. The
	 * HTTP layer reads it from the connection, never from the body. It stays absent when the connection names no
	 * address.
	 */
	address?: string;
	/**
	 * The user agent of the client that signed in, which `/list-sessions` shows next to the address. The HTTP layer
	 * reads it from the `user-agent` header, never from the body.
	 */
	userAgent?: string;
}

/**
 * Parses and validates a session at runtime, and checks `expireAt` as an ISO timestamp.
 *
 * `AuthDanceStorage` parses every record of the two session key spaces with this schema. A record that does not match
 * the shape fails the read, and no broken session reaches a caller. `response.ts` also embeds the schema in the token
 * response and in the session list response, which puts the shape in the OpenAPI specification.
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
