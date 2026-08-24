import * as v from "valibot";
import { AuthDanceIdentityComponentPublic } from "./identity.ts";
import { AuthDancePrompt } from "./prompt.ts";
import { AuthDanceSession } from "./session.ts";

/**
 * The next move of the dance, as the client receives it.
 *
 * `signIn`, `signUp`, `enroll`, `unenroll`, `rotate`, `recover`, `subscribe`, `unsubscribe` and `delete` answer with
 * this shape. `submitPrompt` answers with it while a step remains.
 */
export interface AuthDanceResponseState {
	/** The in-progress dance, encrypted as a JWE (A256GCM). The client sends this opaque string with the next call. */
	state: string;
	/** What the client renders next: one input, or a choice between the branches of the choreography. */
	prompt: AuthDancePrompt;
	/**
	 * The moment the flow expires.
	 *
	 * The flow duration under `api.durations` sets this deadline when the flow starts. An answer to a prompt never
	 * extends the flow. The HTTP layer serializes the value to an ISO 8601 string.
	 */
	expireAt: Date;
}

/**
 * Parses and validates an `AuthDanceResponseState` at runtime.
 *
 * `app.ts` documents the HTTP body with a schema of its own, because `expireAt` is a `Date` here and an ISO 8601 string
 * on the wire.
 */
export const AuthDanceResponseState: v.GenericSchema<AuthDanceResponseState> = v.pipe(
	v.object({
		state: v.string(),
		prompt: AuthDancePrompt,
		expireAt: v.date(),
	}),
	v.title("AuthDanceResponseState"),
	v.description("The state of an authentication response"),
);

/**
 * What a completed sign-in or sign-up mints, and what a refresh returns again.
 *
 * `submitPrompt` answers with this shape on the last step of a sign-in or a sign-up. `refreshToken` answers with it as
 * well.
 */
export interface AuthDanceResponseTokens {
	/** The three HS256 JWTs of the session. */
	tokens: {
		/**
		 * The bearer token every authenticated route reads. It carries the session id as `sub` and the moment of the
		 * sign-in as `auth_time`.
		 */
		access_token: string;
		/**
		 * The identity token. It carries the identity id as `sub`, and the scope-filtered identity `data` in its
		 * protected header.
		 */
		id_token: string;
		/**
		 * The token `refreshToken` exchanges for a new set. It carries the session id as `sub` and the session scopes
		 * in its protected header. A refresh keeps `auth_time`, so a refresh never opens the elevated window again.
		 */
		refresh_token: string;
	};
	/** The session record a sign-in or a sign-up minted, or the record a refresh used again. */
	session: AuthDanceSession;
	/** Who the tokens belong to. */
	identity: {
		/** The identity id, a ksuid with an `id_` prefix. */
		id: string;
		/**
		 * The identity `data` entries the session scopes allow. These are the same claims the protected header of the
		 * `id_token` carries. The server keeps every other entry.
		 */
		data?: Record<string, unknown>;
	};
}

/** Parses and validates an `AuthDanceResponseTokens` at runtime. */
export const AuthDanceResponseTokens: v.GenericSchema<AuthDanceResponseTokens> = v.pipe(
	v.object({
		tokens: v.object({
			access_token: v.string(),
			id_token: v.string(),
			refresh_token: v.string(),
		}),
		session: AuthDanceSession,
		identity: v.pipe(
			v.object({
				id: v.string(),
				data: v.optional(v.record(v.string(), v.unknown())),
			}),
			v.title("AuthDanceResponseIdentity"),
			v.description("The identity returned from the auth API"),
		),
	}),
	v.title("AuthDanceResponseTokens"),
	v.description("The tokens returned from the auth API"),
);

/**
 * A call that succeeded and returns nothing else.
 *
 * `signOut`, `sendPrompt`, `sendMessage` and `sendMessageTo` answer with this shape. `submitPrompt` answers with it on
 * the last step of `unenroll`, `unsubscribe`, `delete`, `subscribe`, `enroll`, `rotate` and `recover`.
 */
export interface AuthDanceResponseResult {
	/** Always `true`. A client uses this literal to identify the shape among the members of `AuthDanceResponse`. */
	success: true;
}

/** Parses and validates an `AuthDanceResponseResult` at runtime. */
export const AuthDanceResponseResult: v.GenericSchema<AuthDanceResponseResult> = v.pipe(
	v.object({
		success: v.literal(true),
	}),
	v.title("AuthDanceResponseResult"),
	v.description("A successful result from the auth API that carries no further payload"),
);

/**
 * Every session open on the identity, and the one that made the call.
 *
 * The `/list-sessions` route builds this shape from storage. No `AuthDanceApi` method returns it, and it is not a member
 * of the `AuthDanceResponse` union.
 */
export interface AuthDanceResponseSessions {
	/**
	 * The open sessions, each with the address and the user agent of the caller that opened it. Either one is absent
	 * when the connection did not report it. The route sorts the list by id with `localeCompare`, so locale collation
	 * can put two ids out of creation order. A sign-out with `others` destroys exactly these.
	 */
	sessions: AuthDanceSession[];
	/** The id of the session that made the call. It names one entry of `sessions`. */
	current: string;
}

/** Parses and validates an `AuthDanceResponseSessions` at runtime. */
export const AuthDanceResponseSessions: v.GenericSchema<AuthDanceResponseSessions> = v.pipe(
	v.object({
		sessions: v.array(AuthDanceSession),
		current: v.string(),
	}),
	v.title("AuthDanceResponseSessions"),
	v.description("Every session currently open on the identity, and which of them made the call"),
);

/**
 * Every component enrolled on the identity, without the private `data` of each component.
 *
 * The `/list-components` route builds this shape. No `AuthDanceApi` method returns it, and it is not a member of the
 * `AuthDanceResponse` union.
 */
export interface AuthDanceResponseComponents {
	/**
	 * The enrolled identifications, challenges and channels, under the names the management routes take as `name`. For
	 * an identification or a challenge, `confirmed` means the owner proved control. For a channel it means the library
	 * proved delivery. The value a component holds never appears here.
	 */
	components: AuthDanceIdentityComponentPublic[];
}

/** Parses and validates an `AuthDanceResponseComponents` at runtime. */
export const AuthDanceResponseComponents: v.GenericSchema<AuthDanceResponseComponents> = v.pipe(
	v.object({
		components: v.array(AuthDanceIdentityComponentPublic),
	}),
	v.title("AuthDanceResponseComponents"),
	v.description(
		"Every component enrolled on the identity — its identifications, its challenges and its channels — without the private data each holds",
	),
);

/**
 * What `submitPrompt` returns: the next prompt, the tokens of a completed authentication, or a bare success for a
 * completed management flow.
 */
export type AuthDanceResponse = AuthDanceResponseState | AuthDanceResponseTokens | AuthDanceResponseResult;

/** Parses and validates any of the three response shapes at runtime. */
export const AuthDanceResponse: v.GenericSchema<AuthDanceResponse> = v.pipe(
	v.union([AuthDanceResponseState, AuthDanceResponseTokens, AuthDanceResponseResult]),
	v.title("AuthDanceResponse"),
	v.description("The response from the auth API"),
);
