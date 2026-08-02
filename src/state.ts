import { AuthDanceIdentityChannel, AuthDanceIdentityComponent } from "./identity.ts";
import * as v from "valibot";

/**
 * The in-progress dance of a caller who signs in to an identity that already exists.
 *
 * The state carries no submitted value. It carries the path the dance walked so far, and the library asks the
 * choreography what comes next.
 */
export interface AuthDanceStateSignIn {
	/**
	 * The id of this dance, a ksuid with an `st_` prefix.
	 *
	 * A component keys its own per-dance storage under this id, for example the pending one-time code.
	 */
	id: string;
	/** The discriminator that tells the library this dance is a sign-in. */
	kind: "sign-in";
	/**
	 * The names of the components the caller already answered, oldest first.
	 *
	 * The library appends one name for every value it accepts, then reads the path to get the next prompt. An empty
	 * path means the dance stays at its first step.
	 */
	path: string[];
	/**
	 * The identity a component resolved, absent until one step resolves it.
	 *
	 * A later step that resolves a different identity fails with `IDENTITY_MISMATCH`. The per-identity rate limit
	 * buckets also key on this id, so a wrong password costs a slot on the identity behind the attempt.
	 */
	identityId?: string;
}

/**
 * Parses and validates a sign-in state.
 *
 * The library runs it as one member of the `AuthDanceState` union every time it decrypts the opaque state string.
 */
export const AuthDanceStateSignIn: v.GenericSchema<AuthDanceStateSignIn> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("sign-in"),
		path: v.array(v.string()),
		identityId: v.optional(v.string()),
	}),
	v.title("AuthDanceStateSignIn"),
	v.description(
		"An authentication state object that represents a sign-in process, including the state id, kind, and path of the authentication flow.",
	),
);

/**
 * The in-progress dance of a caller who creates a new identity.
 *
 * Sign-up collects the components that sign-in verifies, so the two flows always match. The identity reaches
 * storage only at the last step, so an abandoned sign-up leaves no identity record.
 */
export interface AuthDanceStateSignUp {
	/** The id of this dance, a ksuid with an `st_` prefix. */
	id: string;
	/** The discriminator that tells the library this dance is a sign-up. */
	kind: "sign-up";
	/**
	 * The id of the identity this dance builds, a ksuid with an `id_` prefix.
	 *
	 * The library mints the id when the dance starts, so a component already sees the identity it contributes to. The
	 * identity itself reaches storage only when the dance completes. No rate limit bucket keys on this id, because
	 * a caller can always start another sign-up.
	 */
	identityId: string;
	/**
	 * The identity components collected so far, each with the private data it holds.
	 *
	 * The confirmed identifications and challenges make the path the dance walked so far. A component that waits for a
	 * validation therefore does not advance the choreography. A channel a component also yields never counts as a
	 * step.
	 */
	components: AuthDanceIdentityComponent[];
}

/** Parses and validates a sign-up state, as one member of the `AuthDanceState` union. */
export const AuthDanceStateSignUp: v.GenericSchema<AuthDanceStateSignUp> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("sign-up"),
		identityId: v.string(),
		components: v.array(AuthDanceIdentityComponent),
	}),
	v.title("AuthDanceStateSignUp"),
	v.description(
		"An authentication state object that represents a sign-up process, including the state id, kind, components, and channels of the authentication flow.",
	),
);

/**
 * The in-progress dance of an authenticated caller who adds one component to the identity.
 *
 * The flow starts from an access token instead of the first step of the choreography, and it demands a recent
 * sign-in. Past the elevated window the library answers `FRESH_SIGN_IN_REQUIRED`.
 */
export interface AuthDanceStateEnroll {
	/** The id of this dance, a ksuid with an `st_` prefix. */
	id: string;
	/** The discriminator that tells the library this dance is an enrollment. */
	kind: "enroll";
	/**
	 * The session the caller started the enrollment from.
	 *
	 * The library resolves the identity to change through this session, and the rate limit buckets key on it.
	 */
	sessionId: string;
	/** The name of the component the caller enrolls. */
	component: string;
	/**
	 * What the component produced for the submitted value: the identification or challenge itself, plus any channel
	 * it also yields.
	 *
	 * An empty list means the library has not collected the value yet. The library accepts the value once. A second
	 * value fails with `COMPONENT_ALREADY_COLLECTED`, because everything after the first belongs to the validation
	 * round.
	 */
	components: AuthDanceIdentityComponent[];
}

/** Parses and validates an enrollment state, as one member of the `AuthDanceState` union. */
export const AuthDanceStateEnroll: v.GenericSchema<AuthDanceStateEnroll> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("enroll"),
		sessionId: v.string(),
		component: v.string(),
		components: v.array(AuthDanceIdentityComponent),
	}),
	v.title("AuthDanceStateEnroll"),
	v.description(
		"An authentication state object that represents the enrollment of a component for an identity, including the state id, kind, the name of the component being enrolled and the identity components collected so far.",
	),
);

/**
 * The in-progress dance of an authenticated caller who removes one component from the identity.
 *
 * The library refuses the removal with `WOULD_LOCK_OUT` when no path through the choreography stays completable.
 * The caller answers one confirmation prompt, so this state holds no collected value.
 */
export interface AuthDanceStateUnenroll {
	/** The id of this dance, a ksuid with an `st_` prefix. */
	id: string;
	/** The discriminator that tells the library this dance is an unenrollment. */
	kind: "unenroll";
	/** The session the caller started the removal from, and the subject the rate limit buckets key on. */
	sessionId: string;
	/** The name of the component the caller removes. */
	component: string;
}

/** Parses and validates an unenrollment state, as one member of the `AuthDanceState` union. */
export const AuthDanceStateUnenroll: v.GenericSchema<AuthDanceStateUnenroll> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("unenroll"),
		sessionId: v.string(),
		component: v.string(),
	}),
	v.title("AuthDanceStateUnenroll"),
	v.description(
		"An authentication state object that represents the removal of a component from an identity, including the state id, kind, and the removed component.",
	),
);

/**
 * The in-progress dance of an authenticated caller who replaces the value of one enrolled component.
 *
 * The flow runs in two phases. First the caller proves control of the current value. Then the library collects
 * the replacement and validates it.
 */
export interface AuthDanceStateRotate {
	/** The id of this dance, a ksuid with an `st_` prefix. */
	id: string;
	/** The discriminator that tells the library this dance is a rotation. */
	kind: "rotate";
	/** The session the caller started the rotation from, and the subject the rate limit buckets key on. */
	sessionId: string;
	/** The name of the component the caller rotates. */
	component: string;
	/**
	 * True once the caller proves control of the current value.
	 *
	 * For a component that offers no verification, the library sets this flag true from the start. A code the library
	 * sends to the current email address proves control. A password typed again proves nothing the access token does
	 * not already establish. While this flag stays false, the library refuses a replacement with `CONTROL_NOT_PROVEN`.
	 */
	verified: boolean;
	/**
	 * The replacement the component produced, plus any channel it also yields.
	 *
	 * An empty list means the library has not collected the replacement yet. The library writes the replacement to
	 * the identity by name, so it supersedes the value it replaces instead of joining it.
	 */
	components: AuthDanceIdentityComponent[];
}

/** Parses and validates a rotation state, as one member of the `AuthDanceState` union. */
export const AuthDanceStateRotate: v.GenericSchema<AuthDanceStateRotate> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("rotate"),
		sessionId: v.string(),
		component: v.string(),
		verified: v.boolean(),
		components: v.array(AuthDanceIdentityComponent),
	}),
	v.title("AuthDanceStateRotate"),
	v.description(
		"An authentication state object that represents the rotation of a component for an identity, including the state id, kind, the name of the component being rotated, whether control of the currently enrolled component has been proven (true from the start for a component that offers no verification), and the identity components collected so far.",
	),
);

/**
 * The in-progress dance of a caller with no session who recovers an identity.
 *
 * The caller proves control of one component the choreography can start with. The library then resets every
 * component the choreography still requires after it, which is exactly what the caller could not provide. The flow
 * completes with a success result, never with tokens.
 */
export interface AuthDanceStateRecover {
	/** The id of this dance, a ksuid with an `st_` prefix. */
	id: string;
	/** The discriminator that tells the library this dance is a recovery. */
	kind: "recover";
	/**
	 * The name of the component the recovery started from.
	 *
	 * The component has to be an identification. It has to be verifiable. It has to be a first move of the
	 * choreography. Otherwise the library answers `COMPONENT_NOT_RECOVERABLE`. This name also opens the path the
	 * reset walks.
	 */
	component: string;
	/**
	 * The identity the recovery component resolved, absent until the caller submits the identification.
	 *
	 * The first prompt is the component's own, so nothing about the identity reaches the caller before that step. A
	 * validation call before that step fails with `RECOVERY_NOT_IDENTIFIED`.
	 */
	identityId?: string;
	/**
	 * True once the caller proves control of the component the recovery started from.
	 *
	 * The library resets nothing before then, and it answers `CONTROL_NOT_PROVEN` to a value the caller submits early.
	 */
	verified: boolean;
	/**
	 * The replacement components collected during the reset.
	 *
	 * The confirmed identifications and challenges follow the recovery component on the path, so the choreography
	 * gives the next component to reset. The library writes each replacement to the identity by name.
	 */
	components: AuthDanceIdentityComponent[];
}

/** Parses and validates a recovery state, as one member of the `AuthDanceState` union. */
export const AuthDanceStateRecover: v.GenericSchema<AuthDanceStateRecover> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("recover"),
		component: v.string(),
		identityId: v.optional(v.string()),
		verified: v.boolean(),
		components: v.array(AuthDanceIdentityComponent),
	}),
	v.title("AuthDanceStateRecover"),
	v.description(
		"An authentication state object that represents the recovery of an identity through one of its components, including the state id, kind, the name of the component the recovery started from, the identity that component resolved to, whether control of it has been proven, and the replacement components collected so far.",
	),
);

/**
 * The in-progress dance of an authenticated caller who adds a channel to the identity.
 *
 * A subscription is asymmetric. The library delivers the confirming code over a channel the identity already
 * confirmed, because the new channel proves nothing yet. Without such a channel it answers
 * `NO_VERIFICATION_CHANNEL`.
 */
export interface AuthDanceStateSubscribe {
	/** The id of this dance, a ksuid with an `st_` prefix. */
	id: string;
	/** The discriminator that tells the library this dance is a subscription. */
	kind: "subscribe";
	/** The session the caller started the subscription from, and the subject the rate limit buckets key on. */
	sessionId: string;
	/**
	 * The pending channel record, unconfirmed for as long as the dance runs.
	 *
	 * The library stores the submitted recipient in the private `data` of the record, keyed by the channel name. The
	 * record joins the components of the identity only after the code validates it.
	 */
	channel: AuthDanceIdentityChannel;
	/**
	 * False while the library still collects the recipient, true once the library accepts it.
	 *
	 * The library sets this flag when it returns the one-time code prompt. After that, it rejects a second recipient
	 * with `INVALID_STATE_FOR_FLOW`.
	 */
	validating: boolean;
}

/** Parses and validates a subscription state, as one member of the `AuthDanceState` union. */
export const AuthDanceStateSubscribe: v.GenericSchema<AuthDanceStateSubscribe> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("subscribe"),
		sessionId: v.string(),
		channel: AuthDanceIdentityChannel,
		validating: v.boolean(),
	}),
	v.title("AuthDanceStateSubscribe"),
	v.description(
		"An authentication state object that represents the subscription to a channel for an identity, including the state id, kind, and the subscribed channel.",
	),
);

/**
 * The in-progress dance of an authenticated caller who removes a channel from the identity.
 *
 * The library refuses the removal with `CHANNEL_IN_USE` while a component still links to the channel. The caller
 * answers one confirmation prompt, so this state carries no collected value.
 */
export interface AuthDanceStateUnsubscribe {
	/** The id of this dance, a ksuid with an `st_` prefix. */
	id: string;
	/** The discriminator that tells the library this dance is an unsubscription. */
	kind: "unsubscribe";
	/** The session the caller started the removal from, and the subject the rate limit buckets key on. */
	sessionId: string;
	/** The name of the channel the caller removes. */
	channel: string;
}

/** Parses and validates an unsubscription state, as one member of the `AuthDanceState` union. */
export const AuthDanceStateUnsubscribe: v.GenericSchema<AuthDanceStateUnsubscribe> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("unsubscribe"),
		sessionId: v.string(),
		channel: v.string(),
	}),
	v.title("AuthDanceStateUnsubscribe"),
	v.description(
		"An authentication state object that represents the removal of a channel from an identity, including the state id, kind, and the removed channel.",
	),
);

/**
 * The in-progress dance of an authenticated caller who deletes the whole identity.
 *
 * The flow needs a recent sign-in and one explicit confirmation, and nothing more. No component has to keep the
 * choreography completable, because the caller asked for the lock out.
 */
export interface AuthDanceStateDelete {
	/** The id of this dance, a ksuid with an `st_` prefix. */
	id: string;
	/** The discriminator that tells the library this dance is a deletion. */
	kind: "delete";
	/**
	 * The session the caller started the deletion from.
	 *
	 * The library resolves the identity to delete through this session, then deletes every session of that identity.
	 */
	sessionId: string;
}

/** Parses and validates a deletion state, as one member of the `AuthDanceState` union. */
export const AuthDanceStateDelete: v.GenericSchema<AuthDanceStateDelete> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("delete"),
		sessionId: v.string(),
	}),
	v.title("AuthDanceStateDelete"),
	v.description(
		"An authentication state object that represents the deletion of the whole identity, including the state id, kind, and the session the deletion was started from.",
	),
);

/**
 * Every shape the in-progress dance can take, one per flow. The `kind` field picks the member.
 *
 * The client holds this payload as an encrypted JWE (A256GCM) and passes it as an opaque string to every step.
 * A half-finished dance therefore needs no server-side table and no garbage collection.
 */
export type AuthDanceState =
	| AuthDanceStateSignIn
	| AuthDanceStateSignUp
	| AuthDanceStateEnroll
	| AuthDanceStateUnenroll
	| AuthDanceStateRotate
	| AuthDanceStateRecover
	| AuthDanceStateSubscribe
	| AuthDanceStateUnsubscribe
	| AuthDanceStateDelete;

/**
 * Parses and validates the payload the library reads from a decrypted state.
 *
 * The state comes from the client, so a payload that no longer matches this union is stale or forged. The library
 * answers `INVALID_STATE` for such a payload instead of a server fault.
 */
export const AuthDanceState: v.GenericSchema<AuthDanceState> = v.pipe(
	v.union([
		AuthDanceStateSignIn,
		AuthDanceStateSignUp,
		AuthDanceStateEnroll,
		AuthDanceStateUnenroll,
		AuthDanceStateRotate,
		AuthDanceStateRecover,
		AuthDanceStateSubscribe,
		AuthDanceStateUnsubscribe,
		AuthDanceStateDelete,
	]),
	v.title("AuthDanceState"),
	v.description(
		"An authentication state object that can represent various authentication processes, including sign-in, sign-up, and component/channel management.",
	),
);
