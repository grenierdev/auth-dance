import { AuthDanceIdentityChannel, AuthDanceIdentityComponent } from "./identity.ts";
import * as v from "valibot";

/** The in-progress dance of an owner who signs in to an identity that already exists. */
export interface AuthDanceStateSignIn {
	/** The id of this dance, a ksuid with an `st_` prefix. */
	id: string;
	/** The discriminator for a sign-in dance. */
	kind: "sign-in";
	/** The names of the components the owner already answered, oldest first. */
	path: string[];
	/**
	 * The identity a component resolved, absent until one step resolves it.
	 * A later step that resolves a different identity fails with `IDENTITY_MISMATCH`.
	 */
	identityId?: string;
}

/** Parses and validates a sign-in state. */
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

/** The in-progress dance of an owner who creates a new identity. The identity reaches storage only at the last step. */
export interface AuthDanceStateSignUp {
	/** The id of this dance, a ksuid with an `st_` prefix. */
	id: string;
	/** The discriminator for a sign-up dance. */
	kind: "sign-up";
	/** The id of the identity this dance builds, a ksuid with an `id_` prefix. The library mints it when the dance starts. */
	identityId: string;
	/** The identity components collected so far. A component that waits for a validation does not advance the choreography. */
	components: AuthDanceIdentityComponent[];
}

/** Parses and validates a sign-up state. */
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
 * The in-progress dance of an authenticated owner who adds one component to the identity.
 * The flow needs a recent sign-in. Past the elevated window the library answers `FRESH_SIGN_IN_REQUIRED`.
 */
export interface AuthDanceStateEnroll {
	/** The id of this dance, a ksuid with an `st_` prefix. */
	id: string;
	/** The discriminator for an enrollment dance. */
	kind: "enroll";
	/** The session the owner started the enrollment from, and the subject the rate limit buckets key on. */
	sessionId: string;
	/** The name of the component the owner enrolls. */
	component: string;
	/** What the component produced, plus any channel it also yields. A second value fails with `COMPONENT_ALREADY_COLLECTED`. */
	components: AuthDanceIdentityComponent[];
}

/** Parses and validates an enrollment state. */
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
 * The in-progress dance of an authenticated owner who removes one component from the identity.
 * The library refuses the removal with `WOULD_LOCK_OUT` when no path through the choreography stays completable.
 */
export interface AuthDanceStateUnenroll {
	/** The id of this dance, a ksuid with an `st_` prefix. */
	id: string;
	/** The discriminator for an unenrollment dance. */
	kind: "unenroll";
	/** The session the owner started the removal from, and the subject the rate limit buckets key on. */
	sessionId: string;
	/** The name of the component the owner removes. */
	component: string;
}

/** Parses and validates an unenrollment state. */
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

/** The in-progress dance of an authenticated owner who replaces the value of one enrolled component. */
export interface AuthDanceStateRotate {
	/** The id of this dance, a ksuid with an `st_` prefix. */
	id: string;
	/** The discriminator for a rotation dance. */
	kind: "rotate";
	/** The session the owner started the rotation from, and the subject the rate limit buckets key on. */
	sessionId: string;
	/** The name of the component the owner rotates. */
	component: string;
	/**
	 * True once the owner proves control of the current value. The library sets it true from the start for a component
	 * with no verification step. While this flag stays false, `submitPrompt` reads the value it gets as that proof.
	 */
	verified: boolean;
	/** The replacement the component produced, plus any channel it also yields. The library writes it to the identity by name. */
	components: AuthDanceIdentityComponent[];
}

/** Parses and validates a rotation state. */
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
 * The in-progress dance of an owner with no session who recovers one component of an identity.
 * The owner picks another component to prove control through. The flow completes with a success result, never with tokens.
 */
export interface AuthDanceStateRecover {
	/** The id of this dance, a ksuid with an `st_` prefix. */
	id: string;
	/** The discriminator for a recovery dance. */
	kind: "recover";
	/**
	 * The name of the component the recovery resets, as the owner named it.
	 * The library answers `COMPONENT_NOT_RECOVERABLE` when no other step can identify the owner and prove control on its own.
	 */
	component: string;
	/** The name of the component the owner proves control through, absent until the owner picks one. */
	identification?: string;
	/** The identity the picked component resolved. A validation call before that step fails with `RECOVERY_NOT_IDENTIFIED`. */
	identityId?: string;
	/** True once the owner proves control of the picked component. Before that, `submitPrompt` reads a value as the proof. */
	verified: boolean;
	/** The replacement the recovered component produced, plus any channel it also yields. The library writes it by name. */
	components: AuthDanceIdentityComponent[];
}

/** Parses and validates a recovery state. */
export const AuthDanceStateRecover: v.GenericSchema<AuthDanceStateRecover> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("recover"),
		component: v.string(),
		identification: v.optional(v.string()),
		identityId: v.optional(v.string()),
		verified: v.boolean(),
		components: v.array(AuthDanceIdentityComponent),
	}),
	v.title("AuthDanceStateRecover"),
	v.description(
		"An authentication state object that represents the recovery of one component of an identity, including the state id, kind, the name of the component being recovered, the component the caller proves control through, the identity that component resolved to, whether control of it has been proven, and the replacement collected so far.",
	),
);

/**
 * The in-progress dance of an authenticated owner who adds a channel to the identity.
 * The library delivers the one-time code over the new channel itself, to the recipient this dance collects.
 */
export interface AuthDanceStateSubscribe {
	/** The id of this dance, a ksuid with an `st_` prefix. */
	id: string;
	/** The discriminator for a subscription dance. */
	kind: "subscribe";
	/** The session the owner started the subscription from, and the subject the rate limit buckets key on. */
	sessionId: string;
	/**
	 * The pending channel record, unconfirmed for as long as the dance runs. The library stores the submitted recipient in
	 * the private `data` of the record, keyed by the channel name.
	 */
	channel: AuthDanceIdentityChannel;
	/** True once the library accepts the recipient. After that, `submitPrompt` reads the value it gets as the one-time code. */
	validating: boolean;
}

/** Parses and validates a subscription state. */
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
 * The in-progress dance of an authenticated owner who removes a channel from the identity.
 * The removal takes every component the channel links to with it. The library refuses it with `WOULD_LOCK_OUT` when no
 * path through the choreography survives that set.
 */
export interface AuthDanceStateUnsubscribe {
	/** The id of this dance, a ksuid with an `st_` prefix. */
	id: string;
	/** The discriminator for an unsubscription dance. */
	kind: "unsubscribe";
	/** The session the owner started the removal from, and the subject the rate limit buckets key on. */
	sessionId: string;
	/** The name of the channel the owner removes. */
	channel: string;
}

/** Parses and validates an unsubscription state. */
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

/** The in-progress dance of an authenticated owner who deletes the whole identity. It needs a recent sign-in and one confirmation. */
export interface AuthDanceStateDelete {
	/** The id of this dance, a ksuid with an `st_` prefix. */
	id: string;
	/** The discriminator for a deletion dance. */
	kind: "delete";
	/** The session the owner started the deletion from. The library deletes every session of that identity. */
	sessionId: string;
}

/** Parses and validates a deletion state. */
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
 * The client holds this payload as an encrypted JWE (A256GCM) and passes it as an opaque string to every step.
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

/** Parses and validates a decrypted state payload. A payload that does not match this union answers `INVALID_STATE`. */
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
