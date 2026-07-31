import { IdentityChannel, IdentityComponent } from "./identity.ts";
import * as v from "valibot";

export interface AuthStateSignIn {
	id: string;
	kind: "sign-in";
	path: string[];
	identityId?: string;
}

export const AuthStateSignIn: v.GenericSchema<AuthStateSignIn> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("sign-in"),
		path: v.array(v.string()),
		identityId: v.optional(v.string()),
	}),
	v.title("AuthStateSignIn"),
	v.description(
		"An authentication state object that represents a sign-in process, including the state id, kind, and path of the authentication flow.",
	),
);

export interface AuthStateSignUp {
	id: string;
	kind: "sign-up";
	identityId: string;
	components: IdentityComponent[];
}

export const AuthStateSignUp: v.GenericSchema<AuthStateSignUp> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("sign-up"),
		identityId: v.string(),
		components: v.array(IdentityComponent),
	}),
	v.title("AuthStateSignUp"),
	v.description(
		"An authentication state object that represents a sign-up process, including the state id, kind, components, and channels of the authentication flow.",
	),
);

export interface AuthStateEnroll {
	id: string;
	kind: "enroll";
	sessionId: string;
	component: string;
	components: IdentityComponent[];
}

export const AuthStateEnroll: v.GenericSchema<AuthStateEnroll> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("enroll"),
		sessionId: v.string(),
		component: v.string(),
		components: v.array(IdentityComponent),
	}),
	v.title("AuthStateEnroll"),
	v.description(
		"An authentication state object that represents the enrollment of a component for an identity, including the state id, kind, the name of the component being enrolled and the identity components collected so far.",
	),
);

export interface AuthStateUnenroll {
	id: string;
	kind: "unenroll";
	sessionId: string;
	component: string;
}

export const AuthStateUnenroll: v.GenericSchema<AuthStateUnenroll> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("unenroll"),
		sessionId: v.string(),
		component: v.string(),
	}),
	v.title("AuthStateUnenroll"),
	v.description(
		"An authentication state object that represents the removal of a component from an identity, including the state id, kind, and the removed component.",
	),
);

export interface AuthStateRotate {
	id: string;
	kind: "rotate";
	sessionId: string;
	component: string;
	verified: boolean;
	components: IdentityComponent[];
}

export const AuthStateRotate: v.GenericSchema<AuthStateRotate> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("rotate"),
		sessionId: v.string(),
		component: v.string(),
		verified: v.boolean(),
		components: v.array(IdentityComponent),
	}),
	v.title("AuthStateRotate"),
	v.description(
		"An authentication state object that represents the rotation of a component for an identity, including the state id, kind, the name of the component being rotated, whether control of the currently enrolled component has been proven (true from the start for a component that offers no verification), and the identity components collected so far.",
	),
);

export interface AuthStateRecover {
	id: string;
	kind: "recover";
	component: string;
	identityId?: string;
	verified: boolean;
	components: IdentityComponent[];
}

export const AuthStateRecover: v.GenericSchema<AuthStateRecover> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("recover"),
		component: v.string(),
		identityId: v.optional(v.string()),
		verified: v.boolean(),
		components: v.array(IdentityComponent),
	}),
	v.title("AuthStateRecover"),
	v.description(
		"An authentication state object that represents the recovery of an identity through one of its components, including the state id, kind, the name of the component the recovery started from, the identity that component resolved to, whether control of it has been proven, and the replacement components collected so far.",
	),
);

export interface AuthStateSubscribe {
	id: string;
	kind: "subscribe";
	sessionId: string;
	channel: IdentityChannel;
	validating: boolean;
}

export const AuthStateSubscribe: v.GenericSchema<AuthStateSubscribe> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("subscribe"),
		sessionId: v.string(),
		channel: IdentityChannel,
		validating: v.boolean(),
	}),
	v.title("AuthStateSubscribe"),
	v.description(
		"An authentication state object that represents the subscription to a channel for an identity, including the state id, kind, and the subscribed channel.",
	),
);

export interface AuthStateUnsubscribe {
	id: string;
	kind: "unsubscribe";
	sessionId: string;
	channel: string;
}

export const AuthStateUnsubscribe: v.GenericSchema<AuthStateUnsubscribe> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("unsubscribe"),
		sessionId: v.string(),
		channel: v.string(),
	}),
	v.title("AuthStateUnsubscribe"),
	v.description(
		"An authentication state object that represents the removal of a channel from an identity, including the state id, kind, and the removed channel.",
	),
);

export interface AuthStateDelete {
	id: string;
	kind: "delete";
	sessionId: string;
}

export const AuthStateDelete: v.GenericSchema<AuthStateDelete> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("delete"),
		sessionId: v.string(),
	}),
	v.title("AuthStateDelete"),
	v.description(
		"An authentication state object that represents the deletion of the whole identity, including the state id, kind, and the session the deletion was started from.",
	),
);

export type AuthState =
	| AuthStateSignIn
	| AuthStateSignUp
	| AuthStateEnroll
	| AuthStateUnenroll
	| AuthStateRotate
	| AuthStateRecover
	| AuthStateSubscribe
	| AuthStateUnsubscribe
	| AuthStateDelete;

export const AuthState: v.GenericSchema<AuthState> = v.pipe(
	v.union([
		AuthStateSignIn,
		AuthStateSignUp,
		AuthStateEnroll,
		AuthStateUnenroll,
		AuthStateRotate,
		AuthStateRecover,
		AuthStateSubscribe,
		AuthStateUnsubscribe,
		AuthStateDelete,
	]),
	v.title("AuthState"),
	v.description(
		"An authentication state object that can represent various authentication processes, including sign-in, sign-up, and component/channel management.",
	),
);
