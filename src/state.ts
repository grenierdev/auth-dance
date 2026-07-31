import { IdentityChannel, IdentityComponent } from "./identity.ts";
import * as v from "valibot";

export interface AuthDanceStateSignIn {
	id: string;
	kind: "sign-in";
	path: string[];
	identityId?: string;
}

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

export interface AuthDanceStateSignUp {
	id: string;
	kind: "sign-up";
	identityId: string;
	components: IdentityComponent[];
}

export const AuthDanceStateSignUp: v.GenericSchema<AuthDanceStateSignUp> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("sign-up"),
		identityId: v.string(),
		components: v.array(IdentityComponent),
	}),
	v.title("AuthDanceStateSignUp"),
	v.description(
		"An authentication state object that represents a sign-up process, including the state id, kind, components, and channels of the authentication flow.",
	),
);

export interface AuthDanceStateEnroll {
	id: string;
	kind: "enroll";
	sessionId: string;
	component: string;
	components: IdentityComponent[];
}

export const AuthDanceStateEnroll: v.GenericSchema<AuthDanceStateEnroll> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("enroll"),
		sessionId: v.string(),
		component: v.string(),
		components: v.array(IdentityComponent),
	}),
	v.title("AuthDanceStateEnroll"),
	v.description(
		"An authentication state object that represents the enrollment of a component for an identity, including the state id, kind, the name of the component being enrolled and the identity components collected so far.",
	),
);

export interface AuthDanceStateUnenroll {
	id: string;
	kind: "unenroll";
	sessionId: string;
	component: string;
}

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

export interface AuthDanceStateRotate {
	id: string;
	kind: "rotate";
	sessionId: string;
	component: string;
	verified: boolean;
	components: IdentityComponent[];
}

export const AuthDanceStateRotate: v.GenericSchema<AuthDanceStateRotate> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("rotate"),
		sessionId: v.string(),
		component: v.string(),
		verified: v.boolean(),
		components: v.array(IdentityComponent),
	}),
	v.title("AuthDanceStateRotate"),
	v.description(
		"An authentication state object that represents the rotation of a component for an identity, including the state id, kind, the name of the component being rotated, whether control of the currently enrolled component has been proven (true from the start for a component that offers no verification), and the identity components collected so far.",
	),
);

export interface AuthDanceStateRecover {
	id: string;
	kind: "recover";
	component: string;
	identityId?: string;
	verified: boolean;
	components: IdentityComponent[];
}

export const AuthDanceStateRecover: v.GenericSchema<AuthDanceStateRecover> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("recover"),
		component: v.string(),
		identityId: v.optional(v.string()),
		verified: v.boolean(),
		components: v.array(IdentityComponent),
	}),
	v.title("AuthDanceStateRecover"),
	v.description(
		"An authentication state object that represents the recovery of an identity through one of its components, including the state id, kind, the name of the component the recovery started from, the identity that component resolved to, whether control of it has been proven, and the replacement components collected so far.",
	),
);

export interface AuthDanceStateSubscribe {
	id: string;
	kind: "subscribe";
	sessionId: string;
	channel: IdentityChannel;
	validating: boolean;
}

export const AuthDanceStateSubscribe: v.GenericSchema<AuthDanceStateSubscribe> = v.pipe(
	v.object({
		id: v.string(),
		kind: v.literal("subscribe"),
		sessionId: v.string(),
		channel: IdentityChannel,
		validating: v.boolean(),
	}),
	v.title("AuthDanceStateSubscribe"),
	v.description(
		"An authentication state object that represents the subscription to a channel for an identity, including the state id, kind, and the subscribed channel.",
	),
);

export interface AuthDanceStateUnsubscribe {
	id: string;
	kind: "unsubscribe";
	sessionId: string;
	channel: string;
}

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

export interface AuthDanceStateDelete {
	id: string;
	kind: "delete";
	sessionId: string;
}

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
