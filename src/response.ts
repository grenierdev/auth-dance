import * as v from "valibot";
import { AuthDanceIdentityComponentPublic } from "./identity.ts";
import { AuthDancePrompt } from "./prompt.ts";
import { AuthDanceSession } from "./session.ts";

export interface AuthDanceResponseState {
	state: string;
	prompt: AuthDancePrompt;
	expireAt: Date;
}

export const AuthDanceResponseState: v.GenericSchema<AuthDanceResponseState> = v.pipe(
	v.object({
		state: v.string(),
		prompt: AuthDancePrompt,
		expireAt: v.date(),
	}),
	v.title("AuthDanceResponseState"),
	v.description("The state of an authentication response"),
);

export interface AuthDanceResponseTokens {
	tokens: {
		access_token: string;
		id_token: string;
		refresh_token: string;
	};
	session: AuthDanceSession;
	identity: {
		id: string;
		data?: Record<string, unknown>;
	};
}

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

export interface AuthDanceResponseResult {
	success: true;
}

export const AuthDanceResponseResult: v.GenericSchema<AuthDanceResponseResult> = v.pipe(
	v.object({
		success: v.literal(true),
	}),
	v.title("AuthDanceResponseResult"),
	v.description("A successful result from the auth API that carries no further payload"),
);

export interface AuthDanceResponseSessions {
	sessions: AuthDanceSession[];
	current: string;
}

export const AuthDanceResponseSessions: v.GenericSchema<AuthDanceResponseSessions> = v.pipe(
	v.object({
		sessions: v.array(AuthDanceSession),
		current: v.string(),
	}),
	v.title("AuthDanceResponseSessions"),
	v.description("Every session currently open on the identity, and which of them made the call"),
);

export interface AuthDanceResponseComponents {
	components: AuthDanceIdentityComponentPublic[];
}

export const AuthDanceResponseComponents: v.GenericSchema<AuthDanceResponseComponents> = v.pipe(
	v.object({
		components: v.array(AuthDanceIdentityComponentPublic),
	}),
	v.title("AuthDanceResponseComponents"),
	v.description(
		"Every component enrolled on the identity — its identifications, its challenges and its channels — without the private data each holds",
	),
);

export type AuthDanceResponse = AuthDanceResponseState | AuthDanceResponseTokens | AuthDanceResponseResult;

export const AuthDanceResponse: v.GenericSchema<AuthDanceResponse> = v.pipe(
	v.union([AuthDanceResponseState, AuthDanceResponseTokens, AuthDanceResponseResult]),
	v.title("AuthDanceResponse"),
	v.description("The response from the auth API"),
);
