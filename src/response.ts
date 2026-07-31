import * as v from "valibot";
import { IdentityComponentPublic } from "./identity.ts";
import { AuthPrompt } from "./prompt.ts";
import { AuthSession } from "./session.ts";

export interface AuthResponseState {
	state: string;
	prompt: AuthPrompt;
	expireAt: Date;
}

export const AuthResponseState: v.GenericSchema<AuthResponseState> = v.pipe(
	v.object({
		state: v.string(),
		prompt: AuthPrompt,
		expireAt: v.date(),
	}),
	v.title("AuthResponseState"),
	v.description("The state of an authentication response"),
);

export interface AuthResponseTokens {
	tokens: {
		access_token: string;
		id_token: string;
		refresh_token: string;
	};
	session: AuthSession;
	identity: {
		id: string;
		data?: Record<string, unknown>;
	};
}

export const AuthResponseTokens: v.GenericSchema<AuthResponseTokens> = v.pipe(
	v.object({
		tokens: v.object({
			access_token: v.string(),
			id_token: v.string(),
			refresh_token: v.string(),
		}),
		session: AuthSession,
		identity: v.pipe(
			v.object({
				id: v.string(),
				data: v.optional(v.record(v.string(), v.unknown())),
			}),
			v.title("AuthResponseIdentity"),
			v.description("The identity returned from the auth API"),
		),
	}),
	v.title("AuthResponseTokens"),
	v.description("The tokens returned from the auth API"),
);

export interface AuthResponseResult {
	success: true;
}

export const AuthResponseResult: v.GenericSchema<AuthResponseResult> = v.pipe(
	v.object({
		success: v.literal(true),
	}),
	v.title("AuthResponseResult"),
	v.description("A successful result from the auth API that carries no further payload"),
);

export interface AuthResponseSessions {
	sessions: AuthSession[];
	current: string;
}

export const AuthResponseSessions: v.GenericSchema<AuthResponseSessions> = v.pipe(
	v.object({
		sessions: v.array(AuthSession),
		current: v.string(),
	}),
	v.title("AuthResponseSessions"),
	v.description("Every session currently open on the identity, and which of them made the call"),
);

export interface AuthResponseComponents {
	components: IdentityComponentPublic[];
}

export const AuthResponseComponents: v.GenericSchema<AuthResponseComponents> = v.pipe(
	v.object({
		components: v.array(IdentityComponentPublic),
	}),
	v.title("AuthResponseComponents"),
	v.description(
		"Every component enrolled on the identity — its identifications, its challenges and its channels — without the private data each holds",
	),
);

export type AuthResponse = AuthResponseState | AuthResponseTokens | AuthResponseResult;

export const AuthResponse: v.GenericSchema<AuthResponse> = v.pipe(
	v.union([AuthResponseState, AuthResponseTokens, AuthResponseResult]),
	v.title("AuthResponse"),
	v.description("The response from the auth API"),
);
