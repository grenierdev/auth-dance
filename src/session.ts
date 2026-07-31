import * as v from "valibot";

export interface AuthDanceSession {
	id: string;
	identityId: string;
	scopes: string[];
	expireAt: string;
	address?: string;
	userAgent?: string;
}

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
