import * as v from "valibot";
import { AuthDanceIdentityChannel } from "./identity.ts";

// export interface AuthDanceMessage {
// 	identityId: string;
// 	subject: string;
// 	content: Record<string, string>;
// }

// export const AuthDanceMessage: v.GenericSchema<AuthDanceMessage> = v.pipe(
// 	v.object({
// 		identityId: v.string(),
// 		subject: v.string(),
// 		content: v.record(v.string(), v.string()),
// 	}),
// 	v.title("AuthDanceMessage"),
// 	v.description("An auth message object that contains a identityId, subject, and content."),
// );

export interface AuthDanceMessage {
	recipient: AuthDanceIdentityChannel;
	subject: string;
	content: Record<string, string>;
}

export const AuthDanceMessage: v.GenericSchema<AuthDanceMessage> = v.pipe(
	v.object({
		recipient: AuthDanceIdentityChannel,
		subject: v.string(),
		content: v.record(v.string(), v.string()),
	}),
	v.title("AuthDanceMessage"),
	v.description("An auth message object that contains a recipient, subject, and content."),
);
