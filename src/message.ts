import * as v from "valibot";
import { IdentityChannel } from "./identity.ts";

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
	recipient: IdentityChannel;
	subject: string;
	content: Record<string, string>;
}

export const AuthDanceMessage: v.GenericSchema<AuthDanceMessage> = v.pipe(
	v.object({
		recipient: IdentityChannel,
		subject: v.string(),
		content: v.record(v.string(), v.string()),
	}),
	v.title("AuthDanceMessage"),
	v.description("An auth message object that contains a recipient, subject, and content."),
);
