import * as v from "valibot";
import { IdentityChannel } from "./identity.ts";

// export interface AuthMessage {
// 	identityId: string;
// 	subject: string;
// 	content: Record<string, string>;
// }

// export const AuthMessage: v.GenericSchema<AuthMessage> = v.pipe(
// 	v.object({
// 		identityId: v.string(),
// 		subject: v.string(),
// 		content: v.record(v.string(), v.string()),
// 	}),
// 	v.title("AuthMessage"),
// 	v.description("An auth message object that contains a identityId, subject, and content."),
// );

export interface AuthMessage {
	recipient: IdentityChannel;
	subject: string;
	content: Record<string, string>;
}

export const AuthMessage: v.GenericSchema<AuthMessage> = v.pipe(
	v.object({
		recipient: IdentityChannel,
		subject: v.string(),
		content: v.record(v.string(), v.string()),
	}),
	v.title("AuthMessage"),
	v.description("An auth message object that contains a recipient, subject, and content."),
);
