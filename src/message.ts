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

/**
 * The payload a channel delivers.
 *
 * A component builds a message in `sendPrompt`. The library then hands the message to the channel that
 * `recipient.channel` names, and raises `UnknownChannelError` when no channel carries that name.
 */
export interface AuthDanceMessage {
	/**
	 * The channel record of the identity that receives the message. The `channel` name selects the channel that
	 * delivers. The private `data` holds the recipient that channel needs, the address for example.
	 */
	recipient: AuthDanceIdentityChannel;
	/** The subject line of the message, the title of a mail for example. */
	subject: string;
	/**
	 * The body of the message, one entry per media type. `OtpAuthDanceComponent` puts the bare code under
	 * `text/x-code`, and it fills `text/plain` and `text/html` with placeholders.
	 */
	content: Record<string, string>;
}

/**
 * Parses and validates a message at runtime, and checks `recipient` with the
 * {@link AuthDanceIdentityChannel} schema.
 *
 * No HTTP route accepts a message. A caller uses this schema to check a payload of its own before it calls
 * `sendMessage`.
 */
export const AuthDanceMessage: v.GenericSchema<AuthDanceMessage> = v.pipe(
	v.object({
		recipient: AuthDanceIdentityChannel,
		subject: v.string(),
		content: v.record(v.string(), v.string()),
	}),
	v.title("AuthDanceMessage"),
	v.description("An auth message object that contains a recipient, subject, and content."),
);
