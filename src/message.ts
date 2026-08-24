import * as v from "valibot";
import { AuthDanceIdentityChannel } from "./identity.ts";

/**
 * The payload a channel delivers.
 *
 * A component builds a message in `sendPrompt`. The library hands the message to the channel that `recipient.channel`
 * names. It raises `UnknownChannelError` when no channel carries that name.
 */
export interface AuthDanceMessage {
	/**
	 * The channel record of the identity that receives the message. The private `data` holds the recipient that channel
	 * needs, the address for example.
	 */
	recipient: AuthDanceIdentityChannel;
	/** The subject line of the message, the title of a mail for example. */
	subject: string;
	/**
	 * The body of the message, one entry per media type. `OtpAuthDanceComponent` puts the bare one-time code under
	 * `text/x-code`.
	 */
	content: Record<string, string>;
}

/** Parses and validates a message at runtime. */
export const AuthDanceMessage: v.GenericSchema<AuthDanceMessage> = v.pipe(
	v.object({
		recipient: AuthDanceIdentityChannel,
		subject: v.string(),
		content: v.record(v.string(), v.string()),
	}),
	v.title("AuthDanceMessage"),
	v.description("An auth message object that contains a recipient, subject, and content."),
);
