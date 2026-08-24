import type { AuthDanceIdentity, AuthDanceIdentityChannel } from "./identity.ts";
import type { AuthDanceMessage } from "./message.ts";
import type { AuthDancePromptInput } from "./prompt.ts";
import type { AuthDanceStorage } from "./storage.ts";

/** What the library hands a channel when it asks for a prompt. `getPrompt` is the only method that reads this context. */
export interface AuthDanceChannelContext {
	/** The store the channel reads and writes through. A channel keeps its own records in the key-value part. */
	storage: AuthDanceStorage;
	/** The id of the dance in progress. A channel that writes a record for this dance keys the record on this id. */
	stateId: string;
	/** The name the library registered the channel under. The channel puts the name in the prompt it builds. */
	name: string;
	/** Which flow runs this step. Only `subscribe` builds this context, so the value is `subscribe`. */
	flow: string;
	/** The identity the flow acts for. `subscribe` resolves it before it collects anything, so a channel always reads one. */
	identity?: AuthDanceIdentity;
}

/** Where the library delivers a message. A deployment implements this interface once per medium, mail or SMS. */
export interface AuthDanceChannel {
	/**
	 * Delivers one message to the recipient the message carries. The library calls this method for a prompt, a
	 * validation, `AuthDanceApi.sendMessageTo` and `AuthDanceApi.sendMessage`.
	 */
	sendMessage(message: AuthDanceMessage): Promise<void>;
	/** Builds the prompt that collects the recipient, the address or the phone number a `subscribe` attaches. */
	getPrompt(context: AuthDanceChannelContext): Promise<AuthDancePromptInput>;
	/**
	 * Converts a collected recipient into the channel record an identity holds. The recipient goes in the private
	 * `data` bag of that record, and the library never discloses that bag to a client. No flow calls this method.
	 *
	 * @param channel The name to store the record under.
	 * @param value The recipient the owner submitted.
	 * @param confirmed Whether the owner already proved control of `value`.
	 */
	getIdentityChannel(channel: string, value: unknown, confirmed: boolean): Promise<AuthDanceIdentityChannel>;
}
