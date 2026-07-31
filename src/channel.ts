import type { AuthDanceIdentity, AuthDanceIdentityChannel } from "./identity.ts";
import type { AuthDanceMessage } from "./message.ts";
import type { AuthDancePromptInput } from "./prompt.ts";
import type { AuthDanceStorage } from "./storage.ts";

export interface AuthDanceChannelContext {
	storage: AuthDanceStorage;
	stateId: string;
	name: string;
	flow: string;
	identity?: AuthDanceIdentity;
}

export interface AuthDanceChannel {
	sendMessage(message: AuthDanceMessage): Promise<void>;
	getPrompt(context: AuthDanceChannelContext): Promise<AuthDancePromptInput>;
	getIdentityChannel(channel: string, value: unknown, confirmed: boolean): Promise<AuthDanceIdentityChannel>;
}
