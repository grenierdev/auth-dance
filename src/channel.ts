import type { Identity, IdentityChannel } from "./identity.ts";
import type { AuthMessage } from "./message.ts";
import type { AuthPromptInput } from "./prompt.ts";
import type { AuthStorage } from "./storage.ts";

export interface AuthChannelContext {
	storage: AuthStorage;
	stateId: string;
	name: string;
	flow: string;
	identity?: Identity;
}

export interface AuthChannel {
	sendMessage(message: AuthMessage): Promise<void>;
	getPrompt(context: AuthChannelContext): Promise<AuthPromptInput>;
	getIdentityChannel(channel: string, value: unknown, confirmed: boolean): Promise<IdentityChannel>;
}
