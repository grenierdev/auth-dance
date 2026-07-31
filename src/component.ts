import type { Identity, IdentityComponent } from "./identity.ts";
import type { AuthMessage } from "./message.ts";
import type { AuthPromptInput } from "./prompt.ts";
import type { AuthStorage } from "./storage.ts";

export interface AuthComponentContext {
	storage: AuthStorage;
	stateId: string;
	name: string;
	flow: string;
	identity?: Identity;
}

export interface AuthComponent {
	// What the component contributes to an identity: an "identification" resolves an identity on its own
	// (an email address), a "challenge" can only be checked against one (a password).
	kind: IdentityComponent["kind"];
	// Whether the component can prove control of its own value — an OTP sent to the address it identifies
	// with proves something, re-typing a password proves nothing. Implies `verificationComponent`.
	verifiable: boolean;
	getPrompt(context: AuthComponentContext): Promise<AuthPromptInput>;
	sendPrompt?(locale: string, context: AuthComponentContext): Promise<AuthMessage>;
	getIdentityComponent(component: string, value: unknown, confirmed: boolean): Promise<IdentityComponent[]>;
	verificationComponent?(context: AuthComponentContext): Promise<AuthComponent>;
	verifyPrompt(value: unknown, context: AuthComponentContext): Promise<boolean | Identity["id"]>;
}
