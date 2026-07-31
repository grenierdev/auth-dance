import type { Identity, IdentityComponent } from "./identity.ts";
import type { AuthDanceMessage } from "./message.ts";
import type { AuthDancePromptInput } from "./prompt.ts";
import type { AuthDanceStorage } from "./storage.ts";

export interface AuthDanceComponentContext {
	storage: AuthDanceStorage;
	stateId: string;
	name: string;
	flow: string;
	identity?: Identity;
}

export interface AuthDanceComponent {
	// What the component contributes to an identity: an "identification" resolves an identity on its own
	// (an email address), a "challenge" can only be checked against one (a password).
	kind: IdentityComponent["kind"];
	// Whether the component can prove control of its own value — an OTP sent to the address it identifies
	// with proves something, re-typing a password proves nothing. Implies `verificationComponent`.
	verifiable: boolean;
	getPrompt(context: AuthDanceComponentContext): Promise<AuthDancePromptInput>;
	sendPrompt?(locale: string, context: AuthDanceComponentContext): Promise<AuthDanceMessage>;
	getIdentityComponent(component: string, value: unknown, confirmed: boolean): Promise<IdentityComponent[]>;
	verificationComponent?(context: AuthDanceComponentContext): Promise<AuthDanceComponent>;
	verifyPrompt(value: unknown, context: AuthDanceComponentContext): Promise<boolean | Identity["id"]>;
}
