/**
 * @module
 *
 * The nine flows.
 *
 * The client starts a flow, answers each prompt at `/submit-prompt`, and repeats until the answer carries tokens or a
 * plain success. The state between two calls is the opaque string the library hands back.
 */

import type { AuthDancePrompt, AuthDancePromptInput } from "auth-dance";

/** What a flow needs before it starts. */
export interface FlowDefinition {
	/** What a button shows. */
	label: string;
	/** The route that starts the flow. */
	path: string;
	/** Whether the start carries a bearer token. Every authenticated flow also needs a recent sign-in. */
	authenticated: boolean;
	/** What the body names: nothing, a component, or a channel of `api.channels`. */
	argument: "none" | "component" | "channel";
}

/**
 * Every flow the library runs, under the name its route uses.
 *
 * The six authenticated flows check the elevated window first. Past `durations.elevated` they answer
 * `FRESH_SIGN_IN_REQUIRED`.
 */
export const FLOWS = {
	"sign-in": { label: "Sign in", path: "/sign-in", authenticated: false, argument: "none" },
	"sign-up": { label: "Sign up", path: "/sign-up", authenticated: false, argument: "none" },
	"recover": { label: "Recover", path: "/recover", authenticated: false, argument: "component" },
	"enroll": { label: "Enroll", path: "/enroll", authenticated: true, argument: "component" },
	"unenroll": { label: "Unenroll", path: "/unenroll", authenticated: true, argument: "component" },
	"rotate": { label: "Rotate", path: "/rotate", authenticated: true, argument: "component" },
	"subscribe": { label: "Subscribe", path: "/subscribe", authenticated: true, argument: "channel" },
	"unsubscribe": { label: "Unsubscribe", path: "/unsubscribe", authenticated: true, argument: "channel" },
	"delete": { label: "Delete identity", path: "/delete", authenticated: true, argument: "none" },
} as const satisfies Record<string, FlowDefinition>;

/** The name of a flow, and the key of {@link FLOWS}. */
export type FlowName = keyof typeof FLOWS;

/** The flow names, in the order the start card lists them. */
export const FLOW_NAMES = Object.keys(FLOWS) as FlowName[];

/** One flow in progress. */
export interface Step {
	/** The flow that is running. */
	flow: FlowName;
	/** The opaque state of the dance in progress. Every later call echoes it back. */
	state: string;
	/** What the owner answers next: one input, or a choice between branches. */
	prompt: AuthDancePrompt;
	/** The moment the flow expires, as an ISO 8601 string. */
	expireAt: string;
	/** The names answered so far in this flow. */
	trail: string[];
}

/** Every input a prompt puts on screen: the prompt itself, or one field per branch of a choice. */
export function promptInputs(prompt: AuthDancePrompt): AuthDancePromptInput[] {
	if (prompt.kind === "input") {
		return [prompt];
	}
	return prompt.components.filter((branch): branch is AuthDancePromptInput => branch.kind === "input");
}

/** The prompt the owner is answering. A name that is not a branch of a choice earns `COMPONENT_NOT_IN_CHOREOGRAPHY`. */
export function activePrompt(prompt: AuthDancePrompt, branch?: string): AuthDancePromptInput | undefined {
	if (prompt.kind === "input") {
		return prompt;
	}
	return promptInputs(prompt).find((candidate) => candidate.name === branch);
}

/** Whether the current step is worth a send button. `sendable` alone does not mean there is something to deliver. */
export function isSendable(step: Step): boolean {
	return promptInputs(step.prompt).some((input) => input.sendable && input.type === "otp");
}
