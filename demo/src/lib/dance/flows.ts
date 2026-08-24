/**
 * @module
 *
 * The nine flows.
 *
 * A flow works the same way everywhere: the client starts one, receives a prompt, submits a value to
 * `/submit-prompt`, receives the next prompt, and repeats until the answer carries tokens or a plain success. The
 * state between two calls is the opaque string the library hands back, so the page keeps nothing else.
 *
 * A prompt that collects a value and a prompt that proves control of a value already collected look the same, and
 * they go to the same route. The state carries which of the two the flow is waiting for, so the client keeps no
 * record of it.
 *
 * Everything here is a pure function of what came back. No React, no store, no library instance.
 */

import type { AuthDancePrompt, AuthDancePromptInput } from "auth-dance";

/** What a flow needs before it starts, and what it is called. */
export interface FlowDefinition {
	/** What a button shows. */
	label: string;
	/** The route that starts the flow. */
	path: string;
	/** Whether the start carries a bearer token. Every authenticated flow also needs a recent sign-in. */
	authenticated: boolean;
	/** What the body names: nothing, a component of the choreography, or a channel of `api.channels`. */
	argument: "none" | "component" | "channel";
}

/**
 * Every flow the library runs, under the name its route uses.
 *
 * The six authenticated ones all check the elevated window at the start, so past `durations.elevated` they answer
 * `FRESH_SIGN_IN_REQUIRED` before anything else happens. A refresh keeps `auth_time`, so it never reopens that window.
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

/** The name of a flow, which is also the key of {@link FLOWS} and the route that starts it. */
export type FlowName = keyof typeof FLOWS;

/** The flow names, in the order the start card lists them. */
export const FLOW_NAMES = Object.keys(FLOWS) as FlowName[];

/** One flow in progress, as far as the page is concerned. */
export interface Step {
	/** The flow that is running. */
	flow: FlowName;
	/** The opaque state of the dance in progress, which every later call echoes back. */
	state: string;
	/** What the owner answers next: one input, or a choice between the branches of the choreography. */
	prompt: AuthDancePrompt;
	/** The moment the flow expires, as an ISO 8601 string. */
	expireAt: string;
	/** The names answered so far in this flow, for the progress trail. */
	trail: string[];
}

/**
 * Every input a prompt puts on screen: the prompt itself, or one field per branch of a choice.
 *
 * A choice node of a choreography holds components only, so every branch is an input. The filter states that rather
 * than trusting it.
 */
export function promptInputs(prompt: AuthDancePrompt): AuthDancePromptInput[] {
	if (prompt.kind === "input") {
		return [prompt];
	}
	return prompt.components.filter((branch): branch is AuthDancePromptInput => branch.kind === "input");
}

/**
 * The prompt the owner is answering: the input itself, or the branch picked in a choice.
 *
 * A choice is a fork of the choreography. Every branch is a whole path, and the name submitted takes that one. A name
 * that is not a branch earns `COMPONENT_NOT_IN_CHOREOGRAPHY`, so the picked branch has to be one of these.
 */
export function activePrompt(prompt: AuthDancePrompt, branch?: string): AuthDancePromptInput | undefined {
	if (prompt.kind === "input") {
		return prompt;
	}
	return promptInputs(prompt).find((candidate) => candidate.name === branch);
}

/**
 * Whether the current step is worth offering a send button for.
 *
 * `sendable` is advisory: the library never reads the flag, and it says the value can travel over a channel one day,
 * not that there is anything to deliver now. A prompt the library can deliver is one it already knows the recipient
 * of, which is a one-time code it is about to mail. The recipient a subscribe collects is sendable too, in that
 * sense, but nothing can be sent there until the owner has given it.
 */
export function isSendable(step: Step): boolean {
	return promptInputs(step.prompt).some((input) => input.sendable && input.type === "otp");
}
