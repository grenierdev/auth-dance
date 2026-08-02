import * as v from "valibot";

/**
 * One input the client renders for the current step.
 *
 * A component or a channel builds this prompt for the step it owns. The library builds a confirmation prompt
 * on its own. The client returns the value under the same `name`, to `submitPrompt` or to `submitValidation`.
 */
export interface AuthDancePromptInput {
	/** Marks the prompt as one input, and not a {@link AuthDancePromptChoice}. */
	kind: "input";
	/**
	 * The name the client returns with the value. A step of the choreography uses the component name. A
	 * subscribe or an unsubscribe uses the channel name. A delete confirmation uses `identity`.
	 */
	name: string;
	/**
	 * What the client collects. The components of the library use `email`, `password` and `otp`. A confirmation
	 * prompt uses `confirmation`, and a channel prompt carries the type the channel declares.
	 */
	type: string;
	/**
	 * `true` when the library can deliver the value over a channel, a one-time code for example. The client
	 * then calls `sendPrompt`, or `sendValidation` during a validation, before it submits an answer. The
	 * library never reads this flag itself.
	 */
	sendable: boolean;
	/**
	 * Extra rules a component publishes about the value, length bounds for example. A client can hold the owner
	 * to those rules before it spends a round trip on the value. No component in the box fills this field, and
	 * the library never reads it. What it holds is between a component of your own and your client.
	 */
	options?: Record<string, unknown>;
}

/**
 * Parses and validates one input prompt at runtime. The HTTP layer also reuses it to describe the prompt of
 * a state response in the generated OpenAPI document.
 */
export const AuthDancePromptInput: v.GenericSchema<AuthDancePromptInput> = v.pipe(
	v.object({
		kind: v.literal("input"),
		name: v.string(),
		type: v.string(),
		sendable: v.boolean(),
		options: v.optional(v.record(v.string(), v.unknown())),
	}),
	v.title("PromptComponent"),
	v.description("A single prompt component"),
);

/**
 * A choice between the branches of the choreography, where the owner picks the branch to take.
 *
 * The state machine builds a choice when the next move holds more than one component. It asks each of those
 * components for its prompt, and it collects the prompts here. The name the owner answers with selects the
 * branch.
 *
 * @typeParam T - The prompt of one branch. A `choice` node of a choreography holds components only, so the
 * state machine puts input prompts here.
 */
export interface AuthDancePromptChoice<T extends AuthDancePrompt = AuthDancePrompt> {
	/** Marks the prompt as a choice, and not one {@link AuthDancePromptInput}. */
	kind: "choice";
	/** One prompt for each branch of the choice. An answer to any one of them takes that branch. */
	components: T[];
}

/**
 * Parses and validates a choice prompt at runtime. `v.lazy` carries the self reference of the type.
 *
 * The HTTP layer describes a choice one level deep instead of reusing this schema. A `v.lazy` schema leaves a
 * dangling reference in the generated OpenAPI document.
 */
export const AuthDancePromptChoice: v.GenericSchema<AuthDancePromptChoice> = v.lazy(() =>
	v.pipe(
		v.object({
			kind: v.literal("choice"),
			components: v.array(AuthDancePrompt),
		}),
		v.title("PromptChoice"),
		v.description("A choice of prompt components"),
	)
);

/**
 * What the client renders next: one input, or a choice between branches. The `kind` field names the form.
 *
 * The library sends a validation as a second prompt, to prove control of a value it already collected. A
 * validation has the same shape as any other prompt.
 */
export type AuthDancePrompt = AuthDancePromptInput | AuthDancePromptChoice;

/**
 * Parses and validates either prompt form at runtime. `AuthDanceResponseState` uses it for the `prompt` the
 * library returns beside every state.
 */
export const AuthDancePrompt: v.GenericSchema<AuthDancePrompt> = v.pipe(
	v.union([AuthDancePromptInput, AuthDancePromptChoice]),
	v.title("Prompt"),
	v.description("A prompt, which can be a component or a choice"),
);
