import * as v from "valibot";

/** One input the client renders for the current step. The client returns the value under the same `name`, to `submitPrompt`. */
export interface AuthDancePromptInput {
	/** Marks the prompt as one input, and not a {@link AuthDancePromptChoice}. */
	kind: "input";
	/**
	 * The name the client returns with the value. A choreography step uses the component name. A subscribe or an
	 * unsubscribe uses the channel name. A delete confirmation uses `identity`.
	 */
	name: string;
	/** What the client collects: `email`, `password`, `otp`, `confirmation`, or the type a channel declares. */
	type: string;
	/** `true` when the library can deliver the value over a channel. The client then calls `sendPrompt` first. */
	sendable: boolean;
	/**
	 * Extra rules a component publishes about the value, length bounds for example. The library never reads it.
	 */
	options?: Record<string, unknown>;
}

/** Parses one input prompt at runtime. */
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

/** A choice between the branches of the choreography. The name the owner answers with selects the branch. */
export interface AuthDancePromptChoice<T extends AuthDancePrompt = AuthDancePrompt> {
	/** Marks the prompt as a choice, and not one {@link AuthDancePromptInput}. */
	kind: "choice";
	/** One prompt for each branch of the choice. An answer to any one of them takes that branch. */
	components: T[];
}

/** Parses a choice prompt at runtime. The HTTP layer must not reuse it. A lazy schema breaks the OpenAPI document. */
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

/** What the client renders next: one input, or a choice between branches. The `kind` field names the form. */
export type AuthDancePrompt = AuthDancePromptInput | AuthDancePromptChoice;

/** Parses either prompt form at runtime. */
export const AuthDancePrompt: v.GenericSchema<AuthDancePrompt> = v.pipe(
	v.union([AuthDancePromptInput, AuthDancePromptChoice]),
	v.title("Prompt"),
	v.description("A prompt, which can be a component or a choice"),
);
