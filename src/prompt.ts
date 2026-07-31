import * as v from "valibot";

export interface AuthPromptInput {
	kind: "input";
	name: string;
	type: string;
	sendable: boolean;
	options?: Record<string, unknown>;
}

export const AuthPromptInput: v.GenericSchema<AuthPromptInput> = v.pipe(
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

export interface AuthPromptChoice<T extends AuthPrompt = AuthPrompt> {
	kind: "choice";
	components: T[];
}

export const AuthPromptChoice: v.GenericSchema<AuthPromptChoice> = v.lazy(() =>
	v.pipe(
		v.object({
			kind: v.literal("choice"),
			components: v.array(AuthPrompt),
		}),
		v.title("PromptChoice"),
		v.description("A choice of prompt components"),
	)
);

export type AuthPrompt = AuthPromptInput | AuthPromptChoice;

export const AuthPrompt: v.GenericSchema<AuthPrompt> = v.pipe(
	v.union([AuthPromptInput, AuthPromptChoice]),
	v.title("Prompt"),
	v.description("A prompt, which can be a component or a choice"),
);
