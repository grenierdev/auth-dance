import * as v from "valibot";

export interface AuthDancePromptInput {
	kind: "input";
	name: string;
	type: string;
	sendable: boolean;
	options?: Record<string, unknown>;
}

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

export interface AuthDancePromptChoice<T extends AuthDancePrompt = AuthDancePrompt> {
	kind: "choice";
	components: T[];
}

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

export type AuthDancePrompt = AuthDancePromptInput | AuthDancePromptChoice;

export const AuthDancePrompt: v.GenericSchema<AuthDancePrompt> = v.pipe(
	v.union([AuthDancePromptInput, AuthDancePromptChoice]),
	v.title("Prompt"),
	v.description("A prompt, which can be a component or a choice"),
);
