/**
 * @module
 *
 * The body of the card while a flow is running. One prompt is on screen at a time.
 *
 * {@link AuthDancePromptSwitch} of `auth-dance/react` picks what to render: it reads the input the owner answers off
 * the handle and routes it to the row of {@link PROMPT_FIELDS} for its type. Nothing here reads a `type`, and nothing
 * here holds the dance: every answer goes back through the handle.
 */

import { useEffect, useState } from "react";
import { type AuthDanceFlowHandle, type AuthDancePromptInput, AuthDancePromptSwitch } from "auth-dance/react";

import { Badge } from "@/components/ui/badge.tsx";
import { Button } from "@/components/ui/button.tsx";
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field.tsx";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs.tsx";
import { describeFailure, isSendable, useDance, useDanceActions } from "@/lib/dance/index.ts";
import { clock } from "@/lib/format.ts";

import { FlowTrail } from "./flow-trail.tsx";
import { fieldFor, focusPromptField, initialValue, PROMPT_FIELDS, promptFieldId, takesCode } from "./prompt-fields.tsx";

/** What the running card hands the form. */
export interface PromptFormProps {
	/** The dance in progress, as `useAuthDanceFlow` hands it out. */
	flow: AuthDanceFlowHandle;
	/** Called once the owner drops the flow, so the card can go back to the start. */
	onLeave: () => void;
}

/** The prompt in progress: the trail, the branches when the dance forks, and the field the owner answers. */
export function PromptForm({ flow, onLeave }: PromptFormProps) {
	// Every type renders the same step, and the step reads the row of the type it was given. One entry per row of
	// `PROMPT_FIELDS` is what the switch reads, so a new row is all a new type needs.
	const step = (prompt: AuthDancePromptInput, handle: AuthDanceFlowHandle) => (
		// A new prompt is a new field, and the value of the one before it must not survive into it.
		<PromptStep key={`${handle.trail.length}:${prompt.name}`} prompt={prompt} flow={handle} onLeave={onLeave} />
	);
	const prompts = Object.fromEntries(Object.keys(PROMPT_FIELDS).map((type) => [type, step]));

	return (
		<div className="flex flex-col gap-6">
			<div className="flex flex-col gap-3">
				<Badge variant="outline" className="self-start font-mono">POST /submit-prompt</Badge>
				<FlowTrail flow={flow} />
			</div>

			<FieldGroup>
				<FieldSet>
					<FieldLegend variant="label">Answer the prompt</FieldLegend>
					{flow.prompt?.kind === "choice" && <BranchTabs flow={flow} />}
					<AuthDancePromptSwitch
						flow={flow}
						prompts={prompts}
						choice={() => <FieldDescription>Pick a branch above.</FieldDescription>}
						// A type this page holds no row for lands here, and the row of `text` collects it.
						fallback={(_, handle) => handle.current ? step(handle.current, handle) : null}
					/>
				</FieldSet>
			</FieldGroup>
		</div>
	);
}

/**
 * The branches of a choice, as a tab list. The library leaves no branch picked, so the first one is picked here, the
 * way a tab list shows its first tab.
 */
function BranchTabs({ flow }: { flow: AuthDanceFlowHandle }) {
	useEffect(() => {
		const first = flow.choices[0];
		if (first && flow.selected === undefined) {
			void flow.choose(first.name);
		}
	}, [flow]);

	return (
		<>
			<FieldDescription>The dance forks here. Pick a branch and answer it.</FieldDescription>
			<Tabs value={flow.selected ?? ""} onValueChange={(value) => void flow.choose(String(value))}>
				<TabsList className="w-full">
					{flow.choices.map((input) => (
						<TabsTrigger key={input.name} value={input.name} className="font-mono">
							{input.name}
						</TabsTrigger>
					))}
				</TabsList>
			</Tabs>
		</>
	);
}

/** What one step of a dance needs. */
interface PromptStepProps {
	/** The one input the owner answers now. */
	prompt: AuthDancePromptInput;
	/** The dance in progress. */
	flow: AuthDanceFlowHandle;
	/** Called once the owner drops the flow. */
	onLeave: () => void;
}

/** The label, the control, the metadata line and the buttons of one step. The value of the field lives here. */
function PromptStep({ prompt, flow, onLeave }: PromptStepProps) {
	const { code } = useDance();
	const { clearCode } = useDanceActions();
	const field = fieldFor(prompt.type);
	const id = promptFieldId(prompt.name);
	const [value, setValue] = useState<unknown>(() => initialValue(prompt));
	// What a ceremony refused with. The library never saw the value, so this stays out of `flow.error`.
	const [failure, setFailure] = useState<string | undefined>(undefined);
	const expireAt = flow.choreography?.expireAt;

	// A code the inbox handed over lands in the one field that takes one.
	useEffect(() => {
		if (code && takesCode(prompt)) {
			setValue(code.value);
			clearCode();
			focusPromptField(prompt.name);
		}
	}, [code, prompt, clearCode]);

	const submit = (): void => {
		setFailure(undefined);
		const resolve = field.resolve;
		if (!resolve) {
			void flow.submitPrompt(value);
			return;
		}
		// A type that nothing types into builds its value here. Nothing is awaited in front of the call, so the browser
		// still counts this press as the gesture a passkey ceremony asks for.
		void resolve(prompt).then(
			(resolved) => flow.submitPrompt(resolved),
			(cause: unknown) => setFailure(describeFailure(cause)),
		);
	};

	return (
		<form
			className="flex flex-col gap-6"
			onSubmit={(event) => {
				event.preventDefault();
				submit();
			}}
		>
			<Field>
				<FieldLabel htmlFor={id}>{field.label}</FieldLabel>
				{field.control({ prompt, id, value, disabled: flow.pending, onValueChange: setValue })}
				<FieldDescription className="font-mono text-xs">
					name <span className="text-foreground">{prompt.name}</span> · type <span className="text-foreground">{prompt.type}</span>
					{prompt.sendable ? " · sendable" : ""}
				</FieldDescription>
				<FieldError>{failure}</FieldError>
			</Field>

			<Field>
				<Button type="submit" disabled={flow.pending || flow.expired}>Submit</Button>
				<div className="flex flex-wrap items-center justify-between gap-2">
					<span className="text-xs text-muted-foreground">{expireAt ? `Expires ${clock(expireAt)}` : ""}</span>
					<div className="flex flex-wrap gap-2">
						<Button
							type="button"
							size="sm"
							variant="ghost"
							disabled={flow.pending}
							onClick={() => void flow.abandon().then(onLeave)}
						>
							Abandon
						</Button>
						{
							/* `sendable` is advisory metadata the library never reads. A send button needs a known recipient. */
						}
						{isSendable(flow) && (
							<Button
								type="button"
								size="sm"
								variant="outline"
								disabled={flow.pending}
								onClick={() => void flow.sendPrompt()}
							>
								Send it to me
							</Button>
						)}
					</div>
				</div>
			</Field>
		</form>
	);
}
