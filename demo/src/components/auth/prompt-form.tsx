/**
 * @module
 *
 * The body of the card while a flow is running.
 *
 * One prompt is on screen at a time and the form knows nothing about which one: it asks {@link promptInputs} what to
 * render, {@link activePrompt} what is being answered, and hands the rest to the store. Every answer goes to the same
 * route, whether the prompt collects a value or proves control of one, which is what the badge shows.
 */

import { Badge } from "@/components/ui/badge.tsx";
import { Button } from "@/components/ui/button.tsx";
import { Field, FieldDescription, FieldGroup, FieldLegend, FieldSet } from "@/components/ui/field.tsx";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs.tsx";
import { activePrompt, isSendable, promptInputs, useDance, useDanceActions } from "@/lib/dance/index.ts";
import { clock } from "@/lib/format.ts";

import { FlowTrail } from "./flow-trail.tsx";
import { PromptField } from "./prompt-fields.tsx";

/** The prompt in progress: the trail, the fields it asks for, and the three things that can be done with them. */
export function PromptForm() {
	const { step, branch, busy } = useDance();
	const { submitCurrent, sendCurrent, cancel, setBranch } = useDanceActions();

	if (!step) {
		return null;
	}

	const inputs = promptInputs(step.prompt);
	const target = activePrompt(step.prompt, branch);

	return (
		<form
			className="flex flex-col gap-6"
			onSubmit={(event) => {
				event.preventDefault();
				void submitCurrent();
			}}
		>
			<div className="flex flex-col gap-3">
				<Badge variant="outline" className="self-start font-mono">POST /submit-prompt</Badge>
				<FlowTrail step={step} />
			</div>

			<FieldGroup>
				<FieldSet>
					<FieldLegend variant="label">Answer the prompt</FieldLegend>
					{step.prompt.kind === "input" ? <PromptField prompt={step.prompt} /> : (
						// A choice is a fork of the choreography: every branch is a whole path, and answering one takes it.
						// Which is why the picker sits above the fields rather than beside them.
						<>
							<FieldDescription>The dance forks here. Pick a branch and answer it.</FieldDescription>
							<Tabs value={branch ?? ""} onValueChange={(value) => setBranch(String(value))}>
								<TabsList className="w-full">
									{inputs.map((input) => (
										<TabsTrigger key={input.name} value={input.name} className="font-mono">
											{input.name}
										</TabsTrigger>
									))}
								</TabsList>
								{inputs.map((input) => (
									<TabsContent key={input.name} value={input.name} className="pt-2">
										<PromptField prompt={input} />
									</TabsContent>
								))}
							</Tabs>
						</>
					)}
				</FieldSet>

				<Field>
					<Button type="submit" disabled={busy || !target}>Submit</Button>
					<div className="flex flex-wrap items-center justify-between gap-2">
						<span className="text-xs text-muted-foreground">Expires {clock(step.expireAt)}</span>
						<div className="flex flex-wrap gap-2">
							<Button type="button" size="sm" variant="ghost" disabled={busy} onClick={() => void cancel()}>Abandon</Button>
							{
								/*
								`sendable` is advisory metadata the library never reads, so it alone is not the rule. A prompt worth a
								send button is one whose recipient the library already knows, which is a one-time code it is about to
								mail.
							*/
							}
							{isSendable(step) && (
								<Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => void sendCurrent()}>
									Send it to me
								</Button>
							)}
						</div>
					</div>
				</Field>
			</FieldGroup>
		</form>
	);
}
