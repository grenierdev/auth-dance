/**
 * @module
 *
 * How one type of prompt is collected, one entry per type.
 *
 * The flow driver never looks at a `type` itself. It asks this table to render, and the table hands back a controlled
 * control wired to the value the store already holds under the name of the prompt. That is the whole seam: a component
 * of your own can declare any other type, and adding a row here is the only change the page needs.
 */

import type { ReactNode } from "react";
import type { AuthDancePromptInput } from "auth-dance";
import { REGEXP_ONLY_DIGITS } from "input-otp";

import { Checkbox } from "@/components/ui/checkbox";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { InputOTP, InputOTPGroup, InputOTPSeparator, InputOTPSlot } from "@/components/ui/input-otp";
import { useDance, useDanceActions } from "@/lib/dance";

/** Everything a control is given. Nothing else is in scope for it, which keeps a new type of field a one-liner. */
export interface PromptControlProps {
	/** The prompt being collected. A type of your own reads whatever it published under `options` from here. */
	prompt: AuthDancePromptInput;
	/** The id the visible label points at, and the id the inbox moves focus to when it fills a code. */
	id: string;
	/** What the store holds under the name of the prompt. Every control casts it at the edge, because the store is untyped here. */
	value: unknown;
	/** Writes the store. A confirmation writes a boolean, everything else writes a string. */
	onValueChange: (next: unknown) => void;
	/** Whether an action is running, in which case nothing takes input. */
	disabled: boolean;
}

/** One row of the table: what the label says, and the control under it. */
export interface PromptFieldDefinition {
	/** What the visible label says. */
	label: string;
	/** The control, which is always controlled: it reads `value` and writes through `onValueChange`. */
	control: (props: PromptControlProps) => ReactNode;
}

/**
 * Every type this page knows how to collect.
 *
 * The library ships `email`, `password` and `otp`, and builds `confirmation` itself. A channel contributes whatever
 * type it declares, `phone` here. A component of your own can declare any other type: add an entry and the flow driver
 * needs no change, because it only ever asks this table to render.
 */
export const PROMPT_FIELDS: Record<string, PromptFieldDefinition> = {
	text: {
		label: "Value",
		control: ({ id, value, disabled, onValueChange }) => (
			<Input
				id={id}
				type="text"
				autoComplete="off"
				value={String(value ?? "")}
				disabled={disabled}
				onChange={(event) => onValueChange(event.target.value)}
			/>
		),
	},
	email: {
		label: "Email address",
		control: ({ id, value, disabled, onValueChange }) => (
			<Input
				id={id}
				type="email"
				autoComplete="email"
				placeholder="john.doe@example.com"
				value={String(value ?? "")}
				disabled={disabled}
				onChange={(event) => onValueChange(event.target.value)}
			/>
		),
	},
	password: {
		label: "Password",
		control: ({ id, value, disabled, onValueChange }) => (
			<Input
				id={id}
				type="password"
				autoComplete="current-password"
				value={String(value ?? "")}
				disabled={disabled}
				onChange={(event) => onValueChange(event.target.value)}
			/>
		),
	},
	phone: {
		label: "Phone number",
		control: ({ id, value, disabled, onValueChange }) => (
			<Input
				id={id}
				type="tel"
				autoComplete="tel"
				placeholder="5551234567"
				value={String(value ?? "")}
				disabled={disabled}
				onChange={(event) => onValueChange(event.target.value)}
			/>
		),
	},
	otp: {
		label: "One-time code",
		control: ({ id, value, disabled, onValueChange }) => (
			<InputOTP
				id={id}
				maxLength={6}
				pattern={REGEXP_ONLY_DIGITS}
				autoComplete="one-time-code"
				containerClassName="gap-2"
				value={String(value ?? "")}
				disabled={disabled}
				onChange={(next) => onValueChange(next)}
			>
				<InputOTPGroup>
					<InputOTPSlot index={0} />
					<InputOTPSlot index={1} />
					<InputOTPSlot index={2} />
				</InputOTPGroup>
				<InputOTPSeparator />
				<InputOTPGroup>
					<InputOTPSlot index={3} />
					<InputOTPSlot index={4} />
					<InputOTPSlot index={5} />
				</InputOTPGroup>
			</InputOTP>
		),
	},
	confirmation: {
		label: "Confirmation",
		// The library takes the boolean true and nothing else, so an unchecked box submits false on purpose: the
		// refusal it earns is part of what this demo shows. Nothing here pre-checks it and nothing blocks the submit.
		control: ({ id, value, disabled, onValueChange }) => (
			<Field orientation="horizontal">
				<Checkbox id={id} checked={value === true} disabled={disabled} onCheckedChange={(checked) => onValueChange(checked)} />
				<span className="text-sm leading-snug">Yes, go ahead</span>
			</Field>
		),
	},
};

/** The row for a type, falling through to a plain text input for a type this page has never met. */
export function fieldFor(type: string): PromptFieldDefinition {
	return PROMPT_FIELDS[type] ?? PROMPT_FIELDS.text;
}

/** Where a field of the current prompt lives in the document, which is how the inbox moves focus onto a code. */
export function promptFieldId(name: string): string {
	return `prompt-${name}`;
}

/**
 * Moves the caret to a field of the current prompt.
 *
 * It lives here because this module is the one that decides where a field lands in the document, and a caller that
 * had to know the id would have to be changed with it.
 *
 * The click that fills a field is also the click that closes the slideout it was clicked in, and the dialog pulls
 * focus back to its trigger while it goes. Asking for the field on the next frame lands after that, which is the whole
 * reason this is not a plain `focus()`.
 */
export function focusPromptField(name: string): void {
	requestAnimationFrame(() => {
		document.getElementById(promptFieldId(name))?.focus();
	});
}

/** The label, the control and the metadata line for one input of the current prompt. */
export function PromptField({ prompt }: { prompt: AuthDancePromptInput }) {
	const { values, busy } = useDance();
	const { setPromptValue } = useDanceActions();

	const field = fieldFor(prompt.type);
	const id = promptFieldId(prompt.name);

	return (
		<Field>
			<FieldLabel htmlFor={id}>{field.label}</FieldLabel>
			{field.control({
				prompt,
				id,
				value: values[prompt.name],
				disabled: busy,
				onValueChange: (next) => setPromptValue(prompt.name, next),
			})}
			<FieldDescription className="font-mono text-xs">
				name <span className="text-foreground">{prompt.name}</span> · type <span className="text-foreground">{prompt.type}</span>
				{prompt.sendable ? " · sendable" : ""}
			</FieldDescription>
		</Field>
	);
}
