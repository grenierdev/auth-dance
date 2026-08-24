/**
 * @module
 *
 * How one type of prompt is collected, one entry per type. The flow driver never reads a `type` itself. To support a new
 * type, add a row to {@link PROMPT_FIELDS}.
 */

import type { ReactNode } from "react";
import type { AuthDancePromptInput } from "auth-dance";
import { REGEXP_ONLY_DIGITS } from "input-otp";

import { Checkbox } from "@/components/ui/checkbox.tsx";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field.tsx";
import { Input } from "@/components/ui/input.tsx";
import { InputOTP, InputOTPGroup, InputOTPSeparator, InputOTPSlot } from "@/components/ui/input-otp.tsx";
import { useDance, useDanceActions } from "@/lib/dance/index.ts";

/** Everything a control is given. */
export interface PromptControlProps {
	/** The prompt being collected. A type of your own reads its `options` from here. */
	prompt: AuthDancePromptInput;
	/** The id the visible label points at, and the id the inbox moves focus to. */
	id: string;
	/** What the store holds under the name of the prompt. */
	value: unknown;
	/** Writes the store. A confirmation writes a boolean, everything else writes a string. */
	onValueChange: (next: unknown) => void;
	/** Whether an action is running. No control takes input then. */
	disabled: boolean;
}

/** One row of the table: what the label says, and the control under it. */
export interface PromptFieldDefinition {
	/** What the visible label says. */
	label: string;
	/** The control. It reads `value` and writes through `onValueChange`. */
	control: (props: PromptControlProps) => ReactNode;
}

/** Every type this page knows how to collect. The library ships `email`, `password` and `otp`, and builds `confirmation`. */
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
		// The library takes the boolean true and nothing else. An unchecked box submits false, and the library refuses it.
		control: ({ id, value, disabled, onValueChange }) => (
			<Field orientation="horizontal">
				<Checkbox id={id} checked={value === true} disabled={disabled} onCheckedChange={(checked) => onValueChange(checked)} />
				<span className="text-sm leading-snug">Yes, go ahead</span>
			</Field>
		),
	},
};

/** The row for a type. An unknown type gets a plain text input. */
export function fieldFor(type: string): PromptFieldDefinition {
	return PROMPT_FIELDS[type] ?? PROMPT_FIELDS.text;
}

/** Where a field of the current prompt lives in the document. */
export function promptFieldId(name: string): string {
	return `prompt-${name}`;
}

/** Moves the caret to a field on the next frame, after a dialog that closes on the same click restores its focus. */
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
