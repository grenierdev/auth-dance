/**
 * @module
 *
 * How one type of prompt is collected, one entry per type. Nothing here reads a `type` itself. To support a new type,
 * add a row to {@link PROMPT_FIELDS}: `AuthDancePromptSwitch` then routes that type to it.
 *
 * A row that nothing types into declares `resolve` instead. The submit button runs it, and what it answers is the value
 * of the prompt. A row that starts on something other than an empty string declares `initial`.
 */

import type { ReactNode } from "react";
import { generateKey } from "auth-dance";
import type { AuthDancePromptInput } from "auth-dance/react";
import { REGEXP_ONLY_DIGITS } from "input-otp";

import { Checkbox } from "@/components/ui/checkbox.tsx";
import { Field } from "@/components/ui/field.tsx";
import { Input } from "@/components/ui/input.tsx";
import { InputOTP, InputOTPGroup, InputOTPSeparator, InputOTPSlot } from "@/components/ui/input-otp.tsx";

import { runCeremony } from "@/lib/webauthn.ts";

import { TotpKeyField } from "./totp-key-field.tsx";
import { WebAuthnField } from "./webauthn-field.tsx";

/** Everything a control is given. */
export interface PromptControlProps {
	/** The prompt being collected. A type of your own reads its `options` from here. */
	prompt: AuthDancePromptInput;
	/** The id the visible label points at, and the id the inbox moves focus to. */
	id: string;
	/** What the step holds under the name of the prompt. */
	value: unknown;
	/** Writes the value of the step. A confirmation writes a boolean, everything else writes a string. */
	onValueChange: (next: unknown) => void;
	/** Whether a call is out. No control takes input then. */
	disabled: boolean;
}

/** One row of the table: what the label says, and the control under it. */
export interface PromptFieldDefinition {
	/** What the visible label says. */
	label: string;
	/** The control. It reads `value` and writes through `onValueChange`. */
	control: (props: PromptControlProps) => ReactNode;
	/**
	 * What the control holds before the owner touches it. Without one the field starts on an empty string.
	 */
	initial?: (prompt: AuthDancePromptInput) => unknown;
	/**
	 * Builds the value when the submit button is pressed, for a type that nothing types into. Without it the button
	 * sends what the control wrote. What this rejects with lands under the field.
	 */
	resolve?: (prompt: AuthDancePromptInput) => Promise<unknown>;
}

/**
 * Every type this page knows how to collect. The library ships `email`, `password`, `otp`, `totp`, `totp-key`,
 * `webauthn` and `webauthn-create`, and builds `confirmation`.
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
	"totp-key": {
		label: "Authenticator key",
		// The library never generates a key and never delivers one, so the browser draws it. The control only shows it.
		initial: () => generateKey(16),
		control: ({ prompt, id, value }) => <TotpKeyField prompt={prompt} id={id} value={value} />,
	},
	totp: {
		label: "Authenticator code",
		control: ({ prompt, id, value, disabled, onValueChange }) => {
			const digits = typeof prompt.options?.digits === "number" ? prompt.options.digits : 6;
			return (
				<InputOTP
					id={id}
					maxLength={digits}
					pattern={REGEXP_ONLY_DIGITS}
					autoComplete="one-time-code"
					containerClassName="gap-2"
					value={String(value ?? "")}
					disabled={disabled}
					onChange={(next) => onValueChange(next)}
				>
					<InputOTPGroup>
						{Array.from({ length: digits }, (_, index) => <InputOTPSlot key={index} index={index} />)}
					</InputOTPGroup>
				</InputOTP>
			);
		},
	},
	"webauthn-create": {
		label: "Passkey",
		// Nothing is typed. The submit button runs the ceremony, and the answer of the authenticator is the value.
		control: ({ prompt, id }) => <WebAuthnField prompt={prompt} id={id} />,
		resolve: runCeremony,
	},
	webauthn: {
		label: "Passkey",
		control: ({ prompt, id }) => <WebAuthnField prompt={prompt} id={id} />,
		resolve: runCeremony,
	},
	confirmation: {
		label: "Confirmation",
		// The library takes the boolean true and nothing else. An unchecked box submits false, and the library refuses it.
		initial: () => false,
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

/** What one field holds before the owner touches it. */
export function initialValue(prompt: AuthDancePromptInput): unknown {
	return fieldFor(prompt.type).initial?.(prompt) ?? "";
}

/** Whether a field of this type takes a code out of the inbox. */
export function takesCode(prompt: AuthDancePromptInput): boolean {
	return prompt.type === "otp" || prompt.type === "totp";
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
