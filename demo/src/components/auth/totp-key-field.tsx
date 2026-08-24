/**
 * @module
 *
 * The control behind the `totp-key` prompt type. The key is generated in the browser, and the library sees it once,
 * when the flow submits it. Nothing delivers it, so the owner takes it off the screen: the QR code goes into an
 * authenticator app, and the key below it is the same value typed by hand.
 */

import { useMemo } from "react";
import type { AuthDancePromptInput } from "auth-dance";
import { isOTPAlgorithm, toURI } from "auth-dance";
import { QRCodeSVG } from "qrcode.react";

import { Input } from "@/components/ui/input.tsx";
import { useDance } from "@/lib/dance/index.ts";

/** What the control needs out of {@link PromptControlProps}. The key is read-only, so it writes nothing back. */
export interface TotpKeyFieldProps {
	/** The prompt being collected. `options` carries the digits, the period and the hash of the codes it derives. */
	prompt: AuthDancePromptInput;
	/** The id the visible label points at. */
	id: string;
	/** The key the store generated when the prompt arrived. */
	value: unknown;
}

/** Reads one number out of the free-form `options` bag of a prompt. */
function numberOption(prompt: AuthDancePromptInput, key: string, fallback: number): number {
	const value = prompt.options?.[key];
	return typeof value === "number" ? value : fallback;
}

/** The QR code of the `otpauth://` URI, and the key it carries, under the label of the prompt. */
export function TotpKeyField({ prompt, id, value }: TotpKeyFieldProps) {
	const { session } = useDance();
	const key = String(value ?? "");
	// The account name the authenticator app shows beside the code. A sign-up has no identity yet.
	const label = String(session?.identity.data?.name ?? session?.identity.id ?? "auth-dance demo");
	const algorithm = prompt.options?.algorithm;

	const uri = useMemo(() => {
		if (!key) {
			return "";
		}
		return toURI({
			type: "totp",
			secret: key,
			label,
			digits: numberOption(prompt, "digits", 6),
			period: numberOption(prompt, "period", 30),
			algorithm: isOTPAlgorithm(algorithm) ? algorithm : "SHA-1",
		});
	}, [key, label, prompt, algorithm]);

	return (
		<div className="flex flex-col items-center gap-3">
			{/* The QR code is read as dark on light. It keeps its own ground, whatever the page theme is. */}
			<div className="rounded-md border bg-white p-3">
				{uri ? <QRCodeSVG value={uri} size={168} marginSize={0} /> : <div className="size-[168px]" />}
			</div>
			<Input id={id} readOnly value={key} className="text-center font-mono tracking-[0.2em]" />
			<p className="text-center text-xs text-muted-foreground">
				Scan the code with an authenticator app, or type the key into it. The next prompt asks for the code the app shows.
			</p>
		</div>
	);
}
