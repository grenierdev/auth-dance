/**
 * @module
 *
 * The control behind the `webauthn-create` and `webauthn` prompt types. Neither one is typed, and neither one holds
 * a button: the submit button of the form runs the ceremony, through the `resolve` of the row in
 * {@link PROMPT_FIELDS}. This control only says what pressing it will do, and what the prompt asked the
 * authenticator for.
 */

import type { AuthDancePromptInput } from "auth-dance";

import type { CreationOptionsJSON, RequestOptionsJSON } from "@/lib/webauthn.ts";
import { webAuthnAvailable } from "@/lib/webauthn.ts";

/** What the control needs out of the props every control is given. */
export interface WebAuthnFieldProps {
	/** The prompt being answered. `options.publicKey` carries the whole argument of the ceremony. */
	prompt: AuthDancePromptInput;
	/** The id the visible label points at. */
	id: string;
}

/** One line of the summary. */
function Detail({ label, value }: { label: string; value: string }) {
	return (
		<div className="flex justify-between gap-4">
			<span>{label}</span>
			<span className="text-foreground">{value}</span>
		</div>
	);
}

/** What the submit button is about to ask the authenticator for. */
export function WebAuthnField({ prompt, id }: WebAuthnFieldProps) {
	const registering = prompt.type === "webauthn-create";
	const options = prompt.options?.publicKey as (CreationOptionsJSON & RequestOptionsJSON) | undefined;

	if (!webAuthnAvailable()) {
		return (
			<p id={id} className="text-sm text-muted-foreground">
				This browser holds no Web Authentication API. It needs a secure context, which means HTTPS or `localhost`.
			</p>
		);
	}

	const named = (registering ? options?.excludeCredentials : options?.allowCredentials)?.length ?? 0;

	return (
		<div id={id} className="flex flex-col gap-3">
			<p className="text-sm text-muted-foreground">
				{registering
					? "Submit, and the authenticator makes a key pair for this domain. The server keeps the public half, and the private half never leaves the device. The next prompt asks you to sign with it."
					: "Submit, and the authenticator signs the challenge of this prompt. The signature is the answer, and it is also what says who you are."}
			</p>

			{/* The authenticator keeps a passkey for good. This page keeps its identities in a Map that a reload erases. */}
			{registering ? null : (
				<p className="text-xs text-muted-foreground">
					Pick the passkey this page made{" "}
					<em>since the last reload</em>. The demo keeps every identity in memory, so a reload, and any change in the options panel, leaves
					the passkeys of the run before it with nobody to sign in as.
				</p>
			)}

			<div className="flex flex-col gap-1 rounded-md border bg-muted/40 p-3 font-mono text-xs text-muted-foreground">
				<Detail label="rp.id" value={String(options?.rp?.id ?? options?.rpId ?? "—")} />
				{registering
					? (
						<>
							<Detail label="user.name" value={String(options?.user?.name ?? "—")} />
							<Detail label="pubKeyCredParams" value={(options?.pubKeyCredParams ?? []).map((p) => p.alg).join(", ") || "—"} />
							<Detail label="residentKey" value={String(options?.authenticatorSelection?.residentKey ?? "—")} />
							<Detail label="attestation" value={String(options?.attestation ?? "—")} />
							<Detail label="excludeCredentials" value={String(named)} />
						</>
					)
					: (
						<>
							<Detail label="userVerification" value={String(options?.userVerification ?? "—")} />
							{/* An empty list asks the authenticator for a credential it keeps itself, which is what a sign-in does. */}
							<Detail label="allowCredentials" value={named === 0 ? "none — any passkey of this domain" : String(named)} />
						</>
					)}
			</div>
		</div>
	);
}
