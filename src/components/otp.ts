import type { AuthDanceComponent, AuthDanceComponentContext } from "../component.ts";
import type { AuthDanceIdentity, AuthDanceIdentityChannel, AuthDanceIdentityComponent } from "../identity.ts";
import type { AuthDanceMessage } from "../message.ts";
import type { AuthDancePromptInput } from "../prompt.ts";
import { otp } from "../otp.ts";
import { ChannelNotSubscribedError, ComponentNotVerifiableError } from "../error.ts";

export interface OtpAuthDanceComponentOptions {
	channel: string;
	digits?: number;
	ttl?: number;
	subject?: Record<string, string | ((code: string, context: AuthDanceComponentContext) => string)>;
	html?: Record<string, string | ((code: string, context: AuthDanceComponentContext) => string)>;
	text?: Record<string, string | ((code: string, context: AuthDanceComponentContext) => string)>;
}

/**
 * A one-time code that the library delivers over a channel. A verifiable component uses it to prove control of its own value.
 * `sendPrompt` writes the code to KV under `otp/<stateId>/<name>`. `verifyPrompt` deletes that key on a match, so a code works
 * one time only. The key-value store drops a code that nobody submits at the end of the time to live.
 */
export class OtpAuthDanceComponent implements AuthDanceComponent {
	/** The record kind the component contributes to an identity. A `challenge` proves a claim, and never resolves an identity. */
	readonly kind: AuthDanceIdentityComponent["kind"] = "challenge";
	/** This component has no verification of its own. */
	readonly verifiable = false;

	#options: OtpAuthDanceComponentOptions;

	/**
	 * @param options The name of the channel that delivers the code, the number of digits in a code (default `6`), and the time
	 * that a code stays valid, in seconds (default `300`). The identity must hold a channel with the given name.
	 */
	constructor(options: OtpAuthDanceComponentOptions) {
		this.#options = options;
	}

	/**
	 * Builds the challenge record this component contributes to an identity. The record holds no code.
	 * @param component The name of the step in the choreography.
	 * @param value What the owner submitted. The record keeps it under `data.recipient` without a type check.
	 * @param confirmed Whether the owner already proved control of the value. Defaults to `false`.
	 * @returns One challenge record.
	 */
	// deno-lint-ignore require-await
	async getIdentityComponent(
		component: string,
		value: unknown,
		confirmed: boolean = false,
	): Promise<AuthDanceIdentityComponent[]> {
		return [
			{
				kind: "challenge",
				component,
				confirmed,
				data: { recipient: value },
			},
		];
	}

	/** Describes the code entry the client renders. The prompt is sendable, so the client can ask for a fresh code. */
	// deno-lint-ignore require-await
	async getPrompt(context: AuthDanceComponentContext): Promise<AuthDancePromptInput> {
		return {
			kind: "input",
			name: context.name,
			type: "otp",
			sendable: true,
		};
	}

	/**
	 * Compares the submitted code with the one in KV, then deletes the key so a code works one time only.
	 * @returns `true` when the code matches. `false` in every other case, which includes an expired code and a used code.
	 */
	async verifyPrompt(response: unknown, context: AuthDanceComponentContext): Promise<boolean | AuthDanceIdentity["id"]> {
		const value = typeof response === "string" ? response : null;
		if (!value) {
			return false;
		}
		const code = await context.storage.getKv(`otp/${context.stateId}/${context.name}`);
		if (!code) {
			return false;
		}
		if (code !== value) {
			return false;
		}
		await context.storage.unsetKv(`otp/${context.stateId}/${context.name}`);
		return true;
	}

	/**
	 * Generates a code, stores it under `otp/<stateId>/<name>` for the time to live, and returns the message to deliver.
	 * The recipient is the channel that the identity holds under the configured channel name, and never a value from the
	 * client. `content["text/x-code"]` holds the code. The component ignores `locale`.
	 * @throws {@link ChannelNotSubscribedError} When the context carries no identity, or the identity holds no channel with
	 * the configured name.
	 */
	async sendPrompt(_locale: string, context: AuthDanceComponentContext): Promise<AuthDanceMessage> {
		const identityChannel = context.identity?.components
			.find((c): c is AuthDanceIdentityChannel => c.kind === "channel" && c.component === this.#options.channel);
		if (!identityChannel) {
			throw new ChannelNotSubscribedError(this.#options.channel);
		}
		const code = otp({ digits: this.#options.digits ?? 6 });
		await context.storage.setKv(`otp/${context.stateId}/${context.name}`, code, this.#options.ttl ?? 300);
		const subject = this.#options.subject?.["en"] instanceof Function
			? this.#options.subject?.["en"](code, context)
			: this.#options.subject?.["en"] ?? "Your one-time code";
		const text = this.#options.text?.["en"] instanceof Function
			? this.#options.text?.["en"](code, context)
			: this.#options.text?.["en"] ?? `Your one-time code is: ${code}`;
		const html = this.#options.html?.["en"] instanceof Function
			? this.#options.html?.["en"](code, context)
			: this.#options.html?.["en"] ?? `<p>Your one-time code is: <strong>${code}</strong></p>`;
		return {
			recipient: identityChannel,
			subject,
			content: {
				"text/x-code": code,
				"text/plain": text,
				"text/html": html,
			},
		};
	}

	/**
	 * Always throws, because another component uses this one as its verification.
	 * @throws {@link ComponentNotVerifiableError} On every call. The message carries the step name.
	 */
	// deno-lint-ignore require-await
	async verificationComponent?(context: AuthDanceComponentContext): Promise<AuthDanceComponent> {
		throw new ComponentNotVerifiableError(context.name);
	}
}
