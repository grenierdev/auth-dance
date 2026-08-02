import type { AuthDanceComponent, AuthDanceComponentContext } from "../component.ts";
import type { AuthDanceIdentity, AuthDanceIdentityChannel, AuthDanceIdentityComponent } from "../identity.ts";
import type { AuthDanceMessage } from "../message.ts";
import type { AuthDancePromptInput } from "../prompt.ts";
import { otp } from "../otp.ts";
import { ChannelNotSubscribedError, ComponentNotVerifiableError } from "../error.ts";

/**
 * A one-time code that the library delivers over a channel. A verifiable component uses it to prove control of
 * its own value, as `EmailAuthDanceComponent` does.
 *
 * The code never reaches the identity record. `sendPrompt` writes it to KV under `otp/<stateId>/<name>`, so one
 * code belongs to one state and one step of it. `verifyPrompt` deletes that key on a match, so a code works one
 * time only. The key-value store drops a code that nobody submits when the time to live ends.
 *
 * This is the only sendable component of the library. The client asks the library to deliver the code, and then
 * submits it the same way it submits any other prompt value.
 */
export default class OtpAuthDanceComponent implements AuthDanceComponent {
	/** The record the component contributes to an identity. A `challenge` proves a claim against an identity, and never resolves one. */
	readonly kind: AuthDanceIdentityComponent["kind"] = "challenge";
	/**
	 * A verifiable component uses the OTP as its verification. The OTP has none of its own, so
	 * `verificationComponent` throws instead of returning one.
	 */
	readonly verifiable = false;
	#channel: string;
	#digits: number;
	#ttl: number;

	/**
	 * Sets the channel that carries a one-time code, the length of the code, and the time that the code stays valid.
	 * @param channel The name of the channel that delivers the code. The identity must hold a channel with this name.
	 * @param digits The number of digits in each code the component generates. Defaults to `6`.
	 * @param ttl How long a code stays valid, in seconds. The key-value store drops the code at the end of this time.
	 * Defaults to `300` seconds.
	 */
	constructor(channel: string, digits: number = 6, ttl: number = 300) {
		this.#channel = channel;
		this.#digits = digits;
		this.#ttl = ttl;
	}

	/**
	 * Builds the challenge record the OTP contributes to an identity.
	 *
	 * The record holds no code. It keeps the submitted value under `data.recipient`. The code itself stays in KV,
	 * under the key of the state and the step.
	 * @param component The name the record carries, which is the name of the step in the choreography.
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

	/**
	 * Describes the code entry the client renders. The prompt is sendable, so the client can ask the library for a
	 * fresh code before the owner types anything.
	 */
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
	 *
	 * A code that expired, a code the owner already used, and a KV read that fails all give `false`. The library
	 * treats them as a rejected value, not as a fault of its own.
	 * @returns `true` when the code matches. `false` in every other case, which includes a value that is not a string.
	 */
	async verifyPrompt(response: unknown, context: AuthDanceComponentContext): Promise<boolean | AuthDanceIdentity["id"]> {
		const value = typeof response === "string" ? response : null;
		if (!value) {
			return false;
		}
		const code = await context.storage.getKv(`otp/${context.stateId}/${context.name}`).catch((_) => null);
		if (!code) {
			return false;
		}
		if (code !== value) {
			return false;
		}
		await context.storage.unsetKv(`otp/${context.stateId}/${context.name}`).catch((_) => null);
		return true;
	}

	/**
	 * Generates a code, stores it under `otp/<stateId>/<name>` for the configured time to live, and returns the
	 * message to deliver.
	 *
	 * The recipient is the channel the identity holds under the configured channel name. The code therefore goes to
	 * an address the identity already carries, and never to a value the client supplies. `content["text/x-code"]`
	 * holds the code. The component ignores `locale` for now, and the subject and the readable bodies are
	 * placeholders.
	 * @throws {@link ChannelNotSubscribedError} When the context carries no identity, or the identity holds no
	 * channel with the configured name.
	 */
	async sendPrompt(_locale: string, context: AuthDanceComponentContext): Promise<AuthDanceMessage> {
		const identityChannel = context.identity?.components
			.find((c): c is AuthDanceIdentityChannel => c.kind === "channel" && c.channel === this.#channel);
		if (!identityChannel) {
			throw new ChannelNotSubscribedError(this.#channel);
		}
		const code = otp({ digits: this.#digits });
		await context.storage.setKv(`otp/${context.stateId}/${context.name}`, code, this.#ttl);
		return {
			recipient: identityChannel,
			subject: "todo!",
			content: {
				"text/x-code": code,
				"text/plain": "todo!",
				"text/html": "todo!",
			},
		};
	}

	/**
	 * Always throws. As `verifiable` states, another component uses the OTP as its verification, so the OTP has
	 * none of its own.
	 * @throws {@link ComponentNotVerifiableError} On every call. The error message carries the step name from the
	 * context.
	 */
	// deno-lint-ignore require-await
	async verificationComponent?(context: AuthDanceComponentContext): Promise<AuthDanceComponent> {
		throw new ComponentNotVerifiableError(context.name);
	}
}
