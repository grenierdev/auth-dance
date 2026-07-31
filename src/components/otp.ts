import type { AuthComponent, AuthComponentContext } from "../component.ts";
import type { Identity, IdentityChannel, IdentityComponent } from "../identity.ts";
import type { AuthMessage } from "../message.ts";
import type { AuthPromptInput } from "../prompt.ts";
import { otp } from "../otp.ts";
import { ChannelNotSubscribedError, ComponentNotVerifiableError } from "../error.ts";

export default class OtpAuthComponent implements AuthComponent {
	readonly kind: IdentityComponent["kind"] = "challenge";
	// The OTP is what other components verify themselves with; it has no verification of its own.
	readonly verifiable = false;
	#channel: string;
	#digits: number;
	#ttl: number;

	constructor(channel: string, digits: number = 6, ttl: number = 300) {
		this.#channel = channel;
		this.#digits = digits;
		this.#ttl = ttl;
	}

	// deno-lint-ignore require-await
	async getIdentityComponent(
		component: string,
		value: unknown,
		confirmed: boolean = false,
	): Promise<IdentityComponent[]> {
		return [
			{
				kind: "challenge",
				component,
				confirmed,
				data: { recipient: value },
			},
		];
	}

	// deno-lint-ignore require-await
	async getPrompt(context: AuthComponentContext): Promise<AuthPromptInput> {
		return {
			kind: "input",
			name: context.name,
			type: "otp",
			sendable: true,
		};
	}

	async verifyPrompt(response: unknown, context: AuthComponentContext): Promise<boolean | Identity["id"]> {
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

	async sendPrompt(_locale: string, context: AuthComponentContext): Promise<AuthMessage> {
		const identityChannel = context.identity?.components
			.find((c): c is IdentityChannel => c.kind === "channel" && c.channel === this.#channel);
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

	// deno-lint-ignore require-await
	async verificationComponent?(context: AuthComponentContext): Promise<AuthComponent> {
		// See `verifiable` above: the OTP is the verification, so it has none of its own.
		throw new ComponentNotVerifiableError(context.name);
	}
}
