import type { AuthDanceComponent, AuthDanceComponentContext } from "../component.ts";
import type { Identity, IdentityComponent, IdentityIdentification } from "../identity.ts";
import type { AuthDancePromptInput } from "../prompt.ts";
import OtpAuthDanceComponent from "./otp.ts";

export default class EmailAuthDanceComponent implements AuthDanceComponent {
	readonly kind: IdentityComponent["kind"] = "identification";
	readonly verifiable = true;
	#channel: string;

	constructor(channel: string) {
		this.#channel = channel;
	}

	// deno-lint-ignore require-await
	async getIdentityComponent(
		component: string,
		value: unknown,
		confirmed: boolean = false,
	): Promise<IdentityComponent[]> {
		const email = typeof value === "string" ? value : "";
		return [
			{
				kind: "identification",
				component,
				confirmed,
				identification: email,
			},
			{
				kind: "channel",
				channel: this.#channel,
				confirmed: true,
				data: { email },
				linkedTo: [component],
			},
		];
	}

	// deno-lint-ignore require-await
	async getPrompt(context: AuthDanceComponentContext): Promise<AuthDancePromptInput> {
		return {
			kind: "input",
			name: context.name,
			type: "email",
			sendable: false,
		};
	}

	async verifyPrompt(response: unknown, context: AuthDanceComponentContext): Promise<boolean | Identity["id"]> {
		const identification = typeof response === "string" ? response : null;
		if (!identification) {
			return false;
		}
		const identity = await context.storage
			.getIdentityByIdentification("email", identification)
			.catch((_) => null);
		if (!identity) {
			return false;
		}
		const identityComponent = identity.components
			.find((c): c is IdentityIdentification => c.kind === "identification" && c.component === context.name);
		if (
			!identityComponent ||
			!("identification" in identityComponent) ||
			identityComponent.identification !== identification ||
			identityComponent.confirmed === false
		) {
			return false;
		}
		return identity.id;
	}

	// deno-lint-ignore require-await
	async verificationComponent?(_context: AuthDanceComponentContext): Promise<AuthDanceComponent> {
		return new OtpAuthDanceComponent(this.#channel);
	}
}
