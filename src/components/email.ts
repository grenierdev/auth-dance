import type { AuthDanceComponent, AuthDanceComponentContext } from "../component.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent, AuthDanceIdentityIdentification } from "../identity.ts";
import type { AuthDancePromptInput } from "../prompt.ts";
import { OtpAuthDanceComponent, type OtpAuthDanceComponentOptions } from "./otp.ts";

export interface EmailAuthDanceComponentOptions extends OtpAuthDanceComponentOptions {
	/**
	 * The name the one-time code component is registered under in `AuthDanceApiOptions.components`. Give it a name
	 * of its own. A name that also sits after this component in the same dance is collected twice in one sign-up,
	 * which fails with `ComponentAlreadyCollectedError`.
	 */
	challenge: string;
}

/**
 * An email address as the step that resolves the identity, and a code sent to that address as the proof.
 *
 * The component contributes three records that `linkedTo` binds into one set: the identification that holds the
 * address, the channel that reaches it, and the one-time code challenge under `options.challenge`.
 */
export class EmailAuthDanceComponent implements AuthDanceComponent {
	/** The record the component contributes to an identity. An `identification` resolves an identity on its own. */
	readonly kind: AuthDanceIdentityComponent["kind"] = "identification";
	/** The address can prove control of itself. `verificationComponent` returns the component that sends the code. */
	readonly verifiable = true;

	#options: EmailAuthDanceComponentOptions;

	/**
	 * Creates the component over one named channel, and under one name for the code that proves the address.
	 * @param options `channel` names the channel, `challenge` names the one-time code component. Every other key
	 * configures that code.
	 */
	constructor(options: EmailAuthDanceComponentOptions) {
		this.#options = options;
	}

	/**
	 * Builds the three records an address contributes: the identification, the channel that reaches it, and the
	 * one-time code challenge.
	 *
	 * `confirmed` reaches the identification and the challenge, never the channel. A value that is not a string
	 * becomes an empty address.
	 * @param confirmed Whether the owner already proved control of the address. Defaults to `false`.
	 * @returns The identification record first, then the channel record, then the challenge record.
	 */
	async getIdentityComponent(
		component: string,
		value: unknown,
		confirmed: boolean = false,
	): Promise<AuthDanceIdentityComponent[]> {
		const email = typeof value === "string" ? value : "";
		const challenges = await new OtpAuthDanceComponent(this.#options)
			.getIdentityComponent(this.#options.challenge, email, confirmed);
		return [
			{
				kind: "identification",
				component,
				confirmed,
				identification: email,
			},
			{
				kind: "channel",
				component: this.#options.channel,
				confirmed: true,
				data: { email },
				linkedTo: [component],
			},
			...challenges.map((challenge) => ({ ...challenge, linkedTo: [component] })),
		];
	}

	/** Describes the address entry the client renders. The prompt is not sendable. */
	// deno-lint-ignore require-await
	async getPrompt(context: AuthDanceComponentContext): Promise<AuthDancePromptInput> {
		return {
			kind: "input",
			name: context.name,
			type: "email",
			sendable: false,
		};
	}

	/**
	 * Resolves the identity an address belongs to. The identity must hold a confirmed identification under
	 * `context.name` that carries the same address. The component normalizes nothing.
	 * @returns The id of the identity that owns the address, or `false`. A value that is not a string gives `false`.
	 */
	async verifyPrompt(response: unknown, context: AuthDanceComponentContext): Promise<boolean | AuthDanceIdentity["id"]> {
		const identification = typeof response === "string" ? response : null;
		if (!identification) {
			return false;
		}
		const identity = await context.storage
			.getIdentityByIdentification(context.name, identification)
			.catch((_) => null);
		if (!identity) {
			return false;
		}
		const identityComponent = identity.components
			.find((c): c is AuthDanceIdentityIdentification => c.kind === "identification" && c.component === context.name);
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

	/**
	 * Builds the one-time code component that proves control of the address, over the same channel, with the default
	 * six digits and the default time to live of 300 seconds. The component reads the recipient from the identity in
	 * the context.
	 */
	// deno-lint-ignore require-await
	async verificationComponent?(_context: AuthDanceComponentContext): Promise<AuthDanceComponent> {
		return new OtpAuthDanceComponent(this.#options);
	}
}
