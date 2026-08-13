import type { AuthDanceComponent, AuthDanceComponentContext } from "../component.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent, AuthDanceIdentityIdentification } from "../identity.ts";
import type { AuthDancePromptInput } from "../prompt.ts";
import { OtpAuthDanceComponent, type OtpAuthDanceComponentOptions } from "./otp.ts";

export interface EmailAuthDanceComponentOptions extends OtpAuthDanceComponentOptions {
	/**
	 * The name the one-time code component is registered under in `AuthDanceApiOptions.components`. The challenge
	 * record the component contributes carries this name, so the identity holds the code factor under the same
	 * name a choreography step would name it by.
	 *
	 * Give it a name of its own. A name that also sits after this component in the same dance is collected twice
	 * in one sign-up, which the library refuses with `ComponentAlreadyCollectedError`.
	 */
	challenge: string;
}

/**
 * An email address as the step that resolves the identity, and a code sent to that address as the proof.
 *
 * The component contributes three records, and `linkedTo` binds them into one set. The identification holds the
 * address and answers who the owner is. The channel record gives the library somewhere to deliver a message. The
 * challenge record is the one-time code the library delivers over that channel, under the name
 * `options.challenge`. The channel and the challenge each name the identification in their `linkedTo`, so
 * `unenroll` and `unsubscribe` take all three down together rather than leaving a part behind.
 *
 * The verification is an `OtpAuthDanceComponent` over the same channel. The owner must read the code at the
 * address, so a match proves the address belongs to the owner.
 */
export class EmailAuthDanceComponent implements AuthDanceComponent {
	/** The record the component contributes to an identity. An `identification` resolves an identity on its own. */
	readonly kind: AuthDanceIdentityComponent["kind"] = "identification";
	/**
	 * The address can prove control of itself, because a code that the library sends to it reaches the owner.
	 * `verificationComponent` returns the component that sends the code.
	 */
	readonly verifiable = true;

	#options: EmailAuthDanceComponentOptions;

	/**
	 * Creates the component over one named channel, and under one name for the code that proves the address.
	 *
	 * The component keeps both names and puts them on the records it builds. The one-time code that proves control
	 * of the address travels over the channel, and the challenge record it contributes carries `options.challenge`.
	 * @param options `channel` names the channel the component contributes, `challenge` names the one-time code
	 * component. Every other key configures that code, exactly as `OtpAuthDanceComponent` reads it.
	 */
	constructor(options: EmailAuthDanceComponentOptions) {
		this.#options = options;
	}

	/**
	 * Builds the three records an address contributes: the identification, the channel that reaches it, and the
	 * one-time code challenge the library delivers over that channel.
	 *
	 * The channel record keeps the address in `data.email` and carries `confirmed: true`, because the
	 * identification beside it holds the same address. The challenge record comes from `OtpAuthDanceComponent`
	 * itself, so the code factor is recorded the same way whether this component contributes it or a choreography
	 * step collects it. Both name the identification in their `linkedTo`. A value that is not a string becomes an
	 * empty address.
	 *
	 * `confirmed` reaches the identification and the challenge, never the channel. The library confirms the record
	 * that carries the name of the step it ran, so a flow that collects this component leaves the challenge
	 * unconfirmed until something confirms it under its own name.
	 * @param component The name the identification carries, which is the name of the step in the choreography.
	 * @param value What the owner submitted. All three records hold this address.
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

	/**
	 * Describes the address entry the client renders. The prompt is not sendable: the owner types the address, and
	 * the library has nowhere to deliver a message before it holds one.
	 */
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
	 * Resolves the identity an address belongs to.
	 *
	 * The lookup passes `context.name` as the identification component name, which is the name the record carries.
	 * A deployment that declares the component twice — a work address and a personal one, say — therefore resolves
	 * each name through its own records. The identity then has to hold an identification under that name carrying
	 * the same address, and confirmed: an identification that nobody confirmed gives `false`. The component
	 * normalizes nothing, so the lookup and the comparison both use the address as the client typed it.
	 * @returns The id of the identity that owns the address. `false` in every other case, which includes a value
	 * that is not a string.
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
	 * Builds the OTP that proves control of the address. The OTP is an `OtpAuthDanceComponent` over the same channel,
	 * with the default six digits and the default time to live of 300 seconds.
	 *
	 * The OTP reads the recipient from the identity in the context. The library puts the records collected in this
	 * flow first, so the code goes to the address the owner just claimed.
	 */
	// deno-lint-ignore require-await
	async verificationComponent?(_context: AuthDanceComponentContext): Promise<AuthDanceComponent> {
		return new OtpAuthDanceComponent(this.#options);
	}
}
