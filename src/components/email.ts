import type { AuthDanceComponent, AuthDanceComponentContext } from "../component.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent, AuthDanceIdentityIdentification } from "../identity.ts";
import type { AuthDancePromptInput } from "../prompt.ts";
import OtpAuthDanceComponent from "./otp.ts";

/**
 * An email address as the step that resolves the identity, and a code sent to that address as the proof.
 *
 * The component contributes two records. The identification holds the address and answers who the owner is. The
 * channel record gives the library somewhere to deliver a message, and its `linkedTo` names the identification.
 * `unsubscribe` therefore refuses to detach the channel while that identification stays enrolled.
 *
 * The verification is an `OtpAuthDanceComponent` over the same channel. The owner must read the code at the
 * address, so a match proves the address belongs to the owner.
 */
export default class EmailAuthDanceComponent implements AuthDanceComponent {
	/** The record the component contributes to an identity. An `identification` resolves an identity on its own. */
	readonly kind: AuthDanceIdentityComponent["kind"] = "identification";
	/**
	 * The address can prove control of itself, because a code that the library sends to it reaches the owner.
	 * `verificationComponent` returns the component that sends the code.
	 */
	readonly verifiable = true;
	#channel: string;

	/**
	 * Creates the component over one named channel.
	 *
	 * The component keeps the name and puts it on the channel record it builds. The one-time code that proves control
	 * of the address travels over the same channel.
	 * @param channel The name of the channel the component contributes.
	 */
	constructor(channel: string) {
		this.#channel = channel;
	}

	/**
	 * Builds the two records an address contributes: the identification, and the channel that reaches it.
	 *
	 * The channel record keeps the address in `data.email` and carries `confirmed: true`, and its `linkedTo` names
	 * the identification. A value that is not a string becomes an empty address.
	 * @param component The name the identification carries, which is the name of the step in the choreography.
	 * @param value What the owner submitted. Both records hold this address.
	 * @param confirmed Whether the owner already proved control of the address. It applies to the identification
	 * only. Defaults to `false`.
	 * @returns The identification record first, then the channel record.
	 */
	// deno-lint-ignore require-await
	async getIdentityComponent(
		component: string,
		value: unknown,
		confirmed: boolean = false,
	): Promise<AuthDanceIdentityComponent[]> {
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
				component: this.#channel,
				confirmed: true,
				data: { email },
				linkedTo: [component],
			},
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
		return new OtpAuthDanceComponent(this.#channel);
	}
}
