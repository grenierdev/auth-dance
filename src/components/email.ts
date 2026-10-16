import type { AuthDanceComponent, AuthDanceComponentContext } from "../component.ts";
import { normalizeEmailAddress } from "../email-address.ts";
import { InvalidPromptValueError } from "../error.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent, AuthDanceIdentityIdentification } from "../identity.ts";
import type { AuthDancePromptInput } from "../prompt.ts";
import type { AuthDanceStorage } from "../storage.ts";
import { OtpAuthDanceComponent, type OtpAuthDanceComponentOptions } from "./otp.ts";

export { normalizeEmailAddress } from "../email-address.ts";

export interface EmailAuthDanceComponentOptions extends OtpAuthDanceComponentOptions {
	/**
	 * The name the one-time code challenge is stored under. Register an `OtpAuthDanceComponent` under the same name in
	 * `AuthDanceApiOptions.components`.
	 *
	 * For a sign-in by address and code, put the step of this name right after the address:
	 * `sequence("email", "otp")` with `challenge: "otp"`. A sign-up then proves the address, and asks for a second
	 * code for the `otp` step. A code step under a name of its own fails in a sign-up, because the sign-up then
	 * collects the code as a value.
	 */
	challenge: string;
	/**
	 * Keeps the case of the local part. Without it, `Victim@Example.com` and `victim@example.com` name one identity.
	 * Set it only for a mail system where the local part depends on its case.
	 * @defaultValue `false`
	 */
	preserveLocalCase?: boolean;
}

/**
 * An email address as the step that resolves the identity, and a code sent to that address as the proof.
 *
 * The component contributes three records that `linkedTo` binds into one set: the identification that holds the
 * address, the channel that reaches it, and the one-time code challenge under `options.challenge`.
 *
 * In a sign-in the address names an identity and proves nothing. Follow it with a step that proves control, a
 * password or the one-time code step under `options.challenge`.
 *
 * The component stores and looks up each address in the form `normalizeEmailAddress` gives: trimmed, in NFC, and in
 * lower case, the local part included unless `options.preserveLocalCase` is set.
 */
export class EmailAuthDanceComponent implements AuthDanceComponent {
	/** The record the component contributes to an identity. An `identification` resolves an identity on its own. */
	readonly kind: AuthDanceIdentityComponent["kind"] = "identification";
	/** The address can prove control of itself. `verificationComponent` returns the component that sends the code. */
	readonly verifiable = true;
	/** Anyone can type an address, so an accepted value names an identity and proves nothing. */
	readonly proves = false;

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
	 * one-time code challenge. All three hold the normalized address.
	 *
	 * `confirmed` reaches the identification and the challenge, never the channel.
	 * @param confirmed Whether the owner already proved control of the address. Defaults to `false`.
	 * @returns The identification record first, then the channel record, then the challenge record.
	 * @throws {InvalidPromptValueError} The value is not one address. See `normalizeEmailAddress`.
	 */
	async getIdentityComponent(component: string, value: unknown, confirmed: boolean = false): Promise<AuthDanceIdentityComponent[]> {
		const email = normalizeEmailAddress(value, this.#options);
		if (email === null) {
			throw new InvalidPromptValueError(`${component} must be one email address`);
		}
		const challenges = await new OtpAuthDanceComponent(this.#options).getIdentityComponent(this.#options.challenge, email, confirmed);
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
	 * `context.name` that carries the same address. The component normalizes the value the same way
	 * `getIdentityComponent` does before the lookup.
	 * @returns The id of the identity that owns the address, or `false`. A value that is not one address gives `false`.
	 */
	async verifyPrompt(response: unknown, context: AuthDanceComponentContext): Promise<boolean | AuthDanceIdentity["id"]> {
		const identification = normalizeEmailAddress(response, this.#options);
		if (identification === null) {
			return false;
		}
		const identity = await context.storage.getIdentityByIdentification(context.name, identification).catch((_) => null);
		if (!identity) {
			return false;
		}
		const identityComponent = identity.components.find(
			(c): c is AuthDanceIdentityIdentification => c.kind === "identification" && c.component === context.name,
		);
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

	async verificationComponent?(_context: AuthDanceComponentContext): Promise<AuthDanceComponent> {
		return new OtpAuthDanceComponent(this.#options);
	}
}

/**
 * Rewrites every identification of `component` into the form `normalizeEmailAddress` gives, for the records that
 * versions before rc.5 stored as typed. Run it one time, with the options the component uses.
 *
 * The function also rewrites the channel and the one-time code challenge that link to each identification. It first
 * groups the identities by normalized address. A group of two or more identities is a collision: two accounts for one
 * inbox. The function reports each collision and changes nothing in it, so a person decides which account stays. An
 * identification that is not one address stays as it is.
 *
 * @param storage The storage that holds the identities.
 * @param component The name the email component is registered under.
 * @param options `preserveLocalCase`, the same value the component uses.
 * @returns The ids of the identities it rewrote, and the ids of each collision group.
 */
export async function normalizeEmailIdentifications(
	storage: AuthDanceStorage,
	component: string,
	options?: { preserveLocalCase?: boolean },
): Promise<{ updated: string[]; collisions: string[][] }> {
	// Adapters read the cursor as the first id of the page or as the id before it, so skip any id already seen.
	const identities = new Map<string, AuthDanceIdentity>();
	for (let cursor: string | undefined; ; ) {
		const page = (await storage.listIdentities(cursor, 100)).filter((identity) => !identities.has(identity.id));
		if (page.length === 0) {
			break;
		}
		for (const identity of page) {
			identities.set(identity.id, identity);
		}
		cursor = page[page.length - 1].id;
	}

	const groups = new Map<string, string[]>();
	const rewrites: Array<{ identity: AuthDanceIdentity; from: string; to: string }> = [];
	for (const identity of identities.values()) {
		const record = identity.components.find(
			(c): c is AuthDanceIdentityIdentification => c.kind === "identification" && c.component === component,
		);
		const normalized = record && normalizeEmailAddress(record.identification, options);
		if (!record || !normalized) {
			continue;
		}
		groups.set(normalized, [...(groups.get(normalized) ?? []), identity.id]);
		if (normalized !== record.identification) {
			rewrites.push({ identity, from: record.identification, to: normalized });
		}
	}

	const collisions = [...groups.values()].filter((ids) => ids.length > 1);
	const colliding = new Set(collisions.flat());
	const updated: string[] = [];
	for (const { identity, from, to } of rewrites) {
		if (colliding.has(identity.id)) {
			continue;
		}
		for (const c of identity.components) {
			if (c.kind === "identification" && c.component === component) {
				c.identification = to;
			} else if (c.linkedTo?.includes(component) && c.data) {
				if (c.kind === "channel" && c.data.email === from) {
					c.data.email = to;
				} else if (c.kind === "challenge" && c.data.recipient === from) {
					c.data.recipient = to;
				}
			}
		}
		await storage.setIdentity(identity);
		updated.push(identity.id);
	}
	return { updated, collisions };
}
