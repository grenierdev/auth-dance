import type { AuthDanceComponent, AuthDanceComponentContext } from "../component.ts";
import { InvalidPromptValueError } from "../error.ts";
import type { AuthDanceIdentity, AuthDanceIdentityChallenge, AuthDanceIdentityComponent } from "../identity.ts";
import type { AuthDancePromptInput } from "../prompt.ts";

/** One document that the owner accepts, terms of service or a privacy notice for example. */
export interface Policy {
	/** The key of the document in the answer and in the stored record. No two documents of a component share it. */
	identifier: string;
	/** The current version of the document. Change it to ask every owner to accept the document again. */
	version: string;
	/** Whether the step refuses an answer that does not accept this document at its current version. */
	required: boolean;
	/** The title of the document, for each locale. The library sends it to the client and never reads it. */
	name: Record<string, string>;
	/** The text of the document, or a link to it, for each locale. The library sends it to the client and never reads it. */
	content: Record<string, string>;
}

/** The answer of the owner: the identifier of each document the owner accepts, mapped to its current version. */
export type PolicyAcceptance = Record<string, string>;

/** Options for {@link PolicyAuthDanceComponent}. */
export interface PolicyAuthDanceComponentOptions {
	/** The documents that the prompt shows, in this order. */
	policies: Policy[];
}

/**
 * A step in which the owner accepts documents, terms of service or a privacy notice for example. The record is a
 * challenge, and its `data` maps the identifier of each accepted document to the accepted version.
 *
 * The prompt has the type `policy`, and `options.policies` holds every document. The owner answers with a
 * {@link PolicyAcceptance}, `{ tos: "2", privacy: "1" }` for example. Each entry names a document of the component
 * at its current version. The step refuses an answer that does not accept a required document, unless the identity
 * already accepted that document at its current version.
 *
 * The step is `skippable`. A sign-in and a recovery dance go past it when the stored record accepts every required
 * document at its current version. An identity with no record of the step always gets the prompt. To ask every owner
 * for a new acceptance, change `version`: the next sign-in shows the step again, and refuses an answer without that
 * version.
 *
 * A sign-in saves the new acceptance on the identity as soon as the step accepts it, and no identity hook fires. A
 * recovery dance checks the answer and does not save it. A `rotate` of the step lets the owner accept an optional
 * document later.
 *
 * Put the step after a step that proves control, for example `sequence("email", "otp", "policy")`:
 * - The step resolves no identity, so it cannot be the first step of a sign-in.
 * - The library goes past the step only after a step that proves control.
 * - A sign-in saves the acceptance before the dance completes. Before a step that proves control, a person who only
 *   knows the address could accept the documents for the identity.
 *
 * The step proves nothing, so `proves` is `false`.
 *
 * @example
 * ```ts
 * new PolicyAuthDanceComponent({
 *     policies: [
 *         { identifier: "tos", version: "2", required: true, name: { en: "Terms" }, content: { en: "https://example.com/tos" } },
 *     ],
 * });
 * ```
 */
export class PolicyAuthDanceComponent implements AuthDanceComponent {
	/** The record kind the component contributes to an identity. An acceptance never resolves an identity. */
	readonly kind: AuthDanceIdentityComponent["kind"] = "challenge";
	/** An acceptance has no value to prove control of, so the class declares no `verificationComponent`. */
	readonly verifiable = false;
	/** Any owner can accept a document, so an accepted value proves nothing. */
	readonly proves = false;
	/** An identity that already accepted every required document needs nothing more from the step. */
	readonly skippable = true;
	#policies: Policy[];

	/**
	 * Keeps a copy of the documents. A later change to `options` does not change the component.
	 * @param options The documents that the prompt shows.
	 * @throws {TypeError} When `options.policies` is empty, when a document has an empty identifier, an empty version
	 * or a `required` that is not a boolean, and when two documents have the same identifier.
	 */
	constructor(options: PolicyAuthDanceComponentOptions) {
		if (!Array.isArray(options.policies) || options.policies.length === 0) {
			throw new TypeError("policies must hold at least one policy");
		}
		const identifiers = new Set<string>();
		for (const policy of options.policies) {
			if (!policy.identifier || typeof policy.identifier !== "string" || !policy.version || typeof policy.version !== "string") {
				throw new TypeError("each policy needs a non-empty identifier and version");
			}
			if (typeof policy.required !== "boolean") {
				throw new TypeError(`policy ${policy.identifier} needs a boolean required`);
			}
			if (identifiers.has(policy.identifier)) {
				throw new TypeError(`policy ${policy.identifier} is declared twice`);
			}
			identifiers.add(policy.identifier);
		}
		this.#policies = structuredClone(options.policies);
	}

	// The answer as entries of known documents, or `null` for an answer that names an unknown document or a version
	// that is not current.
	#parse(value: unknown): PolicyAcceptance | null {
		if (typeof value !== "object" || value === null || Array.isArray(value)) {
			return null;
		}
		const entries = Object.entries(value);
		const known = entries.every(([identifier, version]) =>
			this.#policies.some((p) => p.identifier === identifier && p.version === version),
		);
		return known ? (Object.fromEntries(entries) as PolicyAcceptance) : null;
	}

	#storedRecord(component: string, context: AuthDanceComponentContext): AuthDanceIdentityChallenge | undefined {
		return context.identity?.components.find((c): c is AuthDanceIdentityChallenge => c.kind === "challenge" && c.component === component);
	}

	#acceptsRequired(accepted: Record<string, unknown>): boolean {
		return this.#policies.every((policy) => !policy.required || accepted[policy.identifier] === policy.version);
	}

	/**
	 * Describes the input that the client renders: every document, under the component name. The input is not
	 * sendable.
	 * @returns One input of the type `policy`. `options.policies` holds a copy of the documents.
	 */
	async getPrompt(context: AuthDanceComponentContext): Promise<AuthDancePromptInput> {
		return {
			kind: "input",
			name: context.name,
			type: "policy",
			sendable: false,
			options: { policies: structuredClone(this.#policies) },
		};
	}

	/**
	 * Tells whether the identity already accepted every required document at its current version.
	 * @param context The context of the step, which carries the identity that the earlier steps resolved.
	 * @returns `true` when the identity holds a confirmed record of the step that accepts every required document,
	 * and `false` otherwise.
	 */
	async skipPrompt(context: AuthDanceComponentContext): Promise<boolean> {
		const stored = this.#storedRecord(context.name, context);
		return stored?.confirmed === true && this.#acceptsRequired(stored.data ?? {});
	}

	/**
	 * Turns an answer into the challenge record that the identity keeps. The `sign-up`, `enroll`, `rotate` and
	 * `recover` flows call this method. The record keeps each acceptance that the identity already holds, and adds
	 * the answer to it.
	 * @param component The component name that the record carries.
	 * @param value The {@link PolicyAcceptance} that the owner submitted.
	 * @param confirmed Whether the record starts as confirmed.
	 * @param context The context of the dance, which carries the identity as it stands.
	 * @returns One challenge record whose `data` maps each accepted document to its version.
	 * @throws {InvalidPromptValueError} When the value is not an object, names an unknown document or a version that
	 * is not current, or leaves a required document without acceptance.
	 */
	async getIdentityComponent(
		component: string,
		value: unknown,
		confirmed: boolean,
		context: AuthDanceComponentContext,
	): Promise<AuthDanceIdentityComponent[]> {
		const accepted = this.#parse(value);
		if (!accepted) {
			throw new InvalidPromptValueError("policy answer must map each identifier to the current version of its document");
		}
		const data = { ...this.#storedRecord(component, context)?.data, ...accepted };
		if (!this.#acceptsRequired(data)) {
			throw new InvalidPromptValueError("policy answer must accept every required document");
		}
		return [{ kind: "challenge", component, confirmed, data }];
	}

	/**
	 * Checks an answer against the acceptance that the identity holds.
	 * @param value The {@link PolicyAcceptance} that the owner submitted.
	 * @param context The context of the dance, which carries the identity that the earlier steps resolved.
	 * @returns `true` when the answer and the stored record together accept every required document at its current
	 * version, and `false` otherwise. This method never returns an identity id.
	 */
	async verifyPrompt(value: unknown, context: AuthDanceComponentContext): Promise<boolean | AuthDanceIdentity["id"]> {
		const accepted = this.#parse(value);
		return accepted !== null && this.#acceptsRequired({ ...this.#storedRecord(context.name, context)?.data, ...accepted });
	}

	/**
	 * Saves the acceptance that a sign-in step accepted. The record keeps each acceptance that the identity already
	 * holds. An identity with no record of the step gets one, an identity that enrolled before the step was added
	 * to the choreography for example.
	 * @param value The {@link PolicyAcceptance} that `verifyPrompt` accepted.
	 * @param context The context of the step, which carries the resolved identity.
	 * @returns One confirmed challenge record, or nothing when the answer adds nothing to the stored record.
	 */
	async upgradeIdentityComponent(value: unknown, context: AuthDanceComponentContext): Promise<AuthDanceIdentityComponent[] | undefined> {
		const accepted = this.#parse(value);
		if (!accepted || !context.identity) {
			return undefined;
		}
		const stored = this.#storedRecord(context.name, context);
		if (stored && Object.entries(accepted).every(([identifier, version]) => stored.data?.[identifier] === version)) {
			return undefined;
		}
		return [{ ...stored, kind: "challenge", component: context.name, confirmed: true, data: { ...stored?.data, ...accepted } }];
	}
}
