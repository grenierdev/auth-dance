import type { AuthDanceComponent, AuthDanceComponentContext } from "../component.ts";
import { InvalidPromptValueError } from "../error.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent } from "../identity.ts";
import type { AuthDancePromptInput } from "../prompt.ts";

/** The endpoint that checks a Turnstile token. */
export const TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

// Cloudflare documents 2048 characters as the maximum length of a token.
const MAX_TOKEN_LENGTH = 2048;

/** Options for {@link CloudflareTurnstileAuthDanceComponent}. */
export interface CloudflareTurnstileAuthDanceComponentOptions {
	/** The site key of the widget. The prompt gives it to the client. It is not a secret. */
	siteKey: string;
	/** The secret key of the widget. Only the server reads it, to call the siteverify endpoint. */
	secretKey: string;
	/**
	 * The action that the widget sets and that the server checks. The client gives it to the widget as `action`. A
	 * token for another action is refused. Up to 32 characters: letters, digits, `_` and `-`.
	 */
	action?: string;
	/** The hostnames that can serve the widget. A token from another hostname is refused. Without it, any hostname. */
	hostnames?: string[];
	/**
	 * The time that the server waits for the siteverify endpoint, in milliseconds.
	 * @defaultValue `10000`
	 */
	timeout?: number;
}

/** The options of a prompt of the type `turnstile`. The client gives them to the Turnstile widget. */
export interface CloudflareTurnstilePromptOptions {
	/** The site key of the widget. */
	siteKey: string;
	/** The action of the widget, when the component sets one. */
	action?: string;
}

// The fields of the siteverify answer that the component reads.
interface SiteverifyResponse {
	success?: unknown;
	action?: unknown;
	hostname?: unknown;
}

/**
 * A Cloudflare Turnstile challenge. The client renders the Turnstile widget with the site key of the prompt, and
 * submits the token of the widget as a string. The server sends the token to the siteverify endpoint of Cloudflare.
 * The step slows down a bot that sends many sign-ups or many sign-in attempts.
 *
 * The prompt has the type `turnstile`, and its `options` is a {@link CloudflareTurnstilePromptOptions}. The component
 * keeps no record in KV. Cloudflare accepts a token one time only, and for 300 seconds. After a refused token, the
 * client resets the widget and submits a new token.
 *
 * The step proves nothing about the owner, so `proves` is `false`, and the step resolves no identity. It can come
 * before the first identification of a path, for example `sequence("turnstile", "email", "password")`. Before an
 * identity resolves, the `verify` rate limit has no identity to count against, so only the limits by address apply. A
 * step that proves control must still come at or after the first identification.
 *
 * The component context holds no address, so the component does not send `remoteip` to Cloudflare.
 *
 * When the siteverify endpoint does not answer, or answers with an HTTP error, the component raises an `Error` and not
 * {@link InvalidPromptValueError}. The fault is on the server side, not in the value of the owner.
 *
 * @example
 * ```ts
 * new CloudflareTurnstileAuthDanceComponent({
 *   siteKey: env.TURNSTILE_SITE_KEY,
 *   secretKey: env.TURNSTILE_SECRET_KEY,
 *   action: "sign-in",
 *   hostnames: ["app.example.com"],
 * });
 * ```
 */
export class CloudflareTurnstileAuthDanceComponent implements AuthDanceComponent {
	/** The record kind the component contributes to an identity. A Turnstile challenge never resolves an identity. */
	readonly kind: AuthDanceIdentityComponent["kind"] = "challenge";
	/** A token has no value to prove control of, so the class declares no `verificationComponent`. */
	readonly verifiable = false;
	/** A token tells that a browser passed the challenge, and proves nothing about the owner. */
	readonly proves = false;
	#siteKey: string;
	#secretKey: string;
	#action: string | undefined;
	#hostnames: string[] | undefined;
	#timeout: number;

	/**
	 * @param options The keys of the widget, the action and the hostnames that the server checks, and the time that
	 * the server waits for Cloudflare.
	 * @throws {TypeError} When a key is empty, `action` has more than 32 characters or a character that is not a
	 * letter, a digit, `_` or `-`, `hostnames` is empty, or `timeout` is not a positive number.
	 */
	constructor(options: CloudflareTurnstileAuthDanceComponentOptions) {
		if (!options.siteKey) {
			throw new TypeError("siteKey must not be empty");
		}
		if (!options.secretKey) {
			throw new TypeError("secretKey must not be empty");
		}
		if (options.action !== undefined && !/^[A-Za-z0-9_-]{1,32}$/.test(options.action)) {
			throw new TypeError("action must have 1 to 32 letters, digits, _ or -");
		}
		if (options.hostnames !== undefined && options.hostnames.length === 0) {
			throw new TypeError("hostnames must not be empty");
		}
		const timeout = options.timeout ?? 10_000;
		if (!(timeout > 0)) {
			throw new TypeError("timeout must be a positive number of milliseconds");
		}
		this.#siteKey = options.siteKey;
		this.#secretKey = options.secretKey;
		this.#action = options.action;
		this.#hostnames = options.hostnames ? [...options.hostnames] : undefined;
		this.#timeout = timeout;
	}

	/**
	 * Describes the input that the client renders. The input is not sendable.
	 * @returns One input of the type `turnstile`, whose `options` is a {@link CloudflareTurnstilePromptOptions}.
	 */
	async getPrompt(context: AuthDanceComponentContext): Promise<AuthDancePromptInput> {
		const options: CloudflareTurnstilePromptOptions = { siteKey: this.#siteKey };
		if (this.#action !== undefined) {
			options.action = this.#action;
		}
		return {
			kind: "input",
			name: context.name,
			type: "turnstile",
			sendable: false,
			options: { ...options },
		};
	}

	/**
	 * Builds the challenge record of a sign-up, an enroll, a rotate or a recover. A sign-up calls no `verifyPrompt`, so
	 * this method checks the token itself.
	 * @param component The component name that the record carries.
	 * @param value The token that the owner submitted.
	 * @param confirmed Whether the record starts as confirmed.
	 * @returns One challenge record with no data.
	 * @throws {InvalidPromptValueError} When Cloudflare refuses the token.
	 * @throws {Error} When the siteverify endpoint does not answer, or answers with an HTTP error.
	 */
	async getIdentityComponent(
		component: string,
		value: unknown,
		confirmed: boolean,
		_context: AuthDanceComponentContext,
	): Promise<AuthDanceIdentityComponent[]> {
		if (!(await this.#siteverify(value))) {
			throw new InvalidPromptValueError("Cloudflare Turnstile refused the token");
		}
		return [{ kind: "challenge", component, confirmed }];
	}

	/**
	 * Sends the token to the siteverify endpoint of Cloudflare.
	 * @param value The token that the owner submitted.
	 * @returns `true` when Cloudflare accepts the token, and the action and the hostname agree with the options.
	 * `false` for a value that is not a string of 1 to 2048 characters, and for a token that Cloudflare refuses. This
	 * method never returns an identity id.
	 * @throws {Error} When the siteverify endpoint does not answer, or answers with an HTTP error.
	 */
	async verifyPrompt(value: unknown, _context: AuthDanceComponentContext): Promise<boolean | AuthDanceIdentity["id"]> {
		return this.#siteverify(value);
	}

	// Checks the token with Cloudflare. Returns `false` before the request for a value that cannot be a token.
	async #siteverify(value: unknown): Promise<boolean> {
		if (typeof value !== "string" || value.length === 0 || value.length > MAX_TOKEN_LENGTH) {
			return false;
		}
		const response = await fetch(TURNSTILE_SITEVERIFY_URL, {
			method: "POST",
			headers: { "Content-Type": "application/json", Accept: "application/json" },
			body: JSON.stringify({ secret: this.#secretKey, response: value }),
			signal: AbortSignal.timeout(this.#timeout),
		});
		if (!response.ok) {
			throw new Error(`the Turnstile siteverify endpoint answered ${response.status}`);
		}
		const result = (await response.json().catch(() => null)) as SiteverifyResponse | null;
		if (typeof result !== "object" || result === null || result.success !== true) {
			return false;
		}
		if (this.#action !== undefined && result.action !== this.#action) {
			return false;
		}
		if (this.#hostnames !== undefined && (typeof result.hostname !== "string" || !this.#hostnames.includes(result.hostname))) {
			return false;
		}
		return true;
	}
}
