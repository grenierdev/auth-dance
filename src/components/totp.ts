import type { AuthDanceComponent, AuthDanceComponentContext } from "../component.ts";
import { InvalidPromptValueError } from "../error.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent } from "../identity.ts";
import { isOTPAlgorithm, type OTPAlgorithm, totp } from "../otp.ts";
import type { AuthDancePromptInput } from "../prompt.ts";

/** What a `TotpAuthDanceComponent` reads from a record it stored, with the defaults of the component for a record that omits one. */
interface TotpRecord {
	/** The shared key in base32. */
	key: string;
	/** The HMAC hash that derives the code. */
	algorithm: OTPAlgorithm;
	/** The number of digits in the code. */
	digits: number;
	/** The length of one time step in seconds. */
	period: number;
}

/** The characters of a base32 key, without the padding that `generateKey` never writes. */
const KEY_PATTERN = /^[A-Z2-7]+$/;

/** The characters of a code. */
const CODE_PATTERN = /^[0-9]+$/;

/** Options for {@link TotpAuthDanceComponent}. Every key has a default, so the component takes no options at all. */
export interface TotpAuthDanceComponentOptions {
	/** The number of digits in the code. @defaultValue `6` */
	digits?: number;
	/** The length of one time step in seconds. One code stays valid for one step. @defaultValue `30` */
	period?: number;
	/**
	 * The HMAC hash that derives the code.
	 *
	 * Keep the default. `hotp` truncates at byte 19, which is the last byte of a `SHA-1` HMAC only, so another hash
	 * gives a code that an authenticator app does not match.
	 * @defaultValue `"SHA-1"`
	 */
	algorithm?: OTPAlgorithm;
	/**
	 * The number of time steps the component accepts on each side of the current one, for a clock that drifts. A
	 * window of `1` with the default period accepts a code for 90 seconds. @defaultValue `1`
	 */
	window?: number;
}

/**
 * A time-based code, the TOTP of RFC 6238. The owner keeps the shared key in an authenticator app and answers with
 * the code that the app shows.
 *
 * The component collects the key and it verifies the code, and the type of the prompt names the value the flow
 * asks for:
 *
 * - A `sign-up`, an `enroll`, a `rotate` and a `recover` collect the key, through a prompt of the type `totp-key`.
 *   The client generates the key, keeps it, and submits it. `generateKey` and `toURI` of the `auth-dance` module
 *   build the key and the `otpauth://` URI that the authenticator app reads, and the library never sees either one.
 * - The component is verifiable, so each of those flows then asks for a code that the collected key derives,
 *   through a prompt of the type `totp`. Until that code lands the record stays unconfirmed, and a key that reached
 *   nobody enrolls nobody.
 * - A `sign-in` asks for a code, with the same prompt type `totp`, and verifies it against the key the identity
 *   holds.
 *
 * The store holds the key in base32 under `data.key`, which `/list-components` drops. Anybody that reads the
 * identity store derives every code, so protect that store the way you protect a password store.
 *
 * A code works one time. The component writes the time step it accepted to the key-value store under
 * `totp/<identityId>/<name>`, and it refuses that step and every step before it.
 *
 * @example
 * ```ts
 * const components = { totp: new TotpAuthDanceComponent({ digits: 6, period: 30 }) };
 * ```
 */
export class TotpAuthDanceComponent implements AuthDanceComponent {
	/** The record kind the component contributes to an identity. A code proves a claim, so it never resolves an identity. */
	readonly kind: AuthDanceIdentityComponent["kind"] = "challenge";
	/** The key proves control of itself through a code, so `verificationComponent` returns the component that asks for one. */
	readonly verifiable = true;

	#digits: number;
	#period: number;
	#algorithm: OTPAlgorithm;
	#window: number;
	// Whether this instance is the verification `verificationComponent` returns. It always asks for a code.
	#validation = false;

	/**
	 * Keeps the shape of the codes this component derives.
	 *
	 * A change of `digits`, of `period` or of `algorithm` reaches new records only. Each record carries the values
	 * that built it, and a verification reads them from the record.
	 * @param options The number of digits, the length of a time step, the hash and the drift window.
	 */
	constructor(options: TotpAuthDanceComponentOptions = {}) {
		this.#digits = options.digits ?? 6;
		this.#period = options.period ?? 30;
		this.#algorithm = options.algorithm ?? "SHA-1";
		this.#window = options.window ?? 1;
	}

	// The record the identity holds under `name`, with the defaults of this component for a value it omits. The
	// contexts of a sign-up, an enroll, a rotate and a recover put the collected record first, so a verification
	// that follows a collection reads the new key and never the one it replaces.
	#record(context: AuthDanceComponentContext, name: string): TotpRecord | undefined {
		const stored = context.identity?.components
			.find((c) => c.kind === "challenge" && c.component === name && typeof c.data?.key === "string");
		if (!stored) {
			return undefined;
		}
		const data = stored.data!;
		return {
			key: data.key as string,
			algorithm: isOTPAlgorithm(data.algorithm) ? data.algorithm : this.#algorithm,
			digits: typeof data.digits === "number" ? data.digits : this.#digits,
			period: typeof data.period === "number" ? data.period : this.#period,
		};
	}

	// The submitted key as the store holds it. The method drops the spaces of a key that a human copied, and it
	// puts the key in upper case. `hotp` reads a string key as base32 and refuses a length that is not a multiple
	// of 8, so the method refuses one here, where the failure still names the step.
	#prepareKey(value: unknown): string | null {
		if (typeof value !== "string") {
			return null;
		}
		const key = value.replaceAll(" ", "").toUpperCase();
		if (!key || key.length % 8 !== 0 || !KEY_PATTERN.test(key)) {
			return null;
		}
		return key;
	}

	/**
	 * Turns a submitted key into the challenge record the identity holds. The `sign-up`, `enroll`, `rotate` and
	 * `recover` flows call this method. The record starts unconfirmed, and the code of the verification confirms it.
	 * @param component The component name the record carries.
	 * @param value The shared key in base32. Its length must be a multiple of 8.
	 * @param confirmed Whether the record starts as confirmed.
	 * @returns One challenge record. `data` holds the key, the hash, the number of digits and the length of a step.
	 * @throws {@link InvalidPromptValueError} When the value is not a base32 string with a length that is a multiple
	 * of 8, or when it matches the key it replaces.
	 */
	// deno-lint-ignore require-await
	async getIdentityComponent(
		component: string,
		value: unknown,
		confirmed: boolean,
		context: AuthDanceComponentContext,
	): Promise<AuthDanceIdentityComponent[]> {
		const key = this.#prepareKey(value);
		if (!key) {
			throw new InvalidPromptValueError("totp key must be a base32 string with a length that is a multiple of 8");
		}
		if (this.#record(context, component)?.key === key) {
			throw new InvalidPromptValueError("totp key must differ from the one it replaces");
		}
		return [
			{
				kind: "challenge",
				component,
				confirmed,
				data: {
					key,
					algorithm: this.#algorithm,
					digits: this.#digits,
					period: this.#period,
				},
			},
		];
	}

	// A sign-in verifies a code against the key the identity already holds, so the prompt of that flow asks for the
	// code. Every other flow collects the key, and the verification that follows it asks for the code.
	#promptType(context: AuthDanceComponentContext): "totp-key" | "totp" {
		return this.#validation || context.flow === "sign-in" ? "totp" : "totp-key";
	}

	/**
	 * Describes the entry the client renders, under the component name. The type names the value of the prompt:
	 * `totp-key` for the key the client generates, `totp` for the code that proves it. The input is not sendable,
	 * because no channel delivers a code that the owner already holds.
	 *
	 * `options.digits`, `options.period` and `options.algorithm` build the `otpauth://` URI.
	 * @returns One input for the client to render.
	 */
	// deno-lint-ignore require-await
	async getPrompt(context: AuthDanceComponentContext): Promise<AuthDancePromptInput> {
		return {
			kind: "input",
			name: context.name,
			type: this.#promptType(context),
			sendable: false,
			options: {
				digits: this.#digits,
				period: this.#period,
				algorithm: this.#algorithm,
			},
		};
	}

	/**
	 * Checks a submitted code against the key the identity holds under `context.name`. The method reads the number
	 * of digits, the hash and the length of a step from that record, never from the options of this component.
	 *
	 * The method accepts the current time step and `window` steps on each side. It then writes the step it accepted
	 * to `totp/<identityId>/<name>`, and it refuses that step and every step before it. A code works one time.
	 * @param response The submitted code.
	 * @param context The context of the dance, which carries the identity the code belongs to.
	 * @returns `true` when the code matches. `false` in every other case, which includes an identity with no key, a
	 * value that is not a string of digits, and a code that the owner already spent. This method never returns an
	 * identity id.
	 */
	async verifyPrompt(response: unknown, context: AuthDanceComponentContext): Promise<boolean | AuthDanceIdentity["id"]> {
		const record = this.#record(context, context.name);
		if (!record) {
			return false;
		}
		const code = typeof response === "string" ? response.replaceAll(" ", "") : "";
		if (code.length !== record.digits || !CODE_PATTERN.test(code)) {
			return false;
		}
		const current = Math.floor(Date.now() / 1000 / record.period);
		let accepted: number | undefined;
		for (let step = -this.#window; step <= this.#window; step++) {
			const counter = current + step;
			const expected = await totp({
				key: record.key,
				time: counter * record.period,
				period: record.period,
				algorithm: record.algorithm,
				digits: record.digits,
			});
			// The loop reads every step of the window, so the answer says nothing about the step that matched.
			if (expected === code) {
				accepted = counter;
			}
		}
		if (accepted === undefined) {
			return false;
		}
		const identityId = context.identity?.id;
		if (!identityId) {
			return true;
		}
		const spentKey = `totp/${identityId}/${context.name}`;
		const spent = Number(await context.storage.getKv(spentKey));
		if (Number.isFinite(spent) && accepted <= spent) {
			return false;
		}
		await context.storage.setKv(spentKey, accepted.toString(), record.period * (this.#window * 2 + 1));
		return true;
	}

	/**
	 * Builds the component that proves control of the collected key. It asks for a code, with the same options, and
	 * it derives that code from the key the flow just collected.
	 * @returns The component that asks for the code. Its prompt carries the type `totp`.
	 */
	// deno-lint-ignore require-await
	async verificationComponent(_context: AuthDanceComponentContext): Promise<AuthDanceComponent> {
		const component = new TotpAuthDanceComponent({
			digits: this.#digits,
			period: this.#period,
			algorithm: this.#algorithm,
			window: this.#window,
		});
		component.#validation = true;
		return component;
	}
}
