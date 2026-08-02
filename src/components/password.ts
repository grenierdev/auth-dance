import { argon2id, argon2Verify } from "hash-wasm";
import type { AuthDanceComponent, AuthDanceComponentContext } from "../component.ts";
import { PolicyViolationError } from "../error.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent } from "../identity.ts";
import type { AuthDancePromptInput } from "../prompt.ts";

/**
 * The Argon2id cost that `PasswordAuthDanceComponent` pays for every new hash.
 *
 * The defaults match the OWASP floor for the `m=19456, t=2, p=1` profile. One hash costs about 70 milliseconds and
 * 19 MiB. The cost is deliberate, because an attacker who steals the store pays it again for every guess. A
 * verification reads the cost from the stored record instead of from here. Lower these numbers for a test suite.
 * Never lower them for a deployment.
 */
export interface PasswordParams {
	/** Kibibytes of memory that one hash occupies. Extra GPU cores do not remove this memory cost. */
	memorySize: number;
	/** Passes that Argon2id makes over the memory. This is the `t` cost, and it scales the time one hash takes. */
	iterations: number;
	/** Lanes that Argon2id runs. This is the `p` cost in the PHC string. */
	parallelism: number;
}

/**
 * The length bounds that a password must satisfy before the component stores it.
 *
 * The policy governs what the component writes to an identity. `verifyPrompt` does not apply it, because a length
 * check would reject an old password faster than a wrong one.
 */
export interface PasswordPolicy {
	/**
	 * The fewest code points a stored password may have. NIST SP 800-63B puts length ahead of composition rules,
	 * so length is the only rule here.
	 */
	minLength: number;
	/**
	 * The most code points a stored password may have. This limits the work that one submission can cost. It says
	 * nothing about strength.
	 */
	maxLength: number;
}

/**
 * The cost that `PasswordAuthDanceComponent` uses when the caller passes no `params`.
 *
 * @defaultValue `{ memorySize: 19456, iterations: 2, parallelism: 1 }`
 */
export const DEFAULT_PASSWORD_PARAMS: PasswordParams = { memorySize: 19456, iterations: 2, parallelism: 1 };

/**
 * The length bounds that `PasswordAuthDanceComponent` uses when the caller passes no `policy`.
 *
 * @defaultValue `{ minLength: 12, maxLength: 256 }`
 */
export const DEFAULT_PASSWORD_POLICY: PasswordPolicy = { minLength: 12, maxLength: 256 };

/**
 * A password component. It keeps the password as an Argon2id PHC string in `data.hash`:
 * `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<digest>`.
 *
 * Three properties make that record safe to hold. Argon2id is memory-hard, so a guess costs the attacker what it
 * costs the server. The salt is 16 fresh random bytes per record. No precomputation carries from one identity to
 * the next, and two identities with the same password do not share a record. The parameters travel inside the
 * record, so a later cost increase does not invalidate what the store already holds. Each record verifies against
 * the cost that created it.
 *
 * The constructor secret is a pepper, not a salt. It never reaches the identity store. A stolen copy of the store
 * alone is therefore not enough to crack a password. The component applies the pepper as
 * `HMAC-SHA256(pepper, password)` before the KDF instead of a concatenation. This also flattens the input to 32
 * bytes, which makes the maximum length a policy choice instead of a property of the construction.
 *
 * Keep the pepper in a secret store. A new pepper invalidates every existing record. Only the `rotate` and
 * `recover` flows can rebuild one.
 */
export default class PasswordAuthDanceComponent implements AuthDanceComponent {
	/** A password only proves a claim against an identity, so it is a `challenge` and never resolves an identity. */
	readonly kind: AuthDanceIdentityComponent["kind"] = "challenge";
	/**
	 * A password cannot prove control of its own value. The same text typed a second time proves nothing. The class
	 * therefore declares no `verificationComponent`.
	 */
	readonly verifiable = false;
	#pepper: Promise<CryptoKey>;
	#params: PasswordParams;
	#policy: PasswordPolicy;
	#decoy: Promise<string> | undefined;

	/**
	 * Imports the pepper as an HMAC-SHA256 key and merges the options over the defaults.
	 *
	 * @param pepper The secret that the component mixes into every password before the KDF. Keep it in a secret
	 * store. Never put it in source code.
	 * @param options `params` raises or lowers the Argon2id cost, and `policy` moves the length bounds. The
	 * component merges each one over `DEFAULT_PASSWORD_PARAMS` and `DEFAULT_PASSWORD_POLICY`, so a partial object
	 * is enough.
	 * @example
	 * ```ts
	 * new PasswordAuthDanceComponent(Deno.env.get("PASSWORD_PEPPER")!, { policy: { minLength: 16 } });
	 * ```
	 */
	constructor(pepper: string, options?: { params?: Partial<PasswordParams>; policy?: Partial<PasswordPolicy> }) {
		this.#pepper = crypto.subtle.importKey("raw", new TextEncoder().encode(pepper), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
		this.#params = { ...DEFAULT_PASSWORD_PARAMS, ...options?.params };
		this.#policy = { ...DEFAULT_PASSWORD_POLICY, ...options?.policy };
	}

	/**
	 * Turns a password into the bytes that Argon2id consumes. No plain text travels further than this method.
	 *
	 * The method normalizes the text to NFKC, so the same password from a different keyboard layout still verifies.
	 * When `enforce` is `true`, the method also applies the length policy. Last, it mixes the pepper into the text
	 * with HMAC-SHA256.
	 *
	 * @returns The 32 bytes that Argon2id consumes, or `null`. A value that is not a string gives `null`. An empty
	 * string gives `null` when no length rule rejects it first.
	 * @throws {PolicyViolationError} `enforce` is `true` and the length is outside the policy bounds.
	 */
	async #prepare(value: unknown, enforce: boolean): Promise<Uint8Array | null> {
		if (typeof value !== "string") {
			return null;
		}
		const password = value.normalize("NFKC");
		// Code points rather than UTF-16 units, so an emoji or an accented letter counts once against the policy.
		const length = [...password].length;
		if (enforce && (length < this.#policy.minLength || length > this.#policy.maxLength)) {
			throw new PolicyViolationError(`password must be between ${this.#policy.minLength} and ${this.#policy.maxLength} characters`);
		}
		if (!password) {
			return null;
		}
		return new Uint8Array(await crypto.subtle.sign("HMAC", await this.#pepper, new TextEncoder().encode(password)));
	}

	async #hash(prepared: Uint8Array): Promise<string> {
		return await argon2id({
			password: prepared,
			salt: crypto.getRandomValues(new Uint8Array(16)),
			hashLength: 32,
			outputType: "encoded",
			...this.#params,
		});
	}

	/**
	 * Verifies the prepared bytes against a stored PHC string. The method returns `false` where `argon2Verify`
	 * throws.
	 *
	 * Another pepper, another algorithm, or an older version of this library can leave a record that cannot verify.
	 * That is not a failure of the library. `argon2Verify` throws on anything that is not a PHC string, and that
	 * throw would escape as an `UNKNOWN` 500 instead of a rejected password.
	 */
	async #verify(prepared: Uint8Array, stored: string): Promise<boolean> {
		return await argon2Verify({ password: prepared, hash: stored }).catch(() => false);
	}

	#storedHash(context: AuthDanceComponentContext): string | undefined {
		const stored = context.identity?.components
			.find((c) => c.kind === "challenge" && c.component === context.name && typeof c.data?.hash === "string");
		return stored?.data?.hash as string | undefined;
	}

	/**
	 * Turns a submitted password into the challenge record that the identity keeps. The `sign-up`, `enroll`, `rotate`
	 * and `recover` flows call this method.
	 *
	 * The method applies three rules. The first is the length policy. The second rejects a value that verifies
	 * against the record it replaces. The third rejects a value equal to an identification of its owner, and that
	 * comparison ignores case. The last two rules need `context.identity`, because the value alone does not carry
	 * them.
	 *
	 * `context.identity` is the identity as it stands. A rotation therefore still sees the record under
	 * replacement, and a sign-up sees the address that an earlier step collected. `context.identity` is absent on
	 * the first step of a sign-up, where the last two rules have nothing to check.
	 *
	 * @param component The component name that the record carries.
	 * @param value The submitted password.
	 * @param confirmed Whether the record starts as confirmed.
	 * @param context The context of the dance, which carries the identity as it stands.
	 * @returns One challenge record whose `data.hash` holds the Argon2id PHC string.
	 * @throws {PolicyViolationError} The value is not a string, is empty, is outside the length bounds, matches the
	 * record it replaces, or matches an identification of its owner.
	 */
	async getIdentityComponent(
		component: string,
		value: unknown,
		confirmed: boolean,
		context: AuthDanceComponentContext,
	): Promise<AuthDanceIdentityComponent[]> {
		const prepared = await this.#prepare(value, true);
		if (!prepared) {
			throw new PolicyViolationError("password must be a non-empty string");
		}
		// The two rules that need the identity. `context.identity` is the identity as it stands. A rotation
		// therefore still sees the record under replacement, and a sign-up sees the address that an earlier step
		// collected. The library omits it on the first step of a sign-up, where neither rule has a target.
		const stored = this.#storedHash(context);
		if (stored && await this.#verify(prepared, stored)) {
			throw new PolicyViolationError("password must differ from the one it replaces");
		}
		const password = (value as string).normalize("NFKC");
		const identifies = context.identity?.components
			.some((c) => c.kind === "identification" && c.identification.normalize("NFKC").toLowerCase() === password.toLowerCase());
		if (identifies) {
			throw new PolicyViolationError("password must differ from the value that identifies its owner");
		}
		return [
			{
				kind: "challenge",
				component,
				confirmed,
				data: { hash: await this.#hash(prepared) },
			},
		];
	}

	/**
	 * Describes the input that the client renders: a password field under the component name. The field is not
	 * sendable, because a password has no message to deliver.
	 *
	 * The prompt carries `minLength` and `maxLength` in `options`. A client can therefore hold the owner to the
	 * policy before it spends a round trip on the value.
	 *
	 * @param context The context of the dance, which carries the name of the component.
	 * @returns One password input for the client to render.
	 */
	// deno-lint-ignore require-await
	async getPrompt(context: AuthDanceComponentContext): Promise<AuthDancePromptInput> {
		return {
			kind: "input",
			name: context.name,
			type: "password",
			sendable: false,
			// So a client can hold the owner to the policy before it spends a round trip on the value.
			options: { minLength: this.#policy.minLength, maxLength: this.#policy.maxLength },
		};
	}

	/**
	 * Checks a submitted password against the record that the identity holds.
	 *
	 * The length policy does not apply here. The policy governs what the component may store. A length check would
	 * reject an old password faster than a wrong one, which is a disclosure in itself.
	 *
	 * An identity with no password enrolled costs what a wrong password costs. The component verifies the
	 * submission against a throwaway record at the configured cost. A submission that is not a usable string takes
	 * the same path. The response time then answers no question that the response body refuses to answer.
	 *
	 * @param response The submitted password.
	 * @param context The context of the dance, which carries the identity to check the password against.
	 * @returns `true` when the password matches the stored record, and `false` otherwise. A password never resolves
	 * an identity, so this method never returns an identity id.
	 */
	async verifyPrompt(response: unknown, context: AuthDanceComponentContext): Promise<boolean | AuthDanceIdentity["id"]> {
		// The policy does not apply here. It governs what the component may store. A length check on a submission
		// would reject an older password faster than a wrong one, which is a disclosure in itself.
		const prepared = await this.#prepare(response, false);
		const stored = this.#storedHash(context);
		if (!prepared || !stored) {
			// An identity with no password enrolled must cost what a wrong password costs. If it does not, the
			// response time answers a question that the response body refuses to answer.
			await this.#verify(prepared ?? new Uint8Array(32), await this.#decoyHash());
			return false;
		}
		return await this.#verify(prepared, stored);
	}

	/**
	 * Hashes one throwaway value at the configured cost. The component caches the promise, so it pays this cost one
	 * time only. `verifyPrompt` verifies against this record when it finds no stored record or no usable submission.
	 */
	#decoyHash(): Promise<string> {
		return this.#decoy ??= this.#hash(crypto.getRandomValues(new Uint8Array(32)));
	}
}
