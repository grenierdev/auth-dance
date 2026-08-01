import { argon2id, argon2Verify } from "hash-wasm";
import type { AuthDanceComponent, AuthDanceComponentContext } from "../component.ts";
import { PolicyViolationError } from "../error.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent } from "../identity.ts";
import type { AuthDancePromptInput } from "../prompt.ts";

/**
 * Argon2id cost. The defaults are the OWASP floor for the `m=19456, t=2, p=1` profile — one hash costs about
 * 70ms and 19 MiB, which is the point: an attacker holding the store pays the same per guess. Lower them for a
 * test suite, never for a deployment.
 */
export interface PasswordParams {
	/** Kibibytes of memory one hash occupies. Memory-hardness is what a GPU cannot parallelise away. */
	memorySize: number;
	iterations: number;
	parallelism: number;
}

export interface PasswordPolicy {
	/** NIST SP 800-63B puts length ahead of composition rules, so length is the only rule here. */
	minLength: number;
	/** A bound on the work one submission can ask for, not a statement about strength. */
	maxLength: number;
}

export const DEFAULT_PASSWORD_PARAMS: PasswordParams = { memorySize: 19456, iterations: 2, parallelism: 1 };
export const DEFAULT_PASSWORD_POLICY: PasswordPolicy = { minLength: 12, maxLength: 256 };

/**
 * A password, stored as an Argon2id PHC string in `data.hash`:
 * `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<digest>`.
 *
 * Three properties make that record safe to hold. Argon2id is memory-hard, so guessing costs the attacker what it
 * costs the server. The salt is 16 fresh random bytes per record, so no precomputation carries from one identity to
 * the next and two identities sharing a password do not share a record. The parameters travel inside the record,
 * so raising the cost later does not invalidate what is already stored — a record verifies against the cost it was
 * created with.
 *
 * The constructor secret is a *pepper*, not a salt: it never reaches the identity store, so a dump of the store on
 * its own is not enough to begin cracking. It is applied as `HMAC-SHA256(pepper, password)` before the KDF rather
 * than concatenated, which also flattens the input to 32 bytes and makes the maximum length a policy choice
 * instead of a property of the construction. Keep it in a secret store, and note that changing it invalidates every
 * existing record — only `rotate` and `recover` can rebuild one.
 */
export default class PasswordAuthDanceComponent implements AuthDanceComponent {
	readonly kind: AuthDanceIdentityComponent["kind"] = "challenge";
	readonly verifiable = false;
	#pepper: Promise<CryptoKey>;
	#params: PasswordParams;
	#policy: PasswordPolicy;
	#decoy: Promise<string> | undefined;

	constructor(pepper: string, options?: { params?: Partial<PasswordParams>; policy?: Partial<PasswordPolicy> }) {
		this.#pepper = crypto.subtle.importKey("raw", new TextEncoder().encode(pepper), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
		this.#params = { ...DEFAULT_PASSWORD_PARAMS, ...options?.params };
		this.#policy = { ...DEFAULT_PASSWORD_POLICY, ...options?.policy };
	}

	/**
	 * Everything that happens to a password before it reaches the KDF: the policy is enforced, the text is
	 * NFKC-normalised so the same password typed on a different keyboard layout still verifies, and the pepper is
	 * folded in. Returns the 32 bytes Argon2id consumes, so no plain text travels further than this method.
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
	 * A record produced by another pepper, another algorithm, or an older version of this library is not a failure
	 * of the library — it is a value that cannot verify. `argon2Verify` throws on anything that is not a PHC
	 * string, which would otherwise escape as an `UNKNOWN` 500 instead of a rejected password.
	 */
	async #verify(prepared: Uint8Array, stored: string): Promise<boolean> {
		return await argon2Verify({ password: prepared, hash: stored }).catch(() => false);
	}

	#storedHash(context: AuthDanceComponentContext): string | undefined {
		const stored = context.identity?.components
			.find((c) => c.kind === "challenge" && c.component === context.name && typeof c.data?.hash === "string");
		return stored?.data?.hash as string | undefined;
	}

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
		// The two rules a password cannot check on its own. `context.identity` is the identity as it stands, so
		// during a rotation the record being replaced is still on it, and during a sign-up the address collected
		// a step earlier is. It is absent on the first step of a sign-up, where neither rule has anything to say.
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

	// deno-lint-ignore require-await
	async getPrompt(context: AuthDanceComponentContext): Promise<AuthDancePromptInput> {
		return {
			kind: "input",
			name: context.name,
			type: "password",
			sendable: false,
			// So a client can hold the owner to the policy before spending a round trip on it.
			options: { minLength: this.#policy.minLength, maxLength: this.#policy.maxLength },
		};
	}

	async verifyPrompt(response: unknown, context: AuthDanceComponentContext): Promise<boolean | AuthDanceIdentity["id"]> {
		// The policy is not enforced here: it governs what may be stored, and applying it to a submission would
		// reject an older password faster than it rejects a wrong one, which is a disclosure in itself.
		const prepared = await this.#prepare(response, false);
		const stored = this.#storedHash(context);
		if (!prepared || !stored) {
			// An identity with no password enrolled has to cost what a wrong password costs, or the response time
			// answers a question the response body refuses to.
			await this.#verify(prepared ?? new Uint8Array(32), await this.#decoyHash());
			return false;
		}
		return await this.#verify(prepared, stored);
	}

	/** One throwaway record, hashed once per process at the configured cost, kept only to be verified against. */
	#decoyHash(): Promise<string> {
		return this.#decoy ??= this.#hash(crypto.getRandomValues(new Uint8Array(32)));
	}
}
