import { encodeHex } from "@std/encoding/hex";
import type { AuthDanceComponent, AuthDanceComponentContext } from "../component.ts";
import { IdentityNotResolvedError, InvalidPromptValueError } from "../error.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent } from "../identity.ts";
import type { AuthDancePromptInput } from "../prompt.ts";

/**
 * What turns a salted password into the string that `PasswordAuthDanceComponent` keeps in `data.hash`.
 *
 * The component salts the value before it calls the function. The pepper and the id of the identity are
 * already in front of the password, so the function needs no salt of its own.
 *
 * The function must answer the same string for the same value every time. `verifyPrompt` hashes the
 * submission and compares that string against the stored one, so a function that mixes a random value of its
 * own into the input rejects every password it stored.
 *
 * Make the function slow. The cost is what an attacker who steals the store pays again for every guess.
 */
export type PasswordHasher = (value: string) => Promise<string>;

/**
 * Builds a hasher that derives the record with PBKDF2-HMAC-SHA256 through `crypto.subtle`. The hasher writes
 * `<iterations>:<salt>:<digest>`, and it holds no dependency outside the Web Crypto API.
 *
 * The iteration count travels inside the record, so a later cost increase does not invalidate what the store
 * already holds. The digest of a record still answers to the count that wrote it.
 *
 * The salt of the record is the first 16 bytes of `SHA-256` over the value. The hasher cannot draw a random
 * salt, because it must answer the same string for the same value every time. What makes one record differ
 * from the next is already in the value: the component put the pepper and the id of the identity in front of
 * the password.
 *
 * @param iterations The passes that PBKDF2 makes over the password. This is the cost, and it scales the time
 * one hash takes. The default of 600000 is the OWASP floor for PBKDF2-HMAC-SHA256, and it costs about 200
 * milliseconds a hash. Lower it for a test suite. Never lower it for a deployment.
 * @returns A hasher for the `hasher` parameter of `PasswordAuthDanceComponent`.
 * @example
 * ```ts
 * new PasswordAuthDanceComponent(pepper, pbkdf2PasswordHasher(1_000_000));
 * ```
 */
export function pbkdf2PasswordHasher(iterations: number = 600_000): PasswordHasher {
	return async (value: string): Promise<string> => {
		const encoded = new TextEncoder().encode(value);
		const salt = new Uint8Array(await crypto.subtle.digest("SHA-256", encoded), 0, 16);
		const key = await crypto.subtle.importKey("raw", encoded, { name: "PBKDF2" }, false, ["deriveBits"]);
		const digest = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, key, 256);
		return `${iterations}:${encodeHex(salt)}:${encodeHex(digest)}`;
	};
}

/**
 * What the component hashes when it holds no submission to hash. Only the cost of that hash matters, and the
 * result never leaves `verifyPrompt`.
 */
const DECOY_PASSWORD = "decoy";

/**
 * What compares two signatures of the same length in a time that says nothing about where they differ. Both
 * arrays that `timingSafeEqual` hands over measure 32 bytes, so no implementation of this type reads a length.
 */
type ConstantTimeEqual = (left: Uint8Array, right: Uint8Array) => boolean;

/**
 * The comparison that `timingSafeEqual` runs. One resolution serves the whole process.
 */
let constantTimeEqual: Promise<ConstantTimeEqual> | undefined;

/**
 * The HMAC key that signs both sides of a comparison. One random key serves the whole process, and nothing
 * outside this module ever holds it.
 */
let comparisonKey: Promise<CryptoKey> | undefined;

/** Draws the key that signs the two strings `timingSafeEqual` compares. */
function resolveComparisonKey(): Promise<CryptoKey> {
	return crypto.subtle.importKey(
		"raw",
		crypto.getRandomValues(new Uint8Array(32)),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
}

/**
 * Finds the comparison that the runtime holds. Workers keeps one on `crypto.subtle`, Node and Deno keep one in
 * `node:crypto`, and a runtime with neither gets the loop above.
 *
 * Both native comparisons throw where the two arrays differ in length. The signatures never do.
 */
async function resolveConstantTimeEqual(): Promise<ConstantTimeEqual> {
	// Cloudflare Workers. The method is an extension of the Web Crypto API, so the standard type does not carry it.
	const subtle = crypto.subtle as SubtleCrypto & { timingSafeEqual?: ConstantTimeEqual };
	if (typeof subtle.timingSafeEqual === "function") {
		return subtle.timingSafeEqual.bind(subtle);
	}
	try {
		// Node and Deno. The specifier stays in a variable, because a bundler resolves a literal one at build
		// time: a Workers build with no `nodejs_compat` fails on a module that this line never reaches there.
		const specifier = "node:crypto";
		const { timingSafeEqual } = await import(specifier);
		if (typeof timingSafeEqual === "function") {
			return timingSafeEqual;
		}
	} catch {
		// The runtime holds no `node:crypto`, and the loop below answers the same thing.
	}
	/**
	 * Compares the two signatures in a loop that reads every byte of both. This is what the module falls back on
	 * where the runtime holds no comparison of its own.
	 *
	 * A JIT is free to compile this loop into something that stops early, and nothing in the language prevents it.
	 * The native comparisons that `resolveConstantTimeEqual` looks for first hold a guarantee that this loop only
	 * approaches.
	 */
	return function fallbackConstantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
		let difference = 0;
		for (let i = 0; i < left.length; i++) {
			difference |= left[i] ^ right[i];
		}
		return difference === 0;
	};
}

/**
 * Compares two hashes in a time that says nothing about where they differ.
 *
 * The function signs each string with an HMAC key that nobody outside this module holds, then hands the two
 * signatures to the comparison that the runtime holds. An attacker cannot aim a guess at a signature they cannot
 * predict. Both signatures are 32 bytes whatever the two strings measure, so the comparison reads the same bytes
 * for a record of any length — and it never meets the two lengths that make a native comparison throw. A record
 * that another pepper, another hasher or an older version of this library wrote is therefore rejected here rather
 * than raised out of `verifyPrompt`, and so is the empty string that stands in for a password nobody enrolled.
 */
async function timingSafeEqual(left: string, right: string): Promise<boolean> {
	const [equals, key] = await Promise.all([
		constantTimeEqual ??= resolveConstantTimeEqual(),
		comparisonKey ??= resolveComparisonKey(),
	]);
	const encoder = new TextEncoder();
	const [a, b] = await Promise.all([
		crypto.subtle.sign("HMAC", key, encoder.encode(left)),
		crypto.subtle.sign("HMAC", key, encoder.encode(right)),
	]);
	return equals(new Uint8Array(a), new Uint8Array(b));
}

/**
 * A password component. It keeps the password as a hash in `data.hash`. The hasher decides what that string
 * holds, and `pbkdf2PasswordHasher`, the one the component falls back on, writes `<iterations>:<salt>:<digest>`.
 *
 * The component never hands the password to the hasher alone. It puts the pepper and the id of the identity in
 * front of it first. The id salts the input: no precomputation carries from one identity to the next, two
 * identities with the same password do not share a record, and a record lifted out of the store verifies
 * against no other identity. The pepper is a secret that never reaches the identity store, so a stolen copy of
 * the store alone is not enough to crack a password.
 *
 * The hasher must answer the same string for the same input every time. `verifyPrompt` hashes the submission
 * and compares that string against the stored one, in a time that says nothing about where the two differ. A
 * hasher that draws a salt of its own rejects every password it stored, and the salt this construction needs
 * is already in the input.
 *
 * Keep the pepper in a secret store. A new pepper invalidates every existing record, and so does a hasher that
 * answers something else for the same input. Only the `rotate` and `recover` flows can rebuild one.
 */
export class PasswordAuthDanceComponent implements AuthDanceComponent {
	/** A password only proves a claim against an identity, so it is a `challenge` and never resolves an identity. */
	readonly kind: AuthDanceIdentityComponent["kind"] = "challenge";
	/**
	 * A password cannot prove control of its own value. The same text typed a second time proves nothing. The class
	 * therefore declares no `verificationComponent`.
	 */
	readonly verifiable = false;
	#pepper: string;
	#hasher: PasswordHasher;

	/**
	 * Keeps the pepper and the hasher.
	 *
	 * @param pepper The secret that the component puts in front of every password, ahead of the id of the
	 * identity. Keep it in a secret store. Never put it in source code.
	 * @param hasher What turns the salted password into the stored string.
	 * @example
	 * ```ts
	 * new PasswordAuthDanceComponent(Deno.env.get("PASSWORD_PEPPER")!, pbkdf2PasswordHasher(1_000_000));
	 * ```
	 */
	constructor(pepper: string, hasher: PasswordHasher = pbkdf2PasswordHasher()) {
		this.#pepper = pepper;
		this.#hasher = hasher;
	}

	/**
	 * Turns a password into the value that the hasher consumes. No plain text travels further than this method.
	 *
	 * The method normalizes the text to NFKC, so the same password from a different keyboard layout still verifies.
	 * Then it puts the pepper and the id of the identity in front of the text. Those two salt the value, and they
	 * carry into the hash.
	 *
	 * @returns The salted password, or `null`. A value that is not a string gives `null`, and so does an empty
	 * string.
	 */
	#prepare(value: unknown, identityId: string): string | null {
		if (typeof value !== "string") {
			return null;
		}
		const password = value.normalize("NFKC");
		if (!password) {
			return null;
		}
		return `${this.#pepper}:${identityId}:${password}`;
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
	 * The method applies two rules. The first rejects a value that hashes to the record it replaces. The second
	 * rejects a value equal to an identification of its owner, and that comparison ignores case. Both rules need
	 * `context.identity`, because the value alone does not carry them.
	 *
	 * `context.identity` is the identity as it stands. A rotation therefore still sees the record under
	 * replacement, and a sign-up sees the address that an earlier step collected. The id on it salts the hash, so
	 * the method needs one even where neither rule has a target.
	 *
	 * @param component The component name that the record carries.
	 * @param value The submitted password.
	 * @param confirmed Whether the record starts as confirmed.
	 * @param context The context of the dance, which carries the identity as it stands.
	 * @returns One challenge record whose `data.hash` holds what the hasher answered.
	 * @throws {IdentityNotResolvedError} The context carries no identity, so the method cannot salt the hash.
	 * @throws {InvalidPromptValueError} The value is not a string, is empty, matches the record it replaces, or
	 * matches an identification of its owner.
	 */
	async getIdentityComponent(
		component: string,
		value: unknown,
		confirmed: boolean,
		context: AuthDanceComponentContext,
	): Promise<AuthDanceIdentityComponent[]> {
		// The id of the identity salts the hash, and only the same id verifies it again. A record written under
		// another id, or under none, is a record that nothing can verify.
		const identityId = context.identity?.id;
		if (!identityId) {
			throw new IdentityNotResolvedError(component);
		}
		const prepared = this.#prepare(value, identityId);
		if (!prepared) {
			throw new InvalidPromptValueError("password must be a non-empty string");
		}
		const hash = await this.#hasher(prepared);
		// The two rules that need the identity. `context.identity` is the identity as it stands. A rotation
		// therefore still sees the record under replacement, and a sign-up sees the address that an earlier step
		// collected.
		const stored = this.#storedHash(context);
		if (stored && await timingSafeEqual(hash, stored)) {
			throw new InvalidPromptValueError("password must differ from the one it replaces");
		}
		const password = (value as string).normalize("NFKC");
		const identifies = context.identity?.components
			.some((c) => c.kind === "identification" && c.identification.normalize("NFKC").toLowerCase() === password.toLowerCase());
		if (identifies) {
			throw new InvalidPromptValueError("password must differ from the value that identifies its owner");
		}
		return [
			{
				kind: "challenge",
				component,
				confirmed,
				data: { hash },
			},
		];
	}

	/**
	 * Describes the input that the client renders: a password field under the component name. The field is not
	 * sendable, because a password has no message to deliver.
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
		};
	}

	/**
	 * Checks a submitted password against the record that the identity holds. The method hashes the submission and
	 * compares that string against the stored one.
	 *
	 * The rules that `getIdentityComponent` applies do not apply here. They govern what the component may store,
	 * and a submission that one of them refuses must cost what a wrong password costs.
	 *
	 * An identity with no password enrolled costs what a wrong password costs. The component hashes a throwaway
	 * value instead. A submission that is not a usable string takes the same path. The response time then answers
	 * no question that the response body refuses to answer.
	 *
	 * A record that another pepper, another hasher, or an older version of this library wrote is a record that
	 * cannot match. The method rejects it the way it rejects a wrong password.
	 *
	 * @param response The submitted password.
	 * @param context The context of the dance, which carries the identity to check the password against.
	 * @returns `true` when the password matches the stored record, and `false` otherwise. A password never resolves
	 * an identity, so this method never returns an identity id.
	 */
	async verifyPrompt(response: unknown, context: AuthDanceComponentContext): Promise<boolean | AuthDanceIdentity["id"]> {
		const prepared = this.#prepare(response, context.identity?.id ?? "");
		const stored = this.#storedHash(context);
		// An identity with no password enrolled must cost what a wrong password costs. If it does not, the
		// response time answers a question that the response body refuses to answer.
		const hash = await this.#hasher(prepared ?? DECOY_PASSWORD);
		const matches = await timingSafeEqual(hash, stored ?? "");
		return prepared !== null && stored !== undefined && matches;
	}
}
