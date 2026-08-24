import { encodeHex } from "@std/encoding/hex";
import type { AuthDanceComponent, AuthDanceComponentContext } from "../component.ts";
import { IdentityNotResolvedError, InvalidPromptValueError } from "../error.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent } from "../identity.ts";
import type { AuthDancePromptInput } from "../prompt.ts";

/**
 * Turns a salted password into the string that `PasswordAuthDanceComponent` keeps in `data.hash`. The function
 * must answer the same string for the same value every time. Make the function slow.
 */
export type PasswordHasher = (value: string) => Promise<string>;

/**
 * Builds a hasher that derives the record with PBKDF2-HMAC-SHA256 through `crypto.subtle`. The hasher writes
 * `<iterations>:<salt>:<digest>`, and the salt is the first 16 bytes of `SHA-256` over the value.
 *
 * @param iterations The passes that PBKDF2 makes over the password. The default of 600000 is the OWASP floor for
 * PBKDF2-HMAC-SHA256, and it costs about 200 milliseconds a hash. Lower it for a test suite only.
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

/** What the component hashes when it holds no submission to hash. */
const DECOY_PASSWORD = "decoy";

/** Compares two signatures of the same length in a time that says nothing about where they differ. */
type ConstantTimeEqual = (left: Uint8Array, right: Uint8Array) => boolean;

/** The comparison that `timingSafeEqual` runs. */
let constantTimeEqual: Promise<ConstantTimeEqual> | undefined;

/** The HMAC key that signs both sides of a comparison. Nothing outside this module holds it. */
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

/** Finds the comparison that the runtime holds. Workers keeps one on `crypto.subtle`, Node and Deno in `node:crypto`. */
async function resolveConstantTimeEqual(): Promise<ConstantTimeEqual> {
	// Cloudflare Workers.
	const subtle = crypto.subtle as SubtleCrypto & { timingSafeEqual?: ConstantTimeEqual };
	if (typeof subtle.timingSafeEqual === "function") {
		return subtle.timingSafeEqual.bind(subtle);
	}
	try {
		// Node and Deno. The specifier stays in a variable, because a bundler resolves a literal one at build time.
		const specifier = "node:crypto";
		const { timingSafeEqual } = await import(specifier);
		if (typeof timingSafeEqual === "function") {
			return timingSafeEqual;
		}
	} catch {
		// The runtime holds no `node:crypto`.
	}
	/** Compares the two signatures in a loop that reads every byte of both. A JIT can compile it to stop early. */
	return function fallbackConstantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
		let difference = 0;
		for (let i = 0; i < left.length; i++) {
			difference |= left[i] ^ right[i];
		}
		return difference === 0;
	};
}

/**
 * Compares two hashes in a time that says nothing about where they differ. The function signs each string with an
 * HMAC key that nothing outside this module holds, then it compares the two 32-byte signatures. A record that
 * another pepper, another hasher or an older version of this library wrote gives `false` here.
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
 * A password component. It keeps the password as a hash in `data.hash`. `pbkdf2PasswordHasher`, the default,
 * writes `<iterations>:<salt>:<digest>`.
 *
 * The component puts the pepper and the id of the identity in front of the password before it calls the hasher.
 * The hasher must answer the same string for the same input every time.
 *
 * Keep the pepper in a secret store. A new pepper invalidates every record, and so does a new hasher. Only the
 * `rotate` and `recover` flows can rebuild one.
 */
export class PasswordAuthDanceComponent implements AuthDanceComponent {
	/** A password only proves a claim against an identity, so it is a `challenge`. */
	readonly kind: AuthDanceIdentityComponent["kind"] = "challenge";
	/** A password cannot prove control of its own value, so the class declares no `verificationComponent`. */
	readonly verifiable = false;
	#pepper: string;
	#hasher: PasswordHasher;

	/**
	 * Keeps the pepper and the hasher.
	 *
	 * @param pepper The secret that the component puts in front of every password. Keep it in a secret store.
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
	 * Turns a password into the value that the hasher consumes. The method normalizes the text to NFKC, then it puts
	 * the pepper and the id of the identity in front of the text.
	 * @returns The salted password, or `null` for a value that is not a string and for an empty string.
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
	 * @param component The component name that the record carries.
	 * @param value The submitted password.
	 * @param confirmed Whether the record starts as confirmed.
	 * @param context The context of the dance, which carries the identity as it stands.
	 * @returns One challenge record whose `data.hash` holds what the hasher answered.
	 * @throws {IdentityNotResolvedError} The context carries no identity, so the method cannot salt the hash.
	 * @throws {InvalidPromptValueError} The value is not a string, is empty, matches the record it replaces, or
	 * matches an identification of its owner. The comparison against an identification ignores case.
	 */
	async getIdentityComponent(
		component: string,
		value: unknown,
		confirmed: boolean,
		context: AuthDanceComponentContext,
	): Promise<AuthDanceIdentityComponent[]> {
		const identityId = context.identity?.id;
		if (!identityId) {
			throw new IdentityNotResolvedError(component);
		}
		const prepared = this.#prepare(value, identityId);
		if (!prepared) {
			throw new InvalidPromptValueError("password must be a non-empty string");
		}
		const hash = await this.#hasher(prepared);
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
	 * sendable.
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
	 * Checks a submitted password against the record that the identity holds.
	 *
	 * An identity with no password enrolled costs what a wrong password costs, and so does a submission that is not a
	 * usable string. The rules of `getIdentityComponent` do not apply here.
	 * @param response The submitted password.
	 * @param context The context of the dance, which carries the identity to check the password against.
	 * @returns `true` when the password matches the stored record, and `false` otherwise. This method never returns
	 * an identity id.
	 */
	async verifyPrompt(response: unknown, context: AuthDanceComponentContext): Promise<boolean | AuthDanceIdentity["id"]> {
		const prepared = this.#prepare(response, context.identity?.id ?? "");
		const stored = this.#storedHash(context);
		const hash = await this.#hasher(prepared ?? DECOY_PASSWORD);
		const matches = await timingSafeEqual(hash, stored ?? "");
		return prepared !== null && stored !== undefined && matches;
	}
}
