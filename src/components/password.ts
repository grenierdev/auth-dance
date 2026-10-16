import { hex } from "@scure/base";
import type { AuthDanceComponent, AuthDanceComponentContext } from "../component.ts";
import { IdentityNotResolvedError, InvalidPromptValueError } from "../error.ts";
import type { AuthDanceIdentity, AuthDanceIdentityChallenge, AuthDanceIdentityComponent } from "../identity.ts";
import type { AuthDancePromptInput } from "../prompt.ts";

/**
 * Turns a salted password into the record that `PasswordAuthDanceComponent` keeps in `data.hash`, and checks a
 * password against that record. Make `hash` and `verify` slow.
 */
export interface PasswordHasher {
	/** Hashes the value with a fresh random salt. Two calls on one value give two different records. */
	hash(value: string): Promise<string>;
	/** Derives again with the parameters the record carries, and compares in constant time. */
	verify(value: string, record: string): Promise<boolean>;
	/** Whether the record uses older parameters than this hasher writes. */
	needsRehash(record: string): boolean;
}

/** The tag in front of a record that `pbkdf2PasswordHasher` writes. */
const PBKDF2_TAG = "pbkdf2-sha256";

/** The most passes a record can ask for. A tampered record with a larger count would stall the worker. */
const PBKDF2_MAX_ITERATIONS = 10_000_000;

/** The parameters and the digest that one record holds. */
interface Pbkdf2Record {
	/** Whether the record has the 3-field form that versions before rc.5 wrote. */
	legacy: boolean;
	iterations: number;
	salt: Uint8Array;
	digest: string;
}

/** Reads a record. Returns `null` for a record in another form, and for an iteration count out of bounds. */
function parsePbkdf2Record(record: string): Pbkdf2Record | null {
	const parts = record.split(":");
	const legacy = parts.length === 3;
	if (!legacy && (parts.length !== 4 || parts[0] !== PBKDF2_TAG)) {
		return null;
	}
	const [iterations, salt, digest] = legacy ? parts : parts.slice(1);
	if (!/^[1-9][0-9]{0,7}$/.test(iterations) || !/^(?:[0-9a-f]{2})+$/.test(salt) || !/^[0-9a-f]{64}$/.test(digest)) {
		return null;
	}
	const count = Number(iterations);
	if (count > PBKDF2_MAX_ITERATIONS) {
		return null;
	}
	return { legacy, iterations: count, salt: hex.decode(salt), digest };
}

/** Derives a 256-bit PBKDF2-HMAC-SHA256 digest, in hex. */
async function pbkdf2(value: string, salt: Uint8Array, iterations: number): Promise<string> {
	const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(value), { name: "PBKDF2" }, false, ["deriveBits"]);
	const digest = await crypto.subtle.deriveBits(
		{ name: "PBKDF2", salt: salt as Uint8Array<ArrayBuffer>, iterations, hash: "SHA-256" },
		key,
		256,
	);
	return hex.encode(new Uint8Array(digest));
}

/**
 * Builds a hasher that derives the record with PBKDF2-HMAC-SHA256 through `crypto.subtle`. The hasher writes
 * `pbkdf2-sha256:<iterations>:<salt>:<digest>`. The salt is 16 random bytes, and each `hash` draws a new one.
 *
 * `verify` also reads the `<iterations>:<salt>:<digest>` record that versions before rc.5 wrote, and `needsRehash`
 * reports that record. `verify` refuses a record that asks for fewer than 1 or more than 10000000 passes.
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
	if (!Number.isInteger(iterations) || iterations < 1 || iterations > PBKDF2_MAX_ITERATIONS) {
		throw new RangeError(`iterations must be an integer from 1 to ${PBKDF2_MAX_ITERATIONS}`);
	}
	return {
		async hash(value: string): Promise<string> {
			const salt = crypto.getRandomValues(new Uint8Array(16));
			return `${PBKDF2_TAG}:${iterations}:${hex.encode(salt)}:${await pbkdf2(value, salt, iterations)}`;
		},
		async verify(value: string, record: string): Promise<boolean> {
			const parsed = parsePbkdf2Record(record);
			if (!parsed) {
				// A record in another form costs one derivation too, the same as a wrong password.
				await pbkdf2(value, new Uint8Array(16), iterations);
				return false;
			}
			return timingSafeEqual(await pbkdf2(value, parsed.salt, parsed.iterations), parsed.digest);
		},
		needsRehash(record: string): boolean {
			const parsed = parsePbkdf2Record(record);
			return !parsed || parsed.legacy || parsed.iterations < iterations;
		},
	};
}

/** The shortest pepper the component accepts, in UTF-8 bytes. */
const MIN_PEPPER_BYTES = 16;

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
	return crypto.subtle.importKey("raw", crypto.getRandomValues(new Uint8Array(32)), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
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
 * Compares two digests in a time that says nothing about where they differ. The function signs each string with an
 * HMAC key that nothing outside this module holds, then it compares the two 32-byte signatures.
 */
async function timingSafeEqual(left: string, right: string): Promise<boolean> {
	const [equals, key] = await Promise.all([
		// biome-ignore lint/suspicious/noAssignInExpressions: Cache the crypto initialization promise.
		(constantTimeEqual ??= resolveConstantTimeEqual()),
		// biome-ignore lint/suspicious/noAssignInExpressions: Cache the crypto initialization promise.
		(comparisonKey ??= resolveComparisonKey()),
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
 * writes `pbkdf2-sha256:<iterations>:<salt>:<digest>` with a random salt for each record.
 *
 * The component puts the pepper and the id of the identity in front of the password before it calls the hasher.
 * The id binds a record to its owner, so a record copied to another identity does not verify.
 *
 * Keep the pepper in a secret store, apart from the identity store. A new pepper invalidates every record. Only the
 * `rotate` and `recover` flows can rebuild one. A sign-in rewrites a record that `needsRehash` reports.
 */
export class PasswordAuthDanceComponent implements AuthDanceComponent {
	/** A password only proves a claim against an identity, so it is a `challenge`. */
	readonly kind: AuthDanceIdentityComponent["kind"] = "challenge";
	/** A password cannot prove control of its own value, so the class declares no `verificationComponent`. */
	readonly verifiable = false;
	#pepper: string;
	#hasher: PasswordHasher;
	#decoy: Promise<string> | undefined;

	/**
	 * Keeps the pepper and the hasher.
	 *
	 * @param pepper The secret that the component puts in front of every password. It holds at least 16 bytes. Keep it
	 * in a secret store, and make it with `openssl rand -base64 32`.
	 * @param hasher What turns the salted password into the stored record, and checks a password against it.
	 * @throws {TypeError} The pepper is not a string, or holds fewer than 16 bytes. An unset environment variable
	 * gives this error.
	 * @example
	 * ```ts
	 * new PasswordAuthDanceComponent(process.env.PASSWORD_PEPPER!, pbkdf2PasswordHasher(1_000_000));
	 * ```
	 */
	constructor(pepper: string, hasher: PasswordHasher = pbkdf2PasswordHasher()) {
		if (typeof pepper !== "string" || new TextEncoder().encode(pepper).length < MIN_PEPPER_BYTES) {
			throw new TypeError(`pepper must be a string of at least ${MIN_PEPPER_BYTES} bytes; make one with openssl rand -base64 32`);
		}
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

	#storedRecord(context: AuthDanceComponentContext): AuthDanceIdentityChallenge | undefined {
		return context.identity?.components.find(
			(c): c is AuthDanceIdentityChallenge => c.kind === "challenge" && c.component === context.name && typeof c.data?.hash === "string",
		);
	}

	#storedHash(context: AuthDanceComponentContext): string | undefined {
		return this.#storedRecord(context)?.data?.hash as string | undefined;
	}

	// The record a check runs against when the identity holds none. It costs the configured passes, so a missing
	// record costs what a wrong password costs.
	#decoyRecord(): Promise<string> {
		this.#decoy ??= this.#hasher.hash(DECOY_PASSWORD);
		return this.#decoy;
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
		const stored = this.#storedHash(context);
		if (stored && (await this.#hasher.verify(prepared, stored))) {
			throw new InvalidPromptValueError("password must differ from the one it replaces");
		}
		const password = (value as string).normalize("NFKC");
		const identifies = context.identity?.components.some(
			(c) => c.kind === "identification" && c.identification.normalize("NFKC").toLowerCase() === password.toLowerCase(),
		);
		if (identifies) {
			throw new InvalidPromptValueError("password must differ from the value that identifies its owner");
		}
		return [
			{
				kind: "challenge",
				component,
				confirmed,
				data: { hash: await this.#hasher.hash(prepared) },
			},
		];
	}

	/**
	 * Describes the input that the client renders: a password field under the component name. The field is not
	 * sendable.
	 * @returns One password input for the client to render.
	 */

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
		const matches = await this.#hasher.verify(prepared ?? DECOY_PASSWORD, stored ?? (await this.#decoyRecord()));
		return prepared !== null && stored !== undefined && matches;
	}

	/**
	 * Rewrites a record that `needsRehash` reports, with the password a sign-in just accepted. The record keeps its
	 * links and its other data.
	 * @param value The password that `verifyPrompt` accepted.
	 * @param context The context of the step, which carries the resolved identity.
	 * @returns One confirmed challenge record, or nothing when the stored record is current.
	 */
	async upgradeIdentityComponent(value: unknown, context: AuthDanceComponentContext): Promise<AuthDanceIdentityComponent[] | undefined> {
		const stored = this.#storedRecord(context);
		if (!stored || !context.identity || !this.#hasher.needsRehash(stored.data!.hash as string)) {
			return undefined;
		}
		const prepared = this.#prepare(value, context.identity.id);
		if (!prepared) {
			return undefined;
		}
		return [{ ...stored, confirmed: true, data: { ...stored.data, hash: await this.#hasher.hash(prepared) } }];
	}
}
