import { decodeBase32 } from "@std/encoding/base32";

/** The name of the HMAC hash that derives a one-time password. */
export type OTPAlgorithm = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";

/** Options for {@link hotp}, the counter-based one-time password of RFC 4226. */
export type HOTPOptions = {
	/** The shared key. A string must be base32 with a length that is a multiple of 8. A `CryptoKey` must use `HMAC`. */
	readonly key: string | CryptoKey;
	/** The HMAC hash that derives the code. @defaultValue `"SHA-1"` */
	readonly algorithm?: OTPAlgorithm;
	/** The number of digits in the code. `hotp` adds leading zeros. @defaultValue `6` */
	readonly digits?: number;
};

/** Options for {@link totp}, the time-based one-time password of RFC 6238. */
export type TOTPOptions = {
	/** The shared key. `totp` reads a string as base32. */
	readonly key: string | CryptoKey;
	/** The length of one time step in seconds. One code stays valid for one step. */
	readonly period: number;
	/** The HMAC hash that derives the code. @defaultValue `"SHA-1"` */
	readonly algorithm?: OTPAlgorithm;
	/** The number of digits in the code. @defaultValue `6` */
	readonly digits?: number;
};

/** Options for {@link otp}. */
export type OTPOptions = {
	/** The number of digits in the code. @defaultValue `6` */
	readonly digits?: number;
};

/** Tests whether `value` is one of the four hash names of {@link OTPAlgorithm}. */
export function isOTPAlgorithm(value?: unknown): value is OTPAlgorithm {
	return !!value && typeof value === "string" &&
		["SHA-1", "SHA-256", "SHA-384", "SHA-512"].includes(value);
}

/** Narrows `value` to {@link OTPAlgorithm}. @throws {@link InvalidOTPAlgorithmError} When `value` is not a hash name. */
export function assertOTPAlgorithm(
	value?: unknown,
): asserts value is OTPAlgorithm {
	if (!isOTPAlgorithm(value)) {
		throw new InvalidOTPAlgorithmError();
	}
}

/** {@link assertOTPAlgorithm} throws this error for a value that is not a hash name of {@link OTPAlgorithm}. */
export class InvalidOTPAlgorithmError extends Error {}

/** Tests whether `value` matches {@link HOTPOptions}. The guard checks `algorithm` and `digits` only when `value` carries them. */
export function isHOTPOptions(value?: unknown): value is HOTPOptions {
	return !!value && typeof value === "object" && "key" in value &&
		(typeof value.key === "string" || value.key instanceof CryptoKey) &&
		(!("algorithm" in value) || isOTPAlgorithm(value.algorithm)) &&
		(!("digits" in value) || typeof value.digits === "number");
}

/** Narrows `value` to {@link HOTPOptions}. @throws {@link InvalidHOTPOptionsError} When `value` does not match the shape. */
export function assertHOTPOptions(
	value?: unknown,
): asserts value is HOTPOptions {
	if (!isHOTPOptions(value)) {
		throw new InvalidHOTPOptionsError();
	}
}

/** {@link assertHOTPOptions} throws this error for a value that does not match {@link HOTPOptions}. */
export class InvalidHOTPOptionsError extends Error {}

/** Tests whether `value` matches {@link TOTPOptions}. The guard checks `algorithm` and `digits` only when `value` carries them. */
export function isTOTPOptions(value?: unknown): value is TOTPOptions {
	return !!value && typeof value === "object" && "key" in value &&
		(typeof value.key === "string" || value.key instanceof CryptoKey) &&
		"period" in value && typeof value.period === "number" &&
		(!("algorithm" in value) || isOTPAlgorithm(value.algorithm)) &&
		(!("digits" in value) || typeof value.digits === "number");
}

/** Narrows `value` to {@link TOTPOptions}. @throws {@link InvalidTOTPOptionsError} When `value` does not match the shape. */
export function assertTOTPOptions(
	value?: unknown,
): asserts value is TOTPOptions {
	if (!isTOTPOptions(value)) {
		throw new InvalidTOTPOptionsError();
	}
}

/** {@link assertTOTPOptions} throws this error for a value that does not match {@link TOTPOptions}. */
export class InvalidTOTPOptionsError extends Error {}

/** Tests whether `value` carries a numeric `digits`. The guard requires `digits`, although {@link OTPOptions} marks it optional. */
export function isOTPOptions(value?: unknown): value is OTPOptions {
	return !!value && typeof value === "object" && "digits" in value &&
		typeof value.digits === "number";
}

/** Narrows `value` to {@link OTPOptions}. @throws {@link InvalidOTPOptionsError} When `value` does not match the shape. */
export function assertOTPOptions(
	value?: unknown,
): asserts value is OTPOptions {
	if (!isOTPOptions(value)) {
		throw new InvalidOTPOptionsError();
	}
}

/** {@link assertOTPOptions} throws this error for a value that does not match {@link OTPOptions}. */
export class InvalidOTPOptionsError extends Error {}

function padCounter(counter: number): Uint8Array<ArrayBuffer> {
	const pairs = counter.toString(16).padStart(16, "0").match(/..?/g)!;
	const array = pairs.map((v) => parseInt(v, 16));
	return Uint8Array.from(array);
}

/**
 * Extracts a 31-bit number from an HMAC, the dynamic truncation of RFC 4226.
 * Byte 19 is the last byte of a SHA-1 HMAC only. A larger hash gives a code that another implementation does not match.
 */
function truncate(hmac: Uint8Array): number {
	const offset = hmac[19] & 0b1111;
	return ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) |
		(hmac[offset + 2] << 8) | hmac[offset + 3];
}

/**
 * Generates a counter-based one-time password, the HOTP of RFC 4226.
 * @param counter The counter of the code. The client and the server must hold the same value.
 * @returns The code as a string of `digits` characters, with leading zeros.
 * @throws {@link InvalidOTPAlgorithmError} When `algorithm` is not a name of {@link OTPAlgorithm}.
 * @throws {RangeError} When `key` is a string with a length that is not a multiple of 8.
 * @throws {Error} When `key` is not a string, and not a `CryptoKey` with the `HMAC` algorithm.
 * @example
 * ```ts
 * const code = await hotp({ key: generateKey(16), counter: 1 });
 * ```
 */
export async function hotp(
	{ key, counter, algorithm = "SHA-1", digits = 6 }: HOTPOptions & {
		counter: number;
	},
): Promise<string> {
	assertOTPAlgorithm(algorithm);
	let cryptoKey: CryptoKey;
	if (key instanceof CryptoKey) {
		if (key.algorithm.name !== "HMAC") {
			throw new Error(`Expected \`key.algorithm.name\` to be equal to "HMAC".`);
		}
		cryptoKey = key;
	} else if (typeof key === "string") {
		if (key.length % 8 !== 0) {
			throw new RangeError("Expected key length to be a multiple of 8.");
		}
		cryptoKey = await crypto.subtle.importKey(
			"raw",
			Uint8Array.from(decodeBase32(key)),
			{ name: "HMAC", hash: algorithm },
			false,
			["sign"],
		);
	} else {
		throw new Error(
			`Expected \`key\` to be either a string or a CryptoKey, got ${key}.`,
		);
	}
	const hmac = new Uint8Array(
		await crypto.subtle.sign("HMAC", cryptoKey, padCounter(counter)),
	);
	const num = truncate(hmac);
	return num.toString().padStart(digits, "0").slice(-digits);
}

/**
 * Generates a time-based one-time password, the TOTP of RFC 6238. The function divides the time by `period` to get a counter.
 * @param time The time in seconds since the epoch. Defaults to the current time.
 * @param period The length of one time step in seconds. Defaults to `60`.
 * @returns The code as a string of `digits` characters, with leading zeros.
 * @example
 * ```ts
 * const code = await totp({ key: generateKey(16), period: 30 });
 * ```
 */
export function totp(
	{ key, time = Date.now() / 1000, period = 60, algorithm, digits }:
		& TOTPOptions
		& { time?: number },
): Promise<string> {
	return hotp({ key, counter: Math.floor(time / period), algorithm, digits });
}

/**
 * Generates a random code from `crypto.getRandomValues`. No key derives this code, so the sender must keep it to check the answer.
 * @param digits The number of digits in the code. Defaults to `6`.
 * @returns The code as a string of `digits` characters, with leading zeros.
 */
export function otp({ digits = 6 }: { digits?: number } = {}): string {
	const hmac = new Uint8Array(digits);
	crypto.getRandomValues(hmac);
	const num = truncate(hmac);
	return num.toString().padStart(digits, "0").slice(-digits);
}

/**
 * Generates a random shared key for {@link hotp} and {@link totp}.
 * Give a `length` that is a multiple of 8, because `hotp` rejects a string key of any other length.
 * @param length The number of characters in the key. Defaults to `16`.
 * @param alphabet The characters that the function picks. Defaults to the base32 alphabet, `"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"`.
 * @returns The key as a string of `length` characters.
 */
export function generateKey(length = 16, alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"): string {
	const buffer = new Uint8Array(length);
	crypto.getRandomValues(buffer);
	let key = "";
	for (let i = 0; i < buffer.length; i++) {
		key += alphabet[buffer[i] % alphabet.length];
	}
	return key;
}

/** Options for {@link toURI}. Use the `"hotp"` variant for a counter-based code and the `"totp"` variant for a time-based code. */
export type OTPAuthDanceURIOptions =
	| {
		/** Marks the URI as counter-based. */
		type: "hotp";
		/** The shared key in base32. */
		secret: string;
		/** The account name that the authenticator app shows. */
		label: string;
		/** The HMAC hash that derives the code. @defaultValue `"SHA-1"` */
		algorithm?: OTPAlgorithm;
		/** The number of digits in the code. @defaultValue `6` */
		digits?: number;
		/** The first counter of the sequence. `toURI` rejects the `"hotp"` variant without it. */
		counter: number;
	}
	| {
		/** Marks the URI as time-based. */
		type: "totp";
		/** The shared key in base32. */
		secret: string;
		/** The account name that the authenticator app shows. */
		label: string;
		/** The HMAC hash that derives the code. @defaultValue `"SHA-1"` */
		algorithm?: OTPAlgorithm;
		/** The number of digits in the code. @defaultValue `6` */
		digits?: number;
		/** The length of one time step in seconds. Pass the same value to {@link totp}, which uses `60` by default. @defaultValue `30` */
		period?: number;
	};

/**
 * Builds the `otpauth://` URI that an authenticator app reads from a QR code.
 * The function writes the default `digits`, `algorithm`, and `period` values into the given `options` object.
 * @returns The URI. The host is the type, the path is the encoded label, and the query carries the secret and the options.
 * @throws {Error} When the `"hotp"` variant carries no numeric `counter`.
 * @throws {Error} When `period`, `digits`, or `algorithm` has a value of the wrong type.
 * @example
 * ```ts
 * toURI({ type: "totp", secret: generateKey(16), label: "john.doe@example.com" });
 * // otpauth://totp/john.doe%40example.com?digits=6&algorithm=SHA-1&period=30&secret=…
 * ```
 */
export function toURI(options: OTPAuthDanceURIOptions): string {
	options.digits ??= 6;
	options.algorithm ??= "SHA-1";
	if (options.type === "hotp") {
		if (!("counter" in options) || typeof options.counter !== "number") {
			throw new Error(`Type "hotp" require a "counter" value.`);
		}
	} else {
		options.period ??= 30;
		if (
			"period" in options && options.period &&
			typeof options.period !== "number"
		) {
			throw new Error(`When provided, the "period" options must be a number.`);
		}
	}
	if (
		"digits" in options && options.digits && typeof options.digits !== "number"
	) {
		throw new Error(`When provided, the "digits" options must be a number.`);
	}
	if (
		"algorithm" in options && options.algorithm &&
		!isOTPAlgorithm(options.algorithm)
	) {
		throw new Error(
			`When provided, the "algorithm" options must be either "SHA-1", "SHA-256", "SHA-384" or "SHA-512".`,
		);
	}
	const { type, secret, label, ...rest } = options;
	const uri = new URL(`otpauth://${type}/${encodeURIComponent(label)}`);
	for (const [key, value] of Object.entries(rest)) {
		uri.searchParams.set(key, value.toString());
	}
	uri.searchParams.set("secret", secret);
	return uri.toString();
}
