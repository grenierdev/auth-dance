// The user code of RFC 8628 §6.1: 8 characters of a base-20 alphabet with no vowel, so no word can form, shown as
// XXXX-XXXX. 20^8 is about 2^34.5.
const ALPHABET = "BCDFGHJKLMNPQRSTVWXZ";
const LENGTH = 8;

/** A new user code, normalized: 8 characters of the alphabet, with no dash. */
export function generateUserCode(): string {
	let code = "";
	while (code.length < LENGTH) {
		for (const byte of crypto.getRandomValues(new Uint8Array(LENGTH))) {
			// 240 is the largest multiple of 20 under 256. A byte at or above it would favour the first characters.
			if (byte < 240 && code.length < LENGTH) {
				code += ALPHABET[byte % ALPHABET.length];
			}
		}
	}
	return code;
}

/**
 * Reads a user code the owner typed, RFC 8628 §6.1: case does not count, and a character outside the alphabet, a dash
 * or a space for example, drops out.
 *
 * @returns The normalized code, or `undefined` when what is left is not 8 characters of the alphabet.
 */
export function normalizeUserCode(value: unknown): string | undefined {
	if (typeof value !== "string" || value.length > 64) {
		return undefined;
	}
	const code = value.toUpperCase().replace(/[^A-Z]/g, "");
	return code.length === LENGTH && [...code].every((character) => ALPHABET.includes(character)) ? code : undefined;
}

/** Shows a normalized user code as XXXX-XXXX, RFC 8628 §6.1. */
export function formatUserCode(code: string): string {
	return `${code.slice(0, LENGTH / 2)}-${code.slice(LENGTH / 2)}`;
}
