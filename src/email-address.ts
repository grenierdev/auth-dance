/** The longest address the library stores, in characters. */
const MAX_ADDRESS_LENGTH = 254;

/** A white space or a control character, which no stored address holds. */
const FORBIDDEN = /[\s\p{Cc}]/u;

/**
 * Returns the address in the form the library stores, or `null` for a value that is not one address.
 *
 * The function trims the value, normalizes it to NFC, and lower-cases the domain. It also lower-cases the local part,
 * unless `options.preserveLocalCase` is set: RFC 5321 makes the local part case-sensitive, but large mail providers do
 * not, and two identities for one inbox cause more harm than a mailbox that depends on that case.
 *
 * It refuses a value that is not a string, a value with a white space or a control character inside, a value longer
 * than 254 characters, and a value without exactly one `@`. It also refuses an empty local part, and a domain with no
 * dot or with an empty label. A domain stays in Unicode. The function does not convert it to Punycode.
 *
 * @param value What the owner submitted.
 * @param options `preserveLocalCase` keeps the case of the local part.
 * @returns The address to store and to look up, or `null`.
 * @example
 * ```ts
 * normalizeEmailAddress("  Victim@Example.COM "); // "victim@example.com"
 * ```
 */
export function normalizeEmailAddress(value: unknown, options?: { preserveLocalCase?: boolean }): string | null {
	if (typeof value !== "string") {
		return null;
	}
	const address = value.trim().normalize("NFC");
	if (address.length === 0 || address.length > MAX_ADDRESS_LENGTH || FORBIDDEN.test(address)) {
		return null;
	}
	const at = address.indexOf("@");
	if (at === -1 || at !== address.lastIndexOf("@")) {
		return null;
	}
	const local = address.slice(0, at);
	const domain = address.slice(at + 1).toLowerCase();
	const labels = domain.split(".");
	if (local === "" || labels.length < 2 || labels.some((label) => label === "")) {
		return null;
	}
	return `${options?.preserveLocalCase ? local : local.toLowerCase()}@${domain}`;
}
