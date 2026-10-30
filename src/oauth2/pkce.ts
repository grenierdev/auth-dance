import { constantTimeEqual, sha256 } from "./records.ts";

// RFC 7636 §4.1: code-verifier = 43*128unreserved.
const CODE_VERIFIER = /^[A-Za-z0-9\-._~]{43,128}$/;

// RFC 7636 §4.2: with S256, the challenge is BASE64URL(SHA256(verifier)), 43 characters with no padding.
const CODE_CHALLENGE = /^[A-Za-z0-9_-]{43}$/;

/** Whether a value has the shape of an S256 code challenge, RFC 7636 §4.2. */
export function isCodeChallenge(value: unknown): value is string {
	return typeof value === "string" && CODE_CHALLENGE.test(value);
}

/**
 * Checks a code verifier against the S256 challenge of the authorization request, RFC 7636 §4.6. A verifier with the
 * wrong syntax fails before any hash.
 */
export async function verifyCodeVerifier(verifier: string, challenge: string): Promise<boolean> {
	return CODE_VERIFIER.test(verifier) && constantTimeEqual(await sha256(verifier), challenge);
}
