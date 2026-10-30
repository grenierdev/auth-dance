import { ok } from "node:assert";
import { describe, it } from "vitest";
import { isCodeChallenge, verifyCodeVerifier } from "./pkce.ts";
import { sha256 } from "./records.ts";

// RFC 7636 Appendix B.
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

describe("pkce", () => {
	it("should verify the S256 example of RFC 7636", async () => {
		ok(isCodeChallenge(CHALLENGE));
		ok(await verifyCodeVerifier(VERIFIER, CHALLENGE));
		ok(!(await verifyCodeVerifier(`${VERIFIER.slice(0, -1)}l`, CHALLENGE)));
	});
	it("should refuse a verifier outside 43 to 128 unreserved characters", async () => {
		for (const verifier of ["a".repeat(42), "a".repeat(129), `${"a".repeat(42)}+`, `${"a".repeat(42)} `]) {
			ok(!(await verifyCodeVerifier(verifier, CHALLENGE)), verifier);
		}
		// Every unreserved character passes.
		ok(await verifyCodeVerifier("~._-".repeat(32), await sha256("~._-".repeat(32))));
	});
	it("should refuse a challenge that is not 43 base64url characters", () => {
		for (const challenge of [undefined, "", CHALLENGE.slice(1), `${CHALLENGE}=`, `${CHALLENGE.slice(1)}+`, VERIFIER.repeat(2)]) {
			ok(!isCodeChallenge(challenge), String(challenge));
		}
	});
});
