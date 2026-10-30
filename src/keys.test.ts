import { deepEqual, ok, rejects, throws } from "node:assert";
import { decodeProtectedHeader } from "jose/decode/protected_header";
import { calculateJwkThumbprint } from "jose/jwk/thumbprint";
import { SignJWT } from "jose/jwt/sign";
import { exportJWK } from "jose/key/export";
import { generateKeyPair } from "jose/key/generate/keypair";
import { beforeAll, describe, it } from "vitest";
import { TEST_SIGNING_KEYS } from "./fixtures.test.ts";
import { AuthDanceKeys, type AuthDanceSigningKey, generateSigningKey } from "./keys.ts";

type Jwk = AuthDanceSigningKey["jwk"];

const PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

const claims = { iss: "https://auth.example.com", aud: "https://api.example.com", sub: "id_1" };
const checks = { issuer: claims.iss, audience: claims.aud };

async function rsaKey(alg: "RS256" | "PS256"): Promise<Jwk> {
	const { privateKey } = await generateKeyPair(alg, { extractable: true });
	const jwk = await exportJWK(privateKey);
	return { ...jwk, kid: await calculateJwkThumbprint(jwk), alg };
}

describe("AuthDanceKeys", () => {
	let older: Jwk;
	let newer: Jwk;

	beforeAll(async () => {
		older = TEST_SIGNING_KEYS[0];
		newer = await generateSigningKey();
	});

	it("should sign with the first key and verify", async () => {
		const keys = new AuthDanceKeys([older]);
		const token = await keys.sign(claims);
		deepEqual(decodeProtectedHeader(token), { alg: "ES256", kid: older.kid });
		deepEqual(await keys.verify(token, checks), claims);
	});
	it("should set typ when given", async () => {
		const keys = new AuthDanceKeys([older]);
		const token = await keys.sign(claims, { typ: "at+jwt" });
		deepEqual(decodeProtectedHeader(token).typ, "at+jwt");
		deepEqual(await keys.verify(token, { ...checks, typ: "at+jwt" }), claims);
	});
	it("should pass the claim checks to the verification", async () => {
		const keys = new AuthDanceKeys([older]);
		const token = await keys.sign(claims);
		await rejects(() => keys.verify(token, { ...checks, audience: "cli_other" }));
		await rejects(() => keys.verify(token, { ...checks, issuer: "https://other.example.com" }));
	});
	it("should sign and verify with every algorithm it accepts", async () => {
		for (const jwk of [await generateSigningKey("EdDSA"), await rsaKey("RS256"), await rsaKey("PS256")]) {
			const keys = await AuthDanceKeys.fromJwks([jwk]);
			const token = await keys.sign(claims);
			deepEqual(decodeProtectedHeader(token), { alg: jwk.alg, kid: jwk.kid });
			deepEqual(await keys.verify(token, checks), claims);
		}
	});
	it("should pick the key by kid after a rotation", async () => {
		const before = await new AuthDanceKeys([older]).sign(claims);
		const rotated = new AuthDanceKeys([newer, older]);
		const after = await rotated.sign(claims);
		deepEqual(decodeProtectedHeader(after).kid, newer.kid);
		deepEqual(await rotated.verify(before, checks), claims);
		deepEqual(await rotated.verify(after, checks), claims);
		// Once the old key leaves the list, its tokens fail.
		await rejects(() => new AuthDanceKeys([newer]).verify(before, checks));
	});
	it("should verify with a key that holds its public part only", async () => {
		const before = await new AuthDanceKeys([older]).sign(claims);
		const [retired] = new AuthDanceKeys([older]).jwks().keys;
		const rotated = new AuthDanceKeys([newer, retired as Jwk]);
		deepEqual(await rotated.verify(before, checks), claims);
	});
	it("should refuse a token with no kid, an unknown kid or another alg", async () => {
		const keys = new AuthDanceKeys([older]);
		const { privateKey } = await generateKeyPair("ES256");
		const sign = (header: { alg: string; kid?: string }) => new SignJWT(claims).setProtectedHeader(header).sign(privateKey);
		await rejects(() => keys.verify("not-a-jwt", checks));
		await rejects(async () => keys.verify(await sign({ alg: "ES256" }), checks));
		await rejects(async () => keys.verify(await sign({ alg: "ES256", kid: "unknown" }), checks));
		// The right kid, signed by another key.
		await rejects(async () => keys.verify(await sign({ alg: "ES256", kid: older.kid }), checks));
		// An HS256 token under the kid of the key. No symmetric key exists to check it.
		const hs256 = await new SignJWT(claims).setProtectedHeader({ alg: "HS256", kid: older.kid }).sign(new Uint8Array(32));
		await rejects(() => keys.verify(hs256, checks));
	});
	it("should refuse a symmetric key", () => {
		throws(
			() => new AuthDanceKeys([{ kty: "oct", k: "zdJXI1jwuXW8A19fns0E_B4HSYm7AUHLGlU9WLo8mxs", kid: "hmac", alg: "HS256" }]),
			(error) => error instanceof TypeError && /symmetric/.test(error.message),
		);
	});
	it("should refuse two keys with the same kid", () => {
		throws(
			() => new AuthDanceKeys([older, { ...newer, kid: older.kid }]),
			(error) => error instanceof TypeError && /share the kid/.test(error.message),
		);
	});
	it("should refuse a key the shape of which does not sign", async () => {
		const { kid: _kid, ...noKid } = older;
		const { d: _d, ...publicOnly } = older;
		const refused: unknown[] = [
			[],
			[noKid],
			[{ ...older, kid: "" }],
			[{ ...older, alg: "ES384" }],
			[{ ...older, alg: "none" }],
			[{ ...older, alg: "EdDSA" }],
			[{ ...older, crv: "P-384" }],
			[{ ...older, x: undefined }],
			[{ ...older, use: "enc" }],
			// The first key signs, so it needs its private part.
			[publicOnly],
		];
		for (const keys of refused) {
			throws(() => new AuthDanceKeys(keys as Jwk[]), TypeError);
		}
	});
	it("should refuse key material that does not import, in fromJwks", async () => {
		const broken = { ...older, x: older.y, y: older.x };
		// The shape is right, so the constructor accepts it.
		new AuthDanceKeys([broken]);
		await rejects(() => AuthDanceKeys.fromJwks([broken]));
	});
	it("should publish no private member", async () => {
		const rsa = await rsaKey("RS256");
		const { keys } = new AuthDanceKeys([older, newer, rsa]).jwks();
		deepEqual(
			keys.map((jwk) => (jwk as Jwk).kid),
			[older.kid, newer.kid, rsa.kid],
		);
		for (const jwk of keys) {
			deepEqual(jwk.use, "sig");
			ok(typeof jwk.alg === "string");
			ok(PRIVATE_MEMBERS.every((member) => !(member in jwk)));
		}
		deepEqual(keys[0], { kty: "EC", crv: "P-256", x: older.x, y: older.y, kid: older.kid, alg: "ES256", use: "sig" });
	});
	it("should hand out a copy of the JWK Set", () => {
		const keys = new AuthDanceKeys([older]);
		const jwks = keys.jwks();
		jwks.keys[0].x = "tampered";
		deepEqual(keys.jwks().keys[0].x, older.x);
	});
});

describe("generateSigningKey", () => {
	it("should generate an ES256 key named by its thumbprint", async () => {
		const jwk = await generateSigningKey();
		deepEqual([jwk.kty, jwk.crv, jwk.alg, jwk.use], ["EC", "P-256", "ES256", "sig"]);
		ok(typeof jwk.d === "string");
		deepEqual(jwk.kid, await calculateJwkThumbprint(jwk));
	});
	it("should generate an EdDSA key", async () => {
		const jwk = await generateSigningKey("EdDSA");
		deepEqual([jwk.kty, jwk.crv, jwk.alg], ["OKP", "Ed25519", "EdDSA"]);
		await AuthDanceKeys.fromJwks([jwk]);
	});
});
