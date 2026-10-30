import type { JWTPayload } from "jose";
import { JWKSNoMatchingKey } from "jose/errors";
import { calculateJwkThumbprint } from "jose/jwk/thumbprint";
import { SignJWT } from "jose/jwt/sign";
import { type JWTVerifyOptions, jwtVerify } from "jose/jwt/verify";
import { exportJWK } from "jose/key/export";
import { generateKeyPair } from "jose/key/generate/keypair";
import { importJWK } from "jose/key/import";

/** One key that signs the tokens. */
export interface AuthDanceSigningKey {
	/** A private JWK with `kid` and `alg`. ES256, EdDSA (Ed25519), RS256 or PS256. */
	jwk: JsonWebKey & { kid: string; alg: string };
}

// The key type, the curve and the public members each algorithm needs: RFC 7518 §3.3 to §3.5, and RFC 8037 §3.1.
const ALGORITHMS = new Map<string, { kty: string; crv?: string; members: (keyof JsonWebKey)[] }>([
	["ES256", { kty: "EC", crv: "P-256", members: ["x", "y"] }],
	["EdDSA", { kty: "OKP", crv: "Ed25519", members: ["x"] }],
	["RS256", { kty: "RSA", members: ["n", "e"] }],
	["PS256", { kty: "RSA", members: ["n", "e"] }],
]);

// A key and its import. The first use imports the key, and every later use gets the same promise.
interface ImportedJwk {
	jwk: AuthDanceSigningKey["jwk"];
	key?: Promise<CryptoKey | Uint8Array>;
}

function imported(entry: ImportedJwk): Promise<CryptoKey | Uint8Array> {
	entry.key ??= importJWK(entry.jwk, entry.jwk.alg);
	return entry.key;
}

// `signs` is true for the first key, the only key that needs its private part.
function checkKey(jwk: AuthDanceSigningKey["jwk"], signs: boolean): void {
	if (typeof jwk !== "object" || jwk === null) {
		throw new TypeError("a signing key must be a JWK object");
	}
	if (jwk.kty === "oct") {
		throw new TypeError("a signing key is symmetric (kty oct); give an asymmetric key, for example from generateSigningKey()");
	}
	if (typeof jwk.kid !== "string" || jwk.kid === "") {
		throw new TypeError("a signing key has no kid");
	}
	const expected = ALGORITHMS.get(jwk.alg);
	if (!expected) {
		throw new TypeError(`signing key ${jwk.kid} has alg ${jwk.alg}; give ES256, EdDSA, RS256 or PS256`);
	}
	if (jwk.kty !== expected.kty || jwk.crv !== expected.crv) {
		throw new TypeError(`signing key ${jwk.kid} is not the ${expected.crv ?? expected.kty} key that alg ${jwk.alg} needs`);
	}
	if (expected.members.some((member) => typeof jwk[member] !== "string")) {
		throw new TypeError(`signing key ${jwk.kid} misses one of ${expected.members.join(", ")}`);
	}
	if (jwk.use !== undefined && jwk.use !== "sig") {
		throw new TypeError(`signing key ${jwk.kid} has use ${jwk.use}, not sig`);
	}
	if (signs && typeof jwk.d !== "string") {
		throw new TypeError(`signing key ${jwk.kid} is the first key, and has no private part`);
	}
}

// Copies the public members only, so no private member reaches the JWK Set, whatever else the input holds.
function publicJwk(jwk: AuthDanceSigningKey["jwk"]): AuthDanceSigningKey["jwk"] {
	const { kid, alg } = jwk;
	switch (jwk.kty) {
		case "EC":
			return { kty: "EC", crv: jwk.crv, x: jwk.x, y: jwk.y, kid, alg, use: "sig" };
		case "OKP":
			return { kty: "OKP", crv: jwk.crv, x: jwk.x, kid, alg, use: "sig" };
		default:
			return { kty: "RSA", n: jwk.n, e: jwk.e, kid, alg, use: "sig" };
	}
}

/**
 * The keys that sign and verify the tokens. The first key signs. Every key verifies, so a token stays valid after a
 * rotation for as long as its key stays in the list.
 *
 * Each key is an asymmetric JWK with `kid` and `alg`: ES256, EdDSA (Ed25519), RS256 or PS256. The first key holds its
 * private part. A key after the first can hold its public part only, because it signs nothing.
 *
 * The constructor checks the shape of each key and imports none of them. The first `sign` imports the first key, and
 * the first `verify` for a `kid` imports that key. Each key imports one time. `fromJwks` imports every key at once.
 *
 * @example
 * ```ts
 * const keys = await AuthDanceKeys.fromJwks([JSON.parse(process.env.AUTH_SIGNING_KEY!)]);
 * const token = await keys.sign({ iss: "https://auth.example.com", aud: "https://api.example.com", sub: "id_…" });
 * const payload = await keys.verify(token, { issuer: "https://auth.example.com", audience: "https://api.example.com" });
 * ```
 */
export class AuthDanceKeys {
	#signer: ImportedJwk;
	#verifiers: Map<string, ImportedJwk>;

	/**
	 * Checks the keys. It imports nothing, so bad key material fails on the first `sign` or `verify`. Use `fromJwks`
	 * to make it fail at once.
	 *
	 * @param keys The JWKs. The first key signs.
	 * @throws {TypeError} When the list is empty, when a key is symmetric, has no `kid`, has an `alg` other than ES256,
	 * EdDSA, RS256 or PS256, does not match its `alg`, or has `use` other than `sig`, when two keys share a `kid`, and
	 * when the first key has no private part.
	 */
	constructor(keys: AuthDanceSigningKey["jwk"][]) {
		if (!Array.isArray(keys) || keys.length === 0) {
			throw new TypeError("keys holds no signing key; generate one with generateSigningKey()");
		}
		this.#verifiers = new Map();
		keys.forEach((jwk, index) => {
			checkKey(jwk, index === 0);
			if (this.#verifiers.has(jwk.kid)) {
				throw new TypeError(`two signing keys share the kid ${jwk.kid}`);
			}
			this.#verifiers.set(jwk.kid, { jwk: publicJwk(jwk) });
		});
		this.#signer = { jwk: { ...keys[0] } };
	}

	/**
	 * Checks the keys and imports each of them one time, so bad key material fails here and not on the first token.
	 *
	 * @param keys The JWKs. The first key signs.
	 * @returns The keys, ready to sign and verify.
	 * @throws {TypeError} For the same reasons as the constructor.
	 * @throws The error the runtime raises when it cannot import a key.
	 */
	static async fromJwks(keys: AuthDanceSigningKey["jwk"][]): Promise<AuthDanceKeys> {
		const instance = new AuthDanceKeys(keys);
		await Promise.all([imported(instance.#signer), ...[...instance.#verifiers.values()].map(imported)]);
		return instance;
	}

	/**
	 * Signs a JWT with the first key. The header holds `alg`, `kid`, and `typ` when `options.typ` holds a value.
	 *
	 * The payload goes out as it is. Put every registered claim in it, `iss`, `aud`, `exp` and the others.
	 *
	 * @param payload The claims of the token.
	 * @param options `typ` sets the `typ` header, for example `at+jwt` for an RFC 9068 access token.
	 * @returns The signed JWT.
	 */
	async sign(payload: JWTPayload, options?: { typ?: string }): Promise<string> {
		const { alg, kid } = this.#signer.jwk;
		const header = options?.typ === undefined ? { alg, kid } : { alg, kid, typ: options.typ };
		return new SignJWT(payload).setProtectedHeader(header).sign(await imported(this.#signer));
	}

	/**
	 * Verifies a JWT with the key its `kid` names. A token with no `kid`, with a `kid` no key holds, or with an `alg`
	 * other than the one of that key fails.
	 *
	 * @param token The JWT.
	 * @param options The claim checks, for example `issuer` and `audience`.
	 * @returns The payload of the token.
	 * @throws The `jose` error that names the check that failed.
	 */
	async verify(token: string, options: JWTVerifyOptions): Promise<JWTPayload> {
		const { payload } = await jwtVerify(
			token,
			async (header) => {
				const entry = typeof header.kid === "string" ? this.#verifiers.get(header.kid) : undefined;
				if (!entry || header.alg !== entry.jwk.alg) {
					throw new JWKSNoMatchingKey();
				}
				return imported(entry);
			},
			options,
		);
		return payload;
	}

	/**
	 * The public JWK Set, RFC 7517 §5. Each key holds `kid`, `alg`, `use: "sig"` and its public members, and no
	 * private member.
	 *
	 * @returns A new object on each call.
	 */
	jwks(): { keys: JsonWebKey[] } {
		return { keys: [...this.#verifiers.values()].map(({ jwk }) => ({ ...jwk })) };
	}
}

/**
 * Generates one signing key for a setup script. Keep the result in a secret store, and give it in `keys`.
 *
 * @param alg The algorithm of the key. @defaultValue `"ES256"`
 * @returns A private JWK with `alg` and `use: "sig"`. Its `kid` is its JWK thumbprint, RFC 7638.
 *
 * @example
 * ```sh
 * node --input-type=module -e "import { generateSigningKey } from 'auth-dance'; console.log(JSON.stringify(await generateSigningKey()))"
 * ```
 */
export async function generateSigningKey(alg: "ES256" | "EdDSA" = "ES256"): Promise<AuthDanceSigningKey["jwk"]> {
	const { privateKey } = await generateKeyPair(alg, { extractable: true });
	const jwk = await exportJWK(privateKey);
	return { ...jwk, kid: await calculateJwkThumbprint(jwk), alg, use: "sig" };
}
