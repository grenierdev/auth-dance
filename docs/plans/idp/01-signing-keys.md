# Plan 01: Signing keys

A breaking change to the core. It comes first because every token the IdP mints needs a key that a third party can
check without holding the secret.

## Today

`AuthDanceApi` signs the access, refresh and ID tokens with HS256 under `options.secret`, and it encrypts the flow
state with the same key (`dir` + `A256GCM`). `tokens.issuer` defaults to `"acme"`.

## Target

- `secret` only encrypts the flow state. It no longer signs anything.
- A new `keys` option signs every token. It holds asymmetric private JWKs, and the first one is the active key.
  The others remain valid for verification, so an old key keeps working for the life of its last token.
- `tokens.issuer` is required and must be an `https:` URL (`http://localhost` passes in tests). RFC 8414 §2 and
  plan 02 need it as a URL, and the default `"acme"` goes away.
- Every token carries `kid` in its header and `aud`. The core tokens use `aud: <issuer>`. The IdP tokens use the
  client or the resource, so a core access token never passes as an IdP access token, and the reverse.

## API

```ts
// src/keys.ts
export interface AuthDanceSigningKey {
	/** A private JWK with `kid` and `alg`. ES256, EdDSA (Ed25519), RS256 or PS256. */
	jwk: JsonWebKey & { kid: string; alg: string };
}

export class AuthDanceKeys {
	static async fromJwks(keys: AuthDanceSigningKey["jwk"][]): Promise<AuthDanceKeys>;
	/** Imports once, refuses a symmetric key, a key without `kid`, two keys with the same `kid`. */
	sign(payload: JWTPayload, options: { typ?: string; ... }): Promise<string>;
	verify(token: string, options: JWTVerifyOptions): Promise<JWTPayload>; // picks the key by `kid`
	/** The public JWK Set: `kid`, `alg`, `use: "sig"`, no private member. */
	jwks(): { keys: JsonWebKey[] };
}

/** Generate one key for a setup script. */
export function generateSigningKey(alg?: "ES256" | "EdDSA"): Promise<AuthDanceSigningKey["jwk"]>;
```

`AuthDanceApiOptions.keys: AuthDanceSigningKey["jwk"][]`. The constructor stays synchronous, so key import is lazy
and memoized, like the discovery in `oidc.ts`. A key provider for a KMS is out of scope. `AuthDanceKeys` is the seam
where one would plug in later.

## Steps

1. Add `src/keys.ts` with `AuthDanceKeys` and `generateSigningKey`, on `jose` (`importJWK`, `SignJWT`,
   `createLocalJWKSet`). Tests: sign and verify, a `kid` lookup after rotation, refusal of `oct` keys and duplicate
   `kid`s, no private member in `jwks()`.
2. In `src/api.ts`, `#generateTokens`, `#verifiedClaims` and `verifyAccessToken` move to `AuthDanceKeys`. Set
   `aud`, and require it on verification. `#decodedSecret` stays for `#encryptState`/`#decryptState`.
3. Make `tokens.issuer` required, and validate it as a URL in the constructor.
4. Add `api.jwks()` and a `GET /.well-known/jwks.json` route to `createAuthDanceApp`. It is the first GET of the
   core app. Its doc comment ("Every route is a POST") changes.
5. Update `README.md` (setup now generates a key), the `createAuthDance` examples, and every test fixture. Add a
   test helper that generates one ES256 key per suite, so the tests stay fast.
6. Changelog entry under breaking changes: the token format, the required `keys`, the required `issuer`.

## Open points

- ES256 is the default because keys are small and Workers sign it fast. RS256 stays allowed for relying parties that
  accept nothing else.
- The core `id_token` today is not an OIDC ID token (`sub` is the identity, `claims` is nested). The OIDC plan
  reshapes it. This plan changes only its signature.
