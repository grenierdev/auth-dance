# Plan 02: Foundation

The module, the client storage, the records, the error model and the metadata document. When this plan ends,
`auth-dance/idp` builds, serves `/.well-known/oauth-authorization-server`, and stores clients. It issues no token yet.

## Module entry

`src/idp.ts`, exported as `auth-dance/idp`:

```ts
export { AuthDanceProviderApi, createAuthDanceProviderApi } from "./idp/api.ts";
export { type AuthDanceProviderApp, createAuthDanceProviderApp } from "./idp/app.ts";
export { AuthDanceClientStorage, type AuthDanceClientProvider } from "./idp/storage.ts";
export * from "./idp/client.ts";
export * from "./idp/error.ts";
export function createAuthDanceProvider(options: AuthDanceProviderOptions): AuthDanceProvider;
```

## Options

```ts
export interface AuthDanceProviderApiOptions {
	/** The core state machine. The IdP verifies dance tokens with it, and keeps its records in `api.storage`. */
	api: AuthDanceApi;
	/** The registered clients. */
	clients: AuthDanceClientStorage;
	/** The issuer URL, the `iss` of every token and the base of the metadata. It must equal `api` tokens.issuer. */
	issuer: string;
	/** The signing keys. @defaultValue the keys of `api`. */
	keys?: AuthDanceKeys;
	/** Encrypts the browser cookies (CSRF binding, remembered login). A base64url key, apart from the core secret. */
	secret: string;
	/** Where `/authorize` hands off. Each URL gets `?login_challenge=` or `?consent_challenge=`. */
	ui: { login: string; consent: string; error?: string };
	/**
	 * The scopes the server knows. A request for another scope fails with `invalid_scope`. `description` is for the
	 * consent page, and can be keyed by language tag.
	 */
	scopes: Record<string, { description: string | Record<string, string> }>;
	durations?: {
		challenge?: number; // 600
		code?: number; // 60, RFC 6749 §4.1.2 recommends 10 minutes at most
		access?: number; // 300
		refresh?: number; // 86400
		refresh_leeway?: number; // 10
		remember?: number; // 0, which means no remembered login
	};
	limits?: { address?: { token?: AuthDanceRateLimit; register?: AuthDanceRateLimit; introspect?: AuthDanceRateLimit } };
	hooks?: AuthDanceProviderHooks; // onGrantCreated, onGrantRevoked, onClientRegistered, onError
}
```

## Registered client

`src/idp/client.ts`. The field names follow RFC 7591 §2, so `/register` (plan 06) reads and returns them unchanged.

```ts
export interface AuthDanceRegisteredClient {
	client_id: string; // cli_ ksuid
	client_secret_hash?: string; // SHA-256 base64url. The secret never sits in storage.
	client_secret_expires_at: number; // 0 = never
	client_id_issued_at: number;
	redirect_uris: string[];
	token_endpoint_auth_method: "client_secret_basic" | "client_secret_post" | "none";
	grant_types: ("authorization_code" | "refresh_token" | "client_credentials")[];
	response_types: "code"[];
	scope: string; // space-separated, the ceiling of what the client may ask
	client_name?: string;
	client_uri?: string;
	logo_uri?: string;
	tos_uri?: string;
	policy_uri?: string;
	contacts?: string[];
	software_id?: string;
	software_version?: string;
	/** Language-tagged variants, RFC 7591 §2.2: `{ "client_name#fr-CA": "…" }`. */
	localized?: Record<string, string>;
	// Server-side only. /register can never set these.
	skip_consent?: boolean; // first-party apps
	introspect?: boolean; // may introspect tokens of other clients, plan 04
	registered_by?: "admin" | "dynamic";
}
```

Also in `client.ts`:

- `AuthDanceRegisteredClient` as a valibot schema, the way `session.ts` does it.
- `validateRedirectUri(uri)`: an absolute URI with no fragment (RFC 6749 §3.1.2). It accepts `https:`, `http:` only
  on loopback (RFC 8252 §7.3), and a private-use scheme with a dot in it (RFC 8252 §7.1). It refuses `javascript:`,
  `data:` and `file:`.
- `matchRedirectUri(client, uri)`: exact string match, except the loopback port, which may change (RFC 8252 §7.3).
  No pattern matching (RFC 9700 §4.1.3).
- `isPublic(client)`: `token_endpoint_auth_method === "none"`.

## Client storage

`src/idp/storage.ts`, built like `AuthDanceStorage`:

```ts
export interface AuthDanceClientProvider {
	get(clientId: string): Promise<AuthDanceRegisteredClient | undefined>;
	list(cursor?: string, limit?: number): Promise<AuthDanceRegisteredClient[]>;
	set(client: AuthDanceRegisteredClient): Promise<void>;
	delete(clientId: string): Promise<void>;
}

export class AuthDanceClientStorage {
	constructor(options: { clients: AuthDanceClientProvider });
	/** Mint `cli_` id, generate a 32-byte secret for confidential clients, store its hash. Returns the plain secret once. */
	createClient(metadata): Promise<{ client: AuthDanceRegisteredClient; client_secret?: string }>;
	getClient(id), listClients(cursor, limit), updateClient(client), deleteClient(id);
	rotateSecret(id): Promise<string>;
	/** Constant-time comparison of SHA-256 hashes. Also checks client_secret_expires_at. */
	verifySecret(client, secret): Promise<boolean>;
}
```

Adapters:

- `MemoryClientProvider` in `providers/memory.ts`, `Disposable` like its neighbours. It can also be seeded with a
  static list: `new MemoryClientProvider([{ … }])`.
- `CloudflareD1ClientProvider` in `providers/cloudflare.ts`, with a `"client"` table in `sqlite.sql` (`id`,
  `metadata` JSON, `created_at`, `updated_at`).
- `createAuthDanceMemoryStorage` and `createAuthDanceCloudflareStorage` stay as they are. Each provider file gets a
  `createAuthDance*ClientStorage` helper.
- A shared suite in `provider.test.ts` that both adapters register, as the identity providers do.

## Records

`src/idp/records.ts`. Typed helpers over `api.storage.getKv`/`setKv`/`unsetKv`/`listKv`, each with a valibot
schema. All keys sit under `idp/`, so they never collide with `session/`, `sessions/` or `otp/`.

| Key                                | Holds                                                         | TTL             |
| ---------------------------------- | ------------------------------------------------------------- | --------------- |
| `idp/login/<challenge>`            | The validated authorization request, CSRF hash, login result  | `challenge`     |
| `idp/consent/<challenge>`          | The request, the identity, the session, `aat`                 | `challenge`     |
| `idp/code/<sha256>`                | Grant id, client, redirect URI, PKCE challenge, `usedAt?`     | `code`          |
| `idp/grant/<gid>`                  | Client, identity?, session?, scopes, refresh hashes, `aat`    | `refresh`       |
| `idp/grants/<identityId>/<gid>`    | Index for "apps that have access to my account"               | `refresh`       |
| `idp/consents/<identityId>/<cid>`  | Granted scopes, `grantedAt`                                   | none            |

Every token value and every code is stored as a SHA-256 hash, never as is.

## Errors

`src/idp/error.ts`. One abstract class, apart from `AuthDanceError`, because the wire format differs:

```ts
export abstract class AuthDanceOAuthError extends Error {
	abstract readonly error: string; // the RFC code
	abstract readonly status: 400 | 401 | 403 | 404 | 503;
	readonly description?: string; // safe to send. Never internal detail.
}
```

The classes: `InvalidRequestError`, `InvalidClientError` (401), `InvalidGrantError`, `UnauthorizedClientError`,
`UnsupportedGrantTypeError`, `UnsupportedResponseTypeError`, `InvalidScopeError`, `AccessDeniedError`,
`ServerError`, `TemporarilyUnavailableError` (RFC 6749 §4.1.2.1, §5.2), `UnsupportedTokenTypeError` (RFC 7009),
`InvalidRedirectUriError`, `InvalidClientMetadataError`, `InvalidSoftwareStatementError`,
`UnapprovedSoftwareStatementError` (RFC 7591 §3.2.2). `RateLimitedError` from the core still answers 429.

## App skeleton

`src/idp/app.ts`:

- `Hono<{ Bindings: { idp: AuthDanceProviderApi } }>`, with `basePath` and `address` options identical to
  `AuthDanceAppOptions`. It reuses `cloudflareAddress` and `forwardedAddress` from `src/app.ts`.
- `onError`: an `AuthDanceOAuthError` answers `status` and `{ error, error_description }`, and adds
  `WWW-Authenticate: Basic` on a 401 when the request used Basic (RFC 6749 §5.2). Anything else answers 500
  `{ error: "server_error" }`.
- The per-address middleware, as in the core app, with its own buckets.
- `Cache-Control: no-store` and `Pragma: no-cache` on every JSON answer (RFC 6749 §5.1).
- `GET /.well-known/oauth-authorization-server`, RFC 8414 §2: `issuer`, `authorization_endpoint`,
  `token_endpoint`, `jwks_uri`, `registration_endpoint` (when enabled), `scopes_supported`,
  `response_types_supported: ["code"]`, `grant_types_supported`, `token_endpoint_auth_methods_supported`,
  `revocation_endpoint`, `introspection_endpoint` and their `*_auth_methods_supported`,
  `code_challenge_methods_supported: ["S256"]`, `authorization_response_iss_parameter_supported: true`. The OIDC plan
  extends this builder for `openid-configuration`.
- `GET /jwks.json`, which serves `keys.jwks()`.

## Steps

1. `package.json` export and `src/idp.ts` entry. `tsc` builds an empty module.
2. `client.ts` with its schema and URI rules, and tests.
3. `storage.ts`, the two adapters, the shared provider suite and the SQL table.
4. `records.ts` and tests on `MemoryKvProvider`.
5. `error.ts`.
6. `api.ts` constructor: validate `issuer` against `api`, decode `secret`, check that `ui` URLs are absolute.
   `app.ts` skeleton with metadata and JWKS. Tests against the in-process `fetch`.
7. Add a README section stub: "Auth Dance as an identity provider".
