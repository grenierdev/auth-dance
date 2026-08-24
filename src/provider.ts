import type { AuthDanceIdentity } from "./identity.ts";

/**
 * The adapter that holds every identity: its id, its free-form data bag and its components.
 *
 * Only `MemoryIdentityProvider` ships today. You write the persistent adapter yourself.
 */
export interface AuthDanceIdentityProvider {
	/**
	 * Read one page of stored identities.
	 *
	 * @param cursor The cursor that points to the first identity of the page. Without it, start at the first identity.
	 * @param limit The number of identities to return at most. Without it, return every identity.
	 * @returns The identities of the page, or an empty array when the page matches none.
	 */
	list: (cursor?: string, limit?: number) => Promise<AuthDanceIdentity[]>;
	/**
	 * Read one identity by id.
	 *
	 * @param id A ksuid with an `id_` prefix.
	 * @returns The identity, or `undefined` when the store holds no identity under the id.
	 */
	get: (id: string) => Promise<AuthDanceIdentity | undefined>;
	/**
	 * Find the identity that claims one identification.
	 *
	 * @param component The name of the identification component, for example `email`.
	 * @param identification The value the identity claims under that component.
	 * @returns The identity, or `undefined` when no identity claims the value.
	 */
	getByIdentification: (component: string, identification: string) => Promise<AuthDanceIdentity | undefined>;
	/**
	 * Write a whole identity under `identity.id`, and replace the record already stored there.
	 *
	 * After the write, `getByIdentification` must find the identity by each identification component it now holds.
	 */
	set: (identity: AuthDanceIdentity) => Promise<void>;
	/** Delete one identity by id. An id the store does not hold is not a failure. */
	delete: (id: string) => Promise<void>;
}

/**
 * The adapter that holds the string records the library needs for a short time.
 *
 * It sees three key spaces: `session/<id>`, `sessions/<identityId>/<id>` and `otp/<stateId>/<name>`.
 */
export interface AuthDanceKvProvider {
	/**
	 * Read the value one key holds.
	 *
	 * Make your adapter resolve `undefined` for a key it does not hold. A rejection fails the whole listing in
	 * `AuthDanceStorage.listSession`.
	 *
	 * @returns The stored string, or `undefined` for a key that holds nothing or that has expired.
	 */
	get: (key: string) => Promise<string | undefined>;
	/**
	 * List the keys under a prefix. The adapter yields keys, not values.
	 *
	 * @param prefix The start of the keys to match, for example `sessions/id_2abc/`.
	 * @param offset The number of keys to skip. Without it, start at the first key.
	 * @param limit The number of keys to return at most. Without it, return every key that matches.
	 * @returns The matching keys, or an empty array when the prefix matches none.
	 */
	list: (prefix: string, offset?: number, limit?: number) => Promise<string[]>;
	/**
	 * Write a value under a key, and replace what the key already holds.
	 *
	 * @param ttl How long the value stays readable, as a count of seconds. An adapter over a store that counts in
	 * another unit converts it. Without a ttl the value stays until a caller unsets it.
	 */
	set: (key: string, value: string, ttl?: number) => Promise<void>;
	/** Delete one key. A key that holds nothing is not a failure. */
	unset: (key: string) => Promise<void>;
}

/** The answer to one hit of a rate limit bucket: whether the call may continue, and how long a retry must wait. */
export interface AuthDanceRateLimiterResult {
	/**
	 * `true` while the bucket still has room inside its window. On `false` both `AuthDanceApi` and the HTTP layer
	 * throw `RateLimitedError`, which the HTTP layer answers with a 429.
	 */
	allowed: boolean;
	/**
	 * How long the caller waits before a retry, in seconds. The HTTP layer copies it into the `Retry-After` header of
	 * the 429. `undefined` when the adapter reports no wait.
	 */
	retryAfter: number | undefined;
}

/**
 * The adapter that counts the hits of a rate limit bucket.
 *
 * `AuthDanceApi` consumes the per-identity buckets. The HTTP layer consumes the per-address buckets. Only
 * `MemoryRateLimiterProvider` ships today, and it keeps one fixed window per key.
 */
export interface AuthDanceRateLimiterProvider {
	/**
	 * Count one hit of a bucket, then report whether the call may continue.
	 *
	 * @param key The bucket that holds the count. `AuthDanceApi` keys a per-identity bucket as `<bucket>:<subject>`,
	 * such as `verify:identity:id_2abc`. The HTTP layer keys its own buckets as `address:request:<address>` and
	 * `address:send:<address>`.
	 * @param limit The number of hits the bucket allows inside one window.
	 * @param window The length of the bucket window. The adapter decides the unit. Both callers in this library
	 * multiply the configured window in seconds by 1000.
	 */
	limit: (key: string, limit: number, window: number) => Promise<AuthDanceRateLimiterResult>;
}
