import { ksuid } from "./id.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent } from "./identity.ts";
import type {
	AuthDanceIdentityProvider,
	AuthDanceKvProvider,
	AuthDanceRateLimiterProvider,
	AuthDanceRateLimiterResult,
} from "./provider.ts";
import { parse } from "valibot";
import { AuthDanceSession } from "./session.ts";

/**
 * The three adapters that an `AuthDanceStorage` uses.
 *
 * You replace an adapter, never the storage class. Each adapter holds one kind of data, so a deployment can put
 * identities, short-lived records and rate limit counters in three different stores.
 */
export interface AuthDanceStorageOptions {
	/** The adapter that holds every identity, its data bag and its components. */
	identity: AuthDanceIdentityProvider;
	/** The adapter that holds the string records: the two session key spaces and the pending one-time codes. */
	kv: AuthDanceKvProvider;
	/** The adapter that counts the hits of a rate limit bucket. */
	rate_limiter: AuthDanceRateLimiterProvider;
}

/**
 * The storage layer of the library.
 *
 * The class delegates every read and write to one of the three adapters. It also owns the key spaces that the key
 * value adapter sees. A session lives twice: at `session/<id>` for a read by id, and at
 * `sessions/<identityId>/<id>` as the index of one identity. A pending one-time code lives at
 * `otp/<stateId>/<name>`. `OtpAuthDanceComponent` writes, reads and deletes that key with `setKv`, `getKv` and
 * `unsetKv`.
 */
export class AuthDanceStorage {
	#options: AuthDanceStorageOptions;

	/**
	 * Build a storage on the three adapters. The class keeps the three adapters and adds the key spaces on top of
	 * them.
	 *
	 * @param options The three adapters this storage delegates to.
	 */
	constructor(options: AuthDanceStorageOptions) {
		this.#options = options;
	}

	/**
	 * Create an identity with a fresh `id_` ksuid and save it with the identity adapter. Touches no key space.
	 *
	 * @param data The free-form data bag of the identity. An absent value becomes an empty object.
	 * @param components The components the identity starts with. An absent value becomes an empty list.
	 * @returns The saved identity, with the id this call generated.
	 */
	async createIdentity(
		data?: Record<string, unknown>,
		components?: Array<AuthDanceIdentityComponent>,
	): Promise<AuthDanceIdentity> {
		const identity: AuthDanceIdentity = {
			id: ksuid("id_"),
			data: data ?? {},
			components: components ?? [],
		};
		await this.setIdentity(identity);
		return Promise.resolve(identity);
	}

	/**
	 * List identities with the identity adapter. Touches no key space.
	 *
	 * The method passes `offset` and `limit` to the adapter untouched, so the adapter decides how it paginates.
	 */
	listIdentities(offset?: number, limit?: number): Promise<AuthDanceIdentity[]> {
		return this.#options.identity.list(offset, limit);
	}

	/**
	 * Read one identity by id with the identity adapter. Touches no key space.
	 *
	 * @returns The identity, or `undefined` when no identity holds the id.
	 */
	getIdentity(id: string): Promise<AuthDanceIdentity | undefined> {
		return this.#options.identity.get(id);
	}

	/**
	 * Find the identity that holds one identification with the identity adapter. Touches no key space.
	 *
	 * This is how a sign-in resolves an identity from a submitted value. `EmailAuthDanceComponent` calls it with
	 * the address the client typed.
	 *
	 * @param type The name of the identification component, for example `email`.
	 * @param identification The value the identity claims under that component.
	 * @returns The identity, or `undefined` when no identity claims the value.
	 */
	getIdentityByIdentification(type: string, identification: string): Promise<AuthDanceIdentity | undefined> {
		return this.#options.identity.getByIdentification(type, identification);
	}

	/**
	 * Write a whole identity with the identity adapter. Touches no key space.
	 *
	 * The adapter keys the record on `identity.id`, so the call also updates an identity that already exists.
	 * Every flow that enrolls, rotates or confirms a component saves the identity again this way.
	 */
	setIdentity(identity: AuthDanceIdentity): Promise<void> {
		return this.#options.identity.set(identity);
	}

	/**
	 * Delete one identity by id with the identity adapter. Touches no key space.
	 *
	 * The sessions of the identity live in the key value adapter, so this call does not delete them. The delete
	 * flow lists them with `listSession` and deletes each one with `deleteSession` before it calls this method.
	 */
	deleteIdentity(id: string): Promise<void> {
		return this.#options.identity.delete(id);
	}

	/**
	 * Read one raw value with the key value adapter, in any key space.
	 *
	 * The contract allows `undefined` for a key that holds nothing, but an adapter may reject instead.
	 * `MemoryKvProvider` rejects a missing or expired key with `KVKeyNotFoundError`, so a caller that treats
	 * absence as normal catches the rejection. `OtpAuthDanceComponent` catches it on `otp/<stateId>/<name>`.
	 */
	getKv(key: string): Promise<string | undefined> {
		return this.#options.kv.get(key);
	}

	/**
	 * List the keys under a prefix with the key value adapter, in any key space.
	 *
	 * The adapter yields keys, not values, so a caller still reads each key. `listSession` does exactly that on
	 * the `sessions/<identityId>/` prefix.
	 */
	listKv(prefix: string, limit?: number, offset?: number): Promise<string[]> {
		return this.#options.kv.list(prefix, limit, offset);
	}

	/**
	 * Write one raw value with the key value adapter, in any key space.
	 *
	 * @param ttl How long the value stays readable. The storage passes the number to the adapter untouched, so the
	 * adapter decides the unit. `createSession` derives a count of seconds from the session expiry, and
	 * `OtpAuthDanceComponent` passes the lifetime of the code in seconds. `MemoryKvProvider` adds the number to a
	 * millisecond clock. Without a ttl the value stays until a caller unsets it.
	 */
	setKv(key: string, value: string, ttl?: number): Promise<void> {
		return this.#options.kv.set(key, value, ttl);
	}

	/**
	 * Delete one key with the key value adapter, in any key space.
	 */
	unsetKv(key: string): Promise<void> {
		return this.#options.kv.unset(key);
	}

	/**
	 * Create a session for an identity and write it to both session key spaces with the key value adapter.
	 *
	 * The session gets a fresh `ses_` ksuid. The same JSON goes to `session/${id}` for a read by id, and to
	 * `sessions/${identityId}/${id}` as the index of one identity. Both writes carry the same time to live, a
	 * count of seconds from now to `expireAt`. Read `setKv` about that unit.
	 *
	 * @param options.identityId The identity this session signs in.
	 * @param options.scopes The scopes the session carries.
	 * @param options.expireAt The moment the session ends. It also sets the time to live of both records.
	 * @param options.address The address of the client that signed in.
	 * @param options.userAgent The user agent of the client that signed in.
	 * @returns The session both records hold, with `expireAt` as an ISO timestamp.
	 */
	async createSession(
		options: { identityId: string; scopes: string[]; expireAt: Date; address?: string; userAgent?: string },
	): Promise<AuthDanceSession> {
		const id = ksuid("ses_");
		const session: AuthDanceSession = {
			id,
			identityId: options.identityId,
			scopes: options.scopes,
			expireAt: options.expireAt.toISOString(),
			address: options.address,
			userAgent: options.userAgent,
		};
		const ttl = Math.floor((options.expireAt.getTime() - Date.now()) / 1000);
		await Promise.all([
			this.setKv(`session/${session.id}`, JSON.stringify(session), ttl),
			this.setKv(`sessions/${session.identityId}/${session.id}`, JSON.stringify(session), ttl),
		]);
		return session;
	}

	/**
	 * Read one session by id from the `session/<id>` key space with the key value adapter.
	 *
	 * The method parses the stored JSON with the `AuthDanceSession` schema. A record that does not match the shape
	 * makes the call fail. The method never returns a broken session.
	 *
	 * @returns The session, or `undefined` when the key holds nothing. An adapter that rejects a missing key, as
	 * `MemoryKvProvider` does, makes this call reject as well.
	 */
	async getSession(id: string): Promise<AuthDanceSession | undefined> {
		const value = await this.getKv(`session/${id}`);
		if (!value) {
			return undefined;
		}
		return parse(AuthDanceSession, JSON.parse(value));
	}

	/**
	 * Delete one session from both the `session/<id>` and the `sessions/<identityId>/<id>` key spaces.
	 *
	 * The method reads the session first, because the index key needs the `identityId` only the record holds. An
	 * id that resolves to nothing does nothing.
	 */
	async deleteSession(id: string): Promise<void> {
		const session = await this.getSession(id);
		if (!session) {
			return;
		}
		await Promise.all([
			this.unsetKv(`session/${session.id}`),
			this.unsetKv(`sessions/${session.identityId}/${session.id}`),
		]);
	}

	/**
	 * List every session of one identity from the `sessions/<identityId>/` key space with the key value adapter.
	 *
	 * `AuthDanceKvProvider.list` yields keys, not values, so the method still reads every entry. The method skips
	 * a key that the adapter resolves to `undefined`, and it does not fail the whole listing. The index entry and
	 * the session it names expire on their own schedules, so a gap between the two is normal, not a fault. An
	 * adapter that rejects a missing key instead, as `MemoryKvProvider` does, turns that gap into an error. This
	 * is the reason the contract of `get` is `string | undefined`.
	 *
	 * @returns The sessions of the identity, each one parsed with the `AuthDanceSession` schema.
	 */
	async listSession(identityId: string): Promise<AuthDanceSession[]> {
		const keys = await this.#options.kv.list(`sessions/${identityId}/`);
		const values = await Promise.all(keys.map((key) => this.getKv(key)));
		return values
			.filter((value): value is string => value !== undefined)
			.map((value) => parse(AuthDanceSession, JSON.parse(value)));
	}

	/**
	 * Count one hit of a rate limit bucket with the rate limiter adapter. Touches no key space.
	 *
	 * The three arguments go to the adapter untouched. `AuthDanceApi` keys a per-identity bucket as
	 * `<bucket>:<subject>`. The HTTP layer keys a per-address bucket as `address:request:<address>` or
	 * `address:send:<address>`.
	 *
	 * @param key The bucket that holds the count.
	 * @param limit The number of hits the bucket allows inside one window.
	 * @param window The length of the bucket window. The adapter decides the unit. Both callers in this library
	 * multiply the configured window in seconds by 1000, and `MemoryRateLimiterProvider` adds the number to a
	 * millisecond clock.
	 * @returns Whether the adapter allows this hit, and how long the caller waits before a retry.
	 */
	consumeRateLimit(key: string, limit: number, window: number): Promise<AuthDanceRateLimiterResult> {
		return this.#options.rate_limiter.limit(key, limit, window);
	}
}
