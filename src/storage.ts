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
 * The three adapters that an `AuthDanceStorage` uses. Each adapter holds one kind of data, so a deployment can
 * use three different stores.
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
 * The storage layer of the library. A session lives twice, at `session/<id>` and at
 * `sessions/<identityId>/<id>`. A pending one-time code lives at `otp/<stateId>/<name>`.
 */
export class AuthDanceStorage {
	#options: AuthDanceStorageOptions;

	/** Build a storage on the three adapters. */
	constructor(options: AuthDanceStorageOptions) {
		this.#options = options;
	}

	/**
	 * Create an identity with a fresh `id_` ksuid and save it. An absent `data` becomes an empty object. An absent
	 * `components` becomes an empty list.
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

	/** List identities. The adapter decides how it paginates `cursor` and `limit`. */
	listIdentities(cursor?: string, limit?: number): Promise<AuthDanceIdentity[]> {
		return this.#options.identity.list(cursor, limit);
	}

	/** Read one identity by id. Returns `undefined` when no identity holds the id. */
	getIdentity(id: string): Promise<AuthDanceIdentity | undefined> {
		return this.#options.identity.get(id);
	}

	/**
	 * Find the identity that holds one identification, for example the `email` component and an address. Returns
	 * `undefined` when no identity claims the value.
	 */
	getIdentityByIdentification(type: string, identification: string): Promise<AuthDanceIdentity | undefined> {
		return this.#options.identity.getByIdentification(type, identification);
	}

	/** Write a whole identity. The adapter keys the record on `identity.id`, so the call also updates one that exists. */
	setIdentity(identity: AuthDanceIdentity): Promise<void> {
		return this.#options.identity.set(identity);
	}

	/**
	 * Delete one identity by id. This call does not delete the sessions of the identity. List them with
	 * `listSession` and delete each one with `deleteSession` before you call this method.
	 */
	deleteIdentity(id: string): Promise<void> {
		return this.#options.identity.delete(id);
	}

	/** Read one raw value in any key space. Returns `undefined` for a key that holds nothing or that has expired. */
	getKv(key: string): Promise<string | undefined> {
		return this.#options.kv.get(key);
	}

	/**
	 * List the keys under a prefix, in any key space. The adapter yields keys, not values. Without `offset`, start
	 * at the first key. Without `limit`, return every key that matches.
	 */
	listKv(prefix: string, offset?: number, limit?: number): Promise<string[]> {
		return this.#options.kv.list(prefix, offset, limit);
	}

	/**
	 * Write one raw value in any key space. The `ttl` unit is the choice of the adapter, and both callers in this
	 * library pass seconds. Without a `ttl` the value stays until a caller unsets it.
	 */
	setKv(key: string, value: string, ttl?: number): Promise<void> {
		return this.#options.kv.set(key, value, ttl);
	}

	/** Delete one key with the key value adapter, in any key space. */
	unsetKv(key: string): Promise<void> {
		return this.#options.kv.unset(key);
	}

	/**
	 * Create a session for an identity and write it to both session key spaces. The session gets a fresh `ses_`
	 * ksuid. `options.expireAt` also sets the time to live of both records, in seconds.
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
	 * Read one session by id from the `session/<id>` key space. A record that does not match the `AuthDanceSession`
	 * schema makes the call fail. Returns `undefined` when the key holds nothing.
	 */
	async getSession(id: string): Promise<AuthDanceSession | undefined> {
		const value = await this.getKv(`session/${id}`);
		if (!value) {
			return undefined;
		}
		return parse(AuthDanceSession, JSON.parse(value));
	}

	/**
	 * Delete one session from both the `session/<id>` and the `sessions/<identityId>/<id>` key spaces. An id that
	 * resolves to nothing does nothing.
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
	 * List every session of one identity from the `sessions/<identityId>/` key space. The method skips a key that
	 * the adapter resolves to `undefined`, because the index entry and the session expire on their own schedules.
	 */
	async listSession(identityId: string): Promise<AuthDanceSession[]> {
		const keys = await this.#options.kv.list(`sessions/${identityId}/`);
		const values = await Promise.all(keys.map((key) => this.getKv(key)));
		return values
			.filter((value): value is string => value !== undefined)
			.map((value) => parse(AuthDanceSession, JSON.parse(value)));
	}

	/**
	 * Count one hit of a rate limit bucket. `limit` is the number of hits the bucket allows inside one window. The
	 * `window` unit is the choice of the adapter, and both callers pass milliseconds. The result tells whether the
	 * adapter allows this hit, and how long the caller waits before a retry.
	 */
	consumeRateLimit(key: string, limit: number, window: number): Promise<AuthDanceRateLimiterResult> {
		return this.#options.rate_limiter.limit(key, limit, window);
	}
}
