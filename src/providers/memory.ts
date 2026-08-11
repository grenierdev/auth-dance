import type { AuthDanceChannel, AuthDanceChannelContext } from "../channel.ts";
import { ComponentAlreadyEnrolledError, IdentificationTakenError } from "../error.ts";
import type { AuthDanceIdentity, AuthDanceIdentityChannel, AuthDanceIdentityIdentification } from "../identity.ts";
import type { AuthDanceMessage } from "../message.ts";
import type { AuthDancePromptInput } from "../prompt.ts";
import type {
	AuthDanceIdentityProvider,
	AuthDanceKvProvider,
	AuthDanceRateLimiterProvider,
	AuthDanceRateLimiterResult,
} from "../provider.ts";
import { AuthDanceStorage } from "../storage.ts";

/**
 * An `AuthDanceIdentityProvider` that holds every identity in a `Map`.
 *
 * The map lives in the process memory. A process restart erases every identity. Use this provider for
 * tests and local examples, not for production.
 *
 * `set` stores a clone and every read returns a clone. A caller therefore cannot change stored data
 * through a reference it still holds.
 */
export class MemoryIdentityProvider implements AuthDanceIdentityProvider, Disposable {
	#storage: Map<string, AuthDanceIdentity>;
	#identificationIndex: Map<string, string>;

	/**
	 * Creates a provider with an empty map, or with the identities that `storage` holds.
	 * @param storage Identities to preload, as `[id, identity]` pairs. The provider copies the pairs into
	 * its own map. It does not clone the identity objects themselves. This seed lets a test start from a
	 * known set of identities.
	 */
	constructor(storage?: Iterable<[string, AuthDanceIdentity]>) {
		this.#storage = new Map(storage);
		this.#identificationIndex = new Map(
			this.#storage.values().flatMap((identity) =>
				identity.components
					.filter((c) => c.kind === "identification")
					.map((c) => [`${c.component}:${c.identification}`, identity.id] as const)
			),
		);
	}

	/** Empties the map. A `using` declaration calls this at the end of the block. */
	[Symbol.dispose](): void {
		this.#storage.clear();
	}

	/**
	 * Lists the stored identities in insertion order.
	 *
	 * @param cursor The id of the first identity of the page. Without it, the page starts at the first
	 * identity. An id the map does not hold gives an empty page.
	 * @param limit The number of identities to return at most. Without it, the page runs to the last identity.
	 * @returns A clone of each identity in the range.
	 */
	list(cursor?: string, limit?: number): Promise<AuthDanceIdentity[]> {
		const identities = Array.from(this.#storage.values());
		const cursorIndex = cursor ? identities.findIndex((i) => i.id === cursor) : 0;
		if (cursorIndex === -1) {
			return Promise.resolve([]);
		}
		const results = identities
			.slice(cursorIndex, limit === undefined ? undefined : cursorIndex + limit)
			.map((r) => structuredClone(r));
		return Promise.resolve(results);
	}

	/**
	 * Reads one identity by id.
	 * @returns A clone of the stored identity, or `undefined` when the map holds no such id.
	 */
	get(id: string): Promise<AuthDanceIdentity | undefined> {
		const identity = this.#storage.get(id);
		return Promise.resolve(identity ? structuredClone(identity) : undefined);
	}

	/**
	 * Finds the identity that carries an identification component with this value.
	 *
	 * The provider reads the stored identities one by one until a component matches both `type` and
	 * `identification`. The match ignores the `confirmed` flag of the component.
	 * @param component The component name of the identification, for example `email`.
	 * @param identification The resolved value, for example the email address itself.
	 * @returns A clone of the first identity that matches, or `undefined`.
	 */
	getByIdentification(component: string, identification: string): Promise<AuthDanceIdentity | undefined> {
		const identityId = this.#identificationIndex.get(`${component}:${identification}`);
		if (identityId) {
			const identity = this.#storage.get(identityId);
			if (identity) {
				return Promise.resolve(structuredClone(identity));
			}
		}
		return Promise.resolve(undefined);
	}

	/** Stores a clone of the identity under its own `id`. The provider replaces an earlier identity with the same id. */
	set(identity: AuthDanceIdentity): Promise<void> {
		if (
			identity.components.some((c, i) => identity.components.findIndex((c2) => c2.kind === c.kind && c2.component === c.component) !== i)
		) {
			throw new ComponentAlreadyEnrolledError();
		}
		const identifications = identity.components.filter((c) => c.kind === "identification");
		for (const identification of identifications) {
			const identityId = this.#identificationIndex.get(`${identification.component}:${identification.identification}`);
			if (identityId && identityId !== identity.id) {
				throw new IdentificationTakenError();
			}
		}
		this.#storage.set(identity.id, structuredClone(identity));
		for (const identification of identifications) {
			this.#identificationIndex.set(`${identification.component}:${identification.identification}`, identity.id);
		}
		return Promise.resolve();
	}

	/** Removes the identity with this id. An unknown id is not an error. */
	delete(id: string): Promise<void> {
		const identity = this.#storage.get(id);
		if (identity) {
			const identifications = identity.components.filter((c): c is AuthDanceIdentityIdentification => c.kind === "identification");
			for (const identification of identifications) {
				this.#identificationIndex.delete(`${identification.component}:${identification.identification}`);
			}
		}
		this.#storage.delete(id);
		return Promise.resolve();
	}
}

// One rule for the deadline of an entry: the entry dies at the deadline. `get`, `list` and `clearExpired` all
// read it through this function, so the three never disagree about one entry.
function expired(item: { expiration?: number }, now: number): boolean {
	return item.expiration !== undefined && item.expiration <= now;
}

/**
 * An `AuthDanceKvProvider` that holds every key in a `Map`.
 *
 * The map lives in the process memory. A process restart erases every entry. Use this provider for tests
 * and local examples, not for production.
 *
 * The provider runs no timer. An expired entry stays in the map until a read of its own key, `clearExpired`,
 * `unset` or dispose removes it. `get` and `list` both ignore an expired entry, so the map never reports one.
 */
export class MemoryKvProvider implements AuthDanceKvProvider, Disposable {
	#storage = new Map<string, { value: string; expiration?: number }>();

	/** Empties the map. A `using` declaration calls this at the end of the block. */
	[Symbol.dispose](): void {
		this.#storage.clear();
	}

	/**
	 * Removes every entry whose expiration already passed.
	 *
	 * Nothing in this library calls this method, and no test calls it either. It is a manual hook for a
	 * caller that wants to remove dead entries, because the provider runs no timer of its own.
	 */
	clearExpired(): void {
		const now = Date.now();
		for (const [key, data] of this.#storage) {
			if (expired(data, now)) {
				this.#storage.delete(key);
			}
		}
	}

	/**
	 * Reads the value of one key. A read of an expired key also removes the entry from the map.
	 * @returns The stored value, or `undefined` when the map holds no such key, or when the entry expired.
	 */
	get(key: string): Promise<string | undefined> {
		const item = this.#storage.get(key);
		if (!item) {
			return Promise.resolve(undefined);
		}
		if (expired(item, Date.now())) {
			this.#storage.delete(key);
			return Promise.resolve(undefined);
		}
		return Promise.resolve(structuredClone(item.value));
	}

	/**
	 * Lists the keys that start with `prefix`, in insertion order. The values stay in the map.
	 *
	 * The listing drops an expired key, because `get` resolves `undefined` for one. An entry that expires
	 * between this call and that read is still normal: the two are two calls.
	 * @param offset The number of keys to skip. Without it, the page starts at the first key.
	 * @param limit The number of keys to return at most. Without it, the page runs to the last key.
	 */
	list(prefix: string, offset?: number, limit?: number): Promise<string[]> {
		const now = Date.now();
		const keys = Array.from(this.#storage.entries())
			.filter(([key, item]) => key.startsWith(prefix) && !expired(item, now))
			.map(([key]) => key);
		const start = offset ?? 0;
		return Promise.resolve(keys.slice(start, limit === undefined ? undefined : start + limit));
	}

	/**
	 * Writes a value under a key, and replaces an earlier value for the same key.
	 * @param ttl Lifetime of the entry in seconds, as the `AuthDanceKvProvider` contract states. The provider
	 * keeps a millisecond clock, so it multiplies the count before it stores the deadline. Omit `ttl` to keep
	 * the entry until `unset` or until dispose.
	 */
	set(key: string, value: string, ttl?: number): Promise<void> {
		const now = new Date().getTime();
		const expiration = ttl !== undefined ? now + ttl * 1000 : undefined;
		const item = { value, expiration };
		this.#storage.set(key, structuredClone(item));
		return Promise.resolve();
	}

	/** Removes the entry for this key. An unknown key is not an error. */
	unset(key: string): Promise<void> {
		this.#storage.delete(key);
		return Promise.resolve();
	}
}

/**
 * An `AuthDanceRateLimiterProvider` that counts the hits of each bucket in a `Map`.
 *
 * The map lives in the process memory. A process restart erases every counter. Use this provider for
 * tests and local examples, not for production. Each process keeps its own counters, so two processes
 * never share one bucket.
 */
export class MemoryRateLimiterProvider implements AuthDanceRateLimiterProvider, Disposable {
	#storage = new Map<string, { count: number; expiration: number }>();

	/** Empties the map, and with it every counter. A `using` declaration calls this at the end of the block. */
	[Symbol.dispose](): void {
		this.#storage.clear();
	}

	/**
	 * Counts one hit against the bucket of `key` and reports whether the caller may continue.
	 *
	 * The first hit opens a fixed window and sets the counter to 1. A later hit inside the window adds 1 to
	 * the counter while the counter is below `limit`. The first hit after the expiration opens a new window.
	 * @param limit Number of hits that one window allows.
	 * @param window Length of the window in milliseconds. The provider adds this number to the current
	 * clock time. The two callers in this library multiply the configured seconds by 1000 before the call.
	 * @returns `allowed: false` once the bucket is full. For a `limit` of 1 or more the counter stops at
	 * `limit`, so `retryAfter` is always `undefined`. For a `limit` of 0 or less the first hit already sets
	 * the counter above `limit`. A later hit in the same window then carries `retryAfter` in seconds.
	 */
	limit(key: string, limit: number, window: number): Promise<AuthDanceRateLimiterResult> {
		const now = Date.now();
		const entry = this.#storage.get(key);

		if (!entry || entry.expiration <= now) {
			this.#storage.set(key, { count: 1, expiration: now + window });
			return Promise.resolve({ allowed: true, retryAfter: undefined });
		}

		if (entry.count < limit) {
			entry.count += 1;
			return Promise.resolve({ allowed: true, retryAfter: undefined });
		}

		return Promise.resolve({
			allowed: false,
			retryAfter: entry.count > limit ? Math.ceil((entry.expiration - Date.now()) / 1000) : undefined,
		});
	}
}

/**
 * An `AuthDanceChannel` that keeps each message in an array instead of delivering it.
 *
 * The array lives in the process memory. A process restart erases every message. Use this channel for
 * tests and local examples, not for production. A test reads `messages` to get the code that a component
 * sent. 🥔
 *
 * @example
 * ```ts
 * using channel = new MemoryAuthDanceChannel("email");
 * // run a flow that sends a code
 * const code = channel.messages[0].content["text/x-code"];
 * ```
 */
export class MemoryAuthDanceChannel implements AuthDanceChannel, Disposable {
	#type: string;
	/** Each message that `sendMessage` received, in call order. `Symbol.dispose` replaces it with an empty array. */
	messages: AuthDanceMessage[] = [];

	/**
	 * Creates a channel with an empty `messages` array.
	 * @param type The prompt input type that `getPrompt` reports, for example `email` or `phone`. The channel
	 * keeps this value and writes it into every prompt that `getPrompt` builds.
	 */
	constructor(type: string) {
		this.#type = type;
	}

	/** Replaces `messages` with an empty array. A `using` declaration calls this at the end of the block. */
	[Symbol.dispose](): void {
		this.messages = [];
	}

	/** Appends the message to `messages`. The channel delivers nothing. */
	sendMessage(message: AuthDanceMessage): Promise<void> {
		this.messages.push(message);
		return Promise.resolve();
	}

	/**
	 * Builds the prompt that the client renders for this channel.
	 *
	 * The prompt takes its name from `context` and its type from the constructor. It is always `sendable`,
	 * so a client may request a message from the channel.
	 */
	// deno-lint-ignore require-await
	async getPrompt(context: AuthDanceChannelContext): Promise<AuthDancePromptInput> {
		return {
			kind: "input",
			name: context.name,
			type: this.#type,
			sendable: true,
		};
	}

	/**
	 * Builds the channel component that a flow then stores on the identity.
	 *
	 * The channel writes `value` under the `sms` key of `data` for every channel name, because this test
	 * double keeps one shape for all of them.
	 * @param channel The channel name to record on the identity.
	 * @param value The recipient, for example an email address or a phone number.
	 * @param confirmed Whether control of the recipient is already proven. The default is `false`.
	 */
	// deno-lint-ignore require-await
	async getIdentityChannel(channel: string, value: unknown, confirmed: boolean = false): Promise<AuthDanceIdentityChannel> {
		return {
			kind: "channel",
			component: channel,
			confirmed,
			data: { sms: value },
		};
	}
}

export function createAuthDanceMemoryStorage(): AuthDanceStorage {
	return new AuthDanceStorage({
		identity: new MemoryIdentityProvider(),
		kv: new MemoryKvProvider(),
		rate_limiter: new MemoryRateLimiterProvider(),
	});
}
