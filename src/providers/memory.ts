import type { AuthDanceChannel, AuthDanceChannelContext } from "../channel.ts";
import type { AuthDanceIdentity, AuthDanceIdentityChannel, AuthDanceIdentityIdentification } from "../identity.ts";
import type { AuthDanceMessage } from "../message.ts";
import type { AuthDancePromptInput } from "../prompt.ts";
import {
	type AuthDanceIdentityProvider,
	type AuthDanceKvProvider,
	type AuthDanceRateLimiterProvider,
	type AuthDanceRateLimiterResult,
	KVKeyNotFoundError,
} from "../provider.ts";

export class MemoryIdentityProvider implements AuthDanceIdentityProvider, Disposable {
	#storage: Map<string, AuthDanceIdentity>;

	constructor(storage?: Iterable<[string, AuthDanceIdentity]>) {
		this.#storage = new Map(storage);
	}

	[Symbol.dispose](): void {
		this.#storage.clear();
	}

	list(offset?: number, limit?: number): Promise<AuthDanceIdentity[]> {
		const identities = Array.from(this.#storage.values());
		const results = identities
			.slice(offset, limit)
			.map((r) => structuredClone(r));
		return Promise.resolve(results);
	}

	get(id: string): Promise<AuthDanceIdentity | undefined> {
		const identity = this.#storage.get(id);
		return Promise.resolve(identity ? structuredClone(identity) : undefined);
	}

	getByIdentification(type: string, identification: string): Promise<AuthDanceIdentity | undefined> {
		for (const identity of this.#storage.values()) {
			const identityComponent = identity.components.find((c): c is AuthDanceIdentityIdentification =>
				c.kind === "identification" && c.component === type && c.identification === identification
			);
			if (identityComponent) {
				return Promise.resolve(structuredClone(identity));
			}
		}
		return Promise.resolve(undefined);
	}

	set(identity: AuthDanceIdentity): Promise<void> {
		this.#storage.set(identity.id, structuredClone(identity));
		return Promise.resolve();
	}

	delete(id: string): Promise<void> {
		this.#storage.delete(id);
		return Promise.resolve();
	}
}

export class MemoryKvProvider implements AuthDanceKvProvider, Disposable {
	#storage = new Map<string, { value: string; expiration?: number }>();

	[Symbol.dispose](): void {
		this.#storage.clear();
	}

	clearExpired(): void {
		const now = Date.now();
		for (const [key, data] of this.#storage) {
			if (data.expiration && data.expiration <= now) {
				this.#storage.delete(key);
			}
		}
	}

	get(key: string): Promise<string | undefined> {
		const item = this.#storage.get(key);
		if (!item || (item.expiration && item.expiration < new Date().getTime())) {
			return Promise.reject(new KVKeyNotFoundError());
		}
		return Promise.resolve(structuredClone(item.value));
	}

	list(prefix: string, limit?: number, offset?: number): Promise<string[]> {
		const keys = Array.from(this.#storage.keys()).filter((key) => key.startsWith(prefix));
		const slicedKeys = keys.slice(offset, limit);
		return Promise.resolve(slicedKeys);
	}

	set(key: string, value: string, ttl?: number): Promise<void> {
		const now = new Date().getTime();
		const expiration = ttl !== undefined ? now + ttl : undefined;
		const item = { value, expiration };
		this.#storage.set(key, structuredClone(item));
		return Promise.resolve();
	}

	unset(key: string): Promise<void> {
		this.#storage.delete(key);
		return Promise.resolve();
	}
}

export class MemoryRateLimiterProvider implements AuthDanceRateLimiterProvider, Disposable {
	#storage = new Map<string, { count: number; expiration: number }>();

	[Symbol.dispose](): void {
		this.#storage.clear();
	}

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

export class MemoryAuthDanceChannel implements AuthDanceChannel, Disposable {
	#type: string;
	messages: AuthDanceMessage[] = [];

	constructor(type: string) {
		this.#type = type;
	}

	[Symbol.dispose](): void {
		this.messages = [];
	}

	sendMessage(message: AuthDanceMessage): Promise<void> {
		this.messages.push(message);
		return Promise.resolve();
	}

	// deno-lint-ignore require-await
	async getPrompt(context: AuthDanceChannelContext): Promise<AuthDancePromptInput> {
		return {
			kind: "input",
			name: context.name,
			type: this.#type,
			sendable: true,
		};
	}

	// deno-lint-ignore require-await
	async getIdentityChannel(channel: string, value: unknown, confirmed: boolean = false): Promise<AuthDanceIdentityChannel> {
		return {
			kind: "channel",
			channel,
			confirmed,
			data: { sms: value },
		};
	}
}
