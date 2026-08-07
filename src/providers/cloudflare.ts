import { AuthDanceIdentity } from "../identity.ts";
import type {
	AuthDanceIdentityProvider,
	AuthDanceKvProvider,
	AuthDanceRateLimiterProvider,
	AuthDanceRateLimiterResult,
} from "../provider.ts";
import { DurableObject } from "cloudflare:workers"; // IDK why vscode keep complaining about this import, but it works fine in the build
import { parse } from "valibot";
import { AuthDanceStorage } from "../storage.ts";
import { DenoKvProvider } from "auth-dance/providers/deno";

interface KeyMetadata {
	count: number;
	expireAt: number;
}

export class CloudflareD1IdentityProvider implements AuthDanceIdentityProvider {
	#db: D1Database;

	constructor(db: D1Database) {
		this.#db = db;
	}

	async list(cursor?: string, limit?: number): Promise<AuthDanceIdentity[]> {
		const query = `SELECT "id", "data", "components" FROM identities ${cursor ? `WHERE id > ?` : ""} ORDER BY id ASC ${
			limit ? `LIMIT ?` : ""
		}`;
		const params: (string | number)[] = [];
		if (cursor) {
			params.push(cursor);
		}
		if (limit) {
			params.push(limit);
		}
		const result = await this.#db.prepare(query)
			.bind(...params)
			.all<{ id: string; data: string; components: string }>();

		return result.results.map((row) => {
			const identity = parse(AuthDanceIdentity, {
				id: row.id,
				data: row.data ? JSON.parse(row.data) : undefined,
				components: JSON.parse(row.components),
			});
			return identity;
		});
	}

	async get(id: string): Promise<AuthDanceIdentity | undefined> {
		const result = await this.#db.prepare(`SELECT "id", "data", "components" FROM identities WHERE id = ?`)
			.bind(id)
			.first<{ id: string; data: string; components: string }>();
		if (!result) {
			return undefined;
		}
		const identity = parse(AuthDanceIdentity, {
			id: result.id,
			data: result.data ? JSON.parse(result.data) : undefined,
			components: JSON.parse(result.components),
		});
		return identity;
	}

	async getByIdentification(component: string, identification: string): Promise<AuthDanceIdentity | undefined> {
		const result = await this.#db.prepare(
			`SELECT "id", "data", "components" FROM identities I INNER JOIN mv_identity_identification II ON I.identities.id = II.identity_id WHERE II.component = ? AND II.identification = ?`,
		)
			.bind(component, identification)
			.first<{ id: string; data: string; components: string }>();
		if (!result) {
			return undefined;
		}
		const identity = parse(AuthDanceIdentity, {
			id: result.id,
			data: result.data ? JSON.parse(result.data) : undefined,
			components: JSON.parse(result.components),
		});
		return identity;
	}

	async set(identity: AuthDanceIdentity): Promise<void> {
		const data = identity.data ? JSON.stringify(identity.data) : null;
		const components = JSON.stringify(identity.components);
		await this.#db.prepare(
			`INSERT INTO identities (id, data, components) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data, components = excluded.components`,
		)
			.bind(identity.id, data, components)
			.run();
	}

	async delete(id: string): Promise<void> {
		await this.#db.prepare(`DELETE FROM identities WHERE id = ?`)
			.bind(id)
			.run();
	}
}

export class CloudflareKvKvProvider implements AuthDanceKvProvider {
	#kv: KVNamespace;

	constructor(kv: KVNamespace) {
		this.#kv = kv;
	}

	async get(key: string): Promise<string | undefined> {
		const result = await this.#kv.get(key);
		return result ?? undefined;
	}

	async list(prefix: string, cursor?: number, limit?: number): Promise<string[]> {
		const result = await this.#kv.list({ prefix, cursor: cursor?.toString(), limit });
		return result.keys.map((key) => key.name);
	}

	async set(key: string, value: string, ttl?: number): Promise<void> {
		await this.#kv.put(key, value, { expirationTtl: ttl });
	}

	async unset(key: string): Promise<void> {
		await this.#kv.delete(key);
	}
}

export class CloudflareRateLimiterProvider implements AuthDanceRateLimiterProvider {
	#durableObjectNamespace: DurableObjectNamespace<RateLimiterDurableObject>;

	constructor(durableObjectNamespace: DurableObjectNamespace<RateLimiterDurableObject>) {
		this.#durableObjectNamespace = durableObjectNamespace;
	}

	limit(key: string, limit: number, window: number): Promise<AuthDanceRateLimiterResult> {
		const id = this.#durableObjectNamespace.idFromName(key);
		const stub = this.#durableObjectNamespace.get(id);
		return stub.limit(limit, window);
	}
}

/**
 * Durable Object that tracks the request count for a single rate-limit key
 * over a sliding window.
 *
 * State is loaded once at construction and kept in memory; writes back to
 * storage are deferred via `ctx.waitUntil` so that `limit` returns as soon as
 * the in-memory counter has been updated.
 */
export class RateLimiterDurableObject extends DurableObject {
	#meta: KeyMetadata;

	constructor(ctx: DurableObjectState, env: any) {
		super(ctx, env);
		this.#meta = { count: 0, expireAt: 0 };
		ctx.blockConcurrencyWhile(async () => {
			const stored = await ctx.storage.get<KeyMetadata>("meta");
			if (stored) {
				this.#meta = stored;
			}
		});
	}

	/**
	 * Increments the in-memory counter for this key's current window and
	 * reports whether the request is still within the allowed limit. The
	 * updated counter is flushed to storage asynchronously via
	 * `ctx.waitUntil`.
	 * @param limit Maximum number of requests allowed within `period`.
	 * @param period Sliding-window duration in milliseconds.
	 * @returns `true` if the request is allowed, `false` if the limit is exceeded.
	 */
	limit(limit: number, period: number): Promise<AuthDanceRateLimiterResult> {
		const now = Date.now();
		if (this.#meta.expireAt < now) {
			this.#meta = { count: 0, expireAt: now + period };
		}
		this.#meta.count++;
		const meta = this.#meta;
		this.ctx.waitUntil((async () => {
			await this.ctx.storage.put("meta", meta);
			await this.ctx.storage.setAlarm(meta.expireAt);
		})());
		const result = {
			allowed: meta.count <= limit,
			retryAfter: meta.count > limit ? Math.ceil((meta.expireAt - Date.now()) / 1000) : undefined,
		} satisfies AuthDanceRateLimiterResult;
		return Promise.resolve(result);
	}

	/**
	 * Alarm handler that purges the counter once the current window has
	 * elapsed, allowing the Durable Object to be evicted.
	 */
	override async alarm(): Promise<void> {
		if (this.#meta.expireAt <= Date.now()) {
			this.#meta = { count: 0, expireAt: 0 };
			await this.ctx.storage.deleteAll();
		}
	}
}

export function createAuthDanceCloudflareStorage(
	kv: KVNamespace,
	d1: D1Database,
	don: DurableObjectNamespace<RateLimiterDurableObject>,
): AuthDanceStorage {
	return new AuthDanceStorage({
		identity: new CloudflareD1IdentityProvider(d1),
		kv: new CloudflareKvKvProvider(kv),
		rate_limiter: new CloudflareRateLimiterProvider(don),
	});
}
