import { AuthDanceIdentity, type AuthDanceIdentityChannel } from "../identity.ts";
import type {
	AuthDanceIdentityProvider,
	AuthDanceKvProvider,
	AuthDanceRateLimiterProvider,
	AuthDanceRateLimiterResult,
} from "../provider.ts";
import { DurableObject } from "cloudflare:workers";
import { parse } from "valibot";
import { AuthDanceStorage } from "../storage.ts";
import type { AuthDanceChannel, AuthDanceChannelContext } from "../channel.ts";
import type { AuthDanceMessage } from "../message.ts";
import type { AuthDancePromptInput } from "../prompt.ts";

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
		// deno-fmt-ignore
		const query = `SELECT "id", "data", "components" FROM identity ${cursor ? `WHERE id > ?` : ""} ORDER BY id ASC ${limit ? `LIMIT ?` : ""}`;
		const params: (string | number)[] = [];
		if (cursor) {
			params.push(cursor);
		}
		if (limit) {
			params.push(limit);
		}
		const result = await this.#db
			.prepare(query)
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
		// deno-fmt-ignore
		const result = await this.#db
			.prepare(`SELECT "id", "data", "components" FROM identity WHERE id = ?`)
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

	async getByIdentification(
		component: string,
		identification: string,
	): Promise<AuthDanceIdentity | undefined> {
		// deno-fmt-ignore
		const result = await this.#db
			.prepare(`SELECT "id", "data", "components" FROM identity I INNER JOIN mv_identity_identification II ON I.id = II.identity_id WHERE II.component = ? AND II.identification = ?`)
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
		// deno-fmt-ignore
		await this.#db
			.prepare(`INSERT INTO identity (id, data, components) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data, components = excluded.components`)
			.bind(identity.id, data, components)
			.run();
	}

	async delete(id: string): Promise<void> {
		await this.#db.prepare(`DELETE FROM identity WHERE id = ?`)
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

	async list(
		prefix: string,
		offset?: number,
		limit?: number,
	): Promise<string[]> {
		// KV takes an opaque cursor, not a count of keys to skip. The skip happens here, so `limit` includes the skipped keys.
		const start = offset ?? 0;
		const result = await this.#kv.list({
			prefix,
			limit: limit === undefined ? undefined : start + limit,
		});
		return result.keys.map((key) => key.name).slice(start);
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

	constructor(
		durableObjectNamespace: DurableObjectNamespace<
			RateLimiterDurableObject
		>,
	) {
		this.#durableObjectNamespace = durableObjectNamespace;
	}

	limit(
		key: string,
		limit: number,
		window: number,
	): Promise<AuthDanceRateLimiterResult> {
		const id = this.#durableObjectNamespace.idFromName(key);
		const stub = this.#durableObjectNamespace.get(id);
		return stub.limit(limit, window);
	}
}

/**
 * Durable Object that counts the hits of one rate-limit key over a window. The constructor loads the state once and
 * keeps it in memory. Writes back to storage go through `ctx.waitUntil`.
 */
export class RateLimiterDurableObject extends DurableObject {
	#meta: KeyMetadata;

	// deno-lint-ignore no-explicit-any
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
	 * Counts one hit against the current window and reports whether the caller may continue.
	 * @param limit Number of hits that one window allows.
	 * @param period Length of the window in milliseconds.
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

	/** Alarm handler that removes the counter after the current window ends. */
	override async alarm(): Promise<void> {
		if (this.#meta.expireAt <= Date.now()) {
			this.#meta = { count: 0, expireAt: 0 };
			await this.ctx.storage.deleteAll();
		}
	}
}

export class CloudflareSendMailAuthDanceChannel implements AuthDanceChannel {
	#sendMail: SendEmail;
	#options: Pick<EmailReplyMessageBuilder, "from" | "replyTo">;

	constructor(
		sendMail: SendEmail,
		options: Pick<EmailReplyMessageBuilder, "from" | "replyTo">,
	) {
		this.#sendMail = sendMail;
		this.#options = options;
	}

	async sendMessage(message: AuthDanceMessage): Promise<void> {
		const email = message.recipient.data?.email;
		if (!email || typeof email !== "string") {
			throw new Error("Recipient does not have an email address");
		}
		const _result = await this.#sendMail.send({
			from: this.#options.from,
			to: email,
			subject: message.subject,
			replyTo: this.#options.replyTo,
			html: message.content["text/html"]?.toString() ?? undefined,
			text: message.content["text/plain"]?.toString() ?? undefined,
		});
		return Promise.resolve();
	}

	// deno-lint-ignore require-await
	async getPrompt(
		context: AuthDanceChannelContext,
	): Promise<AuthDancePromptInput> {
		return {
			kind: "input",
			name: context.name,
			type: "email",
			sendable: true,
		};
	}

	// deno-lint-ignore require-await
	async getIdentityChannel(
		channel: string,
		value: unknown,
		confirmed: boolean = false,
	): Promise<AuthDanceIdentityChannel> {
		return {
			kind: "channel",
			component: channel,
			confirmed,
			data: { email: value },
		};
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
