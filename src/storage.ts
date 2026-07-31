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

export interface AuthDanceStorageOptions {
	identity: AuthDanceIdentityProvider;
	kv: AuthDanceKvProvider;
	rate_limiter: AuthDanceRateLimiterProvider;
}

export class AuthDanceStorage {
	#options: AuthDanceStorageOptions;

	constructor(options: AuthDanceStorageOptions) {
		this.#options = options;
	}

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

	listIdentities(offset?: number, limit?: number): Promise<AuthDanceIdentity[]> {
		return this.#options.identity.list(offset, limit);
	}

	getIdentity(id: string): Promise<AuthDanceIdentity | undefined> {
		return this.#options.identity.get(id);
	}

	getIdentityByIdentification(type: string, identification: string): Promise<AuthDanceIdentity | undefined> {
		return this.#options.identity.getByIdentification(type, identification);
	}

	setIdentity(identity: AuthDanceIdentity): Promise<void> {
		return this.#options.identity.set(identity);
	}

	deleteIdentity(id: string): Promise<void> {
		return this.#options.identity.delete(id);
	}

	getKv(key: string): Promise<string | undefined> {
		return this.#options.kv.get(key);
	}

	listKv(prefix: string, limit?: number, offset?: number): Promise<string[]> {
		return this.#options.kv.list(prefix, limit, offset);
	}

	setKv(key: string, value: string, ttl?: number): Promise<void> {
		return this.#options.kv.set(key, value, ttl);
	}

	unsetKv(key: string): Promise<void> {
		return this.#options.kv.unset(key);
	}

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

	async getSession(id: string): Promise<AuthDanceSession | undefined> {
		const value = await this.getKv(`session/${id}`);
		if (!value) {
			return undefined;
		}
		return parse(AuthDanceSession, JSON.parse(value));
	}

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

	// `AuthDanceKvProvider.list` yields keys, not values, so every entry still has to be read. A key a provider
	// resolves to `undefined` is skipped rather than failing the whole listing: the index entry and the
	// session it points at expire on their own schedules, so a gap between the two is expected, not a fault.
	// A provider that rejects instead of resolving `undefined` — as `MemoryKvProvider` does — surfaces that
	// gap as an UNKNOWN, which is why the contract is `string | undefined`.
	async listSession(identityId: string): Promise<AuthDanceSession[]> {
		const keys = await this.#options.kv.list(`sessions/${identityId}/`);
		const values = await Promise.all(keys.map((key) => this.getKv(key)));
		return values
			.filter((value): value is string => value !== undefined)
			.map((value) => parse(AuthDanceSession, JSON.parse(value)));
	}

	consumeRateLimit(key: string, limit: number, window: number): Promise<AuthDanceRateLimiterResult> {
		return this.#options.rate_limiter.limit(key, limit, window);
	}
}
