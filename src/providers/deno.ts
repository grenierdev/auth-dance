import type { AuthDanceIdentity } from "../identity.ts";
import type { AuthDanceIdentityProvider, AuthDanceKvProvider } from "../provider.ts";
import { MemoryRateLimiterProvider } from "./memory.ts";
import { AuthDanceStorage } from "../storage.ts";

export class DenoIdentityProvider implements AuthDanceIdentityProvider {
	#kv: Deno.Kv;

	constructor(kv: Deno.Kv) {
		this.#kv = kv;
	}

	async list(cursor?: string, limit?: number): Promise<AuthDanceIdentity[]> {
		const entries = await Array.fromAsync(this.#kv.list<AuthDanceIdentity>({ prefix: ["identity"], start: ["identity", cursor ?? ""] }));
		if (limit !== undefined) {
			entries.splice(limit);
		}
		return entries.map((entry) => entry.value);
	}

	async get(id: string): Promise<AuthDanceIdentity | undefined> {
		const entry = await this.#kv.get<AuthDanceIdentity>(["identity", id]);
		return entry.value ?? undefined;
	}

	async getByIdentification(type: string, identification: string): Promise<AuthDanceIdentity | undefined> {
		const entry = await this.#kv.get<string>(["identification", type, identification]);
		if (!entry.value) {
			return undefined;
		}
		return this.get(entry.value);
	}

	// set: (identity: AuthDanceIdentity) => Promise<void>;
	async set(identity: AuthDanceIdentity): Promise<void> {
		const entry = await this.#kv.get<AuthDanceIdentity>(["identity", identity.id]);
		let atomic = this.#kv.atomic();
		if (entry.value) {
			atomic = atomic.check({ key: ["identity", identity.id], versionstamp: entry.versionstamp });
			for (const component of entry.value.components) {
				if (component.kind === "identification") {
					atomic = atomic.delete(["identification", component.component, component.identification]);
				}
			}
		}
		atomic = atomic.set(["identity", identity.id], identity);
		for (const component of identity.components) {
			if (component.kind === "identification") {
				atomic = atomic.set(["identification", component.component, component.identification], identity.id);
			}
		}
		await atomic.commit();
	}

	async delete(id: string): Promise<void> {
		const entry = await this.#kv.get<AuthDanceIdentity>(["identity", id]);
		if (!entry.value) {
			return;
		}
		const identity = entry.value;
		let atomic = this.#kv.atomic().delete(["identity", id]);
		for (const component of identity.components) {
			if (component.kind === "identification") {
				atomic = atomic.delete(["identification", component.component, component.identification]);
			}
		}
		await atomic.commit();
	}
}

export class DenoKvProvider implements AuthDanceKvProvider {
	#kv: Deno.Kv;

	constructor(kv: Deno.Kv) {
		this.#kv = kv;
	}

	async get(key: string): Promise<string | undefined> {
		const entry = await this.#kv.get<string>(["kv", key]);
		return entry.value ?? undefined;
	}

	async list(prefix: string, cursor?: number, limit?: number): Promise<string[]> {
		const entries = await Array.fromAsync(this.#kv.list<string>({ prefix: ["kv"], start: ["kv", cursor ?? prefix ?? ""] }));
		if (limit !== undefined) {
			entries.splice(limit);
		}
		return entries.map((entry) => entry.key.at(-1)!.toString());
	}

	async set(key: string, value: string, ttl?: number): Promise<void> {
		await this.#kv.set(["kv", key], value, {
			expireIn: ttl ? ttl * 1000 : undefined,
		});
	}

	async unset(key: string): Promise<void> {
		await this.#kv.delete(["kv", key]);
	}
}

export function createAuthDanceDenoStorage(kv: Deno.Kv): AuthDanceStorage {
	return new AuthDanceStorage({
		identity: new DenoIdentityProvider(kv),
		kv: new DenoKvProvider(kv),
		rate_limiter: new MemoryRateLimiterProvider(),
	});
}
