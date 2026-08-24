import { IdentificationTakenError } from "../error.ts";
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

	async set(identity: AuthDanceIdentity): Promise<void> {
		const entry = await this.#kv.get<AuthDanceIdentity>(["identity", identity.id]);
		const keys: Deno.KvKey[] = [];
		for (const component of [...entry.value?.components ?? [], ...identity.components]) {
			if (component.kind === "identification") {
				keys.push(["identification", component.component, component.identification]);
			}
		}
		// `getMany` reads at most 10 keys per call.
		const indexEntries: Deno.KvEntryMaybe<string>[] = [];
		for (let i = 0; i < keys.length; i += 10) {
			indexEntries.push(...await this.#kv.getMany<string[]>(keys.slice(i, i + 10)));
		}
		let atomic = this.#kv.atomic();
		for (const indexEntry of indexEntries) {
			if (indexEntry.value !== null && indexEntry.value !== identity.id) {
				throw new IdentificationTakenError();
			}
			atomic = atomic.check({ key: indexEntry.key, versionstamp: indexEntry.versionstamp });
		}
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
		// A failed check means another writer took one of these keys after the read.
		const result = await atomic.commit();
		if (!result.ok) {
			throw new IdentificationTakenError();
		}
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

	async list(prefix: string, offset?: number, limit?: number): Promise<string[]> {
		const entries = await Array.fromAsync(this.#kv.list<string>({ prefix: ["kv"], start: ["kv", prefix] }));
		const keys = entries.map((entry) => entry.key.at(-1)!.toString()).filter((key) => key.startsWith(prefix));
		const start = offset ?? 0;
		return keys.slice(start, limit === undefined ? undefined : start + limit);
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
