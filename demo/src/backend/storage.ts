import {
	type AuthDanceIdentity,
	type AuthDanceIdentityProvider,
	type AuthDanceKvProvider,
	ComponentAlreadyEnrolledError,
	IdentificationTakenError,
} from "auth-dance";
import type { AuthDanceOauth2Client, AuthDanceOauth2ClientProvider } from "auth-dance/oauth2";
import { type DBSchema, type IDBPDatabase, openDB } from "idb";
import type { DemoMail } from "./mailbox.ts";

/**
 * The database of the demo. A service worker stops when it sits idle, and the memory providers would forget everything
 * with it, so each record the library keeps lives in IndexedDB instead: it survives the worker, and stays in this
 * browser.
 */
interface DemoSchema extends DBSchema {
	identities: { key: string; value: AuthDanceIdentity };
	/** `<component>:<identification>` to the id of the identity that claims it. */
	identifications: { key: string; value: string };
	kv: { key: string; value: { value: string; expiration?: number } };
	clients: { key: string; value: AuthDanceOauth2Client };
	/** The secrets, the signing key and the ids of the demo clients, drawn on the first start. */
	meta: { key: string; value: unknown };
	mail: { key: string; value: DemoMail };
}

export type DemoDatabase = IDBPDatabase<DemoSchema>;

export function openDemoDatabase(): Promise<DemoDatabase> {
	return openDB<DemoSchema>("auth-dance-demo", 1, {
		upgrade(db) {
			db.createObjectStore("identities", { keyPath: "id" });
			db.createObjectStore("identifications");
			db.createObjectStore("kv");
			db.createObjectStore("clients", { keyPath: "client_id" });
			db.createObjectStore("meta");
			db.createObjectStore("mail", { keyPath: "id" });
		},
	});
}

/** Reads one value of `meta`, or draws it with `create` and keeps it. */
export async function remember<T>(db: DemoDatabase, key: string, create: () => T | Promise<T>): Promise<T> {
	const stored = (await db.get("meta", key)) as T | undefined;
	if (stored !== undefined) {
		return stored;
	}
	const value = await create();
	await db.put("meta", value, key);
	return value;
}

/** The keys that start with `prefix`, as an IndexedDB range. */
function prefixRange(prefix: string): IDBKeyRange {
	return IDBKeyRange.bound(prefix, `${prefix}￿`);
}

/** The rules of `MemoryIdentityProvider`, in IndexedDB. The ids are ksuids, so the key order is the creation order. */
export class IndexedDbIdentityProvider implements AuthDanceIdentityProvider {
	#db: DemoDatabase;

	constructor(db: DemoDatabase) {
		this.#db = db;
	}

	async list(cursor?: string, limit?: number): Promise<AuthDanceIdentity[]> {
		if (cursor !== undefined && (await this.#db.getKey("identities", cursor)) === undefined) {
			return [];
		}
		return this.#db.getAll("identities", cursor === undefined ? undefined : IDBKeyRange.lowerBound(cursor), limit);
	}

	get(id: string): Promise<AuthDanceIdentity | undefined> {
		return this.#db.get("identities", id);
	}

	async getByIdentification(component: string, identification: string): Promise<AuthDanceIdentity | undefined> {
		const id = await this.#db.get("identifications", `${component}:${identification}`);
		return id === undefined ? undefined : this.#db.get("identities", id);
	}

	async set(identity: AuthDanceIdentity): Promise<void> {
		if (
			identity.components.some((c, i) => identity.components.findIndex((c2) => c2.kind === c.kind && c2.component === c.component) !== i)
		) {
			throw new ComponentAlreadyEnrolledError();
		}
		const claimed = identity.components.flatMap((c) => (c.kind === "identification" ? [`${c.component}:${c.identification}`] : []));
		// One transaction checks the claims and writes them, so two dances cannot take the same address.
		const tx = this.#db.transaction(["identities", "identifications"], "readwrite");
		const owners = await Promise.all(claimed.map((key) => tx.objectStore("identifications").get(key)));
		if (owners.some((owner) => owner !== undefined && owner !== identity.id)) {
			tx.abort();
			await tx.done.catch(() => {});
			throw new IdentificationTakenError();
		}
		const previous = await tx.objectStore("identities").get(identity.id);
		for (const c of previous?.components ?? []) {
			if (c.kind === "identification" && !claimed.includes(`${c.component}:${c.identification}`)) {
				await tx.objectStore("identifications").delete(`${c.component}:${c.identification}`);
			}
		}
		await tx.objectStore("identities").put(identity);
		await Promise.all(claimed.map((key) => tx.objectStore("identifications").put(identity.id, key)));
		await tx.done;
	}

	async delete(id: string): Promise<void> {
		const tx = this.#db.transaction(["identities", "identifications"], "readwrite");
		const identity = await tx.objectStore("identities").get(id);
		for (const c of identity?.components ?? []) {
			if (c.kind === "identification") {
				await tx.objectStore("identifications").delete(`${c.component}:${c.identification}`);
			}
		}
		await tx.objectStore("identities").delete(id);
		await tx.done;
	}
}

/** The rules of `MemoryKvProvider`, in IndexedDB. An expired key reads as missing until a read removes it. */
export class IndexedDbKvProvider implements AuthDanceKvProvider {
	#db: DemoDatabase;

	constructor(db: DemoDatabase) {
		this.#db = db;
	}

	async get(key: string): Promise<string | undefined> {
		const item = await this.#db.get("kv", key);
		if (item?.expiration !== undefined && item.expiration <= Date.now()) {
			await this.#db.delete("kv", key);
			return undefined;
		}
		return item?.value;
	}

	async list(prefix: string, offset?: number, limit?: number): Promise<string[]> {
		const now = Date.now();
		const keys: string[] = [];
		let cursor = await this.#db.transaction("kv").store.openCursor(prefixRange(prefix));
		while (cursor) {
			if (cursor.value.expiration === undefined || cursor.value.expiration > now) {
				keys.push(cursor.key);
			}
			cursor = await cursor.continue();
		}
		const start = offset ?? 0;
		return keys.slice(start, limit === undefined ? undefined : start + limit);
	}

	async set(key: string, value: string, ttl?: number): Promise<void> {
		await this.#db.put("kv", { value, expiration: ttl === undefined ? undefined : Date.now() + ttl * 1000 }, key);
	}

	async unset(key: string): Promise<void> {
		await this.#db.delete("kv", key);
	}
}

/** The rules of `MemoryOauth2ClientProvider`, in IndexedDB, which already orders the clients by `client_id`. */
export class IndexedDbOauth2ClientProvider implements AuthDanceOauth2ClientProvider {
	#db: DemoDatabase;

	constructor(db: DemoDatabase) {
		this.#db = db;
	}

	get(clientId: string): Promise<AuthDanceOauth2Client | undefined> {
		return this.#db.get("clients", clientId);
	}

	list(cursor?: string, limit?: number): Promise<AuthDanceOauth2Client[]> {
		return this.#db.getAll("clients", cursor === undefined ? undefined : IDBKeyRange.lowerBound(cursor), limit);
	}

	async set(client: AuthDanceOauth2Client): Promise<void> {
		await this.#db.put("clients", client);
	}

	async delete(clientId: string): Promise<void> {
		await this.#db.delete("clients", clientId);
	}
}
