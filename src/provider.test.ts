import { deepEqual, ok } from "node:assert";
import { beforeEach, it } from "vitest";
import { testOauth2Client } from "./fixtures.test.ts";
import type { AuthDanceIdentity } from "./identity.ts";
import type { AuthDanceOauth2ClientProvider } from "./oauth2/storage.ts";
import type { AuthDanceIdentityProvider, AuthDanceKvProvider } from "./provider.ts";

export function testIdentityProvider(factory: () => AuthDanceIdentityProvider | Promise<AuthDanceIdentityProvider>): void {
	let provider: AuthDanceIdentityProvider;
	beforeEach(async () => {
		provider = await factory();
	});

	it("should set and get an identity", async () => {
		const identity = {
			id: "id_123",
			data: { name: "Alice" },
			components: [],
		} satisfies AuthDanceIdentity;
		await provider.set(identity);
		const retrieved = await provider.get("id_123");
		ok(retrieved);
		deepEqual(retrieved.id, identity.id);
		deepEqual(retrieved.data, identity.data);
	});

	it("should return undefined for a non-existent identity", async () => {
		const retrieved = await provider.get("non_existent_id");
		deepEqual(retrieved, undefined);
	});

	it("should delete an identity", async () => {
		const identity = {
			id: "id_456",
			data: { name: "Bob" },
			components: [],
		} satisfies AuthDanceIdentity;
		await provider.set(identity);
		await provider.delete("id_456");
		const retrieved = await provider.get("id_456");
		deepEqual(retrieved, undefined);
	});

	it("should return undefined for getByIdentification when no identity matches", async () => {
		const retrieved = await provider.getByIdentification("email", "nonexistent@example.com");
		deepEqual(retrieved, undefined);
	});

	it("should return the correct identity for getByIdentification when an identity matches", async () => {
		const identity = {
			id: "id_789",
			data: { name: "Charlie" },
			components: [{ kind: "identification", component: "email", identification: "charlie@example.com", confirmed: true }],
		} satisfies AuthDanceIdentity;
		await provider.set(identity);
		const retrieved = await provider.getByIdentification("email", "charlie@example.com");
		ok(retrieved);
		deepEqual(retrieved.id, identity.id);
		deepEqual(retrieved.data, identity.data);
	});

	// `limit` is a count of identities, not the end index of a range.
	it("should return at most limit identities from the cursor", async () => {
		for (const id of ["id_a1", "id_a2", "id_a3"]) {
			await provider.set({ id, data: {}, components: [] } satisfies AuthDanceIdentity);
		}
		const page = await provider.list("id_a2", 1);
		deepEqual(
			page.map((identity) => identity.id),
			["id_a2"],
		);
		const rest = await provider.list("id_a2");
		deepEqual(
			rest.map((identity) => identity.id),
			["id_a2", "id_a3"],
		);
	});

	it("should return undefined for getByIdentification when the component type does not match", async () => {
		const identity = {
			id: "id_101",
			data: { name: "David" },
			components: [{ kind: "identification", component: "email", identification: "david@example.com", confirmed: true }],
		} satisfies AuthDanceIdentity;
		await provider.set(identity);
		const retrieved = await provider.getByIdentification("phone", "123-456-7890");
		deepEqual(retrieved, undefined);
	});
}

export function testKvProvider(factory: () => AuthDanceKvProvider | Promise<AuthDanceKvProvider>): void {
	let provider: AuthDanceKvProvider;
	beforeEach(async () => {
		provider = await factory();
	});

	it("should set and get a key-value pair", async () => {
		await provider.set("test_key", "test_value");
		const value = await provider.get("test_key");
		deepEqual(value, "test_value");
	});

	it("should return undefined for a non-existent key", async () => {
		const value = await provider.get("non_existent_key");
		deepEqual(value, undefined);
	});

	it("should delete a key-value pair", async () => {
		await provider.set("delete_key", "delete_value");
		await provider.unset("delete_key");
		const value = await provider.get("delete_key");
		deepEqual(value, undefined);
	});

	it("should list keys with a given prefix", async () => {
		await provider.set("prefix_key1", "value1");
		await provider.set("prefix_key2", "value2");
		await provider.set("other_key", "value3");

		const keys = await provider.list("prefix_");
		ok(keys.includes("prefix_key1"));
		ok(keys.includes("prefix_key2"));
		ok(!keys.includes("other_key"));
	});

	// `offset` counts the keys to skip. `limit` counts the keys to return.
	it("should return at most limit keys from the offset", async () => {
		await provider.set("page_1", "a");
		await provider.set("page_2", "b");
		await provider.set("page_3", "c");

		deepEqual(await provider.list("page_", 0, 2), ["page_1", "page_2"]);
		deepEqual(await provider.list("page_", 1, 1), ["page_2"]);
		deepEqual(await provider.list("page_", 1), ["page_2", "page_3"]);
	});
}

export function testOauth2ClientProvider(factory: () => AuthDanceOauth2ClientProvider | Promise<AuthDanceOauth2ClientProvider>): void {
	let provider: AuthDanceOauth2ClientProvider;
	beforeEach(async () => {
		provider = await factory();
	});

	it("should set and get a client", async () => {
		const client = testOauth2Client({ client_name: "App", localized: { "client_name#fr-CA": "Appli" }, skip_consent: true });
		await provider.set(client);
		deepEqual(await provider.get(client.client_id), client);
	});

	it("should return undefined for a non-existent client", async () => {
		deepEqual(await provider.get("cli_missing"), undefined);
	});

	it("should replace a client with the same id", async () => {
		await provider.set(testOauth2Client({ scope: "profile" }));
		await provider.set(testOauth2Client({ scope: "email" }));
		deepEqual((await provider.get("cli_test"))?.scope, "email");
	});

	it("should delete a client", async () => {
		await provider.set(testOauth2Client());
		await provider.delete("cli_test");
		deepEqual(await provider.get("cli_test"), undefined);
		// An unknown id is not a failure.
		await provider.delete("cli_test");
	});

	it("should hand out a copy, not the stored record", async () => {
		await provider.set(testOauth2Client());
		const read = await provider.get("cli_test");
		ok(read);
		read.redirect_uris.push("https://evil.example.com/callback");
		deepEqual((await provider.get("cli_test"))?.redirect_uris, ["https://app.example.com/callback"]);
	});

	// The cursor names the first client of the page, and the order is the order of the ids.
	it("should list the clients in the order of their ids, from the cursor", async () => {
		for (const client_id of ["cli_c", "cli_a", "cli_b"]) {
			await provider.set(testOauth2Client({ client_id }));
		}
		const ids = async (cursor?: string, limit?: number) => (await provider.list(cursor, limit)).map((client) => client.client_id);
		deepEqual(await ids(), ["cli_a", "cli_b", "cli_c"]);
		deepEqual(await ids("cli_b"), ["cli_b", "cli_c"]);
		deepEqual(await ids("cli_b", 1), ["cli_b"]);
		deepEqual(await ids(undefined, 2), ["cli_a", "cli_b"]);
		deepEqual(await ids("cli_bb"), ["cli_c"]);
		deepEqual(await ids("cli_d"), []);
	});
}
