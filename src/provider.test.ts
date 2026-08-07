import { beforeEach, it } from "@std/testing/bdd";
import { assert, assertEquals } from "@std/assert";
import type { AuthDanceIdentityProvider, AuthDanceKvProvider } from "./provider.ts";
import type { AuthDanceIdentity } from "./identity.ts";

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
		assert(retrieved);
		assertEquals(retrieved.id, identity.id);
		assertEquals(retrieved.data, identity.data);
	});

	it("should return undefined for a non-existent identity", async () => {
		const retrieved = await provider.get("non_existent_id");
		assertEquals(retrieved, undefined);
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
		assertEquals(retrieved, undefined);
	});

	it("should return undefined for getByIdentification when no identity matches", async () => {
		const retrieved = await provider.getByIdentification("email", "nonexistent@example.com");
		assertEquals(retrieved, undefined);
	});

	it("should return the correct identity for getByIdentification when an identity matches", async () => {
		const identity = {
			id: "id_789",
			data: { name: "Charlie" },
			components: [
				{ kind: "identification", component: "email", identification: "charlie@example.com", confirmed: true },
			],
		} satisfies AuthDanceIdentity;
		await provider.set(identity);
		const retrieved = await provider.getByIdentification("email", "charlie@example.com");
		assert(retrieved);
		assertEquals(retrieved.id, identity.id);
		assertEquals(retrieved.data, identity.data);
	});

	it("should return undefined for getByIdentification when the component type does not match", async () => {
		const identity = {
			id: "id_101",
			data: { name: "David" },
			components: [
				{ kind: "identification", component: "email", identification: "david@example.com", confirmed: true },
			],
		} satisfies AuthDanceIdentity;
		await provider.set(identity);
		const retrieved = await provider.getByIdentification("phone", "123-456-7890");
		assertEquals(retrieved, undefined);
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
		assertEquals(value, "test_value");
	});

	it("should return undefined for a non-existent key", async () => {
		const value = await provider.get("non_existent_key");
		assertEquals(value, undefined);
	});

	it("should delete a key-value pair", async () => {
		await provider.set("delete_key", "delete_value");
		await provider.unset("delete_key");
		const value = await provider.get("delete_key");
		assertEquals(value, undefined);
	});

	it("should list keys with a given prefix", async () => {
		await provider.set("prefix_key1", "value1");
		await provider.set("prefix_key2", "value2");
		await provider.set("other_key", "value3");

		const keys = await provider.list("prefix_");
		assert(keys.includes("prefix_key1"));
		assert(keys.includes("prefix_key2"));
		assert(!keys.includes("other_key"));
	});
}
