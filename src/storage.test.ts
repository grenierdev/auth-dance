import { deepEqual, ok } from "node:assert";
import { beforeEach, describe, it } from "vitest";
import { EmailAuthDanceComponent } from "./components/email.ts";
import { MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "./providers/memory.ts";
import { AuthDanceStorage } from "./storage.ts";

describe("Storage", () => {
	let storage: AuthDanceStorage;
	let email: EmailAuthDanceComponent;

	beforeEach(() => {
		email = new EmailAuthDanceComponent({ channel: "email", challenge: "otp" });
		storage = new AuthDanceStorage({
			identity: new MemoryIdentityProvider(),
			kv: new MemoryKvProvider(),
			rate_limiter: new MemoryRateLimiterProvider(),
		});
	});

	it("should create an identity", async () => {
		const identity = await storage.createIdentity({ name: "John Doe" });
		ok(identity.id);
		deepEqual(identity.data?.name, "John Doe");
	});
	it("should list identities", async () => {
		const identity1 = await storage.createIdentity({ name: "John Doe" });
		const identity2 = await storage.createIdentity({ name: "Jane Doe" });
		const identities = await storage.listIdentities();
		deepEqual(identities.length, 2);
		deepEqual(identities[0], identity1);
		deepEqual(identities[1], identity2);
	});
	it("should get an identity", async () => {
		const identity = await storage.createIdentity({ name: "John Doe" });
		const fetched = await storage.getIdentity(identity.id);
		deepEqual(fetched, identity);
	});
	it("should get an identity by identification", async () => {
		const identity = await storage.createIdentity({ name: "John Doe" }, [
			...(await email.getIdentityComponent("email", "john.doe@example.com")),
		]);
		const fetched = await storage.getIdentityByIdentification("email", "john.doe@example.com");
		deepEqual(fetched, identity);
	});
	it("should delete an identity", async () => {
		const identity = await storage.createIdentity({ name: "John Doe" });
		await storage.deleteIdentity(identity.id);
		const fetched = await storage.getIdentity(identity.id);
		deepEqual(fetched, undefined);
	});
	it("should default identity data to an empty object", async () => {
		const identity = await storage.createIdentity();
		deepEqual(identity.data, {});
		deepEqual(identity.components, []);
	});
	it("should paginate identities with offset", async () => {
		await storage.createIdentity({ name: "A" });
		const second = await storage.createIdentity({ name: "B" });
		const third = await storage.createIdentity({ name: "C" });
		const page = await storage.listIdentities(second.id);
		deepEqual(page.length, 2);
		deepEqual(page[0], second);
		deepEqual(page[1], third);
	});
	it("should return undefined for a missing identity", async () => {
		const fetched = await storage.getIdentity("id_missing");
		deepEqual(fetched, undefined);
	});
	it("should return undefined for a missing identification", async () => {
		const fetched = await storage.getIdentityByIdentification("email", "nobody@example.com");
		deepEqual(fetched, undefined);
	});
	it("should update an existing identity via setIdentity", async () => {
		const identity = await storage.createIdentity({ name: "John Doe" });
		await storage.setIdentity({ ...identity, data: { name: "Jane Doe" } });
		const fetched = await storage.getIdentity(identity.id);
		deepEqual(fetched?.data?.name, "Jane Doe");
	});

	it("should set and get a KV value", async () => {
		await storage.setKv("greeting", "hello");
		deepEqual(await storage.getKv("greeting"), "hello");
	});
	it("should overwrite a KV value", async () => {
		await storage.setKv("greeting", "hello");
		await storage.setKv("greeting", "world");
		deepEqual(await storage.getKv("greeting"), "world");
	});
	it("should list KV keys by prefix", async () => {
		await storage.setKv("user/1", "a");
		await storage.setKv("user/2", "b");
		await storage.setKv("other/1", "c");
		const keys = await storage.listKv("user/");
		deepEqual(keys, ["user/1", "user/2"]);
	});
	it("should page KV keys with an offset and a limit", async () => {
		await storage.setKv("user/1", "a");
		await storage.setKv("user/2", "b");
		await storage.setKv("user/3", "c");
		deepEqual(await storage.listKv("user/", 0, 2), ["user/1", "user/2"]);
		deepEqual(await storage.listKv("user/", 1, 1), ["user/2"]);
	});
	it("should return undefined for a KV key that holds nothing", async () => {
		deepEqual(await storage.getKv("nothing"), undefined);
	});
	it("should unset a KV value", async () => {
		await storage.setKv("greeting", "hello");
		await storage.unsetKv("greeting");
		deepEqual(await storage.listKv("greeting"), []);
	});
	it("should keep a KV value readable for the seconds its ttl counts", async () => {
		// The ttl is a count of seconds.
		await storage.setKv("greeting", "hello", 1);
		await new Promise((resolve) => setTimeout(resolve, 50));
		deepEqual(await storage.getKv("greeting"), "hello");
	});

	it("should create a session stored under both key spaces", async () => {
		const expireAt = new Date(Date.now() + 60_000);
		const session = await storage.createSession({
			identityId: "id_1",
			scopes: ["read"],
			expireAt,
			address: "127.0.0.1",
			userAgent: "test-agent",
		});
		ok(session.id.startsWith("ses_"));
		deepEqual(session.identityId, "id_1");
		deepEqual(session.scopes, ["read"]);
		deepEqual(session.expireAt, expireAt.toISOString());
		deepEqual(session.address, "127.0.0.1");
		deepEqual(session.userAgent, "test-agent");
		deepEqual(await storage.listKv("session/"), [`session/${session.id}`]);
		deepEqual(await storage.listKv(`sessions/id_1/`), [`sessions/id_1/${session.id}`]);
	});
	it("should get a session by id", async () => {
		const session = await storage.createSession({
			identityId: "id_1",
			scopes: ["read"],
			expireAt: new Date(Date.now() + 60_000),
		});
		const fetched = await storage.getSession(session.id);
		deepEqual(fetched?.id, session.id);
		deepEqual(fetched?.identityId, session.identityId);
		deepEqual(fetched?.scopes, session.scopes);
		deepEqual(fetched?.expireAt, session.expireAt);
	});

	it("should delete the refresh record together with its session", async () => {
		const expireAt = new Date(Date.now() + 60_000);
		const session = await storage.createSession({ identityId: "id_1", scopes: [], expireAt });
		await storage.setRefreshRecord(session.id, { current: "a", rotatedAt: 1 }, expireAt);
		deepEqual(await storage.getRefreshRecord(session.id), { current: "a", rotatedAt: 1 });
		// The record sits outside the index of the identity, so a listing never reads it as a session.
		deepEqual(await storage.listKv("sessions/id_1/"), [`sessions/id_1/${session.id}`]);
		await storage.deleteSession(session.id);
		deepEqual(await storage.getRefreshRecord(session.id), undefined);
	});

	it("should allow requests under the rate limit then block", async () => {
		deepEqual(await storage.consumeRateLimit("key", 2, 60_000), { allowed: true, retryAfter: undefined });
		deepEqual(await storage.consumeRateLimit("key", 2, 60_000), { allowed: true, retryAfter: undefined });
		deepEqual(await storage.consumeRateLimit("key", 2, 60_000), { allowed: false, retryAfter: undefined });
	});
	it("should track rate limits per key independently", async () => {
		await storage.consumeRateLimit("a", 1, 60_000);
		const blocked = await storage.consumeRateLimit("a", 1, 60_000);
		const other = await storage.consumeRateLimit("b", 1, 60_000);
		deepEqual(blocked.allowed, false);
		deepEqual(other.allowed, true);
	});
});
