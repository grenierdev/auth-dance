import { beforeEach, describe, it } from "@std/testing/bdd";
import { assert, assertEquals } from "@std/assert";
import { MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "./providers/memory.ts";
import { EmailAuthDanceComponent } from "./components/email.ts";
import { AuthDanceStorage } from "./storage.ts";

describe("Storage", () => {
	let storage: AuthDanceStorage;
	let email: EmailAuthDanceComponent;

	beforeEach(() => {
		email = new EmailAuthDanceComponent({ channel: "email" });
		storage = new AuthDanceStorage({
			identity: new MemoryIdentityProvider(),
			kv: new MemoryKvProvider(),
			rate_limiter: new MemoryRateLimiterProvider(),
		});
	});

	it("should create an identity", async () => {
		const identity = await storage.createIdentity({ name: "John Doe" });
		assert(identity.id);
		assertEquals(identity.data?.name, "John Doe");
	});
	it("should list identities", async () => {
		const identity1 = await storage.createIdentity({ name: "John Doe" });
		const identity2 = await storage.createIdentity({ name: "Jane Doe" });
		const identities = await storage.listIdentities();
		assertEquals(identities.length, 2);
		assertEquals(identities[0], identity1);
		assertEquals(identities[1], identity2);
	});
	it("should get an identity", async () => {
		const identity = await storage.createIdentity({ name: "John Doe" });
		const fetched = await storage.getIdentity(identity.id);
		assertEquals(fetched, identity);
	});
	it("should get an identity by identification", async () => {
		const identity = await storage.createIdentity(
			{ name: "John Doe" },
			[...await email.getIdentityComponent("email", "john.doe@example.com")],
		);
		const fetched = await storage.getIdentityByIdentification("email", "john.doe@example.com");
		assertEquals(fetched, identity);
	});
	it("should delete an identity", async () => {
		const identity = await storage.createIdentity({ name: "John Doe" });
		await storage.deleteIdentity(identity.id);
		const fetched = await storage.getIdentity(identity.id);
		assertEquals(fetched, undefined);
	});
	it("should default identity data to an empty object", async () => {
		const identity = await storage.createIdentity();
		assertEquals(identity.data, {});
		assertEquals(identity.components, []);
	});
	it("should paginate identities with offset", async () => {
		await storage.createIdentity({ name: "A" });
		const second = await storage.createIdentity({ name: "B" });
		const third = await storage.createIdentity({ name: "C" });
		const page = await storage.listIdentities(second.id);
		assertEquals(page.length, 2);
		assertEquals(page[0], second);
		assertEquals(page[1], third);
	});
	it("should return undefined for a missing identity", async () => {
		const fetched = await storage.getIdentity("id_missing");
		assertEquals(fetched, undefined);
	});
	it("should return undefined for a missing identification", async () => {
		const fetched = await storage.getIdentityByIdentification("email", "nobody@example.com");
		assertEquals(fetched, undefined);
	});
	it("should update an existing identity via setIdentity", async () => {
		const identity = await storage.createIdentity({ name: "John Doe" });
		await storage.setIdentity({ ...identity, data: { name: "Jane Doe" } });
		const fetched = await storage.getIdentity(identity.id);
		assertEquals(fetched?.data?.name, "Jane Doe");
	});

	it("should set and get a KV value", async () => {
		await storage.setKv("greeting", "hello");
		assertEquals(await storage.getKv("greeting"), "hello");
	});
	it("should overwrite a KV value", async () => {
		await storage.setKv("greeting", "hello");
		await storage.setKv("greeting", "world");
		assertEquals(await storage.getKv("greeting"), "world");
	});
	it("should list KV keys by prefix", async () => {
		await storage.setKv("user/1", "a");
		await storage.setKv("user/2", "b");
		await storage.setKv("other/1", "c");
		const keys = await storage.listKv("user/");
		assertEquals(keys, ["user/1", "user/2"]);
	});
	// `listKv` and `AuthDanceKvProvider.list` take their three arguments in the same order, so a page asked of the
	// storage is the page the adapter returns.
	it("should page KV keys with an offset and a limit", async () => {
		await storage.setKv("user/1", "a");
		await storage.setKv("user/2", "b");
		await storage.setKv("user/3", "c");
		assertEquals(await storage.listKv("user/", 0, 2), ["user/1", "user/2"]);
		assertEquals(await storage.listKv("user/", 1, 1), ["user/2"]);
	});
	it("should return undefined for a KV key that holds nothing", async () => {
		assertEquals(await storage.getKv("nothing"), undefined);
	});
	it("should unset a KV value", async () => {
		await storage.setKv("greeting", "hello");
		await storage.unsetKv("greeting");
		assertEquals(await storage.listKv("greeting"), []);
	});
	it("should keep a KV value readable for the seconds its ttl counts", async () => {
		// The ttl is a count of seconds, so a value given one of them is still there a fraction of a second on.
		// A provider that added that count to a millisecond clock dropped it here instead, and with it every
		// one-time code a caller took longer than a moment to type.
		await storage.setKv("greeting", "hello", 1);
		await new Promise((resolve) => setTimeout(resolve, 50));
		assertEquals(await storage.getKv("greeting"), "hello");
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
		assert(session.id.startsWith("ses_"));
		assertEquals(session.identityId, "id_1");
		assertEquals(session.scopes, ["read"]);
		assertEquals(session.expireAt, expireAt.toISOString());
		assertEquals(session.address, "127.0.0.1");
		assertEquals(session.userAgent, "test-agent");
		assertEquals(await storage.listKv("session/"), [`session/${session.id}`]);
		assertEquals(await storage.listKv(`sessions/id_1/`), [`sessions/id_1/${session.id}`]);
	});
	it("should get a session by id", async () => {
		const session = await storage.createSession({
			identityId: "id_1",
			scopes: ["read"],
			expireAt: new Date(Date.now() + 60_000),
		});
		const fetched = await storage.getSession(session.id);
		assertEquals(fetched?.id, session.id);
		assertEquals(fetched?.identityId, session.identityId);
		assertEquals(fetched?.scopes, session.scopes);
		assertEquals(fetched?.expireAt, session.expireAt);
	});

	it("should allow requests under the rate limit then block", async () => {
		assertEquals(await storage.consumeRateLimit("key", 2, 60_000), { allowed: true, retryAfter: undefined });
		assertEquals(await storage.consumeRateLimit("key", 2, 60_000), { allowed: true, retryAfter: undefined });
		assertEquals(await storage.consumeRateLimit("key", 2, 60_000), { allowed: false, retryAfter: undefined });
	});
	it("should track rate limits per key independently", async () => {
		await storage.consumeRateLimit("a", 1, 60_000);
		const blocked = await storage.consumeRateLimit("a", 1, 60_000);
		const other = await storage.consumeRateLimit("b", 1, 60_000);
		assertEquals(blocked.allowed, false);
		assertEquals(other.allowed, true);
	});
});
