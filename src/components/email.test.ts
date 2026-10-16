import { deepEqual } from "node:assert";
import { describe, it } from "vitest";
import type { AuthDanceIdentity } from "../identity.ts";
import { MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "../providers/memory.ts";
import { AuthDanceStorage } from "../storage.ts";
import { EmailAuthDanceComponent, normalizeEmailAddress, normalizeEmailIdentifications } from "./email.ts";

describe("normalizeEmailAddress", () => {
	it("should trim the address and put it in lower case", () => {
		deepEqual(normalizeEmailAddress("  Victim@Example.COM "), "victim@example.com");
		deepEqual(normalizeEmailAddress("  Victim@Example.COM ", { preserveLocalCase: true }), "Victim@example.com");
	});

	it("should compose the address to NFC", () => {
		deepEqual(normalizeEmailAddress("José@example.com"), "josé@example.com");
	});

	it("should refuse a value that is not one address", () => {
		for (const value of [
			{},
			undefined,
			42,
			"",
			"a@b",
			"a b@example.com",
			"a@example.com\r\nBcc: x@y.z",
			"@example.com",
			"a@",
			"a@@example.com",
			"a@b@example.com",
			"a@example..com",
			"a@.example.com",
			`${"a".repeat(243)}@example.com`,
		]) {
			deepEqual(normalizeEmailAddress(value), null, JSON.stringify(value));
		}
		// 254 characters is the longest address it keeps.
		deepEqual(normalizeEmailAddress(`${"a".repeat(242)}@example.com`)?.length, 254);
	});
});

describe("normalizeEmailIdentifications", () => {
	it("should rewrite every identification it can, and report two accounts for one inbox", async () => {
		const storage = new AuthDanceStorage({
			identity: new MemoryIdentityProvider(),
			kv: new MemoryKvProvider(),
			rate_limiter: new MemoryRateLimiterProvider(),
		});
		// Records as versions before rc.5 stored them, with the address as typed.
		const legacy = (id: string, address: string): AuthDanceIdentity => ({
			id,
			data: {},
			components: [
				{ kind: "identification", component: "email", identification: address, confirmed: true },
				{ kind: "channel", component: "email", confirmed: true, data: { email: address }, linkedTo: ["email"] },
				{ kind: "challenge", component: "otp", confirmed: true, data: { recipient: address }, linkedTo: ["email"] },
			],
		});
		await storage.setIdentity(legacy("id_1", "a@x.io"));
		await storage.setIdentity(legacy("id_2", "A@x.io"));
		await storage.setIdentity(legacy("id_3", "b@X.io"));

		const result = await normalizeEmailIdentifications(storage, "email");
		deepEqual(result, { updated: ["id_3"], collisions: [["id_1", "id_2"]] });
		deepEqual((await storage.getIdentity("id_3"))?.components, legacy("id_3", "b@x.io").components);
		// A collision stays as it was.
		deepEqual((await storage.getIdentity("id_2"))?.components, legacy("id_2", "A@x.io").components);

		// The rewritten address now resolves through the component.
		const email = new EmailAuthDanceComponent({ channel: "email", challenge: "otp" });
		deepEqual(await email.verifyPrompt("B@x.io", { storage, stateId: "st_1", name: "email", flow: "sign-in" }), "id_3");
	});
});
