import { deepEqual } from "node:assert";
import { describe, it } from "vitest";
import { testOauth2Client } from "../fixtures.test.ts";
import { testIdentityProvider, testKvProvider, testOauth2ClientProvider } from "../provider.test.ts";
import { MemoryIdentityProvider, MemoryKvProvider, MemoryOauth2ClientProvider } from "./memory.ts";

describe("Memory provider", () => {
	testIdentityProvider(() => new MemoryIdentityProvider());
	testKvProvider(() => new MemoryKvProvider());
	testOauth2ClientProvider(() => new MemoryOauth2ClientProvider());

	it("should hold the clients it was seeded with", async () => {
		const seed = testOauth2Client({ client_id: "cli_web" });
		using provider = new MemoryOauth2ClientProvider([seed]);
		deepEqual(await provider.get("cli_web"), seed);
		// The provider stored a clone.
		seed.scope = "admin";
		deepEqual((await provider.get("cli_web"))?.scope, "profile email");
	});

	// A lifetime of zero seconds is already over when the write returns.
	it("should resolve undefined for an expired key", async () => {
		using provider = new MemoryKvProvider();
		await provider.set("otp/state_1/email", "123456", 0);
		deepEqual(await provider.get("otp/state_1/email"), undefined);
	});

	it("should skip an expired key in a listing", async () => {
		using provider = new MemoryKvProvider();
		await provider.set("sessions/id_1/ses_1", "{}", 0);
		await provider.set("sessions/id_1/ses_2", "{}");
		deepEqual(await provider.list("sessions/id_1/"), ["sessions/id_1/ses_2"]);
	});
});
