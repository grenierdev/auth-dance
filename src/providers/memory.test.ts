import { testIdentityProvider, testKvProvider } from "../provider.test.ts";
import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { MemoryIdentityProvider, MemoryKvProvider } from "./memory.ts";

describe("Memory provider", () => {
	testIdentityProvider(() => new MemoryIdentityProvider());
	testKvProvider(() => new MemoryKvProvider());

	// A lifetime of zero seconds is already over when the write returns.
	it("should resolve undefined for an expired key", async () => {
		using provider = new MemoryKvProvider();
		await provider.set("otp/state_1/email", "123456", 0);
		assertEquals(await provider.get("otp/state_1/email"), undefined);
	});

	it("should skip an expired key in a listing", async () => {
		using provider = new MemoryKvProvider();
		await provider.set("sessions/id_1/ses_1", "{}", 0);
		await provider.set("sessions/id_1/ses_2", "{}");
		assertEquals(await provider.list("sessions/id_1/"), ["sessions/id_1/ses_2"]);
	});
});
