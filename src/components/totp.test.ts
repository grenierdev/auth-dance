import { assert, assertEquals, assertFalse, assertRejects } from "@std/assert";
import { FakeTime } from "@std/testing/time";
import type { AuthDanceComponentContext } from "../component.ts";
import { InvalidPromptValueError } from "../error.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent } from "../identity.ts";
import { generateKey, totp } from "../otp.ts";
import { MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "../providers/memory.ts";
import { AuthDanceStorage } from "../storage.ts";
import { TotpAuthDanceComponent } from "./totp.ts";

function context(components: AuthDanceIdentityComponent[] = [], flow = "sign-in", id = "id_test"): AuthDanceComponentContext {
	const identity: AuthDanceIdentity = { id, components };
	return {
		storage: new AuthDanceStorage({
			identity: new MemoryIdentityProvider(),
			kv: new MemoryKvProvider(),
			rate_limiter: new MemoryRateLimiterProvider(),
		}),
		stateId: "state_test",
		name: "totp",
		flow,
		identity,
	};
}

function keyOf(components: AuthDanceIdentityComponent[]): string {
	const challenge = components.find((c) => c.kind === "challenge");
	assert(challenge, "expected a challenge component");
	assertEquals(typeof challenge.data?.key, "string");
	return challenge.data!.key as string;
}

Deno.test("TotpAuthDanceComponent", async (t) => {
	await t.step("should store the key and the shape of its codes", async () => {
		const component = new TotpAuthDanceComponent({ digits: 8, period: 60 });
		const key = generateKey(16);
		const components = await component.getIdentityComponent("totp", key, false, context());
		assertEquals(components.length, 1);
		assertEquals(components[0].kind, "challenge");
		assertEquals(components[0].component, "totp");
		assertEquals(components[0].confirmed, false);
		assertEquals(components[0].data, { key, algorithm: "SHA-1", digits: 8, period: 60 });
	});

	await t.step("should drop the spaces of a key and put it in upper case", async () => {
		const component = new TotpAuthDanceComponent();
		assertEquals(keyOf(await component.getIdentityComponent("totp", "abcdefgh ijklmnop", false, context())), "ABCDEFGHIJKLMNOP");
	});

	await t.step("should refuse a key that is not base32 of a length that is a multiple of 8", async () => {
		const component = new TotpAuthDanceComponent();
		for (const value of ["", "ABCDEFG", "ABCDEFG1", "not a key", 42, null, undefined]) {
			await assertRejects(() => component.getIdentityComponent("totp", value, false, context()), InvalidPromptValueError);
		}
	});

	await t.step("should refuse a key that matches the one it replaces", async () => {
		const component = new TotpAuthDanceComponent();
		const key = generateKey(16);
		const enrolled = await component.getIdentityComponent("totp", key, true, context());
		await assertRejects(
			() => component.getIdentityComponent("totp", key, false, context(enrolled, "rotate")),
			InvalidPromptValueError,
		);
		// Another key rotates.
		assert(await component.getIdentityComponent("totp", generateKey(16), false, context(enrolled, "rotate")));
	});

	await t.step("should verify the code of the enrolled key", async () => {
		using _time = new FakeTime(1_700_000_000_000);
		const component = new TotpAuthDanceComponent();
		const key = generateKey(16);
		const enrolled = await component.getIdentityComponent("totp", key, true, context());
		const code = await totp({ key, period: 30 });
		assertEquals(await component.verifyPrompt(code, context(enrolled)), true);
	});

	await t.step("should read the shape of the codes from the record", async () => {
		using _time = new FakeTime(1_700_000_000_000);
		// The record was written with eight digits and a step of 60 seconds. The options say six and 30.
		const enrolled: AuthDanceIdentityComponent[] = [{
			kind: "challenge",
			component: "totp",
			confirmed: true,
			data: { key: "ABCDEFGHIJKLMNOP", algorithm: "SHA-1", digits: 8, period: 60 },
		}];
		const component = new TotpAuthDanceComponent();
		const code = await totp({ key: "ABCDEFGHIJKLMNOP", period: 60, digits: 8 });
		assertEquals(code.length, 8);
		assertEquals(await component.verifyPrompt(code, context(enrolled)), true);
	});

	await t.step("should accept a code inside the window and refuse one outside it", async () => {
		using _time = new FakeTime(1_700_000_000_000);
		const component = new TotpAuthDanceComponent({ window: 1 });
		const key = generateKey(16);
		const enrolled = await component.getIdentityComponent("totp", key, true, context());
		const previous = await totp({ key, time: Date.now() / 1000 - 30, period: 30 });
		const stale = await totp({ key, time: Date.now() / 1000 - 90, period: 30 });
		assertEquals(await component.verifyPrompt(previous, context(enrolled)), true);
		assertFalse(await component.verifyPrompt(stale, context(enrolled)));
	});

	await t.step("should spend a code one time", async () => {
		using _time = new FakeTime(1_700_000_000_000);
		const component = new TotpAuthDanceComponent();
		const key = generateKey(16);
		const enrolled = await component.getIdentityComponent("totp", key, true, context());
		// One context, so both calls read the same key value store.
		const ctx = context(enrolled);
		const code = await totp({ key, period: 30 });
		assertEquals(await component.verifyPrompt(code, ctx), true);
		assertFalse(await component.verifyPrompt(code, ctx));
	});

	await t.step("should refuse a value that no key derives", async () => {
		using _time = new FakeTime(1_700_000_000_000);
		const component = new TotpAuthDanceComponent();
		const key = generateKey(16);
		const enrolled = await component.getIdentityComponent("totp", key, true, context());
		for (const value of ["000000", "12345", "abcdef", "", 42, null, undefined]) {
			assertFalse(await component.verifyPrompt(value, context(enrolled)));
		}
	});

	await t.step("should refuse a code against an identity that holds no key", async () => {
		using _time = new FakeTime(1_700_000_000_000);
		const component = new TotpAuthDanceComponent();
		assertFalse(await component.verifyPrompt(await totp({ key: generateKey(16), period: 30 }), context()));
	});

	await t.step("should prompt for the key of a collection, and for a code everywhere else", async () => {
		const component = new TotpAuthDanceComponent({ digits: 8, period: 60 });
		const options = { digits: 8, period: 60, algorithm: "SHA-1" };
		// Every flow that collects the key.
		for (const flow of ["sign-up", "enroll", "rotate", "recover"]) {
			const ctx = context([], flow);
			assertEquals(await component.getPrompt(ctx), { kind: "input", name: "totp", type: "totp-key", sendable: false, options });
		}
		// A sign-in verifies a code against the key the identity holds, and collects nothing.
		const signIn = context([], "sign-in");
		assertEquals(await component.getPrompt(signIn), { kind: "input", name: "totp", type: "totp", sendable: false, options });
		// The verification of a collected key asks for the code, whatever flow collected it.
		const enroll = context([], "enroll");
		const verification = await component.verificationComponent(enroll);
		assertEquals(await verification.getPrompt(enroll), { kind: "input", name: "totp", type: "totp", sendable: false, options });
	});

	await t.step("should verify the collected key through the verification component", async () => {
		using _time = new FakeTime(1_700_000_000_000);
		const component = new TotpAuthDanceComponent();
		const key = generateKey(16);
		// The enroll flow puts the collected record in front of the components of the identity.
		const collected = await component.getIdentityComponent("totp", key, false, context());
		const enrolled = await component.getIdentityComponent("totp", generateKey(16), true, context());
		const ctx = context([...collected, ...enrolled], "enroll");
		const verification = await component.verificationComponent(ctx);
		assertEquals(await verification.verifyPrompt(await totp({ key, period: 30 }), ctx), true);
	});
});
