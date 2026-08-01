import { assert, assertEquals, assertFalse, assertRejects } from "@std/assert";
import type { AuthDanceComponentContext } from "../component.ts";
import { PolicyViolationError } from "../error.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent } from "../identity.ts";
import { MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "../providers/memory.ts";
import { AuthDanceStorage } from "../storage.ts";
import PasswordAuthDanceComponent from "./password.ts";

// The cheapest hash Argon2id allows: these cases assert on the shape and the decisions, never on the cost.
const options = { params: { memorySize: 1024, iterations: 1 }, policy: { minLength: 8, maxLength: 64 } };

function context(components: AuthDanceIdentityComponent[] = [], flow = "sign-up"): AuthDanceComponentContext {
	const identity: AuthDanceIdentity = { id: "id_test", components };
	return {
		storage: new AuthDanceStorage({
			identity: new MemoryIdentityProvider(),
			kv: new MemoryKvProvider(),
			rate_limiter: new MemoryRateLimiterProvider(),
		}),
		stateId: "state_test",
		name: "password",
		flow,
		identity,
	};
}

function hashOf(components: AuthDanceIdentityComponent[]): string {
	const challenge = components.find((c) => c.kind === "challenge");
	assert(challenge, "expected a challenge component");
	assertEquals(typeof challenge.data?.hash, "string");
	return challenge.data!.hash as string;
}

Deno.test("PasswordAuthDanceComponent", async (t) => {
	await t.step("should store an argon2id PHC record", async () => {
		const password = new PasswordAuthDanceComponent("pepper", options);
		const hash = hashOf(await password.getIdentityComponent("password", "correct horse", false, context()));
		assert(hash.startsWith("$argon2id$v=19$m=1024,t=1,p=1$"), hash);
		assertEquals(hash.split("$").length, 6);
	});

	await t.step("should salt every record separately", async () => {
		const password = new PasswordAuthDanceComponent("pepper", options);
		const first = hashOf(await password.getIdentityComponent("password", "correct horse", true, context()));
		const second = hashOf(await password.getIdentityComponent("password", "correct horse", true, context()));
		// Two identities sharing a password must not share a record, or the store discloses that they share one.
		assert(first !== second);
	});

	await t.step("should verify the value it stored", async () => {
		const password = new PasswordAuthDanceComponent("pepper", options);
		const stored = await password.getIdentityComponent("password", "correct horse", true, context());
		assertEquals(await password.verifyPrompt("correct horse", context(stored, "sign-in")), true);
		assertFalse(await password.verifyPrompt("wrong horse", context(stored, "sign-in")));
	});

	await t.step("should verify across NFKC-equivalent spellings", async () => {
		const password = new PasswordAuthDanceComponent("pepper", options);
		// Enrolled as e + combining acute (what a macOS client hands over), submitted as a composed \u00e9.
		// Annotated, or the compiler narrows both to literal types and calls the comparison below unintentional.
		const decomposed: string = "cafe\u0301 latte";
		const composed: string = "caf\u00e9 latte";
		assert(decomposed !== composed);
		const stored = await password.getIdentityComponent("password", decomposed, true, context());
		assertEquals(await password.verifyPrompt(composed, context(stored, "sign-in")), true);
	});

	await t.step("should not verify a record made under another pepper", async () => {
		const stored = await new PasswordAuthDanceComponent("pepper", options)
			.getIdentityComponent("password", "correct horse", true, context());
		const other = new PasswordAuthDanceComponent("other pepper", options);
		assertFalse(await other.verifyPrompt("correct horse", context(stored, "sign-in")));
	});

	await t.step("should reject a record it cannot parse instead of throwing", async () => {
		const password = new PasswordAuthDanceComponent("pepper", options);
		// What the pre-Argon2id component stored: base64(SHA-512("salty:foo")), not a PHC string.
		const legacy: AuthDanceIdentityComponent[] = [{
			kind: "challenge",
			component: "password",
			confirmed: true,
			data: { hash: "wRhrDCcYRuGRWi4ZUFFXjBoPZ+f9Iy7rlkMPmyvRXhBaKN4ScLpQ0lDrz0h9BUTLLbLtEEwvZTFAlFhVKGZQZw==" },
		}];
		assertFalse(await password.verifyPrompt("foo", context(legacy, "sign-in")));
	});

	await t.step("should fail an identity with no password enrolled", async () => {
		const password = new PasswordAuthDanceComponent("pepper", options);
		assertFalse(await password.verifyPrompt("correct horse", context([], "sign-in")));
		assertFalse(await password.verifyPrompt(1234, context([], "sign-in")));
		assertFalse(await password.verifyPrompt("", context([], "sign-in")));
	});

	await t.step("should hold a stored value to the length policy", async () => {
		const password = new PasswordAuthDanceComponent("pepper", options);
		await assertRejects(() => password.getIdentityComponent("password", "short", false, context()), PolicyViolationError);
		await assertRejects(() => password.getIdentityComponent("password", "x".repeat(65), false, context()), PolicyViolationError);
		await assertRejects(() => password.getIdentityComponent("password", 1234, false, context()), PolicyViolationError);
	});

	await t.step("should not hold a submitted value to the length policy", async () => {
		// A password enrolled before the policy tightened still has to be verifiable, and rejecting it early would
		// answer faster than a wrong password does.
		const lenient = new PasswordAuthDanceComponent("pepper", { ...options, policy: { minLength: 3, maxLength: 64 } });
		const stored = await lenient.getIdentityComponent("password", "foo", true, context());
		const strict = new PasswordAuthDanceComponent("pepper", options);
		assertEquals(await strict.verifyPrompt("foo", context(stored, "sign-in")), true);
	});

	await t.step("should refuse a replacement identical to the value it replaces", async () => {
		const password = new PasswordAuthDanceComponent("pepper", options);
		const stored = await password.getIdentityComponent("password", "correct horse", true, context());
		await assertRejects(
			() => password.getIdentityComponent("password", "correct horse", false, context(stored, "rotate")),
			PolicyViolationError,
		);
		// A different one goes through, which is the whole point of the check.
		const rotated = await password.getIdentityComponent("password", "battery staple", false, context(stored, "rotate"));
		assert(hashOf(rotated) !== hashOf(stored));
	});

	await t.step("should refuse a password equal to what identifies its owner", async () => {
		const password = new PasswordAuthDanceComponent("pepper", options);
		const collected: AuthDanceIdentityComponent[] = [{
			kind: "identification",
			component: "email",
			identification: "john.doe@example.com",
			confirmed: true,
		}];
		await assertRejects(
			() => password.getIdentityComponent("password", "John.Doe@Example.com", false, context(collected)),
			PolicyViolationError,
		);
	});

	await t.step("should publish the policy on its prompt", async () => {
		const password = new PasswordAuthDanceComponent("pepper", options);
		const prompt = await password.getPrompt(context());
		assertEquals(prompt, {
			kind: "input",
			name: "password",
			type: "password",
			sendable: false,
			options: { minLength: 8, maxLength: 64 },
		});
	});
});
