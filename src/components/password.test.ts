import { assert, assertEquals, assertFalse, assertRejects } from "@std/assert";
import type { AuthDanceComponentContext } from "../component.ts";
import { IdentityNotResolvedError, InvalidPromptValueError } from "../error.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent } from "../identity.ts";
import { MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "../providers/memory.ts";
import { AuthDanceStorage } from "../storage.ts";
import PasswordAuthDanceComponent, { pbkdf2PasswordHasher } from "./password.ts";

// One PBKDF2 pass: these cases assert on the shape and the decisions, never on the cost.
const hasher = pbkdf2PasswordHasher(1);

function context(components: AuthDanceIdentityComponent[] = [], flow = "sign-up", id = "id_test"): AuthDanceComponentContext {
	const identity: AuthDanceIdentity = { id, components };
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
	await t.step("should store an iterations:salt:digest record", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		const hash = hashOf(await password.getIdentityComponent("password", "correct horse", false, context()));
		const parts = hash.split(":");
		assertEquals(parts.length, 3);
		const [iterations, salt, digest] = parts;
		assertEquals(iterations, "1");
		// 16 bytes of salt and a 256-bit digest, both in hex.
		assertEquals(salt.length, 32);
		assertEquals(digest.length, 64);
	});

	await t.step("should salt every record separately", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		const first = hashOf(await password.getIdentityComponent("password", "correct horse", true, context([], "sign-up", "id_first")));
		const second = hashOf(await password.getIdentityComponent("password", "correct horse", true, context([], "sign-up", "id_second")));
		// Two identities sharing a password must not share a record, or the store discloses that they share one.
		assert(first !== second);
	});

	await t.step("should not verify a record against another identity", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		const stored = await password.getIdentityComponent("password", "correct horse", true, context([], "sign-up", "id_first"));
		// The id of the identity salts the hash, so a record lifted out of the store verifies against nobody else.
		assertEquals(await password.verifyPrompt("correct horse", context(stored, "sign-in", "id_first")), true);
		assertFalse(await password.verifyPrompt("correct horse", context(stored, "sign-in", "id_second")));
	});

	await t.step("should refuse to store a record it cannot salt", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		const { identity: _, ...withoutIdentity } = context();
		await assertRejects(
			() => password.getIdentityComponent("password", "correct horse", false, withoutIdentity),
			IdentityNotResolvedError,
		);
	});

	await t.step("should verify the value it stored", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		const stored = await password.getIdentityComponent("password", "correct horse", true, context());
		assertEquals(await password.verifyPrompt("correct horse", context(stored, "sign-in")), true);
		assertFalse(await password.verifyPrompt("wrong horse", context(stored, "sign-in")));
	});

	await t.step("should verify across NFKC-equivalent spellings", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		// Enrolled as e + combining acute (what a macOS client hands over), submitted as a composed \u00e9.
		// Annotated, or the compiler narrows both to literal types and calls the comparison below unintentional.
		const decomposed: string = "cafe\u0301 latte";
		const composed: string = "caf\u00e9 latte";
		assert(decomposed !== composed);
		const stored = await password.getIdentityComponent("password", decomposed, true, context());
		assertEquals(await password.verifyPrompt(composed, context(stored, "sign-in")), true);
	});

	await t.step("should not verify a record made under another pepper", async () => {
		const stored = await new PasswordAuthDanceComponent("pepper", hasher)
			.getIdentityComponent("password", "correct horse", true, context());
		const other = new PasswordAuthDanceComponent("other pepper", hasher);
		assertFalse(await other.verifyPrompt("correct horse", context(stored, "sign-in")));
	});

	await t.step("should reject a record it cannot have written instead of throwing", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		// What an older component stored: base64(SHA-512("salty:foo")), which no hasher here answers.
		const legacy: AuthDanceIdentityComponent[] = [{
			kind: "challenge",
			component: "password",
			confirmed: true,
			data: { hash: "wRhrDCcYRuGRWi4ZUFFXjBoPZ+f9Iy7rlkMPmyvRXhBaKN4ScLpQ0lDrz0h9BUTLLbLtEEwvZTFAlFhVKGZQZw==" },
		}];
		assertFalse(await password.verifyPrompt("foo", context(legacy, "sign-in")));
	});

	await t.step("should fail an identity with no password enrolled", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		assertFalse(await password.verifyPrompt("correct horse", context([], "sign-in")));
		assertFalse(await password.verifyPrompt(1234, context([], "sign-in")));
		assertFalse(await password.verifyPrompt("", context([], "sign-in")));
	});

	await t.step("should refuse to store a value it cannot hash", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		await assertRejects(() => password.getIdentityComponent("password", "", false, context()), InvalidPromptValueError);
		await assertRejects(() => password.getIdentityComponent("password", 1234, false, context()), InvalidPromptValueError);
	});

	await t.step("should refuse a replacement identical to the value it replaces", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		const stored = await password.getIdentityComponent("password", "correct horse", true, context());
		await assertRejects(
			() => password.getIdentityComponent("password", "correct horse", false, context(stored, "rotate")),
			InvalidPromptValueError,
		);
		// A different one goes through, which is the whole point of the check.
		const rotated = await password.getIdentityComponent("password", "battery staple", false, context(stored, "rotate"));
		assert(hashOf(rotated) !== hashOf(stored));
	});

	await t.step("should refuse a password equal to what identifies its owner", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		const collected: AuthDanceIdentityComponent[] = [{
			kind: "identification",
			component: "email",
			identification: "john.doe@example.com",
			confirmed: true,
		}];
		await assertRejects(
			() => password.getIdentityComponent("password", "John.Doe@Example.com", false, context(collected)),
			InvalidPromptValueError,
		);
	});

	await t.step("should prompt for a password field under its own name", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		const prompt = await password.getPrompt(context());
		assertEquals(prompt, {
			kind: "input",
			name: "password",
			type: "password",
			sendable: false,
		});
	});
});
