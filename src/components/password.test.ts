import { deepEqual, ok, rejects } from "node:assert";
import { describe, it, assert as vitestAssert } from "vitest";
import type { AuthDanceComponentContext } from "../component.ts";
import { IdentityNotResolvedError, InvalidPromptValueError } from "../error.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent } from "../identity.ts";
import { MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "../providers/memory.ts";
import { AuthDanceStorage } from "../storage.ts";
import { PasswordAuthDanceComponent, pbkdf2PasswordHasher } from "./password.ts";

// One PBKDF2 pass.
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
	ok(challenge, "expected a challenge component");
	deepEqual(typeof challenge.data?.hash, "string");
	return challenge.data!.hash as string;
}

describe("PasswordAuthDanceComponent", () => {
	it("should store an iterations:salt:digest record", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		const hash = hashOf(await password.getIdentityComponent("password", "correct horse", false, context()));
		const parts = hash.split(":");
		deepEqual(parts.length, 3);
		const [iterations, salt, digest] = parts;
		deepEqual(iterations, "1");
		// 16 bytes of salt and a 256-bit digest, both in hex.
		deepEqual(salt.length, 32);
		deepEqual(digest.length, 64);
	});

	it("should salt every record separately", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		const first = hashOf(await password.getIdentityComponent("password", "correct horse", true, context([], "sign-up", "id_first")));
		const second = hashOf(await password.getIdentityComponent("password", "correct horse", true, context([], "sign-up", "id_second")));
		// Two identities sharing a password must not share a record.
		ok(first !== second);
	});

	it("should not verify a record against another identity", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		const stored = await password.getIdentityComponent("password", "correct horse", true, context([], "sign-up", "id_first"));
		// The id of the identity salts the hash, so a record lifted out of the store verifies against nobody else.
		deepEqual(await password.verifyPrompt("correct horse", context(stored, "sign-in", "id_first")), true);
		vitestAssert.isFalse(await password.verifyPrompt("correct horse", context(stored, "sign-in", "id_second")));
	});

	it("should refuse to store a record it cannot salt", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		const { identity: _, ...withoutIdentity } = context();
		await rejects(() => password.getIdentityComponent("password", "correct horse", false, withoutIdentity), IdentityNotResolvedError);
	});

	it("should verify the value it stored", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		const stored = await password.getIdentityComponent("password", "correct horse", true, context());
		deepEqual(await password.verifyPrompt("correct horse", context(stored, "sign-in")), true);
		vitestAssert.isFalse(await password.verifyPrompt("wrong horse", context(stored, "sign-in")));
	});

	it("should verify across NFKC-equivalent spellings", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		// Enrolled as e + combining acute, submitted as a composed \u00e9.
		const decomposed: string = "cafe\u0301 latte";
		const composed: string = "caf\u00e9 latte";
		ok(decomposed !== composed);
		const stored = await password.getIdentityComponent("password", decomposed, true, context());
		deepEqual(await password.verifyPrompt(composed, context(stored, "sign-in")), true);
	});

	it("should not verify a record made under another pepper", async () => {
		const stored = await new PasswordAuthDanceComponent("pepper", hasher).getIdentityComponent(
			"password",
			"correct horse",
			true,
			context(),
		);
		const other = new PasswordAuthDanceComponent("other pepper", hasher);
		vitestAssert.isFalse(await other.verifyPrompt("correct horse", context(stored, "sign-in")));
	});

	it("should reject a record it cannot have written instead of throwing", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		// A record no hasher here answers: base64(SHA-512("salty:foo")).
		const legacy: AuthDanceIdentityComponent[] = [
			{
				kind: "challenge",
				component: "password",
				confirmed: true,
				data: { hash: "wRhrDCcYRuGRWi4ZUFFXjBoPZ+f9Iy7rlkMPmyvRXhBaKN4ScLpQ0lDrz0h9BUTLLbLtEEwvZTFAlFhVKGZQZw==" },
			},
		];
		vitestAssert.isFalse(await password.verifyPrompt("foo", context(legacy, "sign-in")));
	});

	it("should fail an identity with no password enrolled", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		vitestAssert.isFalse(await password.verifyPrompt("correct horse", context([], "sign-in")));
		vitestAssert.isFalse(await password.verifyPrompt(1234, context([], "sign-in")));
		vitestAssert.isFalse(await password.verifyPrompt("", context([], "sign-in")));
	});

	it("should refuse to store a value it cannot hash", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		await rejects(() => password.getIdentityComponent("password", "", false, context()), InvalidPromptValueError);
		await rejects(() => password.getIdentityComponent("password", 1234, false, context()), InvalidPromptValueError);
	});

	it("should refuse a replacement identical to the value it replaces", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		const stored = await password.getIdentityComponent("password", "correct horse", true, context());
		await rejects(
			() => password.getIdentityComponent("password", "correct horse", false, context(stored, "rotate")),
			InvalidPromptValueError,
		);
		const rotated = await password.getIdentityComponent("password", "battery staple", false, context(stored, "rotate"));
		ok(hashOf(rotated) !== hashOf(stored));
	});

	it("should refuse a password deepEqual to what identifies its owner", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		const collected: AuthDanceIdentityComponent[] = [
			{
				kind: "identification",
				component: "email",
				identification: "john.doe@example.com",
				confirmed: true,
			},
		];
		await rejects(
			() => password.getIdentityComponent("password", "John.Doe@Example.com", false, context(collected)),
			InvalidPromptValueError,
		);
	});

	it("should prompt for a password field under its own name", async () => {
		const password = new PasswordAuthDanceComponent("pepper", hasher);
		const prompt = await password.getPrompt(context());
		deepEqual(prompt, {
			kind: "input",
			name: "password",
			type: "password",
			sendable: false,
		});
	});
});
