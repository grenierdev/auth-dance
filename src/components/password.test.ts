import { deepEqual, ok, rejects, throws } from "node:assert";
import { hex } from "@scure/base";
import { describe, it, assert as vitestAssert } from "vitest";
import type { AuthDanceComponentContext } from "../component.ts";
import { IdentityNotResolvedError, InvalidPromptValueError } from "../error.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent } from "../identity.ts";
import { MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "../providers/memory.ts";
import { AuthDanceStorage } from "../storage.ts";
import { PasswordAuthDanceComponent, pbkdf2PasswordHasher } from "./password.ts";

// One PBKDF2 pass.
const hasher = pbkdf2PasswordHasher(1);
// 32 characters, above the 16-byte floor of the component.
const PEPPER = "tQ3vX9pL2mR7wK5nB8cF1hJ4dG6sA0zE";
const OTHER_PEPPER = "Z8yW1vU4tS7rQ0pO3nM6lK9jI2hG5fE";

// The record that versions before rc.5 wrote: the salt is the first 16 bytes of SHA-256 over the hasher input.
async function legacyRecord(value: string, iterations: number): Promise<string> {
	const encoded = new TextEncoder().encode(value);
	const salt = new Uint8Array(await crypto.subtle.digest("SHA-256", encoded), 0, 16);
	const key = await crypto.subtle.importKey("raw", encoded, { name: "PBKDF2" }, false, ["deriveBits"]);
	const digest = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, key, 256);
	return `${iterations}:${hex.encode(salt)}:${hex.encode(new Uint8Array(digest))}`;
}

function challenge(hash: string): AuthDanceIdentityComponent[] {
	return [{ kind: "challenge", component: "password", confirmed: true, data: { hash } }];
}

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
	it("should store a pbkdf2-sha256:iterations:salt:digest record", async () => {
		const password = new PasswordAuthDanceComponent(PEPPER, hasher);
		const hash = hashOf(await password.getIdentityComponent("password", "correct horse", false, context()));
		const parts = hash.split(":");
		deepEqual(parts.length, 4);
		const [tag, iterations, salt, digest] = parts;
		deepEqual(tag, "pbkdf2-sha256");
		deepEqual(iterations, "1");
		// 16 bytes of salt and a 256-bit digest, both in hex.
		deepEqual(salt.length, 32);
		deepEqual(digest.length, 64);
	});

	it("should not derive the salt from the password", async () => {
		// The audit PoC: a salt of SHA-256(pepper:id:password)[0:16] checks a guess with one SHA-256, and PBKDF2 never runs.
		const password = new PasswordAuthDanceComponent(PEPPER, hasher);
		const hash = hashOf(await password.getIdentityComponent("password", "correct horse", false, context()));
		const salt = hash.split(":")[2];
		const oracle = new Uint8Array(
			await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${PEPPER}:id_test:correct horse`)),
			0,
			16,
		);
		ok(salt !== hex.encode(oracle));
	});

	it("should draw a new salt for each hash of one value", async () => {
		const first = await hasher.hash("correct horse");
		const second = await hasher.hash("correct horse");
		ok(first !== second);
		ok(first.split(":")[2] !== second.split(":")[2]);
		deepEqual(await hasher.verify("correct horse", first), true);
		deepEqual(await hasher.verify("correct horse", second), true);
		deepEqual(await hasher.verify("wrong horse", first), false);
	});

	it("should verify a record that an earlier version wrote, and report it for a rehash", async () => {
		const legacy = await legacyRecord(`${PEPPER}:id_test:correct horse`, 1);
		deepEqual(legacy.split(":").length, 3);
		deepEqual(await hasher.verify(`${PEPPER}:id_test:correct horse`, legacy), true);
		deepEqual(await hasher.verify(`${PEPPER}:id_test:wrong horse`, legacy), false);
		deepEqual(hasher.needsRehash(legacy), true);
		const password = new PasswordAuthDanceComponent(PEPPER, hasher);
		deepEqual(await password.verifyPrompt("correct horse", context(challenge(legacy), "sign-in")), true);
	});

	it("should report a record with fewer passes than it writes", async () => {
		const stronger = pbkdf2PasswordHasher(2);
		const weak = await hasher.hash("correct horse");
		const current = await stronger.hash("correct horse");
		deepEqual(stronger.needsRehash(weak), true);
		deepEqual(stronger.needsRehash(current), false);
		deepEqual(hasher.needsRehash(current), false);
		// The record carries its own count, so the stronger hasher still verifies the weak record.
		deepEqual(await stronger.verify("correct horse", weak), true);
	});

	it("should refuse a record with an iteration count out of bounds, or in another form", async () => {
		const [tag, , salt, digest] = (await hasher.hash("correct horse")).split(":");
		vitestAssert.isFalse(await hasher.verify("correct horse", `${tag}:0:${salt}:${digest}`));
		vitestAssert.isFalse(await hasher.verify("correct horse", `${tag}:10000001:${salt}:${digest}`));
		vitestAssert.isFalse(await hasher.verify("correct horse", `${tag}:1:${salt}`));
		vitestAssert.isFalse(await hasher.verify("correct horse", `${tag}:1:zz:${digest}`));
		vitestAssert.isFalse(await hasher.verify("correct horse", `other:1:${salt}:${digest}`));
		vitestAssert.isFalse(await hasher.verify("correct horse", ""));
	});

	it("should refuse a pepper that is missing or short", () => {
		throws(() => new PasswordAuthDanceComponent(undefined as unknown as string, hasher), TypeError);
		throws(() => new PasswordAuthDanceComponent("", hasher), TypeError);
		throws(() => new PasswordAuthDanceComponent("a".repeat(15), hasher), TypeError);
		new PasswordAuthDanceComponent("a".repeat(16), hasher);
	});

	it("should rewrite a record that needs a rehash, and keep a current one", async () => {
		const password = new PasswordAuthDanceComponent(PEPPER, hasher);
		const legacy = challenge(await legacyRecord(`${PEPPER}:id_test:correct horse`, 1));
		const upgraded = await password.upgradeIdentityComponent("correct horse", context(legacy, "sign-in"));
		ok(upgraded);
		ok(hashOf(upgraded).startsWith("pbkdf2-sha256:"));
		deepEqual(await password.verifyPrompt("correct horse", context(upgraded, "sign-in")), true);
		const current = await password.getIdentityComponent("password", "correct horse", true, context());
		deepEqual(await password.upgradeIdentityComponent("correct horse", context(current, "sign-in")), undefined);
	});

	it("should salt every record separately", async () => {
		const password = new PasswordAuthDanceComponent(PEPPER, hasher);
		const first = hashOf(await password.getIdentityComponent("password", "correct horse", true, context([], "sign-up", "id_first")));
		const second = hashOf(await password.getIdentityComponent("password", "correct horse", true, context([], "sign-up", "id_second")));
		// Two identities sharing a password must not share a record.
		ok(first !== second);
	});

	it("should not verify a record against another identity", async () => {
		const password = new PasswordAuthDanceComponent(PEPPER, hasher);
		const stored = await password.getIdentityComponent("password", "correct horse", true, context([], "sign-up", "id_first"));
		// The id of the identity salts the hash, so a record lifted out of the store verifies against nobody else.
		deepEqual(await password.verifyPrompt("correct horse", context(stored, "sign-in", "id_first")), true);
		vitestAssert.isFalse(await password.verifyPrompt("correct horse", context(stored, "sign-in", "id_second")));
	});

	it("should refuse to store a record it cannot salt", async () => {
		const password = new PasswordAuthDanceComponent(PEPPER, hasher);
		const { identity: _, ...withoutIdentity } = context();
		await rejects(() => password.getIdentityComponent("password", "correct horse", false, withoutIdentity), IdentityNotResolvedError);
	});

	it("should verify the value it stored", async () => {
		const password = new PasswordAuthDanceComponent(PEPPER, hasher);
		const stored = await password.getIdentityComponent("password", "correct horse", true, context());
		deepEqual(await password.verifyPrompt("correct horse", context(stored, "sign-in")), true);
		vitestAssert.isFalse(await password.verifyPrompt("wrong horse", context(stored, "sign-in")));
	});

	it("should verify across NFKC-equivalent spellings", async () => {
		const password = new PasswordAuthDanceComponent(PEPPER, hasher);
		// Enrolled as e + combining acute, submitted as a composed \u00e9.
		const decomposed: string = "cafe\u0301 latte";
		const composed: string = "caf\u00e9 latte";
		ok(decomposed !== composed);
		const stored = await password.getIdentityComponent("password", decomposed, true, context());
		deepEqual(await password.verifyPrompt(composed, context(stored, "sign-in")), true);
	});

	it("should not verify a record made under another pepper", async () => {
		const stored = await new PasswordAuthDanceComponent(PEPPER, hasher).getIdentityComponent("password", "correct horse", true, context());
		const other = new PasswordAuthDanceComponent(OTHER_PEPPER, hasher);
		vitestAssert.isFalse(await other.verifyPrompt("correct horse", context(stored, "sign-in")));
	});

	it("should reject a record it cannot have written instead of throwing", async () => {
		const password = new PasswordAuthDanceComponent(PEPPER, hasher);
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
		const password = new PasswordAuthDanceComponent(PEPPER, hasher);
		vitestAssert.isFalse(await password.verifyPrompt("correct horse", context([], "sign-in")));
		vitestAssert.isFalse(await password.verifyPrompt(1234, context([], "sign-in")));
		vitestAssert.isFalse(await password.verifyPrompt("", context([], "sign-in")));
	});

	it("should refuse to store a value it cannot hash", async () => {
		const password = new PasswordAuthDanceComponent(PEPPER, hasher);
		await rejects(() => password.getIdentityComponent("password", "", false, context()), InvalidPromptValueError);
		await rejects(() => password.getIdentityComponent("password", 1234, false, context()), InvalidPromptValueError);
	});

	it("should refuse a replacement identical to the value it replaces", async () => {
		const password = new PasswordAuthDanceComponent(PEPPER, hasher);
		const stored = await password.getIdentityComponent("password", "correct horse", true, context());
		await rejects(
			() => password.getIdentityComponent("password", "correct horse", false, context(stored, "rotate")),
			InvalidPromptValueError,
		);
		const rotated = await password.getIdentityComponent("password", "battery staple", false, context(stored, "rotate"));
		ok(hashOf(rotated) !== hashOf(stored));
	});

	it("should refuse a password deepEqual to what identifies its owner", async () => {
		const password = new PasswordAuthDanceComponent(PEPPER, hasher);
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
		const password = new PasswordAuthDanceComponent(PEPPER, hasher);
		const prompt = await password.getPrompt(context());
		deepEqual(prompt, {
			kind: "input",
			name: "password",
			type: "password",
			sendable: false,
		});
	});
});
