import { deepEqual, ok, rejects, throws } from "node:assert";
import { describe, it } from "vitest";
import { AuthDanceApi } from "../api.ts";
import { sequence } from "../choreography.ts";
import type { AuthDanceComponent, AuthDanceComponentContext } from "../component.ts";
import { AuthDanceError, InvalidPromptValueError } from "../error.ts";
import { TEST_ISSUER, TEST_SIGNING_KEYS } from "../fixtures.test.ts";
import { MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "../providers/memory.ts";
import type { AuthDanceResponse } from "../response.ts";
import { AuthDanceStorage } from "../storage.ts";
import { PasswordAuthDanceComponent, pbkdf2PasswordHasher } from "./password.ts";
import { PowAuthDanceComponent, type PowPromptOptions, verify, WorkAbortedError, work } from "./pow.ts";

const PEPPER = "tQ3vX9pL2mR7wK5nB8cF1hJ4dG6sA0zE";
const SECRET = "zdJXI1jwuXW8A19fns0E_B4HSYm7AUHLGlU9WLo8mxs";

function storage(): AuthDanceStorage {
	return new AuthDanceStorage({
		identity: new MemoryIdentityProvider(),
		kv: new MemoryKvProvider(),
		rate_limiter: new MemoryRateLimiterProvider(),
	});
}

function context(store = storage(), stateId = "state_test"): AuthDanceComponentContext {
	return { storage: store, stateId, name: "pow", flow: "sign-up" };
}

/** An identification that names the identity by a username. It proves nothing. */
const username: AuthDanceComponent = {
	kind: "identification",
	verifiable: false,
	getPrompt: async (ctx) => ({ kind: "input", name: ctx.name, type: "text", sendable: false }),
	getIdentityComponent: async (component, value, confirmed) => [
		{ kind: "identification", component, identification: String(value), confirmed },
	],
	verifyPrompt: async (value, ctx) => (await ctx.storage.getIdentityByIdentification(ctx.name, String(value)))?.id ?? false,
};

function api(store: AuthDanceStorage): AuthDanceApi {
	return new AuthDanceApi({
		channels: {},
		choreography: sequence("pow", "username", "password"),
		components: {
			pow: new PowAuthDanceComponent({ difficulty: 6 }),
			username,
			password: new PasswordAuthDanceComponent(PEPPER, pbkdf2PasswordHasher(1)),
		},
		secret: SECRET,
		keys: TEST_SIGNING_KEYS,
		tokens: { issuer: TEST_ISSUER },
		storage: store,
	});
}

/** Answers every prompt until the dance ends. A `pow` prompt gets a nonce from `work`, every other prompt its answer. */
async function dance(target: AuthDanceApi, response: AuthDanceResponse, answers: Record<string, unknown>): Promise<AuthDanceResponse> {
	while ("prompt" in response) {
		ok(response.prompt.kind === "input");
		const { name, type, options } = response.prompt;
		const value =
			type === "pow"
				? await work((options as unknown as PowPromptOptions).challenge, (options as unknown as PowPromptOptions).difficulty)
				: answers[name];
		response = await target.submitPrompt({ name, value, state: response.state });
	}
	return response;
}

function promptOptions(prompt: { options?: Record<string, unknown> }): PowPromptOptions {
	return prompt.options as unknown as PowPromptOptions;
}

describe("work and verify", () => {
	it("should find a nonce that verifies", async () => {
		const nonce = await work("challenge", 8);
		ok(await verify("challenge", 8, nonce));
		ok(!(await verify("challenge", 256, nonce)));
	});

	it("should agree on every digest", async () => {
		for (const algorithm of ["SHA-1", "SHA-256", "SHA-384", "SHA-512"] as const) {
			const nonce = await work("challenge", 6, { algorithm });
			ok(await verify("challenge", 6, nonce, algorithm));
		}
	});

	it("should count the same leading zero bits as a count bit by bit", async () => {
		const encoder = new TextEncoder();
		for (let nonce = 0; nonce < 256; nonce++) {
			const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(`challenge${nonce}`)));
			let zeros = 0;
			while (zeros < digest.length * 8 && ((digest[zeros >> 3] >> (7 - (zeros & 7))) & 1) === 0) {
				zeros++;
			}
			ok(zeros === 0 || (await verify("challenge", zeros, nonce)));
			ok(!(await verify("challenge", zeros + 1, nonce)));
		}
	});

	it("should stop when the signal aborts", async () => {
		const controller = new AbortController();
		controller.abort();
		await rejects(work("challenge", 200, { signal: controller.signal }), WorkAbortedError);
	});
});

describe("PowAuthDanceComponent", () => {
	it("should be a challenge that proves nothing and has no verification", () => {
		const pow = new PowAuthDanceComponent();
		deepEqual(pow.kind, "challenge");
		deepEqual(pow.verifiable, false);
		deepEqual(pow.proves, false);
	});

	it("should refuse a difficulty outside the digest and a time to live that is not positive", () => {
		throws(() => new PowAuthDanceComponent({ difficulty: 0 }), TypeError);
		throws(() => new PowAuthDanceComponent({ difficulty: 257 }), TypeError);
		throws(() => new PowAuthDanceComponent({ difficulty: 1.5 }), TypeError);
		throws(() => new PowAuthDanceComponent({ difficulty: 161, algorithm: "SHA-1" }), TypeError);
		throws(() => new PowAuthDanceComponent({ ttl: 0 }), TypeError);
	});

	it("should give back the same challenge until a nonce answers it", async () => {
		const pow = new PowAuthDanceComponent({ difficulty: 6 });
		const ctx = context();
		const first = promptOptions(await pow.getPrompt(ctx));
		deepEqual(promptOptions(await pow.getPrompt(ctx)), first);
		deepEqual(first.difficulty, 6);
		deepEqual(first.algorithm, "SHA-256");
		const other = promptOptions(await pow.getPrompt(context(ctx.storage, "state_other")));
		ok(other.challenge !== first.challenge);
	});

	it("should accept a nonce one time only", async () => {
		const pow = new PowAuthDanceComponent({ difficulty: 6 });
		const ctx = context();
		const { challenge, difficulty } = promptOptions(await pow.getPrompt(ctx));
		const nonce = await work(challenge, difficulty);
		deepEqual(await pow.verifyPrompt(nonce, ctx), true);
		deepEqual(await pow.verifyPrompt(nonce, ctx), false);
	});

	it("should drop the challenge after a wrong nonce", async () => {
		const pow = new PowAuthDanceComponent({ difficulty: 6 });
		const ctx = context();
		const { challenge, difficulty } = promptOptions(await pow.getPrompt(ctx));
		deepEqual(await pow.verifyPrompt("not a nonce", ctx), false);
		deepEqual(await pow.verifyPrompt(await work(challenge, difficulty), ctx), false);
		ok(promptOptions(await pow.getPrompt(ctx)).challenge !== challenge);
	});

	it("should refuse a nonce before any prompt", async () => {
		deepEqual(await new PowAuthDanceComponent().verifyPrompt(0, context()), false);
	});

	it("should check the nonce when it builds the record", async () => {
		const pow = new PowAuthDanceComponent({ difficulty: 6 });
		const ctx = context();
		const { challenge, difficulty } = promptOptions(await pow.getPrompt(ctx));
		await rejects(pow.getIdentityComponent("pow", -1, false, ctx), InvalidPromptValueError);
		const fresh = promptOptions(await pow.getPrompt(ctx));
		ok(fresh.challenge !== challenge);
		deepEqual(await pow.getIdentityComponent("pow", await work(fresh.challenge, difficulty), false, ctx), [
			{ kind: "challenge", component: "pow", confirmed: false },
		]);
	});

	describe("in a dance", () => {
		it("should sign up and sign in with the proof of work before the identification", async () => {
			const store = storage();
			const auth = api(store);
			const created = await dance(auth, await auth.signUp(), { username: "john", password: "correct horse" });
			ok("tokens" in created);
			const signedIn = await dance(auth, await auth.signIn(), { username: "john", password: "correct horse" });
			ok("tokens" in signedIn);
			deepEqual(signedIn.identity.id, created.identity.id);
		});

		it("should refuse a sign-in with a wrong nonce", async () => {
			const auth = api(storage());
			const started = await auth.signIn();
			await rejects(
				() => auth.submitPrompt({ name: "pow", value: -1, state: started.state }),
				(error) => error instanceof AuthDanceError && error.code === "INVALID_PROMPT_VALUE",
			);
		});
	});
});
