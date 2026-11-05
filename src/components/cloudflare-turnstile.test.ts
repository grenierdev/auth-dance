import { deepEqual, ok, rejects, throws } from "node:assert";
import { afterEach, beforeEach, describe, it, vi } from "vitest";
import { AuthDanceApi } from "../api.ts";
import { sequence } from "../choreography.ts";
import type { AuthDanceComponent, AuthDanceComponentContext } from "../component.ts";
import { AuthDanceError, InvalidPromptValueError } from "../error.ts";
import { TEST_ISSUER, TEST_SIGNING_KEYS } from "../fixtures.test.ts";
import { MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "../providers/memory.ts";
import type { AuthDanceResponse } from "../response.ts";
import { AuthDanceStorage } from "../storage.ts";
import {
	CloudflareTurnstileAuthDanceComponent,
	type CloudflareTurnstileAuthDanceComponentOptions,
	TURNSTILE_SITEVERIFY_URL,
} from "./cloudflare-turnstile.ts";
import { PasswordAuthDanceComponent, pbkdf2PasswordHasher } from "./password.ts";

const PEPPER = "tQ3vX9pL2mR7wK5nB8cF1hJ4dG6sA0zE";
const SECRET = "zdJXI1jwuXW8A19fns0E_B4HSYm7AUHLGlU9WLo8mxs";
const SITE_KEY = "1x00000000000000000000AA";
const SECRET_KEY = "1x0000000000000000000000000000000AA";
const GOOD_TOKEN = "good-token";

function storage(): AuthDanceStorage {
	return new AuthDanceStorage({
		identity: new MemoryIdentityProvider(),
		kv: new MemoryKvProvider(),
		rate_limiter: new MemoryRateLimiterProvider(),
	});
}

function context(store = storage()): AuthDanceComponentContext {
	return { storage: store, stateId: "state_test", name: "turnstile", flow: "sign-up" };
}

function turnstile(options: Partial<CloudflareTurnstileAuthDanceComponentOptions> = {}): CloudflareTurnstileAuthDanceComponent {
	return new CloudflareTurnstileAuthDanceComponent({ siteKey: SITE_KEY, secretKey: SECRET_KEY, ...options });
}

/**
 * A siteverify endpoint that accepts `GOOD_TOKEN` one time only, as Cloudflare does. `answer` overrides the fields of
 * a success.
 */
function siteverify(answer: Record<string, unknown> = {}) {
	const spent = new Set<string>();
	return vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
		ok(String(url) === TURNSTILE_SITEVERIFY_URL, `unexpected fetch to ${url}`);
		const body = JSON.parse(String(init?.body));
		deepEqual(body.secret, SECRET_KEY);
		if (body.response !== GOOD_TOKEN || spent.has(body.response)) {
			return Response.json({ success: false, "error-codes": ["invalid-input-response"] });
		}
		spent.add(body.response);
		return Response.json({ success: true, hostname: "app.example.com", action: "sign-in", ...answer });
	});
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
		choreography: sequence("turnstile", "username", "password"),
		components: {
			turnstile: turnstile(),
			username,
			password: new PasswordAuthDanceComponent(PEPPER, pbkdf2PasswordHasher(1)),
		},
		secret: SECRET,
		keys: TEST_SIGNING_KEYS,
		tokens: { issuer: TEST_ISSUER },
		storage: store,
	});
}

/** Answers every prompt until the dance ends. A `turnstile` prompt gets `GOOD_TOKEN`, every other prompt its answer. */
async function dance(target: AuthDanceApi, response: AuthDanceResponse, answers: Record<string, unknown>): Promise<AuthDanceResponse> {
	while ("prompt" in response) {
		ok(response.prompt.kind === "input");
		const { name, type } = response.prompt;
		const value = type === "turnstile" ? GOOD_TOKEN : answers[name];
		response = await target.submitPrompt({ name, value, state: response.state });
	}
	return response;
}

describe("CloudflareTurnstileAuthDanceComponent", () => {
	let fetch: ReturnType<typeof siteverify>;

	beforeEach(() => {
		fetch = siteverify();
		vi.stubGlobal("fetch", fetch);
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it("should be a challenge that proves nothing and has no verification", () => {
		const component = turnstile();
		deepEqual(component.kind, "challenge");
		deepEqual(component.verifiable, false);
		deepEqual(component.proves, false);
	});

	it("should refuse empty keys, a bad action, no hostname and a time to wait that is not positive", () => {
		throws(() => turnstile({ siteKey: "" }), TypeError);
		throws(() => turnstile({ secretKey: "" }), TypeError);
		throws(() => turnstile({ action: "" }), TypeError);
		throws(() => turnstile({ action: "a".repeat(33) }), TypeError);
		throws(() => turnstile({ action: "sign in" }), TypeError);
		throws(() => turnstile({ hostnames: [] }), TypeError);
		throws(() => turnstile({ timeout: 0 }), TypeError);
	});

	it("should give the site key and the action to the client, and never the secret key", async () => {
		deepEqual(await turnstile().getPrompt(context()), {
			kind: "input",
			name: "turnstile",
			type: "turnstile",
			sendable: false,
			options: { siteKey: SITE_KEY },
		});
		deepEqual((await turnstile({ action: "sign-in" }).getPrompt(context())).options, { siteKey: SITE_KEY, action: "sign-in" });
	});

	it("should accept a token one time only", async () => {
		const component = turnstile();
		deepEqual(await component.verifyPrompt(GOOD_TOKEN, context()), true);
		deepEqual(await component.verifyPrompt(GOOD_TOKEN, context()), false);
	});

	it("should refuse a value that cannot be a token without a request", async () => {
		const component = turnstile();
		for (const value of [undefined, 42, "", "x".repeat(2049)]) {
			deepEqual(await component.verifyPrompt(value, context()), false);
		}
		deepEqual(fetch.mock.calls.length, 0);
	});

	it("should refuse a token for another action or another hostname", async () => {
		deepEqual(await turnstile({ action: "sign-up" }).verifyPrompt(GOOD_TOKEN, context()), false);
		vi.stubGlobal("fetch", siteverify());
		deepEqual(await turnstile({ hostnames: ["other.example.com"] }).verifyPrompt(GOOD_TOKEN, context()), false);
		vi.stubGlobal("fetch", siteverify());
		deepEqual(
			await turnstile({ action: "sign-in", hostnames: ["other.example.com", "app.example.com"] }).verifyPrompt(GOOD_TOKEN, context()),
			true,
		);
	});

	it("should raise an error, and not refuse the value, when the siteverify endpoint fails", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => new Response("unavailable", { status: 503 })),
		);
		await rejects(turnstile().verifyPrompt(GOOD_TOKEN, context()), (error) => !(error instanceof AuthDanceError));
	});

	it("should check the token when it builds the record", async () => {
		const component = turnstile();
		await rejects(component.getIdentityComponent("turnstile", "bad-token", false, context()), InvalidPromptValueError);
		deepEqual(await component.getIdentityComponent("turnstile", GOOD_TOKEN, false, context()), [
			{ kind: "challenge", component: "turnstile", confirmed: false },
		]);
	});

	describe("in a dance", () => {
		it("should sign up and sign in with the challenge before the identification", async () => {
			const store = storage();
			const auth = api(store);
			const created = await dance(auth, await auth.signUp(), { username: "john", password: "correct horse" });
			ok("tokens" in created);
			vi.stubGlobal("fetch", siteverify());
			const signedIn = await dance(auth, await auth.signIn(), { username: "john", password: "correct horse" });
			ok("tokens" in signedIn);
			deepEqual(signedIn.identity.id, created.identity.id);
		});

		it("should refuse a sign-in with a bad token", async () => {
			const auth = api(storage());
			const started = await auth.signIn();
			await rejects(
				() => auth.submitPrompt({ name: "turnstile", value: "bad-token", state: started.state }),
				(error) => error instanceof AuthDanceError && error.code === "INVALID_PROMPT_VALUE",
			);
		});
	});
});
