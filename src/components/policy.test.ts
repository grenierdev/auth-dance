import { deepEqual, ok, rejects, throws } from "node:assert";
import { describe, it } from "vitest";
import { AuthDanceApi } from "../api.ts";
import { type AuthDanceChoreography, sequence } from "../choreography.ts";
import type { AuthDanceComponent, AuthDanceComponentContext } from "../component.ts";
import { IdentityNotResolvedError, InvalidPromptValueError } from "../error.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent } from "../identity.ts";
import { MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "../providers/memory.ts";
import type { AuthDanceResponse, AuthDanceResponseTokens } from "../response.ts";
import { AuthDanceStorage } from "../storage.ts";
import { PasswordAuthDanceComponent, pbkdf2PasswordHasher } from "./password.ts";
import { type Policy, PolicyAuthDanceComponent } from "./policy.ts";

const PEPPER = "tQ3vX9pL2mR7wK5nB8cF1hJ4dG6sA0zE";
const SECRET = "zdJXI1jwuXW8A19fns0E_B4HSYm7AUHLGlU9WLo8mxs";

function policies(tos = "1"): Policy[] {
	return [
		{ identifier: "tos", version: tos, required: true, name: { en: "Terms" }, content: { en: "https://example.com/tos" } },
		{ identifier: "newsletter", version: "1", required: false, name: { en: "Newsletter" }, content: { en: "Monthly news." } },
	];
}

function storage(): AuthDanceStorage {
	return new AuthDanceStorage({
		identity: new MemoryIdentityProvider(),
		kv: new MemoryKvProvider(),
		rate_limiter: new MemoryRateLimiterProvider(),
	});
}

function record(data: Record<string, unknown>): AuthDanceIdentityComponent {
	return { kind: "challenge", component: "policy", confirmed: true, data };
}

function context(components: AuthDanceIdentityComponent[] = [], flow = "sign-in"): AuthDanceComponentContext {
	const identity: AuthDanceIdentity = { id: "id_test", components };
	return { storage: storage(), stateId: "state_test", name: "policy", flow, identity };
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

function api(
	store: AuthDanceStorage,
	tos = "1",
	choreography: AuthDanceChoreography = sequence("username", "password", "policy"),
): AuthDanceApi {
	return new AuthDanceApi({
		channels: {},
		choreography,
		components: {
			username,
			password: new PasswordAuthDanceComponent(PEPPER, pbkdf2PasswordHasher(1)),
			policy: new PolicyAuthDanceComponent({ policies: policies(tos) }),
		},
		secret: SECRET,
		storage: store,
	});
}

/** Answers every prompt with the value under its name, until the dance ends. `prompted` gets the name of each prompt. */
async function dance(
	target: AuthDanceApi,
	response: AuthDanceResponse,
	answers: Record<string, unknown>,
	prompted: string[] = [],
): Promise<AuthDanceResponse> {
	while ("prompt" in response) {
		ok(response.prompt.kind === "input");
		const name = response.prompt.name;
		prompted.push(name);
		response = await target.submitPrompt({ name, value: answers[name], state: response.state });
	}
	return response;
}

async function policyData(store: AuthDanceStorage, identityId: string): Promise<Record<string, unknown> | undefined> {
	const identity = await store.getIdentity(identityId);
	return identity?.components.find((c) => c.component === "policy")?.data;
}

describe("PolicyAuthDanceComponent", () => {
	it("should be a skippable challenge that proves nothing and has no verification", () => {
		const policy = new PolicyAuthDanceComponent({ policies: policies() });
		deepEqual(policy.kind, "challenge");
		deepEqual(policy.verifiable, false);
		deepEqual(policy.proves, false);
		deepEqual(policy.skippable, true);
	});

	it("should prompt with every document under the component name", async () => {
		const policy = new PolicyAuthDanceComponent({ policies: policies() });
		deepEqual(await policy.getPrompt(context()), {
			kind: "input",
			name: "policy",
			type: "policy",
			sendable: false,
			options: { policies: policies() },
		});
	});

	it("should keep its own copy of the documents", async () => {
		const declared = policies();
		const policy = new PolicyAuthDanceComponent({ policies: declared });
		declared[0].version = "9";
		const prompt = await policy.getPrompt(context());
		(prompt.options!.policies as Policy[])[0].version = "8";
		deepEqual(await policy.verifyPrompt({ tos: "1" }, context()), true);
		deepEqual(await policy.verifyPrompt({ tos: "9" }, context()), false);
		deepEqual(await policy.verifyPrompt({ tos: "8" }, context()), false);
	});

	it("should refuse a list of documents it cannot check", () => {
		const [tos, newsletter] = policies();
		throws(() => new PolicyAuthDanceComponent({ policies: [] }), TypeError);
		throws(() => new PolicyAuthDanceComponent({ policies: [{ ...tos, identifier: "" }] }), TypeError);
		throws(() => new PolicyAuthDanceComponent({ policies: [{ ...tos, version: "" }] }), TypeError);
		throws(() => new PolicyAuthDanceComponent({ policies: [{ ...tos, required: "yes" as unknown as boolean }] }), TypeError);
		throws(() => new PolicyAuthDanceComponent({ policies: [tos, { ...newsletter, identifier: "tos" }] }), TypeError);
	});

	it("should record the accepted version of each document", async () => {
		const policy = new PolicyAuthDanceComponent({ policies: policies() });
		deepEqual(await policy.getIdentityComponent("policy", { tos: "1", newsletter: "1" }, false, context([], "sign-up")), [
			{ kind: "challenge", component: "policy", confirmed: false, data: { tos: "1", newsletter: "1" } },
		]);
		deepEqual(await policy.getIdentityComponent("policy", { tos: "1" }, true, context([], "sign-up")), [
			{ kind: "challenge", component: "policy", confirmed: true, data: { tos: "1" } },
		]);
	});

	it("should refuse to record an answer that is malformed, unknown, out of date or incomplete", async () => {
		const policy = new PolicyAuthDanceComponent({ policies: policies() });
		const values: unknown[] = [
			undefined,
			null,
			"tos",
			["tos"],
			{ tos: 1 },
			{ tos: "1", other: "1" },
			{ tos: "0" },
			{ newsletter: "1" },
			{},
		];
		for (const value of values) {
			await rejects(policy.getIdentityComponent("policy", value, false, context([], "sign-up")), InvalidPromptValueError);
		}
	});

	it("should keep the acceptance the identity holds when a rotate adds to it", async () => {
		const policy = new PolicyAuthDanceComponent({ policies: policies() });
		deepEqual(await policy.getIdentityComponent("policy", { newsletter: "1" }, false, context([record({ tos: "1" })], "rotate")), [
			{ kind: "challenge", component: "policy", confirmed: false, data: { tos: "1", newsletter: "1" } },
		]);
	});

	it("should accept an answer when it and the stored record accept every required document", async () => {
		const policy = new PolicyAuthDanceComponent({ policies: policies() });
		deepEqual(await policy.verifyPrompt({ tos: "1" }, context()), true);
		deepEqual(await policy.verifyPrompt({ tos: "1", newsletter: "1" }, context()), true);
		deepEqual(await policy.verifyPrompt({}, context([record({ tos: "1" })])), true);
		deepEqual(await policy.verifyPrompt({ newsletter: "1" }, context([record({ tos: "1" })])), true);
	});

	it("should reject an answer that leaves a required document without its current version", async () => {
		const policy = new PolicyAuthDanceComponent({ policies: policies("2") });
		deepEqual(await policy.verifyPrompt({}, context()), false);
		deepEqual(await policy.verifyPrompt({ newsletter: "1" }, context()), false);
		deepEqual(await policy.verifyPrompt({}, context([record({ tos: "1" })])), false);
		deepEqual(await policy.verifyPrompt({ tos: "1" }, context([record({ tos: "1" })])), false);
		deepEqual(await policy.verifyPrompt({ tos: "2", other: "1" }, context()), false);
		deepEqual(await policy.verifyPrompt("tos", context()), false);
		deepEqual(await policy.verifyPrompt(null, context()), false);
	});

	it("should save a new acceptance, and nothing when the answer adds nothing", async () => {
		const policy = new PolicyAuthDanceComponent({ policies: policies("2") });
		const stored = { ...record({ tos: "1", newsletter: "1" }), linkedTo: ["kept"] };
		deepEqual(await policy.upgradeIdentityComponent({ tos: "2" }, context([stored])), [
			{ kind: "challenge", component: "policy", confirmed: true, linkedTo: ["kept"], data: { tos: "2", newsletter: "1" } },
		]);
		deepEqual(await policy.upgradeIdentityComponent({}, context([record({ tos: "2" })])), undefined);
		deepEqual(await policy.upgradeIdentityComponent({ tos: "2" }, context([record({ tos: "2" })])), undefined);
		deepEqual(await policy.upgradeIdentityComponent("tos", context([record({ tos: "1" })])), undefined);
	});

	it("should give a record to an identity that holds none", async () => {
		const policy = new PolicyAuthDanceComponent({ policies: policies() });
		deepEqual(await policy.upgradeIdentityComponent({ tos: "1" }, context()), [
			{ kind: "challenge", component: "policy", confirmed: true, data: { tos: "1" } },
		]);
	});

	it("should skip the step for an identity that accepted every required document", async () => {
		const policy = new PolicyAuthDanceComponent({ policies: policies("2") });
		deepEqual(await policy.skipPrompt(context([record({ tos: "2" })])), true);
		deepEqual(await policy.skipPrompt(context([record({ tos: "2", newsletter: "1" })])), true);
		deepEqual(await policy.skipPrompt(context([record({ tos: "1", newsletter: "1" })])), false);
		deepEqual(await policy.skipPrompt(context([record({ newsletter: "1" })])), false);
		deepEqual(await policy.skipPrompt(context([{ ...record({ tos: "2" }), confirmed: false }])), false);
		deepEqual(await policy.skipPrompt(context()), false);
	});

	it("should skip a step of optional documents only for an identity that holds a record of it", async () => {
		const policy = new PolicyAuthDanceComponent({ policies: [policies()[1]] });
		deepEqual(await policy.skipPrompt(context([record({})])), true);
		deepEqual(await policy.skipPrompt(context()), false);
	});

	describe("in a dance", () => {
		it("should record the acceptance on sign-up, and skip the step on the next sign-in", async () => {
			const store = storage();
			const auth = api(store);
			const created = await dance(auth, await auth.signUp(), { username: "john", password: "correct horse", policy: { tos: "1" } });
			ok("tokens" in created);
			deepEqual(await policyData(store, created.identity.id), { tos: "1" });

			const prompted: string[] = [];
			const signedIn = await dance(auth, await auth.signIn(), { username: "john", password: "correct horse" }, prompted);
			ok("tokens" in signedIn);
			deepEqual(signedIn.identity.id, created.identity.id);
			deepEqual(prompted, ["username", "password"]);
		});

		it("should ask for the new version of a required document and save it", async () => {
			const store = storage();
			const before = api(store, "1");
			const created = await dance(before, await before.signUp(), { username: "john", password: "correct horse", policy: { tos: "1" } });
			ok("tokens" in created);

			const after = api(store, "2");
			await rejects(
				dance(after, await after.signIn(), { username: "john", password: "correct horse", policy: {} }),
				InvalidPromptValueError,
			);
			const prompted: string[] = [];
			const signedIn = await dance(
				after,
				await after.signIn(),
				{ username: "john", password: "correct horse", policy: { tos: "2" } },
				prompted,
			);
			ok("tokens" in signedIn);
			deepEqual(prompted, ["username", "password", "policy"]);
			deepEqual(await policyData(store, created.identity.id), { tos: "2" });

			// The new version is on record, so the next sign-in skips the step again.
			const again: string[] = [];
			ok("tokens" in (await dance(after, await after.signIn(), { username: "john", password: "correct horse" }, again)));
			deepEqual(again, ["username", "password"]);
		});

		it("should give a record to an identity that signed up before the step existed", async () => {
			const store = storage();
			const before = api(store, "1", sequence("username", "password"));
			const created = await dance(before, await before.signUp(), { username: "john", password: "correct horse" });
			ok("tokens" in created);
			deepEqual(await policyData(store, created.identity.id), undefined);

			const after = api(store);
			const prompted: string[] = [];
			const signedIn = await dance(
				after,
				await after.signIn(),
				{ username: "john", password: "correct horse", policy: { tos: "1" } },
				prompted,
			);
			ok("tokens" in signedIn);
			deepEqual(prompted, ["username", "password", "policy"]);
			deepEqual(await policyData(store, created.identity.id), { tos: "1" });
		});

		it("should let a rotate accept an optional document later", async () => {
			const store = storage();
			const auth = api(store);
			const created = (await dance(auth, await auth.signUp(), {
				username: "john",
				password: "correct horse",
				policy: { tos: "1" },
			})) as AuthDanceResponseTokens;
			const rotate = await auth.rotate({ name: "policy", access_token: created.tokens.access_token });
			ok(rotate.prompt.kind === "input" && rotate.prompt.type === "policy");
			deepEqual(await dance(auth, rotate, { policy: { newsletter: "1" } }), { success: true });
			deepEqual(await policyData(store, created.identity.id), { tos: "1", newsletter: "1" });
		});

		it("should not skip the step before a step that proves control", async () => {
			const store = storage();
			const auth = api(store, "1", sequence("username", "policy", "password"));
			const created = await dance(auth, await auth.signUp(), { username: "john", password: "correct horse", policy: { tos: "1" } });
			ok("tokens" in created);
			const prompted: string[] = [];
			ok("tokens" in (await dance(auth, await auth.signIn(), { username: "john", password: "correct horse", policy: {} }, prompted)));
			deepEqual(prompted, ["username", "policy", "password"]);
		});

		it("should not resolve an identity as the first step of a sign-in", async () => {
			const auth = api(storage(), "1", sequence("policy", "username", "password"));
			await rejects(dance(auth, await auth.signIn(), { policy: { tos: "1" } }), IdentityNotResolvedError);
		});
	});
});
