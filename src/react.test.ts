/// <reference lib="dom" />

// jsdom first: it puts a document on the global scope, and react-dom reads that scope the moment it loads.
import "global-jsdom/register";
import { afterEach, beforeEach, describe, it } from "@std/testing/bdd";
import { assert, assertEquals, assertThrows } from "@std/assert";
// @deno-types="npm:@types/react@^19.2.17"
import { act, type ChangeEvent, createElement, type ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryAuthDanceChannel, MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "./providers/memory.ts";
import type { AuthDanceApiOptions } from "./api.ts";
import { choice, sequence } from "./choreography.ts";
import { EmailAuthDanceComponent } from "./components/email.ts";
import { OtpAuthDanceComponent } from "./components/otp.ts";
import { PasswordAuthDanceComponent, pbkdf2PasswordHasher } from "./components/password.ts";
import type { AuthDanceComponentContext } from "./component.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent } from "./identity.ts";
import { ksuid } from "./id.ts";
import { AuthDanceStorage } from "./storage.ts";
import { type AuthDance, createAuthDance } from "./mod.ts";
import { AuthDanceClient, type AuthDanceClientChoreographyStore, webStorageStore } from "./client.ts";
import {
	type AuthDanceFlow,
	type AuthDanceFlowHandle,
	AuthDanceFlowProvider,
	type AuthDancePromptInput,
	AuthDancePromptSwitch,
	AuthDanceProvider,
	type AuthDanceResponse,
	useAuthDanceIdentity,
} from "./react.ts";

// React only runs its act queue when the environment says a test drives it.
// deno-lint-ignore no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

// One PBKDF2 pass, to keep the suites fast.
const TEST_PASSWORD_HASHER = pbkdf2PasswordHasher(1);

const h = createElement;

// These cases drive the flows of client.test.ts through a rendered tree, over the HTTP edge of the same instance.
describe("React", () => {
	let storage: AuthDanceStorage;
	let apiOptions: AuthDanceApiOptions;
	let auth: AuthDance;
	let client: AuthDanceClient;
	let channelEmail: MemoryAuthDanceChannel;
	let channelEmail2: MemoryAuthDanceChannel;
	let channelSms: MemoryAuthDanceChannel;
	let email: EmailAuthDanceComponent;
	let email2: EmailAuthDanceComponent;
	let password: PasswordAuthDanceComponent;

	function build(options?: Partial<AuthDanceApiOptions>): AuthDanceClient {
		auth = createAuthDance({ api: { ...apiOptions, ...options } });
		client = new AuthDanceClient({ baseUrl: "http://local", fetch: auth.fetch });
		return client;
	}

	// Seeds an identity outside a flow. The password record is salted with the id, so the id comes first.
	async function seedIdentity(
		build: (seed: (name: string) => AuthDanceComponentContext) => Promise<AuthDanceIdentityComponent[]>,
	): Promise<AuthDanceIdentity> {
		const identity: AuthDanceIdentity = { id: ksuid("id_"), data: { name: "John Doe" }, components: [] };
		identity.components = await build((name) => ({ storage, stateId: "state_seed", name, flow: "sign-up", identity }));
		await storage.setIdentity(identity);
		return identity;
	}

	// The identity every management case starts from: an address, a password and a phone number.
	function seedJohnDoe(): Promise<AuthDanceIdentity> {
		return seedIdentity(async (seed) => [
			...await email.getIdentityComponent("email", "john.doe@example.com", true),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
			await channelSms.getIdentityChannel("sms", "5551234567", true),
		]);
	}

	// The management cases all start from an authenticated owner, so each one replays this sign-in first.
	async function signIn(): Promise<void> {
		using choreography = await client.signIn();
		await choreography.submitPrompt("john.doe@example.com");
		await choreography.submitPrompt("foo");
		assert(choreography.done);
	}

	// The bare one-time code of the last message a channel took.
	function lastCode(channel: MemoryAuthDanceChannel): string {
		const code = (channel.messages.at(-1)?.content as Record<string, string> | undefined)?.["text/x-code"];
		assert(code, "the channel took no one-time code");
		return code;
	}

	beforeEach(() => {
		localStorage.clear();
		channelEmail = new MemoryAuthDanceChannel("email");
		channelEmail2 = new MemoryAuthDanceChannel("email2");
		channelSms = new MemoryAuthDanceChannel("phone");
		email = new EmailAuthDanceComponent({ channel: "email", challenge: "otp" });
		email2 = new EmailAuthDanceComponent({ channel: "email2", challenge: "otp2" });
		password = new PasswordAuthDanceComponent("salty", TEST_PASSWORD_HASHER);
		storage = new AuthDanceStorage({
			identity: new MemoryIdentityProvider(),
			kv: new MemoryKvProvider(),
			rate_limiter: new MemoryRateLimiterProvider(),
		});
		apiOptions = {
			channels: { email: channelEmail, email2: channelEmail2, sms: channelSms },
			choreography: sequence("email", "password"),
			components: {
				email,
				email2,
				password,
				otp: new OtpAuthDanceComponent({ channel: "email" }),
				otp2: new OtpAuthDanceComponent({ channel: "email2" }),
			},
			secret: "zdJXI1jwuXW8A19fns0E_B4HSYm7AUHLGlU9WLo8mxs", // openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
			storage,
		};
		build();
	});

	afterEach(() => {
		cleanup();
	});

	it("should sign in through the rendered prompts", async () => {
		const identity = await seedJohnDoe();
		render(page({ client, flow: "sign-in" }));

		await answer("email", "john.doe@example.com");
		await answer("password", "foo");

		await waitFor(() => assertEquals(screen.getByTestId("identity").textContent, identity.id));
		assertEquals(screen.getByTestId("done").textContent, "done");
		assertEquals(client.identity?.id, identity.id);
	});

	it("should render the start of the flow only once the call answers", async () => {
		await seedJohnDoe();
		render(page({ client, flow: "sign-in", fallback: true }));

		// The fallback stands in for the children until the dance holds its first prompt.
		assert(screen.queryByTestId("starting"));
		await waitFor(() => assert(screen.queryByTestId("prompt-email")));
		assertEquals(screen.queryByTestId("starting"), null);
	});

	it("should keep the failure the library named, and drop it on demand", async () => {
		await seedJohnDoe();
		render(page({ client, flow: "sign-in" }));

		await answer("email", "john.doe@example.com");
		await answer("password", "wrong");
		await waitFor(() => assertEquals(screen.getByTestId("error").textContent, "InvalidPromptValueError"));

		// The flow does not advance, so the same step answers again.
		assert(screen.queryByTestId("prompt-password"));
		await gesture(() => fireEvent.click(screen.getByTestId("clear-error")));
		assertEquals(screen.queryByTestId("error"), null);

		await answer("password", "foo");
		await waitFor(() => assert(screen.queryByTestId("done")));
	});

	it("should take one branch of a choice", async () => {
		build({ choreography: choice(sequence("email", "password"), "email2") });
		await seedIdentity(async (seed) => [
			...await email2.getIdentityComponent("email2", "john.doe@example.com", true),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
		render(page({ client, flow: "sign-in" }));

		await waitFor(() => assert(screen.queryByTestId("choice")));
		await gesture(() => fireEvent.click(screen.getByTestId("choose-email2")));

		await waitFor(() => assert(screen.queryByTestId("prompt-email2")));
		await answer("email2", "john.doe@example.com");
		await waitFor(() => assert(screen.queryByTestId("done")));
	});

	it("should deliver a one-time code during a sign-up", async () => {
		render(page({ client, flow: "sign-up" }));

		await answer("email", "john.doe@example.com");
		await waitFor(() => assert(screen.queryByTestId("send")));

		await gesture(() => fireEvent.click(screen.getByTestId("send")));
		await waitFor(() => assertEquals(channelEmail.messages.length, 1));

		await answer("email", lastCode(channelEmail));
		await answer("password", "bar");
		await waitFor(() => assert(screen.queryByTestId("done")));
		assert(client.identity?.id);
	});

	it("should go back one step", async () => {
		await seedJohnDoe();
		render(page({ client, flow: "sign-in" }));

		await answer("email", "john.doe@example.com");
		await waitFor(() => assert(screen.queryByTestId("prompt-password")));

		await gesture(() => fireEvent.click(screen.getByTestId("prev")));
		await waitFor(() => assert(screen.queryByTestId("prompt-email")));
	});

	it("should resume a dance out of a store", async () => {
		await seedJohnDoe();
		const store: AuthDanceClientChoreographyStore = webStorageStore("choreography", localStorage);
		render(page({ client, flow: "sign-in", store }));

		await answer("email", "john.doe@example.com");
		await waitFor(() => assert(screen.queryByTestId("prompt-password")));

		// A page that reloads reads the same store, so the dance goes on from the step it left.
		cleanup();
		render(page({ client, flow: "sign-in", store }));
		await waitFor(() => assert(screen.queryByTestId("prompt-password")));

		await answer("password", "foo");
		await waitFor(() => assert(screen.queryByTestId("done")));
		assertEquals(localStorage.getItem("choreography"), null);
	});

	it("should rotate a component for an authenticated owner", async () => {
		const identity = await seedJohnDoe();
		await signIn();
		const before = (await storage.getIdentity(identity.id))?.components
			.find((c) => c.kind === "challenge" && c.component === "password");

		render(page({ client, flow: "rotate", name: "password" }));
		await answer("password", "bar");
		await waitFor(() => assert(screen.queryByTestId("done")));

		const after = (await storage.getIdentity(identity.id))?.components
			.find((c) => c.kind === "challenge" && c.component === "password");
		assert(after?.data?.hash !== before?.data?.hash);
	});

	it("should confirm a delete and drop the tokens", async () => {
		const identity = await seedJohnDoe();
		await signIn();
		const answered: AuthDanceResponse[] = [];
		render(page({ client, flow: "delete", onDone: (response) => answered.push(response) }));

		// The prompt is named `identity` and typed `confirmation`, so the switch falls back to the type.
		await waitFor(() => assert(screen.queryByTestId("prompt-identity")));
		await gesture(() => fireEvent.click(screen.getByTestId("confirm")));

		await waitFor(() => assertEquals(screen.getByTestId("identity").textContent, "anonymous"));
		assertEquals(answered.length, 1);
		assert("success" in answered[0]);
		assertEquals(client.tokens, undefined);
		assertEquals(await storage.getIdentity(identity.id), undefined);
	});

	it("should hold the flow back while it is turned off", async () => {
		await seedJohnDoe();
		render(page({ client, flow: "sign-in", enabled: false }));

		await waitFor(() => assertEquals(screen.getByTestId("fallback").textContent, "over"));
		assertEquals(screen.queryByTestId("prompt-email"), null);
	});

	it("should refuse a hook with no client above it", () => {
		const reported = console.error;
		console.error = () => {};
		try {
			assertThrows(() => render(h(Identity, null)), TypeError);
		} finally {
			console.error = reported;
		}
	});
});

// The page every case renders: the identity of the session, and the flow under it.
function page(options: {
	client: AuthDanceClient;
	flow: AuthDanceFlow;
	name?: string;
	store?: AuthDanceClientChoreographyStore;
	enabled?: boolean;
	fallback?: boolean;
	onDone?: (response: AuthDanceResponse) => void;
}): ReactNode {
	return h(
		AuthDanceProvider,
		{ client: options.client },
		h(Identity, { key: "identity" }),
		h(
			AuthDanceFlowProvider,
			{
				key: "flow",
				flow: options.flow,
				name: options.name,
				store: options.store,
				enabled: options.enabled,
				onDone: options.onDone,
				fallback: options.fallback ? h("p", { "data-testid": "starting" }, "starting") : undefined,
				children: (flow: AuthDanceFlowHandle) => h(Steps, { flow }),
			},
		),
	);
}

function Identity(): ReactNode {
	const identity = useAuthDanceIdentity();
	return h("p", { "data-testid": "identity" }, identity?.id ?? "anonymous");
}

function Steps({ flow }: { flow: AuthDanceFlowHandle }): ReactNode {
	return h(
		"div",
		null,
		flow.error ? h("p", { key: "error", "data-testid": "error" }, (flow.error as Error).name) : null,
		flow.done ? h("p", { key: "done", "data-testid": "done" }, "done") : null,
		h(AuthDancePromptSwitch, {
			key: "switch",
			flow,
			choice: (choices, handle) =>
				h(
					"ul",
					{ "data-testid": "choice" },
					choices.map((branch) =>
						h(
							"li",
							{ key: branch.name },
							h("button", {
								type: "button",
								"data-testid": `choose-${branch.name}`,
								onClick: () => void handle.choose(branch.name),
							}, branch.name),
						)
					),
				),
			prompts: { email: input, password: input, otp: input, confirmation: confirmation },
			fallback: (prompt) => h("p", { "data-testid": "fallback" }, prompt ? prompt.kind : "over"),
		}),
		h("button", { key: "prev", type: "button", "data-testid": "prev", onClick: () => void flow.prev() }, "back"),
		h("button", { key: "clear", type: "button", "data-testid": "clear-error", onClick: () => flow.clearError() }, "clear"),
	);
}

// One text input, and the button that asks the library to deliver the value when it can.
function input(prompt: AuthDancePromptInput, flow: AuthDanceFlowHandle): ReactNode {
	return h(
		"div",
		{ "data-testid": `prompt-${prompt.name}` },
		// A new key on every step, so the input never carries the value of the step before it.
		h("input", {
			key: `${prompt.name}-${flow.trail.length}`,
			"data-testid": "value",
			onChange: (event: ChangeEvent<HTMLInputElement>) => void flow.submitPrompt(event.target.value),
		}),
		prompt.sendable
			? h("button", { key: "send", type: "button", "data-testid": "send", onClick: () => void flow.sendPrompt({ locale: "en" }) }, "send")
			: null,
	);
}

function confirmation(prompt: AuthDancePromptInput, flow: AuthDanceFlowHandle): ReactNode {
	return h(
		"div",
		{ "data-testid": `prompt-${prompt.name}` },
		h("button", { type: "button", "data-testid": "confirm", onClick: () => void flow.confirm() }, "confirm"),
	);
}

// React flushes the answer of an action only when the scope of `act` returns a promise, so every gesture goes through here.
async function gesture(run: () => void): Promise<void> {
	await act(async () => {
		run();
		await Promise.resolve();
	});
}

// Types a value into the step and waits for the answer to land.
async function answer(name: string, value: string): Promise<void> {
	await waitFor(() => assert(screen.queryByTestId(`prompt-${name}`)));
	const field = screen.getByTestId(`prompt-${name}`).querySelector("input");
	assert(field);
	await gesture(() => fireEvent.change(field, { target: { value } }));
}
