import { beforeEach, describe, it } from "@std/testing/bdd";
import { assert, assertEquals, assertNotEquals, assertRejects } from "@std/assert";
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
import {
	AuthDanceClient,
	AuthDanceClientChoreographyPromptError,
	type AuthDanceClientChoreographySnapshot,
	AuthDanceClientChoreographyStateError,
	AuthDanceNotAuthenticatedError,
	webStorageStore,
} from "./client.ts";
import {
	ChannelAlreadySubscribedError,
	ComponentAlreadyEnrolledError,
	ComponentNotRecoverableError,
	ConfirmationRequiredError,
	InvalidPromptValueError,
	InvalidValidationValueError,
	WouldLockOutError,
} from "./error.ts";

// One PBKDF2 pass, to keep the suites fast.
const TEST_PASSWORD_HASHER = pbkdf2PasswordHasher(1);

// These cases run the nine flows of api.test.ts through the client, over the HTTP edge of the same instance.
describe("Client", () => {
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

	// The management flows all start from an authenticated caller, so each one replays this sign-in first.
	async function signIn(on: AuthDanceClient = client): Promise<void> {
		using choreography = await on.signIn();
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

	it("should sign-in and keep the tokens", async () => {
		const identity = await seedJohnDoe();
		const changes: Array<string | undefined> = [];
		using _listener = client.onTokensChange((tokens) => changes.push(tokens?.identity.id));

		using choreography = await client.signIn();
		assertEquals(choreography.flow, "sign-in");
		assert(choreography.current);
		assertEquals(choreography.current.name, "email");
		assertEquals(choreography.current.type, "email");
		assert(!choreography.done);

		const next = await choreography.submitPrompt("john.doe@example.com");
		assert("state" in next);
		assertEquals(choreography.current?.type, "password");
		assertEquals(choreography.trail, ["email"]);

		const last = await choreography.submitPrompt("foo");
		assert("tokens" in last);
		assert(choreography.done);
		assertEquals(choreography.current, null);
		assertEquals(client.identity?.id, identity.id);
		assertEquals(client.tokens?.access_token, last.tokens.access_token);
		assertEquals(client.session?.identityId, identity.id);
		assertEquals(changes, [identity.id]);
	});

	it("should sign-up through a validation", async () => {
		using choreography = await client.signUp();
		assertEquals(choreography.current?.type, "email");

		await choreography.submitPrompt("john.doe@example.com");
		assertEquals(choreography.current?.type, "otp");
		assert(choreography.sendable);

		await choreography.sendPrompt({ locale: "en" });
		assertEquals(channelEmail.messages.length, 1);

		await choreography.submitPrompt(lastCode(channelEmail));
		assertEquals(choreography.current?.type, "password");

		const last = await choreography.submitPrompt("bar");
		assert("tokens" in last);
		assertEquals(choreography.trail, ["email", "email", "password"]);
		assert(client.identity?.id);
		const identity = await storage.getIdentity(client.identity.id);
		assert(identity?.components.find((c) => c.kind === "identification" && c.component === "email"));
	});

	it("should report the failure the library named", async () => {
		await seedJohnDoe();
		using choreography = await client.signIn();
		await choreography.submitPrompt("john.doe@example.com");
		await assertRejects(() => choreography.submitPrompt("wrong"), InvalidPromptValueError);
		// The flow does not advance, so the same state answers the prompt again.
		assertEquals(choreography.current?.type, "password");
		const last = await choreography.submitPrompt("foo");
		assert("tokens" in last);
	});

	it("should pick a branch of a choice", async () => {
		build({ choreography: choice(sequence("email", "password"), "email2") });
		await seedIdentity(async (seed) => [
			...await email.getIdentityComponent("email", "john.doe@example.com", true),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
			...await email2.getIdentityComponent("email2", "john.doe2@example.com", true),
		]);

		using choreography = await client.signIn();
		assertEquals(choreography.prompt?.kind, "choice");
		assertEquals(choreography.choices.map((branch) => branch.name), ["email", "email2"]);
		// A choice answers nothing until the owner picks a branch.
		assertEquals(choreography.current, null);
		await assertRejects(() => choreography.submitPrompt("john.doe@example.com"), AuthDanceClientChoreographyStateError);
		await assertRejects(() => choreography.choose("nothing"), AuthDanceClientChoreographyPromptError);

		await choreography.choose("email2");
		assertEquals(choreography.selected, "email2");
		assertEquals(choreography.current?.name, "email2");

		await choreography.submitPrompt("john.doe2@example.com");
		assert(choreography.done);
		assertEquals(client.identity?.data?.name, "John Doe");
	});

	it("should go back a step and start over", async () => {
		await seedJohnDoe();
		using choreography = await client.signIn();
		const first = choreography.state;
		await choreography.submitPrompt("john.doe@example.com");
		assertEquals(choreography.current?.type, "password");

		await choreography.prev();
		assertEquals(choreography.current?.type, "email");
		assertEquals(choreography.state, first);
		assertEquals(choreography.trail, []);

		await choreography.restart();
		assertEquals(choreography.current?.type, "email");
		assertNotEquals(choreography.state, first);

		await choreography.abandon();
		assert(choreography.done);
		assertEquals(choreography.current, null);
		await assertRejects(() => choreography.submitPrompt("john.doe@example.com"), AuthDanceClientChoreographyStateError);
	});

	it("should keep the progress of a dance in a store", async () => {
		await seedJohnDoe();
		const entries = new Map<string, string>();
		const store = webStorageStore<AuthDanceClientChoreographySnapshot>("choreography", {
			getItem: (key) => entries.get(key) ?? null,
			setItem: (key, value) => void entries.set(key, value),
			removeItem: (key) => void entries.delete(key),
		});

		{
			using choreography = await client.signIn({ store });
			await choreography.submitPrompt("john.doe@example.com");
		}
		assertEquals(store.get()?.flow, "sign-in");

		// The page reloaded. Nothing calls a route: the snapshot carries the whole dance.
		using resumed = await client.resume(store);
		assert(resumed);
		assertEquals(resumed.flow, "sign-in");
		assertEquals(resumed.current?.type, "password");
		assertEquals(resumed.trail, ["email"]);

		await resumed.submitPrompt("foo");
		assert(resumed.done);
		assertEquals(store.get(), null);
	});

	it("should list the sessions and the components of the identity", async () => {
		const identity = await seedJohnDoe();
		await signIn();
		await signIn();

		const listed = await client.listSessions();
		assertEquals(listed.sessions.length, 2);
		assertEquals(listed.current, client.session?.id);
		assert(listed.sessions.every((session) => session.identityId === identity.id));

		// The address yields three records: the identification, the channel it delivers over, and the one-time code challenge.
		const components = await client.listComponents();
		assertEquals(components.map((component) => component.component).sort(), ["email", "email", "otp", "password", "sms"]);
		// The value a component holds never comes back.
		assert(components.every((component) => !("data" in component)));
	});

	it("should sign out", async () => {
		const identity = await seedJohnDoe();
		await signIn();
		const changes: Array<string | undefined> = [];
		using _listener = client.onTokensChange((tokens) => changes.push(tokens?.identity.id));

		await client.signOut();
		assertEquals(client.tokens, undefined);
		assertEquals(changes, [undefined]);
		assertEquals(await storage.listSession(identity.id), []);
		await assertRejects(() => client.listSessions(), AuthDanceNotAuthenticatedError);
	});

	it("should sign out every other session", async () => {
		const identity = await seedJohnDoe();
		await signIn();
		await signIn();

		await client.signOut({ others: true });
		assertEquals(await storage.listSession(identity.id), []);
	});

	it("should exchange the refresh token before a call that needs one", async () => {
		await seedJohnDoe();
		await signIn();
		const first = client.tokens?.access_token;
		// Every access token is inside this window, so every authenticated call exchanges first.
		const eager = new AuthDanceClient({ baseUrl: "http://local", fetch: auth.fetch, tokens: client.credentials, refreshSkew: 1e9 });

		await eager.listSessions();
		assertNotEquals(eager.tokens?.access_token, first);
		assertEquals(eager.session?.id, client.session?.id);
	});

	it("should share one exchange between two calls, and try again after a refused one", async () => {
		await seedJohnDoe();
		await signIn();

		let exchanges = 0;
		let refuse = true;
		const counting = (request: Request): Response | Promise<Response> => {
			if (new URL(request.url).pathname !== "/refresh-token") {
				return auth.fetch(request);
			}
			exchanges++;
			if (refuse) {
				refuse = false;
				throw new Error("simulated network failure");
			}
			return auth.fetch(request);
		};
		const eager = new AuthDanceClient({ baseUrl: "http://local", fetch: counting, tokens: client.credentials, refreshSkew: 1e9 });

		// The refused exchange is not kept, so the next call tries again.
		await assertRejects(() => eager.listSessions());
		assertEquals(exchanges, 1);

		// Two calls at once share one exchange.
		await Promise.all([eager.listSessions(), eager.listComponents()]);
		assertEquals(exchanges, 2);
	});

	it("should enroll a component", async () => {
		const identity = await seedJohnDoe();
		await signIn();

		using choreography = await client.enroll("email2");
		assertEquals(choreography.current?.type, "email");

		await choreography.submitPrompt("john.doe2@example.com");
		assertEquals(choreography.current?.type, "otp");
		await choreography.sendPrompt();
		const last = await choreography.submitPrompt(lastCode(channelEmail2));
		assert("success" in last);
		assert(choreography.done);

		const enrolled = await storage.getIdentity(identity.id);
		assert(enrolled?.components.find((c) => c.kind === "identification" && c.component === "email2"));
		await assertRejects(() => client.enroll("email2"), ComponentAlreadyEnrolledError);
	});

	it("should unenroll a component a choice makes optional", async () => {
		build({ choreography: choice(sequence("email", "password"), "email2") });
		const identity = await seedIdentity(async (seed) => [
			...await email.getIdentityComponent("email", "john.doe@example.com", true),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
			...await email2.getIdentityComponent("email2", "john.doe2@example.com", true),
		]);
		{
			using choreography = await client.signIn();
			await choreography.choose("email");
			await choreography.submitPrompt("john.doe@example.com");
			await choreography.submitPrompt("foo");
		}

		using choreography = await client.unenroll("password");
		assertEquals(choreography.current?.type, "confirmation");
		// Only the boolean true goes through.
		await assertRejects(() => choreography.submitPrompt("yes"), ConfirmationRequiredError);

		const last = await choreography.confirm();
		assert("success" in last);
		const left = await storage.getIdentity(identity.id);
		assert(!left?.components.find((c) => c.kind !== "channel" && c.component === "password"));
	});

	it("should refuse an unenroll the choreography cannot do without", async () => {
		await seedJohnDoe();
		await signIn();
		await assertRejects(() => client.unenroll("password"), WouldLockOutError);
	});

	it("should rotate a component that proves nothing beyond the access token", async () => {
		const identity = await seedJohnDoe();
		await signIn();
		const before = (await storage.getIdentity(identity.id))?.components
			.find((c) => c.kind === "challenge" && c.component === "password");

		using choreography = await client.rotate("password");
		// A password re-typed proves nothing the access token has not established, so the flow collects the replacement at once.
		assertEquals(choreography.current?.type, "password");
		const last = await choreography.submitPrompt("bar");
		assert("success" in last);

		const after = (await storage.getIdentity(identity.id))?.components
			.find((c) => c.kind === "challenge" && c.component === "password");
		assertNotEquals(after?.data?.hash, before?.data?.hash);
	});

	it("should rotate a component through both of its rounds", async () => {
		const identity = await seedJohnDoe();
		await signIn();

		using choreography = await client.rotate("email");
		// The first round proves control of the address the identity carries.
		assertEquals(choreography.current?.type, "otp");
		await choreography.sendPrompt();
		await choreography.submitPrompt(lastCode(channelEmail));

		// The second round collects the replacement, and proves control of it.
		assertEquals(choreography.current?.type, "email");
		await choreography.submitPrompt("john.doe2@example.com");
		assertEquals(choreography.current?.type, "otp");
		await choreography.sendPrompt();
		await assertRejects(() => choreography.submitPrompt("000000"), InvalidValidationValueError);
		const last = await choreography.submitPrompt(lastCode(channelEmail));
		assert("success" in last);

		const rotated = await storage.getIdentity(identity.id);
		assert(
			rotated?.components.find((c) =>
				c.kind === "identification" && c.component === "email" && c.identification === "john.doe2@example.com"
			),
		);
	});

	it("should subscribe a channel", async () => {
		const identity = await seedIdentity(async (seed) => [
			...await email.getIdentityComponent("email", "john.doe@example.com", true),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
		await signIn();

		using choreography = await client.subscribe("sms");
		assertEquals(choreography.current?.type, "phone");

		await choreography.submitPrompt("5551234567");
		// The one-time code goes over the channel being subscribed, to the recipient the flow just collected.
		assertEquals(choreography.current?.type, "otp");
		await choreography.sendPrompt({ locale: "en" });
		const last = await choreography.submitPrompt(lastCode(channelSms));
		assert("success" in last);

		const subscribed = await storage.getIdentity(identity.id);
		assert(subscribed?.components.find((c) => c.kind === "channel" && c.component === "sms" && c.confirmed));
		await assertRejects(() => client.subscribe("sms"), ChannelAlreadySubscribedError);
	});

	it("should unsubscribe a channel", async () => {
		const identity = await seedJohnDoe();
		await signIn();

		using choreography = await client.unsubscribe("sms");
		assertEquals(choreography.current?.type, "confirmation");
		const last = await choreography.confirm();
		assert("success" in last);

		const left = await storage.getIdentity(identity.id);
		assert(!left?.components.find((c) => c.kind === "channel" && c.component === "sms"));
	});

	it("should recover a component", async () => {
		const identity = await seedJohnDoe();
		// This flow is the one open to a caller with no session at all.
		using choreography = await client.recover("password");
		assertEquals(choreography.flow, "recover");
		// "email" is the only component that resolves an identity and proves control of it, so the choice collapses.
		assertEquals(choreography.current?.name, "email");

		await choreography.submitPrompt("john.doe@example.com");
		assertEquals(choreography.current?.type, "otp");
		await choreography.sendPrompt({ locale: "en" });
		await choreography.submitPrompt(lastCode(channelEmail));

		assertEquals(choreography.current?.type, "password");
		const last = await choreography.submitPrompt("bar");
		assert("success" in last);
		// A recovery completes with a bare success, never with tokens.
		assertEquals(client.tokens, undefined);

		const recovered = await storage.getIdentity(identity.id);
		assertNotEquals(
			recovered?.components.find((c) => c.kind === "challenge" && c.component === "password")?.data?.hash,
			identity.components.find((c) => c.kind === "challenge" && c.component === "password")?.data?.hash,
		);
		// The replacement signs in.
		using choreography2 = await client.signIn();
		await choreography2.submitPrompt("john.doe@example.com");
		const tokens = await choreography2.submitPrompt("bar");
		assert("tokens" in tokens);
	});

	it("should refuse a recovery the caller has nothing left to identify through", async () => {
		await seedJohnDoe();
		await assertRejects(() => client.recover("email"), ComponentNotRecoverableError);
	});

	it("should delete the identity and drop the tokens", async () => {
		const identity = await seedJohnDoe();
		await signIn();

		using choreography = await client.delete();
		assertEquals(choreography.current?.name, "identity");
		assertEquals(choreography.current?.type, "confirmation");
		const last = await choreography.confirm();
		assert("success" in last);

		// Every session went with the identity, so no token outlives it.
		assertEquals(client.tokens, undefined);
		assertEquals(await storage.getIdentity(identity.id), undefined);
		assertEquals(await storage.listSession(identity.id), []);
	});

	it("should refuse a flow that needs a session when it holds none", async () => {
		await seedJohnDoe();
		await assertRejects(() => client.enroll("email2"), AuthDanceNotAuthenticatedError);
		await assertRejects(() => client.listComponents(), AuthDanceNotAuthenticatedError);
		await assertRejects(() => client.refreshTokens(), AuthDanceNotAuthenticatedError);
	});
});
