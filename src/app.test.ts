import { beforeEach, describe, it } from "@std/testing/bdd";
import { assert, assertEquals } from "@std/assert";
import { MemoryAuthDanceChannel, MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "./providers/memory.ts";
import type { AuthDanceApiOptions } from "./api.ts";
import { choice, sequence } from "./choreography.ts";
import { EmailAuthDanceComponent } from "./components/email.ts";
import type { AuthDanceComponentContext } from "./component.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent } from "./identity.ts";
import { ksuid } from "./id.ts";
import { PasswordAuthDanceComponent, pbkdf2PasswordHasher } from "./components/password.ts";
import { OtpAuthDanceComponent } from "./components/otp.ts";
import { AuthDanceStorage } from "./storage.ts";
import type { AuthDanceKvProvider } from "./provider.ts";
import { type AuthDance, createAuthDance } from "./mod.ts";

// One PBKDF2 pass, to keep the suites fast.
const TEST_PASSWORD_HASHER = pbkdf2PasswordHasher(1);

// Every response is JSON, failures included, so a call only ever yields a status and a parsed body.
// deno-lint-ignore no-explicit-any
type Json = any;
type Post = (
	path: string,
	body?: unknown,
	headers?: Record<string, string>,
) => Promise<[number, Json]>;

// These cases run the flows of api.test.ts through the HTTP edge. A rejected AuthDanceError arrives as a 500 with `{ error: <code> }`.
describe("App", () => {
	let storage: AuthDanceStorage;
	let apiOptions: AuthDanceApiOptions;
	let post: Post;
	let channelEmail: MemoryAuthDanceChannel;
	let channelEmail2: MemoryAuthDanceChannel;
	let channelSms: MemoryAuthDanceChannel;
	let email: EmailAuthDanceComponent;
	let otp: OtpAuthDanceComponent;
	let email2: EmailAuthDanceComponent;
	let otp2: OtpAuthDanceComponent;
	let password: PasswordAuthDanceComponent;

	// Seeds an identity outside a flow. The password record is salted with the id, so the id comes first.
	async function seedIdentity(
		data: Record<string, unknown>,
		build: (seed: (name: string) => AuthDanceComponentContext) => Promise<AuthDanceIdentityComponent[]>,
	): Promise<AuthDanceIdentity> {
		const identity: AuthDanceIdentity = { id: ksuid("id_"), data, components: [] };
		identity.components = await build((name) => ({ storage, stateId: "state_seed", name, flow: "sign-up", identity }));
		await storage.setIdentity(identity);
		return identity;
	}

	beforeEach(() => {
		channelEmail = new MemoryAuthDanceChannel("email");
		channelEmail2 = new MemoryAuthDanceChannel("email2");
		channelSms = new MemoryAuthDanceChannel("phone");
		email = new EmailAuthDanceComponent({ channel: "email", challenge: "otp" });
		otp = new OtpAuthDanceComponent({ channel: "email" });
		email2 = new EmailAuthDanceComponent({ channel: "email2", challenge: "otp2" });
		otp2 = new OtpAuthDanceComponent({ channel: "email2" });
		password = new PasswordAuthDanceComponent("salty", TEST_PASSWORD_HASHER);
		storage = new AuthDanceStorage({
			identity: new MemoryIdentityProvider(),
			kv: new MemoryKvProvider(),
			rate_limiter: new MemoryRateLimiterProvider(),
		});
		apiOptions = {
			channels: {
				email: channelEmail,
				email2: channelEmail2,
				sms: channelSms,
			},
			choreography: sequence("email", "password"),
			components: { email, password, email2, otp, otp2 },
			secret: "zdJXI1jwuXW8A19fns0E_B4HSYm7AUHLGlU9WLo8mxs", // openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
			storage,
		};
		post = client(createAuthDance({ api: apiOptions }));
	});

	function client(auth: AuthDance): Post {
		return async (path, body, headers = {}) => {
			const response = await auth.fetch(
				new Request(`http://local${path}`, {
					method: "POST",
					headers: { "content-type": "application/json", ...headers },
					body: body === undefined ? undefined : JSON.stringify(body),
				}),
			);
			return [response.status, await response.json()];
		};
	}

	function bearer(access_token: string): Record<string, string> {
		return { authorization: `Bearer ${access_token}` };
	}

	// The management flows all start from an authenticated caller, so each one replays this sign-in first.
	async function signIn(): Promise<Json> {
		const [, result1] = await post("/sign-in");
		const [, result2] = await post("/submit-prompt", {
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		const [status, result3] = await post("/submit-prompt", {
			name: "password",
			value: "foo",
			state: result2.state,
		});
		assertEquals(status, 200);
		assert(result3.tokens);
		return result3;
	}

	it("should sign-in", async () => {
		const identity = await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
		const [status1, result1] = await post("/sign-in");
		assertEquals(status1, 200);
		assertEquals(result1.prompt.kind, "input");
		assertEquals(result1.prompt.type, "email");
		const [status2, result2] = await post("/submit-prompt", {
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assertEquals(status2, 200);
		assert(result2.state);
		assertEquals(result2.prompt.kind, "input");
		assertEquals(result2.prompt.type, "password");
		const [status3, result3] = await post("/submit-prompt", {
			name: "password",
			value: "foo",
			state: result2.state,
		});
		assertEquals(status3, 200);
		assert(result3.tokens);
		assertEquals(result3.identity.id, identity.id);
	});

	it("should not sign-in with a wrong challenge", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
		const [, result1] = await post("/sign-in");
		const [, result2] = await post("/submit-prompt", {
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert(result2.state);
		const [status, rejected] = await post("/submit-prompt", {
			name: "password",
			value: "bar",
			state: result2.state,
		});
		assertEquals(status, 500);
		assertEquals(rejected.error, "INVALID_PROMPT_VALUE");
	});

	it("should not sign-in with an unknown identification", async () => {
		const [, result1] = await post("/sign-in");
		const [status, rejected] = await post("/submit-prompt", {
			name: "email",
			value: "jane.doe@example.com",
			state: result1.state,
		});
		assertEquals(status, 500);
		// The same code as a wrong password. A different code would let a caller enumerate accounts.
		assertEquals(rejected.error, "INVALID_PROMPT_VALUE");
	});

	it("should list the sessions open on the identity", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
		const first = await signIn();
		const second = await signIn();
		const [status, listed] = await post(
			"/list-sessions",
			undefined,
			bearer(second.tokens.access_token),
		);
		assertEquals(status, 200);
		assertEquals(
			listed.sessions.map((s: Json) => s.id).sort(),
			[first.session.id, second.session.id].sort(),
		);
		// `current` names the caller's own session.
		assertEquals(listed.current, second.session.id);
		// A session that has been signed out stops being listed.
		await post(
			"/sign-out",
			{ others: false },
			bearer(first.tokens.access_token),
		);
		const [, afterSignOut] = await post(
			"/list-sessions",
			undefined,
			bearer(second.tokens.access_token),
		);
		assertEquals(afterSignOut.sessions.map((s: Json) => s.id), [
			second.session.id,
		]);
		// The route is authenticated, like every other management route.
		const [rejectedStatus, rejected] = await post("/list-sessions");
		assertEquals(rejectedStatus, 500);
		assertEquals(rejected.error, "INVALID_ACCESS_TOKEN");
	});

	it("should list the components enrolled on the identity", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
		const session = await signIn();
		const [status, listed] = await post(
			"/list-components",
			undefined,
			bearer(session.tokens.access_token),
		);
		assertEquals(status, 200);
		// EmailAuthDanceComponent contributes the identification, the channel and the one-time code challenge.
		assertEquals(listed.components, [
			{
				kind: "identification",
				component: "email",
				identification: "john.doe@example.com",
				confirmed: true,
			},
			{
				kind: "channel",
				component: "email",
				confirmed: true,
				linkedTo: ["email"],
			},
			{
				kind: "challenge",
				component: "otp",
				confirmed: true,
				linkedTo: ["email"],
			},
			{ kind: "challenge", component: "password", confirmed: true },
		]);
		// The component's private store never crosses the edge. The password hash is in there.
		assert(!listed.components.some((c: Json) => "data" in c));
		// The route is authenticated, like every other management route.
		const [rejectedStatus, rejected] = await post("/list-components");
		assertEquals(rejectedStatus, 500);
		assertEquals(rejected.error, "INVALID_ACCESS_TOKEN");
	});

	it("should sign-up", async () => {
		const [, result1] = await post("/sign-up");
		assertEquals(result1.prompt.kind, "input");
		assertEquals(result1.prompt.type, "email");
		const [, result2] = await post("/submit-prompt", {
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert(result2.state);
		assertEquals(result2.prompt.kind, "input");
		assertEquals(result2.prompt.type, "otp");
		assert(result2.prompt.sendable);
		const [, sent] = await post("/send-prompt", {
			name: "email",
			locale: "en",
			state: result2.state,
		});
		assert(sent.success);
		assertEquals(channelEmail.messages.length, 1);
		const code = channelEmail.messages[0].content["text/x-code"];
		assert(code);
		const [, result3] = await post("/submit-prompt", {
			name: "email",
			value: code,
			state: result2.state,
		});
		assert(result3.state);
		const [status, result4] = await post("/submit-prompt", {
			name: "password",
			value: "bar",
			state: result3.state,
		});
		assertEquals(status, 200);
		assert(result4.tokens);
	});

	it("should not validate a wrong otp", async () => {
		const [, result1] = await post("/sign-up");
		const [, result2] = await post("/submit-prompt", {
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert(result2.state);
		await post("/send-prompt", {
			name: "email",
			locale: "en",
			state: result2.state,
		});
		const code = channelEmail.messages[0].content["text/x-code"];
		assert(code);
		const [status, rejected] = await post("/submit-prompt", {
			name: "email",
			value: `${Number(code) + 1}`.padStart(code.length, "0"),
			state: result2.state,
		});
		assertEquals(status, 500);
		assertEquals(rejected.error, "INVALID_VALIDATION_VALUE");
	});

	it("should subscribe", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
		const result3 = await signIn();
		const [, result4] = await post(
			"/subscribe",
			{ name: "sms" },
			bearer(result3.tokens.access_token),
		);
		const [, result5] = await post("/submit-prompt", {
			name: "sms",
			value: "5551234567",
			state: result4.state,
		});
		assert(result5.state);
		assertEquals(result5.prompt.kind, "input");
		assertEquals(result5.prompt.type, "otp");
		assert(result5.prompt.sendable);
		const [, sent] = await post("/send-prompt", {
			name: "sms",
			locale: "en",
			state: result5.state,
		});
		assert(sent.success);
		assertEquals(channelSms.messages.length, 1);
		const code = channelSms.messages[0].content["text/x-code"];
		assert(code);
		const [status, result6] = await post("/submit-prompt", {
			name: "sms",
			value: code,
			state: result5.state,
		});
		assertEquals(status, 200);
		assert(result6.success);
		const identity = await storage.getIdentity(result3.identity.id);
		assert(
			identity?.components.some((c) => c.kind === "channel" && c.component === "sms" && c.confirmed),
		);
	});

	it("should not subscribe a channel already subscribed to", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
		const result3 = await signIn();
		// The email component emits its own "email" channel.
		const [status, rejected] = await post(
			"/subscribe",
			{ name: "email" },
			bearer(result3.tokens.access_token),
		);
		assertEquals(status, 500);
		assertEquals(rejected.error, "CHANNEL_ALREADY_SUBSCRIBED");
	});

	it("should unsubscribe", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
			await channelSms.getIdentityChannel("sms", "5551234567", true),
		]);
		const result3 = await signIn();
		const [, result4] = await post(
			"/unsubscribe",
			{ name: "sms" },
			bearer(result3.tokens.access_token),
		);
		assert(result4.state);
		assertEquals(result4.prompt.kind, "input");
		assertEquals(result4.prompt.type, "confirmation");
		const [status, result5] = await post("/submit-prompt", {
			name: "sms",
			value: true,
			state: result4.state,
		});
		assertEquals(status, 200);
		assert(result5.success);
		const identity = await storage.getIdentity(result3.identity.id);
		assert(identity);
		assert(
			!identity.components.find((c) => c.kind === "channel" && c.component === "sms"),
		);
	});

	it("should not unsubscribe a channel whose collateral the choreography cannot do without", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
		const result3 = await signIn();
		// The "email" channel carries linkedTo: ["email"], so dropping it drops the only path.
		const [status, rejected] = await post(
			"/unsubscribe",
			{ name: "email" },
			bearer(result3.tokens.access_token),
		);
		assertEquals(status, 500);
		assertEquals(rejected.error, "WOULD_LOCK_OUT");
	});

	it("should enroll", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
			await channelSms.getIdentityChannel("sms", "5551234567", true),
		]);
		const result3 = await signIn();
		const [, result4] = await post(
			"/enroll",
			{ name: "email2" },
			bearer(result3.tokens.access_token),
		);
		assertEquals(result4.prompt.kind, "input");
		assertEquals(result4.prompt.type, "email");
		const [, result5] = await post("/submit-prompt", {
			name: "email2",
			value: "john.doe2@example.com",
			state: result4.state,
		});
		assert(result5.state);
		assertEquals(result5.prompt.kind, "input");
		assertEquals(result5.prompt.type, "otp");
		assert(result5.prompt.sendable);
		const [, sent] = await post("/send-prompt", {
			name: "email2",
			locale: "en",
			state: result5.state,
		});
		assert(sent.success);
		assertEquals(channelEmail2.messages.length, 1);
		const code = channelEmail2.messages[0].content["text/x-code"];
		assert(code);
		const [status, result6] = await post("/submit-prompt", {
			name: "email2",
			value: code,
			state: result5.state,
		});
		assertEquals(status, 200);
		assert(result6.success);
		const identity = await storage.getIdentity(result3.identity.id);
		assert(identity);
		assert(
			!identity.components.find((c) => c.kind === "challenge" && c.component === "email2"),
		);
	});

	it("should not enroll a component already enrolled", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
		const result3 = await signIn();
		const [status, rejected] = await post(
			"/enroll",
			{ name: "password" },
			bearer(result3.tokens.access_token),
		);
		assertEquals(status, 500);
		assertEquals(rejected.error, "COMPONENT_ALREADY_ENROLLED");
	});

	it("should unenroll", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
			...await email2.getIdentityComponent(
				"email2",
				"john.doe2@example.com",
				true,
			),
		]);
		const result3 = await signIn();
		const [, result4] = await post(
			"/unenroll",
			{ name: "email2" },
			bearer(result3.tokens.access_token),
		);
		assert(result4.state);
		assertEquals(result4.prompt.kind, "input");
		assertEquals(result4.prompt.type, "confirmation");
		const [status, result5] = await post("/submit-prompt", {
			name: "email2",
			value: true,
			state: result4.state,
		});
		assertEquals(status, 200);
		assert(result5.success);
		const identity = await storage.getIdentity(result3.identity.id);
		assert(identity);
		assert(
			!identity.components.find((c) => c.kind !== "channel" && c.component === "email2"),
		);
	});

	it("should not unenroll a component the choreography cannot do without", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
			...await email2.getIdentityComponent(
				"email2",
				"john.doe2@example.com",
				true,
			),
		]);
		const result3 = await signIn();
		// sequence("email", "password") has no path to an end without "password".
		const [status, rejected] = await post(
			"/unenroll",
			{ name: "password" },
			bearer(result3.tokens.access_token),
		);
		assertEquals(status, 500);
		assertEquals(rejected.error, "WOULD_LOCK_OUT");
		const identity = await storage.getIdentity(result3.identity.id);
		assert(
			identity?.components.find((c) => c.kind === "challenge" && c.component === "password"),
		);
	});

	it("should unenroll a component a choice makes optional", async () => {
		// "email2" alone is an alternative to the email + password path, so "password" becomes droppable.
		post = client(
			createAuthDance({
				api: {
					...apiOptions,
					choreography: choice(sequence("email", "password"), "email2"),
				},
			}),
		);
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
			...await email2.getIdentityComponent(
				"email2",
				"john.doe2@example.com",
				true,
			),
		]);
		const result3 = await signIn();
		const [, result4] = await post(
			"/unenroll",
			{ name: "password" },
			bearer(result3.tokens.access_token),
		);
		assertEquals(result4.prompt.kind, "input");
		assertEquals(result4.prompt.type, "confirmation");
		const [status, result5] = await post("/submit-prompt", {
			name: "password",
			value: true,
			state: result4.state,
		});
		assertEquals(status, 200);
		assert(result5.success);
		const identity = await storage.getIdentity(result3.identity.id);
		assert(identity);
		assert(
			!identity.components.find((c) => c.kind !== "channel" && c.component === "password"),
		);
	});

	it("should delete the identity", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
		const result3 = await signIn();
		// A second session, to show the deletion takes every session with it.
		const _other = await signIn();
		const [, result4] = await post(
			"/delete",
			undefined,
			bearer(result3.tokens.access_token),
		);
		assert(result4.state);
		assertEquals(result4.prompt.kind, "input");
		assertEquals(result4.prompt.type, "confirmation");
		const [status, result5] = await post("/submit-prompt", {
			name: "identity",
			value: true,
			state: result4.state,
		});
		assertEquals(status, 200);
		assert(result5.success);
		assertEquals(await storage.getIdentity(result3.identity.id), undefined);
		assertEquals(await storage.listSession(result3.identity.id), []);
	});

	it("should not delete the identity without an explicit confirmation", async () => {
		const identity = await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
		const result3 = await signIn();
		const [, result4] = await post(
			"/delete",
			undefined,
			bearer(result3.tokens.access_token),
		);
		// The gate is a confirmation, not a truthiness check.
		const [status, rejected] = await post("/submit-prompt", {
			name: "identity",
			value: "yes",
			state: result4.state,
		});
		assertEquals(status, 500);
		assertEquals(rejected.error, "CONFIRMATION_REQUIRED");
		assert(await storage.getIdentity(identity.id));
	});

	it("should rotate password", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
		const result3 = await signIn();
		const [, result4] = await post(
			"/rotate",
			{ name: "password" },
			bearer(result3.tokens.access_token),
		);
		assert(result4.state);
		assertEquals(result4.prompt.kind, "input");
		assertEquals(result4.prompt.type, "password");
		const [status, result5] = await post("/submit-prompt", {
			name: "password",
			value: "bar",
			state: result4.state,
		});
		assertEquals(status, 200);
		assert(result5.success);
		const identity = await storage.getIdentity(result3.identity.id);
		assert(identity);
		assert(
			identity.components.find((c) => c.kind === "challenge" && c.component === "password"),
		);
	});

	it("should rotate email", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
		const result3 = await signIn();
		const [, result4] = await post(
			"/rotate",
			{ name: "email" },
			bearer(result3.tokens.access_token),
		);
		assert(result4.state);
		assertEquals(result4.prompt.kind, "input");
		assertEquals(result4.prompt.type, "otp");
		assert(result4.prompt.sendable);
		const [, sent1] = await post("/send-prompt", {
			name: "email",
			locale: "en",
			state: result4.state,
		});
		assert(sent1.success);
		const code1 = channelEmail.messages[0].content["text/x-code"];
		assert(code1);
		const [, result5] = await post("/submit-prompt", {
			name: "email",
			value: code1,
			state: result4.state,
		});
		assert(result5.state);
		const [, result6] = await post("/submit-prompt", {
			name: "email",
			value: "john.doe2@example.com",
			state: result5.state,
		});
		assert(result6.state);
		assertEquals(result6.prompt.kind, "input");
		assertEquals(result6.prompt.type, "otp");
		assert(result6.prompt.sendable);
		const [, sent2] = await post("/send-prompt", {
			name: "email",
			locale: "en",
			state: result6.state,
		});
		assert(sent2.success);
		const code2 = channelEmail.messages[1].content["text/x-code"];
		assert(code2);
		const [status, result7] = await post("/submit-prompt", {
			name: "email",
			value: code2,
			state: result6.state,
		});
		assertEquals(status, 200);
		assert(result7.success);
		const identity = await storage.getIdentity(result3.identity.id);
		assert(identity);
		assert(
			identity.components.find((c) =>
				c.kind === "identification" && c.component === "email" &&
				c.identification === "john.doe2@example.com"
			),
		);
	});

	it("should recover password", async () => {
		const identity1 = await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
		// "email" is the only component that resolves an identity and proves control of it. The choice collapses to one prompt.
		const [, result1] = await post("/recover", { name: "password" });
		assertEquals(result1.prompt.kind, "input");
		assertEquals(result1.prompt.name, "email");
		assertEquals(result1.prompt.type, "email");
		const [, result2] = await post("/submit-prompt", {
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert(result2.state);
		assertEquals(result2.prompt.kind, "input");
		assertEquals(result2.prompt.type, "otp");
		assert(result2.prompt.sendable);
		const [, sent] = await post("/send-prompt", {
			name: "email",
			locale: "en",
			state: result2.state,
		});
		assert(sent.success);
		assertEquals(channelEmail.messages.length, 1);
		const code = channelEmail.messages[0].content["text/x-code"];
		assert(code);
		const [, result3] = await post("/submit-prompt", {
			name: "email",
			value: code,
			state: result2.state,
		});
		assert(result3.state);
		assertEquals(result3.prompt.kind, "input");
		assertEquals(result3.prompt.type, "password");
		const [status, result4] = await post("/submit-prompt", {
			name: "password",
			value: "bar",
			state: result3.state,
		});
		assertEquals(status, 200);
		assert(result4.success);
		const identity2 = await storage.getIdentity(identity1.id);
		const passwordComponent1 = identity1.components.find((c) => c.kind === "challenge" && c.component === "password");
		const passwordComponent2 = identity2?.components.find((c) => c.kind === "challenge" && c.component === "password");
		assert(passwordComponent1?.data?.hash !== passwordComponent2?.data?.hash);
	});

	it("should not recover a component the caller has nothing left to identify through", async () => {
		// "email" is the only component that identifies and verifies on its own, and it is the one being recovered.
		const [status, rejected] = await post("/recover", { name: "email" });
		assertEquals(status, 500);
		assertEquals(rejected.error, "COMPONENT_NOT_RECOVERABLE");
	});

	it("should reject a forged state without reaching the flow", async () => {
		const [status, rejected] = await post("/submit-prompt", {
			name: "email",
			value: "john.doe@example.com",
			state: "not-a-jwt",
		});
		assertEquals(status, 500);
		assertEquals(rejected.error, "INVALID_STATE");
	});

	it("should surface an unexpected failure as UNKNOWN, not as a business error", async () => {
		// A provider failure is not a business rule. It must carry no business error code.
		const boom = new TypeError("kv is down");
		const brokenKv: AuthDanceKvProvider = {
			get: () => Promise.reject(boom),
			list: () => Promise.reject(boom),
			set: () => Promise.reject(boom),
			unset: () => Promise.reject(boom),
		};
		const brokenPost = client(createAuthDance({
			api: {
				...apiOptions,
				storage: new AuthDanceStorage({
					identity: new MemoryIdentityProvider(),
					kv: brokenKv,
					rate_limiter: new MemoryRateLimiterProvider(),
				}),
			},
		}));
		const [, result1] = await brokenPost("/sign-up");
		const [, result2] = await brokenPost("/submit-prompt", {
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert(result2.state);
		// OtpAuthDanceComponent.sendPrompt writes the code to KV and does not catch.
		const [status, thrown] = await brokenPost("/send-prompt", {
			name: "email",
			locale: "en",
			state: result2.state,
		});
		assertEquals(status, 500);
		assertEquals(thrown.error, "UNKNOWN");
		// The cause must not travel. AuthDanceError keeps `code` as its only own-enumerable property.
		assertEquals(Object.keys(thrown), ["error"]);
	});

	// These cases cover what the edge adds on top of AuthDanceApi: the access token, the caller address, and the body validation.
	describe("http", () => {
		it("should refuse an authenticated route with no bearer token", async () => {
			const [status, rejected] = await post("/enroll", { name: "email2" });
			assertEquals(status, 500);
			assertEquals(rejected.error, "INVALID_ACCESS_TOKEN");
		});

		it("should refuse a deletion with no bearer token", async () => {
			const [status, rejected] = await post("/delete");
			assertEquals(status, 500);
			assertEquals(rejected.error, "INVALID_ACCESS_TOKEN");
		});

		// A malformed header and a rejected token report the same code.
		it("should refuse a malformed authorization header", async () => {
			const [status, rejected] = await post("/enroll", { name: "email2" }, {
				authorization: "Basic aGk6dGhlcmU=",
			});
			assertEquals(status, 500);
			assertEquals(rejected.error, "INVALID_ACCESS_TOKEN");
		});

		it("should answer a malformed body with BAD_REQUEST", async () => {
			const [status, rejected] = await post("/recover", {});
			assertEquals(status, 400);
			assertEquals(rejected.error, "BAD_REQUEST");
		});

		// AuthDanceResponseState carries a Date. The client gets the ISO string.
		it("should serialise expireAt as an ISO timestamp", async () => {
			const [, result] = await post("/sign-in");
			assertEquals(typeof result.expireAt, "string");
			assert(!isNaN(Date.parse(result.expireAt)));
		});

		// The library reads address and userAgent from the connection, never from the body.
		it("should record the caller from the request headers", async () => {
			await seedIdentity({ name: "John Doe" }, async (seed) => [
				...await email.getIdentityComponent(
					"email",
					"john.doe@example.com",
					true,
				),
				...await password.getIdentityComponent("password", "foo", true, seed("password")),
			]);
			const [, result1] = await post("/sign-in");
			const [, result2] = await post("/submit-prompt", {
				name: "email",
				value: "john.doe@example.com",
				state: result1.state,
			});
			const [, result3] = await post("/submit-prompt", {
				name: "password",
				value: "foo",
				state: result2.state,
			}, {
				"cf-connecting-ip": "203.0.113.7",
				"user-agent": "e2e/1.0",
			});
			assertEquals(result3.session.address, "203.0.113.7");
			assertEquals(result3.session.userAgent, "e2e/1.0");
		});

		it("should fall back to the Accept-Language header when no locale is given", async () => {
			const [, result1] = await post("/sign-up");
			const [, result2] = await post("/submit-prompt", {
				name: "email",
				value: "john.doe@example.com",
				state: result1.state,
			});
			const [status, sent] = await post("/send-prompt", {
				name: "email",
				state: result2.state,
			}, {
				"accept-language": "fr-CA,fr;q=0.9",
			});
			assertEquals(status, 200);
			assert(sent.success);
			assertEquals(channelEmail.messages.length, 1);
		});

		it("should not route an unknown path", async () => {
			const auth = createAuthDance({ api: apiOptions });
			const response = await auth.fetch(
				new Request("http://local/nope", { method: "POST" }),
			);
			assertEquals(response.status, 404);
		});

		// The per-address counterpart to the per-identity buckets of api.test.ts.
		describe("rate limit", () => {
			function limitedPost(
				address_rate_limit: NonNullable<
					AuthDanceApiOptions["limits"]
				>["address"],
			): Post {
				return client(
					createAuthDance({ api: { ...apiOptions, limits: { address: address_rate_limit } } }),
				);
			}

			function from(address: string): Record<string, string> {
				return { "cf-connecting-ip": address };
			}

			it("should refuse a flood from one address with 429", async () => {
				const post = limitedPost({ request: { limit: 2, window: 60 } });
				assertEquals(
					(await post("/sign-in", undefined, from("203.0.113.7")))[0],
					200,
				);
				assertEquals(
					(await post("/sign-in", undefined, from("203.0.113.7")))[0],
					200,
				);
				const [status, rejected] = await post(
					"/sign-in",
					undefined,
					from("203.0.113.7"),
				);
				assertEquals(status, 429);
				assertEquals(rejected.error, "RATE_LIMITED");
				// The bucket is on the address, not on the route. A different flow shares the same allowance.
				assertEquals(
					(await post("/recover", { name: "password" }, from("203.0.113.7")))[0],
					429,
				);
			});

			it("should bucket each address on its own", async () => {
				const post = limitedPost({ request: { limit: 1, window: 60 } });
				assertEquals(
					(await post("/sign-in", undefined, from("203.0.113.7")))[0],
					200,
				);
				assertEquals(
					(await post("/sign-in", undefined, from("203.0.113.7")))[0],
					429,
				);
				assertEquals(
					(await post("/sign-in", undefined, from("198.51.100.4")))[0],
					200,
				);
			});

			// The library does not bucket a request that carries no address.
			it("should not bucket a request that carries no address", async () => {
				const post = limitedPost({ request: { limit: 1, window: 60 } });
				for (let attempt = 0; attempt < 3; attempt++) {
					assertEquals((await post("/sign-in"))[0], 200);
				}
			});

			it("should bucket the sending route on top of the request bucket", async () => {
				const post = limitedPost({
					request: { limit: 100, window: 60 },
					send: { limit: 1, window: 60 },
				});
				const [, result1] = await post(
					"/sign-up",
					undefined,
					from("203.0.113.7"),
				);
				const [, result2] = await post(
					"/submit-prompt",
					{
						name: "email",
						value: "john.doe@example.com",
						state: result1.state,
					},
					from("203.0.113.7"),
				);
				assert(result2.state);
				const [sentStatus] = await post("/send-prompt", {
					name: "email",
					state: result2.state,
				}, from("203.0.113.7"));
				assertEquals(sentStatus, 200);
				assertEquals(channelEmail.messages.length, 1);
				// The refusal comes before anything reaches a channel.
				const [status, rejected] = await post("/send-prompt", {
					name: "email",
					state: result2.state,
				}, from("203.0.113.7"));
				assertEquals(status, 429);
				assertEquals(rejected.error, "RATE_LIMITED");
				assertEquals(channelEmail.messages.length, 1);
				// The request bucket is untouched by the send bucket, so the flow itself carries on.
				assertEquals(
					(await post("/sign-in", undefined, from("203.0.113.7")))[0],
					200,
				);
			});

			// The send bucket is mounted on the route, so the router applies it under a prefix as well.
			it("should bucket the sending route under a basePath", async () => {
				const post = client(createAuthDance({
					api: {
						...apiOptions,
						limits: { address: { request: { limit: 100, window: 60 }, send: { limit: 1, window: 60 } } },
					},
					app: { basePath: "/auth" },
				}));
				const [, result1] = await post("/auth/sign-up", undefined, from("203.0.113.7"));
				const [, result2] = await post(
					"/auth/submit-prompt",
					{ name: "email", value: "john.doe@example.com", state: result1.state },
					from("203.0.113.7"),
				);
				assert(result2.state);
				const [sentStatus] = await post("/auth/send-prompt", {
					name: "email",
					state: result2.state,
				}, from("203.0.113.7"));
				assertEquals(sentStatus, 200);
				assertEquals(channelEmail.messages.length, 1);
				const [status, rejected] = await post("/auth/send-prompt", {
					name: "email",
					state: result2.state,
				}, from("203.0.113.7"));
				assertEquals(status, 429);
				assertEquals(rejected.error, "RATE_LIMITED");
				assertEquals(channelEmail.messages.length, 1);
			});
		});
	});
});
