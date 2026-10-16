import { deepEqual, ok, throws } from "node:assert";
import { beforeEach, describe, it } from "vitest";
import type { AuthDanceApiOptions } from "./api.ts";
import { choice, sequence } from "./choreography.ts";
import type { AuthDanceComponentContext } from "./component.ts";
import { EmailAuthDanceComponent } from "./components/email.ts";
import { OtpAuthDanceComponent } from "./components/otp.ts";
import { PasswordAuthDanceComponent, pbkdf2PasswordHasher } from "./components/password.ts";
import { ksuid } from "./id.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent } from "./identity.ts";
import { type AuthDance, createAuthDance, forwardedAddress } from "./mod.ts";
import type { AuthDanceKvProvider } from "./provider.ts";
import { MemoryAuthDanceChannel, MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "./providers/memory.ts";
import { AuthDanceStorage } from "./storage.ts";

// One PBKDF2 pass, to keep the suites fast.
const TEST_PASSWORD_HASHER = pbkdf2PasswordHasher(1);
// 32 characters, above the 16-byte floor of the component.
const TEST_PASSWORD_PEPPER = "tQ3vX9pL2mR7wK5nB8cF1hJ4dG6sA0zE";

// Every response is JSON, failures included, so a call only ever yields a status and a parsed body.

type Json = any;
type Post = (path: string, body?: unknown, headers?: Record<string, string>) => Promise<[number, Json]>;

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
		password = new PasswordAuthDanceComponent(TEST_PASSWORD_PEPPER, TEST_PASSWORD_HASHER);
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
		deepEqual(status, 200);
		ok(result3.tokens);
		return result3;
	}

	it("should sign-in", async () => {
		const identity = await seedIdentity({ name: "John Doe" }, async (seed) => [
			...(await email.getIdentityComponent("email", "john.doe@example.com", true)),
			...(await password.getIdentityComponent("password", "foo", true, seed("password"))),
		]);
		const [status1, result1] = await post("/sign-in");
		deepEqual(status1, 200);
		deepEqual(result1.prompt.kind, "input");
		deepEqual(result1.prompt.type, "email");
		const [status2, result2] = await post("/submit-prompt", {
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		deepEqual(status2, 200);
		ok(result2.state);
		deepEqual(result2.prompt.kind, "input");
		deepEqual(result2.prompt.type, "password");
		const [status3, result3] = await post("/submit-prompt", {
			name: "password",
			value: "foo",
			state: result2.state,
		});
		deepEqual(status3, 200);
		ok(result3.tokens);
		deepEqual(result3.identity.id, identity.id);
	});

	it("should not sign-in with a wrong challenge", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...(await email.getIdentityComponent("email", "john.doe@example.com", true)),
			...(await password.getIdentityComponent("password", "foo", true, seed("password"))),
		]);
		const [, result1] = await post("/sign-in");
		const [, result2] = await post("/submit-prompt", {
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		ok(result2.state);
		const [status, rejected] = await post("/submit-prompt", {
			name: "password",
			value: "bar",
			state: result2.state,
		});
		deepEqual(status, 500);
		deepEqual(rejected.error, "INVALID_PROMPT_VALUE");
	});

	it("should not sign-in with an unknown identification", async () => {
		const [, result1] = await post("/sign-in");
		const [status, rejected] = await post("/submit-prompt", {
			name: "email",
			value: "jane.doe@example.com",
			state: result1.state,
		});
		deepEqual(status, 500);
		// The same code as a wrong password. A different code would let a caller enumerate accounts.
		deepEqual(rejected.error, "INVALID_PROMPT_VALUE");
	});

	it("should list the sessions open on the identity", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...(await email.getIdentityComponent("email", "john.doe@example.com", true)),
			...(await password.getIdentityComponent("password", "foo", true, seed("password"))),
		]);
		const first = await signIn();
		const second = await signIn();
		const [status, listed] = await post("/list-sessions", undefined, bearer(second.tokens.access_token));
		deepEqual(status, 200);
		deepEqual(listed.sessions.map((s: Json) => s.id).sort(), [first.session.id, second.session.id].sort());
		// `current` names the caller's own session.
		deepEqual(listed.current, second.session.id);
		// A session that has been signed out stops being listed.
		await post("/sign-out", { others: false }, bearer(first.tokens.access_token));
		const [, afterSignOut] = await post("/list-sessions", undefined, bearer(second.tokens.access_token));
		deepEqual(
			afterSignOut.sessions.map((s: Json) => s.id),
			[second.session.id],
		);
		// The route is authenticated, like every other management route.
		const [rejectedStatus, rejected] = await post("/list-sessions");
		deepEqual(rejectedStatus, 500);
		deepEqual(rejected.error, "INVALID_ACCESS_TOKEN");
	});

	it("should list the components enrolled on the identity", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...(await email.getIdentityComponent("email", "john.doe@example.com", true)),
			...(await password.getIdentityComponent("password", "foo", true, seed("password"))),
		]);
		const session = await signIn();
		const [status, listed] = await post("/list-components", undefined, bearer(session.tokens.access_token));
		deepEqual(status, 200);
		// EmailAuthDanceComponent contributes the identification, the channel and the one-time code challenge.
		deepEqual(listed.components, [
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
		ok(!listed.components.some((c: Json) => "data" in c));
		// The route is authenticated, like every other management route.
		const [rejectedStatus, rejected] = await post("/list-components");
		deepEqual(rejectedStatus, 500);
		deepEqual(rejected.error, "INVALID_ACCESS_TOKEN");
	});

	it("should refuse to list the components with the access token of a signed-out session", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...(await email.getIdentityComponent("email", "john.doe@example.com", true)),
			...(await password.getIdentityComponent("password", "foo", true, seed("password"))),
		]);
		const session = await signIn();
		await post("/sign-out", { others: false }, bearer(session.tokens.access_token));
		const [status, rejected] = await post("/list-components", undefined, bearer(session.tokens.access_token));
		deepEqual(status, 500);
		deepEqual(rejected.error, "SESSION_NOT_FOUND");
		const [sessionsStatus, sessionsRejected] = await post("/list-sessions", undefined, bearer(session.tokens.access_token));
		deepEqual(sessionsStatus, 500);
		deepEqual(sessionsRejected.error, "SESSION_NOT_FOUND");
	});

	it("should sign-up", async () => {
		const [, result1] = await post("/sign-up");
		deepEqual(result1.prompt.kind, "input");
		deepEqual(result1.prompt.type, "email");
		const [, result2] = await post("/submit-prompt", {
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		ok(result2.state);
		deepEqual(result2.prompt.kind, "input");
		deepEqual(result2.prompt.type, "otp");
		ok(result2.prompt.sendable);
		const [, sent] = await post("/send-prompt", {
			name: "email",
			locale: "en",
			state: result2.state,
		});
		ok(sent.success);
		deepEqual(channelEmail.messages.length, 1);
		const code = channelEmail.messages[0].content["text/x-code"];
		ok(code);
		const [, result3] = await post("/submit-prompt", {
			name: "email",
			value: code,
			state: result2.state,
		});
		ok(result3.state);
		const [status, result4] = await post("/submit-prompt", {
			name: "password",
			value: "bar",
			state: result3.state,
		});
		deepEqual(status, 200);
		ok(result4.tokens);
	});

	it("should not validate a wrong otp", async () => {
		const [, result1] = await post("/sign-up");
		const [, result2] = await post("/submit-prompt", {
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		ok(result2.state);
		await post("/send-prompt", {
			name: "email",
			locale: "en",
			state: result2.state,
		});
		const code = channelEmail.messages[0].content["text/x-code"];
		ok(code);
		const [status, rejected] = await post("/submit-prompt", {
			name: "email",
			value: `${Number(code) + 1}`.padStart(code.length, "0"),
			state: result2.state,
		});
		deepEqual(status, 500);
		deepEqual(rejected.error, "INVALID_VALIDATION_VALUE");
	});

	it("should subscribe", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...(await email.getIdentityComponent("email", "john.doe@example.com", true)),
			...(await password.getIdentityComponent("password", "foo", true, seed("password"))),
		]);
		const result3 = await signIn();
		const [, result4] = await post("/subscribe", { name: "sms" }, bearer(result3.tokens.access_token));
		const [, result5] = await post("/submit-prompt", {
			name: "sms",
			value: "5551234567",
			state: result4.state,
		});
		ok(result5.state);
		deepEqual(result5.prompt.kind, "input");
		deepEqual(result5.prompt.type, "otp");
		ok(result5.prompt.sendable);
		const [, sent] = await post("/send-prompt", {
			name: "sms",
			locale: "en",
			state: result5.state,
		});
		ok(sent.success);
		deepEqual(channelSms.messages.length, 1);
		const code = channelSms.messages[0].content["text/x-code"];
		ok(code);
		const [status, result6] = await post("/submit-prompt", {
			name: "sms",
			value: code,
			state: result5.state,
		});
		deepEqual(status, 200);
		ok(result6.success);
		const identity = await storage.getIdentity(result3.identity.id);
		ok(identity?.components.some((c) => c.kind === "channel" && c.component === "sms" && c.confirmed));
	});

	it("should not subscribe a channel already subscribed to", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...(await email.getIdentityComponent("email", "john.doe@example.com", true)),
			...(await password.getIdentityComponent("password", "foo", true, seed("password"))),
		]);
		const result3 = await signIn();
		// The email component emits its own "email" channel.
		const [status, rejected] = await post("/subscribe", { name: "email" }, bearer(result3.tokens.access_token));
		deepEqual(status, 500);
		deepEqual(rejected.error, "CHANNEL_ALREADY_SUBSCRIBED");
	});

	it("should unsubscribe", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...(await email.getIdentityComponent("email", "john.doe@example.com", true)),
			...(await password.getIdentityComponent("password", "foo", true, seed("password"))),
			await channelSms.getIdentityChannel("sms", "5551234567", true),
		]);
		const result3 = await signIn();
		const [, result4] = await post("/unsubscribe", { name: "sms" }, bearer(result3.tokens.access_token));
		ok(result4.state);
		deepEqual(result4.prompt.kind, "input");
		deepEqual(result4.prompt.type, "confirmation");
		const [status, result5] = await post("/submit-prompt", {
			name: "sms",
			value: true,
			state: result4.state,
		});
		deepEqual(status, 200);
		ok(result5.success);
		const identity = await storage.getIdentity(result3.identity.id);
		ok(identity);
		ok(!identity.components.find((c) => c.kind === "channel" && c.component === "sms"));
	});

	it("should not unsubscribe a channel whose collateral the choreography cannot do without", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...(await email.getIdentityComponent("email", "john.doe@example.com", true)),
			...(await password.getIdentityComponent("password", "foo", true, seed("password"))),
		]);
		const result3 = await signIn();
		// The "email" channel carries linkedTo: ["email"], so dropping it drops the only path.
		const [status, rejected] = await post("/unsubscribe", { name: "email" }, bearer(result3.tokens.access_token));
		deepEqual(status, 500);
		deepEqual(rejected.error, "WOULD_LOCK_OUT");
	});

	it("should enroll", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...(await email.getIdentityComponent("email", "john.doe@example.com", true)),
			...(await password.getIdentityComponent("password", "foo", true, seed("password"))),
			await channelSms.getIdentityChannel("sms", "5551234567", true),
		]);
		const result3 = await signIn();
		const [, result4] = await post("/enroll", { name: "email2" }, bearer(result3.tokens.access_token));
		deepEqual(result4.prompt.kind, "input");
		deepEqual(result4.prompt.type, "email");
		const [, result5] = await post("/submit-prompt", {
			name: "email2",
			value: "john.doe2@example.com",
			state: result4.state,
		});
		ok(result5.state);
		deepEqual(result5.prompt.kind, "input");
		deepEqual(result5.prompt.type, "otp");
		ok(result5.prompt.sendable);
		const [, sent] = await post("/send-prompt", {
			name: "email2",
			locale: "en",
			state: result5.state,
		});
		ok(sent.success);
		deepEqual(channelEmail2.messages.length, 1);
		const code = channelEmail2.messages[0].content["text/x-code"];
		ok(code);
		const [status, result6] = await post("/submit-prompt", {
			name: "email2",
			value: code,
			state: result5.state,
		});
		deepEqual(status, 200);
		ok(result6.success);
		const identity = await storage.getIdentity(result3.identity.id);
		ok(identity);
		ok(!identity.components.find((c) => c.kind === "challenge" && c.component === "email2"));
	});

	it("should not enroll a component already enrolled", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...(await email.getIdentityComponent("email", "john.doe@example.com", true)),
			...(await password.getIdentityComponent("password", "foo", true, seed("password"))),
		]);
		const result3 = await signIn();
		const [status, rejected] = await post("/enroll", { name: "password" }, bearer(result3.tokens.access_token));
		deepEqual(status, 500);
		deepEqual(rejected.error, "COMPONENT_ALREADY_ENROLLED");
	});

	it("should unenroll", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...(await email.getIdentityComponent("email", "john.doe@example.com", true)),
			...(await password.getIdentityComponent("password", "foo", true, seed("password"))),
			...(await email2.getIdentityComponent("email2", "john.doe2@example.com", true)),
		]);
		const result3 = await signIn();
		const [, result4] = await post("/unenroll", { name: "email2" }, bearer(result3.tokens.access_token));
		ok(result4.state);
		deepEqual(result4.prompt.kind, "input");
		deepEqual(result4.prompt.type, "confirmation");
		const [status, result5] = await post("/submit-prompt", {
			name: "email2",
			value: true,
			state: result4.state,
		});
		deepEqual(status, 200);
		ok(result5.success);
		const identity = await storage.getIdentity(result3.identity.id);
		ok(identity);
		ok(!identity.components.find((c) => c.kind !== "channel" && c.component === "email2"));
	});

	it("should not unenroll a component the choreography cannot do without", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...(await email.getIdentityComponent("email", "john.doe@example.com", true)),
			...(await password.getIdentityComponent("password", "foo", true, seed("password"))),
			...(await email2.getIdentityComponent("email2", "john.doe2@example.com", true)),
		]);
		const result3 = await signIn();
		// sequence("email", "password") has no path to an end without "password".
		const [status, rejected] = await post("/unenroll", { name: "password" }, bearer(result3.tokens.access_token));
		deepEqual(status, 500);
		deepEqual(rejected.error, "WOULD_LOCK_OUT");
		const identity = await storage.getIdentity(result3.identity.id);
		ok(identity?.components.find((c) => c.kind === "challenge" && c.component === "password"));
	});

	it("should unenroll a component a choice makes optional", async () => {
		// "email2" and its code are an alternative to the email + password path, so "password" becomes droppable.
		post = client(
			createAuthDance({
				api: {
					...apiOptions,
					choreography: choice(sequence("email", "password"), sequence("email2", "otp2")),
				},
			}),
		);
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...(await email.getIdentityComponent("email", "john.doe@example.com", true)),
			...(await password.getIdentityComponent("password", "foo", true, seed("password"))),
			...(await email2.getIdentityComponent("email2", "john.doe2@example.com", true)),
		]);
		const result3 = await signIn();
		const [, result4] = await post("/unenroll", { name: "password" }, bearer(result3.tokens.access_token));
		deepEqual(result4.prompt.kind, "input");
		deepEqual(result4.prompt.type, "confirmation");
		const [status, result5] = await post("/submit-prompt", {
			name: "password",
			value: true,
			state: result4.state,
		});
		deepEqual(status, 200);
		ok(result5.success);
		const identity = await storage.getIdentity(result3.identity.id);
		ok(identity);
		ok(!identity.components.find((c) => c.kind !== "channel" && c.component === "password"));
	});

	it("should delete the identity", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...(await email.getIdentityComponent("email", "john.doe@example.com", true)),
			...(await password.getIdentityComponent("password", "foo", true, seed("password"))),
		]);
		const result3 = await signIn();
		// A second session, to show the deletion takes every session with it.
		const _other = await signIn();
		const [, result4] = await post("/delete", undefined, bearer(result3.tokens.access_token));
		ok(result4.state);
		deepEqual(result4.prompt.kind, "input");
		deepEqual(result4.prompt.type, "confirmation");
		const [status, result5] = await post("/submit-prompt", {
			name: "identity",
			value: true,
			state: result4.state,
		});
		deepEqual(status, 200);
		ok(result5.success);
		deepEqual(await storage.getIdentity(result3.identity.id), undefined);
		deepEqual(await storage.listSession(result3.identity.id), []);
	});

	it("should not delete the identity without an explicit confirmation", async () => {
		const identity = await seedIdentity({ name: "John Doe" }, async (seed) => [
			...(await email.getIdentityComponent("email", "john.doe@example.com", true)),
			...(await password.getIdentityComponent("password", "foo", true, seed("password"))),
		]);
		const result3 = await signIn();
		const [, result4] = await post("/delete", undefined, bearer(result3.tokens.access_token));
		// The gate is a confirmation, not a truthiness check.
		const [status, rejected] = await post("/submit-prompt", {
			name: "identity",
			value: "yes",
			state: result4.state,
		});
		deepEqual(status, 500);
		deepEqual(rejected.error, "CONFIRMATION_REQUIRED");
		ok(await storage.getIdentity(identity.id));
	});

	it("should rotate password", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...(await email.getIdentityComponent("email", "john.doe@example.com", true)),
			...(await password.getIdentityComponent("password", "foo", true, seed("password"))),
		]);
		const result3 = await signIn();
		const [, result4] = await post("/rotate", { name: "password" }, bearer(result3.tokens.access_token));
		ok(result4.state);
		deepEqual(result4.prompt.kind, "input");
		deepEqual(result4.prompt.type, "password");
		const [status, result5] = await post("/submit-prompt", {
			name: "password",
			value: "bar",
			state: result4.state,
		});
		deepEqual(status, 200);
		ok(result5.success);
		const identity = await storage.getIdentity(result3.identity.id);
		ok(identity);
		ok(identity.components.find((c) => c.kind === "challenge" && c.component === "password"));
	});

	it("should rotate email", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...(await email.getIdentityComponent("email", "john.doe@example.com", true)),
			...(await password.getIdentityComponent("password", "foo", true, seed("password"))),
		]);
		const result3 = await signIn();
		const [, result4] = await post("/rotate", { name: "email" }, bearer(result3.tokens.access_token));
		ok(result4.state);
		deepEqual(result4.prompt.kind, "input");
		deepEqual(result4.prompt.type, "otp");
		ok(result4.prompt.sendable);
		const [, sent1] = await post("/send-prompt", {
			name: "email",
			locale: "en",
			state: result4.state,
		});
		ok(sent1.success);
		const code1 = channelEmail.messages[0].content["text/x-code"];
		ok(code1);
		const [, result5] = await post("/submit-prompt", {
			name: "email",
			value: code1,
			state: result4.state,
		});
		ok(result5.state);
		const [, result6] = await post("/submit-prompt", {
			name: "email",
			value: "john.doe2@example.com",
			state: result5.state,
		});
		ok(result6.state);
		deepEqual(result6.prompt.kind, "input");
		deepEqual(result6.prompt.type, "otp");
		ok(result6.prompt.sendable);
		const [, sent2] = await post("/send-prompt", {
			name: "email",
			locale: "en",
			state: result6.state,
		});
		ok(sent2.success);
		const code2 = channelEmail.messages[1].content["text/x-code"];
		ok(code2);
		const [status, result7] = await post("/submit-prompt", {
			name: "email",
			value: code2,
			state: result6.state,
		});
		deepEqual(status, 200);
		ok(result7.success);
		const identity = await storage.getIdentity(result3.identity.id);
		ok(identity);
		ok(
			identity.components.find(
				(c) => c.kind === "identification" && c.component === "email" && c.identification === "john.doe2@example.com",
			),
		);
	});

	it("should recover password", async () => {
		const identity1 = await seedIdentity({ name: "John Doe" }, async (seed) => [
			...(await email.getIdentityComponent("email", "john.doe@example.com", true)),
			...(await password.getIdentityComponent("password", "foo", true, seed("password"))),
		]);
		// "email" is the only component that resolves an identity and proves control of it. The choice collapses to one prompt.
		const [, result1] = await post("/recover", { name: "password" });
		deepEqual(result1.prompt.kind, "input");
		deepEqual(result1.prompt.name, "email");
		deepEqual(result1.prompt.type, "email");
		const [, result2] = await post("/submit-prompt", {
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		ok(result2.state);
		deepEqual(result2.prompt.kind, "input");
		deepEqual(result2.prompt.type, "otp");
		ok(result2.prompt.sendable);
		const [, sent] = await post("/send-prompt", {
			name: "email",
			locale: "en",
			state: result2.state,
		});
		ok(sent.success);
		deepEqual(channelEmail.messages.length, 1);
		const code = channelEmail.messages[0].content["text/x-code"];
		ok(code);
		const [, result3] = await post("/submit-prompt", {
			name: "email",
			value: code,
			state: result2.state,
		});
		ok(result3.state);
		deepEqual(result3.prompt.kind, "input");
		deepEqual(result3.prompt.type, "password");
		const [status, result4] = await post("/submit-prompt", {
			name: "password",
			value: "bar",
			state: result3.state,
		});
		deepEqual(status, 200);
		ok(result4.success);
		const identity2 = await storage.getIdentity(identity1.id);
		const passwordComponent1 = identity1.components.find((c) => c.kind === "challenge" && c.component === "password");
		const passwordComponent2 = identity2?.components.find((c) => c.kind === "challenge" && c.component === "password");
		ok(passwordComponent1?.data?.hash !== passwordComponent2?.data?.hash);
	});

	it("should not recover a component the caller has nothing left to identify through", async () => {
		// "email" is the only component that identifies and verifies on its own, and it is the one being recovered.
		const [status, rejected] = await post("/recover", { name: "email" });
		deepEqual(status, 500);
		deepEqual(rejected.error, "COMPONENT_NOT_RECOVERABLE");
	});

	it("should reject a forged state without reaching the flow", async () => {
		const [status, rejected] = await post("/submit-prompt", {
			name: "email",
			value: "john.doe@example.com",
			state: "not-a-jwt",
		});
		deepEqual(status, 500);
		deepEqual(rejected.error, "INVALID_STATE");
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
		const brokenPost = client(
			createAuthDance({
				api: {
					...apiOptions,
					storage: new AuthDanceStorage({
						identity: new MemoryIdentityProvider(),
						kv: brokenKv,
						rate_limiter: new MemoryRateLimiterProvider(),
					}),
				},
			}),
		);
		const [, result1] = await brokenPost("/sign-up");
		const [, result2] = await brokenPost("/submit-prompt", {
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		ok(result2.state);
		// OtpAuthDanceComponent.sendPrompt writes the code to KV and does not catch.
		const [status, thrown] = await brokenPost("/send-prompt", {
			name: "email",
			locale: "en",
			state: result2.state,
		});
		deepEqual(status, 500);
		deepEqual(thrown.error, "UNKNOWN");
		// The cause must not travel. AuthDanceError keeps `code` as its only own-enumerable property.
		deepEqual(Object.keys(thrown), ["error"]);
	});

	// These cases cover what the edge adds on top of AuthDanceApi: the access token, the caller address, and the body validation.
	describe("http", () => {
		it("should refuse an authenticated route with no bearer token", async () => {
			const [status, rejected] = await post("/enroll", { name: "email2" });
			deepEqual(status, 500);
			deepEqual(rejected.error, "INVALID_ACCESS_TOKEN");
		});

		it("should refuse a deletion with no bearer token", async () => {
			const [status, rejected] = await post("/delete");
			deepEqual(status, 500);
			deepEqual(rejected.error, "INVALID_ACCESS_TOKEN");
		});

		// A malformed header and a rejected token report the same code.
		it("should refuse a malformed authorization header", async () => {
			const [status, rejected] = await post(
				"/enroll",
				{ name: "email2" },
				{
					authorization: "Basic aGk6dGhlcmU=",
				},
			);
			deepEqual(status, 500);
			deepEqual(rejected.error, "INVALID_ACCESS_TOKEN");
		});

		it("should answer a malformed body with BAD_REQUEST", async () => {
			const [status, rejected] = await post("/recover", {});
			deepEqual(status, 400);
			deepEqual(rejected.error, "BAD_REQUEST");
		});

		// AuthDanceResponseState carries a Date. The client gets the ISO string.
		it("should serialise expireAt as an ISO timestamp", async () => {
			const [, result] = await post("/sign-in");
			deepEqual(typeof result.expireAt, "string");
			ok(!Number.isNaN(Date.parse(result.expireAt)));
		});

		// The library reads address and userAgent from the connection, never from the body.
		it("should record the caller from the request headers", async () => {
			await seedIdentity({ name: "John Doe" }, async (seed) => [
				...(await email.getIdentityComponent("email", "john.doe@example.com", true)),
				...(await password.getIdentityComponent("password", "foo", true, seed("password"))),
			]);
			const [, result1] = await post("/sign-in");
			const [, result2] = await post("/submit-prompt", {
				name: "email",
				value: "john.doe@example.com",
				state: result1.state,
			});
			const [, result3] = await post(
				"/submit-prompt",
				{
					name: "password",
					value: "foo",
					state: result2.state,
				},
				{
					"cf-connecting-ip": "203.0.113.7",
					"user-agent": "e2e/1.0",
				},
			);
			deepEqual(result3.session.address, "203.0.113.7");
			deepEqual(result3.session.userAgent, "e2e/1.0");
		});

		it("should fall back to the Accept-Language header when no locale is given", async () => {
			const [, result1] = await post("/sign-up");
			const [, result2] = await post("/submit-prompt", {
				name: "email",
				value: "john.doe@example.com",
				state: result1.state,
			});
			const [status, sent] = await post(
				"/send-prompt",
				{
					name: "email",
					state: result2.state,
				},
				{
					"accept-language": "fr-CA,fr;q=0.9",
				},
			);
			deepEqual(status, 200);
			ok(sent.success);
			deepEqual(channelEmail.messages.length, 1);
		});

		it("should not route an unknown path", async () => {
			const auth = createAuthDance({ api: apiOptions });
			const response = await auth.fetch(new Request("http://local/nope", { method: "POST" }));
			deepEqual(response.status, 404);
		});

		// The per-address counterpart to the per-identity buckets of api.test.ts.
		describe("rate limit", () => {
			function limitedPost(address_rate_limit: NonNullable<AuthDanceApiOptions["limits"]>["address"]): Post {
				return client(createAuthDance({ api: { ...apiOptions, limits: { address: address_rate_limit } } }));
			}

			function from(address: string): Record<string, string> {
				return { "cf-connecting-ip": address };
			}

			it("should refuse a flood from one address with 429", async () => {
				const post = limitedPost({ request: { limit: 2, window: 60 } });
				deepEqual((await post("/sign-in", undefined, from("203.0.113.7")))[0], 200);
				deepEqual((await post("/sign-in", undefined, from("203.0.113.7")))[0], 200);
				const [status, rejected] = await post("/sign-in", undefined, from("203.0.113.7"));
				deepEqual(status, 429);
				deepEqual(rejected.error, "RATE_LIMITED");
				// The bucket is on the address, not on the route. A different flow shares the same allowance.
				deepEqual((await post("/recover", { name: "password" }, from("203.0.113.7")))[0], 429);
			});

			it("should bucket each address on its own", async () => {
				const post = limitedPost({ request: { limit: 1, window: 60 } });
				deepEqual((await post("/sign-in", undefined, from("203.0.113.7")))[0], 200);
				deepEqual((await post("/sign-in", undefined, from("203.0.113.7")))[0], 429);
				deepEqual((await post("/sign-in", undefined, from("198.51.100.4")))[0], 200);
			});

			// A request with no address used to skip both buckets. Now every such request shares one bucket.
			it("should put every request that carries no address in one shared bucket", async () => {
				const post = limitedPost({ request: { limit: 2, window: 60 } });
				deepEqual((await post("/sign-in"))[0], 200);
				deepEqual((await post("/sign-in"))[0], 200);
				deepEqual((await post("/sign-in"))[0], 429);
				// An address of its own keeps its own bucket.
				deepEqual((await post("/sign-in", undefined, from("203.0.113.7")))[0], 200);
			});

			it("should read the last entry of x-forwarded-for, the one the proxy appended", async () => {
				// The audit PoC: a rotated first entry gave every request a fresh bucket.
				const post = limitedPost({ request: { limit: 2, window: 60 } });
				for (let attempt = 0; attempt < 2; attempt++) {
					const headers = { "x-forwarded-for": `198.51.100.${attempt}, 203.0.113.7` };
					deepEqual((await post("/sign-in", undefined, headers))[0], 200);
				}
				deepEqual((await post("/sign-in", undefined, { "x-forwarded-for": "198.51.100.99, 203.0.113.7" }))[0], 429);
			});

			it("should read the address from the resolver alone", async () => {
				const post = client(
					createAuthDance({
						api: { ...apiOptions, limits: { address: { request: { limit: 1, window: 60 } } } },
						app: { address: (c) => c.req.header("x-real-ip") },
					}),
				);
				deepEqual((await post("/sign-in", undefined, { "x-real-ip": "203.0.113.7", "cf-connecting-ip": "198.51.100.1" }))[0], 200);
				// The other headers change nothing, because the resolver never reads them.
				deepEqual((await post("/sign-in", undefined, { "x-real-ip": "203.0.113.7", "cf-connecting-ip": "198.51.100.2" }))[0], 429);
				deepEqual((await post("/sign-in", undefined, { "x-real-ip": "203.0.113.8", "x-forwarded-for": "203.0.113.7" }))[0], 200);
			});

			it("should read the entry a chain of proxies vouches for", async () => {
				const read = (header: string | undefined, hops: number) =>
					forwardedAddress(hops)({ req: { header: (name: string) => (name === "x-forwarded-for" ? header : undefined) } } as never);
				deepEqual(read("1.1.1.1, 2.2.2.2, 3.3.3.3", 1), "3.3.3.3");
				deepEqual(read("1.1.1.1, 2.2.2.2, 3.3.3.3", 2), "2.2.2.2");
				deepEqual(read("3.3.3.3", 2), undefined);
				deepEqual(read(undefined, 1), undefined);
				throws(() => forwardedAddress(0), RangeError);
			});

			it("should bucket the sending route on top of the request bucket", async () => {
				const post = limitedPost({
					request: { limit: 100, window: 60 },
					send: { limit: 1, window: 60 },
				});
				const [, result1] = await post("/sign-up", undefined, from("203.0.113.7"));
				const [, result2] = await post(
					"/submit-prompt",
					{
						name: "email",
						value: "john.doe@example.com",
						state: result1.state,
					},
					from("203.0.113.7"),
				);
				ok(result2.state);
				const [sentStatus] = await post(
					"/send-prompt",
					{
						name: "email",
						state: result2.state,
					},
					from("203.0.113.7"),
				);
				deepEqual(sentStatus, 200);
				deepEqual(channelEmail.messages.length, 1);
				// The refusal comes before anything reaches a channel.
				const [status, rejected] = await post(
					"/send-prompt",
					{
						name: "email",
						state: result2.state,
					},
					from("203.0.113.7"),
				);
				deepEqual(status, 429);
				deepEqual(rejected.error, "RATE_LIMITED");
				deepEqual(channelEmail.messages.length, 1);
				// The request bucket is untouched by the send bucket, so the flow itself carries on.
				deepEqual((await post("/sign-in", undefined, from("203.0.113.7")))[0], 200);
			});

			// The send bucket is mounted on the route, so the router applies it under a prefix as well.
			it("should bucket the sending route under a basePath", async () => {
				const post = client(
					createAuthDance({
						api: {
							...apiOptions,
							limits: { address: { request: { limit: 100, window: 60 }, send: { limit: 1, window: 60 } } },
						},
						app: { basePath: "/auth" },
					}),
				);
				const [, result1] = await post("/auth/sign-up", undefined, from("203.0.113.7"));
				const [, result2] = await post(
					"/auth/submit-prompt",
					{ name: "email", value: "john.doe@example.com", state: result1.state },
					from("203.0.113.7"),
				);
				ok(result2.state);
				const [sentStatus] = await post(
					"/auth/send-prompt",
					{
						name: "email",
						state: result2.state,
					},
					from("203.0.113.7"),
				);
				deepEqual(sentStatus, 200);
				deepEqual(channelEmail.messages.length, 1);
				const [status, rejected] = await post(
					"/auth/send-prompt",
					{
						name: "email",
						state: result2.state,
					},
					from("203.0.113.7"),
				);
				deepEqual(status, 429);
				deepEqual(rejected.error, "RATE_LIMITED");
				deepEqual(channelEmail.messages.length, 1);
			});
		});
	});
});
