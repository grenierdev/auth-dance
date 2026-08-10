import { beforeEach, describe, it } from "@std/testing/bdd";
import { assert, assertEquals, assertRejects } from "@std/assert";
import { MemoryAuthDanceChannel, MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "./providers/memory.ts";
import {
	AuthDanceApi,
	type AuthDanceApiHooks,
	type AuthDanceApiOptions,
	type AuthDanceHookErrorEvent,
	type AuthDanceIdentityEvent,
	type AuthDanceSessionEvent,
} from "./api.ts";
import type { AuthDanceResponseTokens } from "./response.ts";
import { choice, sequence } from "./choreography.ts";
import { EmailAuthDanceComponent } from "./components/email.ts";
import type { AuthDanceComponentContext } from "./component.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent } from "./identity.ts";
import { ksuid } from "./id.ts";
import { PasswordAuthDanceComponent, pbkdf2PasswordHasher } from "./components/password.ts";
import { AuthDanceStorage } from "./storage.ts";
import { AuthDanceError } from "./error.ts";
import type { AuthDanceKvProvider } from "./provider.ts";
import { decode } from "jose/base64url";
import { decodeJwt } from "jose/jwt/decode";
import { SignJWT } from "jose/jwt/sign";

// PBKDF2 at its real cost is 600000 passes and ~200ms a hash, which these suites pay a few dozen times over. The
// cost is the point in a deployment and pure latency here, so the tests buy a single pass.
const TEST_PASSWORD_HASHER = pbkdf2PasswordHasher(1);

describe("Api", () => {
	let storage: AuthDanceStorage;
	let apiOptions: AuthDanceApiOptions;
	let api: AuthDanceApi;
	let channelEmail: MemoryAuthDanceChannel;
	let channelEmail2: MemoryAuthDanceChannel;
	let channelSms: MemoryAuthDanceChannel;
	let email: EmailAuthDanceComponent;
	let email2: EmailAuthDanceComponent;
	let password: PasswordAuthDanceComponent;

	// Seeding an identity outside a flow. The password record is salted with the id of the identity, so the id
	// comes first and the components are built against it, the way a sign-up mints one before its first step.
	// Hence `setIdentity` rather than `createIdentity`, which mints an id of its own after the fact.
	async function seedIdentity(
		data: Record<string, unknown>,
		build: (seed: (name: string) => AuthDanceComponentContext) => Promise<AuthDanceIdentityComponent[]>,
	): Promise<AuthDanceIdentity> {
		const identity: AuthDanceIdentity = { id: ksuid("id_"), data, components: [] };
		identity.components = await build((name) => ({ storage, stateId: "state_seed", name, flow: "sign-up", identity }));
		await storage.setIdentity(identity);
		return identity;
	}

	// The identity every suite below signs in as, seeded straight into storage rather than through a sign-up.
	async function johnDoe(): Promise<void> {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
	}

	// The two steps of sequence("email", "password"), for a suite that asserts on what happens after a sign-in
	// rather than on the sign-in itself.
	async function signInAsJohnDoe(api: AuthDanceApi): Promise<AuthDanceResponseTokens> {
		const result1 = await api.signIn();
		const result2 = await api.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		const result3 = await api.submitPrompt({
			name: "password",
			value: "foo",
			state: result2.state,
		});
		assert("tokens" in result3);
		return result3;
	}

	beforeEach(() => {
		channelEmail = new MemoryAuthDanceChannel("email");
		channelEmail2 = new MemoryAuthDanceChannel("email2");
		channelSms = new MemoryAuthDanceChannel("phone");
		email = new EmailAuthDanceComponent({ channel: "email" });
		email2 = new EmailAuthDanceComponent({ channel: "email2" });
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
			components: { email, password, email2 },
			secret: "zdJXI1jwuXW8A19fns0E_B4HSYm7AUHLGlU9WLo8mxs", // openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
			storage,
		};
		api = new AuthDanceApi(apiOptions);
	});

	it("should sign-in", async () => {
		const identity = await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
		const result1 = await api.signIn();
		assert(result1.prompt.kind === "input");
		assert(result1.prompt.type === "email");
		const result2 = await api.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		assert(result2.prompt.kind === "input");
		assert(result2.prompt.type === "password");
		const result3 = await api.submitPrompt({
			name: "password",
			value: "foo",
			state: result2.state,
		});
		assert("tokens" in result3);
		assertEquals(result3.identity.id, identity.id);
	});
	it("should sign-in through either component of the same kind", async () => {
		// The email component resolves its records under the name it is declared with, so a deployment can declare
		// it twice — a work address and a personal one — and each name answers for its own identifications only.
		const api = new AuthDanceApi({
			...apiOptions,
			choreography: sequence(choice("email", "email2"), "password"),
		});
		const identity = await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await email2.getIdentityComponent(
				"email2",
				"john.doe2@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
		const result1 = await api.signIn();
		assert(result1.prompt.kind === "choice");
		const result2 = await api.submitPrompt({
			name: "email2",
			value: "john.doe2@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		const result3 = await api.submitPrompt({
			name: "password",
			value: "foo",
			state: result2.state,
		});
		assert("tokens" in result3);
		assertEquals(result3.identity.id, identity.id);
		// And each name answers for its own records alone: the address enrolled under "email" is not an "email2".
		const other1 = await api.signIn();
		const rejected = await assertRejects(
			() =>
				api.submitPrompt({
					name: "email2",
					value: "john.doe@example.com",
					state: other1.state,
				}),
			AuthDanceError,
		);
		assertEquals(rejected.code, "INVALID_PROMPT_VALUE");
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
		const result1 = await api.signIn();
		const result2 = await api.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		// The email step already put the identityId in the state; a rejected password must still stop the
		// choreography instead of walking to the end of it and minting tokens.
		const rejected = await assertRejects(() =>
			api.submitPrompt({
				name: "password",
				value: "bar",
				state: result2.state,
			}), AuthDanceError);
		assertEquals(rejected.code, "INVALID_PROMPT_VALUE");
	});
	it("should not sign-in with an unknown identification", async () => {
		const result1 = await api.signIn();
		const rejected = await assertRejects(() =>
			api.submitPrompt({
				name: "email",
				value: "jane.doe@example.com",
				state: result1.state,
			}), AuthDanceError);
		// Deliberately the same code as a wrong password above: telling the two apart would let a caller
		// enumerate which addresses have an account.
		assertEquals(rejected.code, "INVALID_PROMPT_VALUE");
	});
	it("should sign-up", async () => {
		const result1 = await api.signUp();
		assert(result1.prompt.kind === "input");
		assert(result1.prompt.type === "email");
		const result2 = await api.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		assert(result2.prompt.kind === "input");
		assert(result2.prompt.type === "otp");
		assert(result2.prompt.sendable);
		const sent = await api.sendValidation({
			name: "email",
			locale: "en",
			state: result2.state,
		});
		assert(sent.success);
		assert(channelEmail.messages.length === 1);
		const code = channelEmail.messages[0].content["text/x-code"];
		assert(code);
		const result3 = await api.submitValidation({
			name: "email",
			value: code,
			state: result2.state,
		});
		assert("state" in result3);
		const result4 = await api.submitPrompt({
			name: "password",
			value: "bar",
			state: result3.state,
		});
		assert("tokens" in result4);
	});
	it("should not validate a wrong otp", async () => {
		const result1 = await api.signUp();
		const result2 = await api.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		await api.sendValidation({
			name: "email",
			locale: "en",
			state: result2.state,
		});
		const code = channelEmail.messages[0].content["text/x-code"];
		assert(code);
		const rejected = await assertRejects(() =>
			api.submitValidation({
				name: "email",
				value: `${Number(code) + 1}`.padStart(code.length, "0"),
				state: result2.state,
			}), AuthDanceError);
		assertEquals(rejected.code, "INVALID_VALIDATION_VALUE");
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
		const result1 = await api.signIn();
		const result2 = await api.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		const result3 = await api.submitPrompt({
			name: "password",
			value: "foo",
			state: result2.state,
		});
		assert("tokens" in result3);
		const result4 = await api.subscribe({
			name: "sms",
			access_token: result3.tokens.access_token,
		});
		const result5 = await api.submitPrompt({
			name: "sms",
			value: "5551234567",
			state: result4.state,
		});
		assert("state" in result5);
		assert(result5.prompt.kind === "input");
		assert(result5.prompt.type === "otp");
		assert(result5.prompt.sendable);
		const sent = await api.sendValidation({
			name: "email",
			locale: "en",
			state: result5.state,
		});
		assert(sent.success);
		assert(channelEmail.messages.length === 1);
		const code = channelEmail.messages[0].content["text/x-code"];
		assert(code);
		const result6 = await api.submitValidation({
			name: "sms",
			value: code,
			state: result5.state,
		});
		assert("success" in result6);
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
		const result1 = await api.signIn();
		const result2 = await api.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		const result3 = await api.submitPrompt({
			name: "password",
			value: "foo",
			state: result2.state,
		});
		assert("tokens" in result3);
		// The email component emits its own "email" channel, so the identity is already subscribed to it.
		const rejected = await assertRejects(
			() =>
				api.subscribe({
					name: "email",
					access_token: result3.tokens.access_token,
				}),
			AuthDanceError,
		);
		assertEquals(rejected.code, "CHANNEL_ALREADY_SUBSCRIBED");
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
		const result1 = await api.signIn();
		const result2 = await api.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		const result3 = await api.submitPrompt({
			name: "password",
			value: "foo",
			state: result2.state,
		});
		assert("tokens" in result3);
		const result4 = await api.unsubscribe({
			name: "sms",
			access_token: result3.tokens.access_token,
		});
		assert("state" in result4);
		assert(result4.prompt.kind === "input");
		assert(result4.prompt.type === "confirmation");
		const result5 = await api.submitPrompt({
			name: "sms",
			value: true,
			state: result4.state,
		});
		assert("success" in result5);
		assert(result5.success);
		const identity = await storage.getIdentity(result3.identity.id);
		assert(identity);
		assert(
			!identity.components.find((c) => c.kind === "channel" && c.component === "sms"),
		);
	});
	it("should not unsubscribe a channel a component still relies on", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
		const result1 = await api.signIn();
		const result2 = await api.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		const result3 = await api.submitPrompt({
			name: "password",
			value: "foo",
			state: result2.state,
		});
		assert("tokens" in result3);
		// The "email" channel carries linkedTo: ["email"], and that component is still enrolled — dropping the
		// channel would leave it with no way to verify itself.
		const rejected = await assertRejects(
			() =>
				api.unsubscribe({
					name: "email",
					access_token: result3.tokens.access_token,
				}),
			AuthDanceError,
		);
		assertEquals(rejected.code, "CHANNEL_IN_USE");
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
		const result1 = await api.signIn();
		const result2 = await api.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		const result3 = await api.submitPrompt({
			name: "password",
			value: "foo",
			state: result2.state,
		});
		assert("tokens" in result3);
		const result4 = await api.enroll({
			name: "email2",
			access_token: result3.tokens.access_token,
		});
		assert(result4.prompt.kind === "input");
		assert(result4.prompt.type === "email");
		const result5 = await api.submitPrompt({
			name: "email2",
			value: "john.doe2@example.com",
			state: result4.state,
		});
		assert("state" in result5);
		assert(result5.prompt.kind === "input");
		assert(result5.prompt.type === "otp");
		assert(result5.prompt.sendable);
		const sent = await api.sendValidation({
			name: "email2",
			locale: "en",
			state: result5.state,
		});
		assert(sent.success);
		assert(channelEmail2.messages.length === 1);
		const code = channelEmail2.messages[0].content["text/x-code"];
		assert(code);
		const result6 = await api.submitValidation({
			name: "email2",
			value: code,
			state: result5.state,
		});
		assert("success" in result6);
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
		const result1 = await api.signIn();
		const result2 = await api.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		const result3 = await api.submitPrompt({
			name: "password",
			value: "foo",
			state: result2.state,
		});
		assert("tokens" in result3);
		const rejected = await assertRejects(
			() =>
				api.enroll({
					name: "password",
					access_token: result3.tokens.access_token,
				}),
			AuthDanceError,
		);
		assertEquals(rejected.code, "COMPONENT_ALREADY_ENROLLED");
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
		const result1 = await api.signIn();
		const result2 = await api.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		const result3 = await api.submitPrompt({
			name: "password",
			value: "foo",
			state: result2.state,
		});
		assert("tokens" in result3);
		const result4 = await api.unenroll({
			name: "email2",
			access_token: result3.tokens.access_token,
		});
		assert("state" in result4);
		assert(result4.prompt.kind === "input");
		assert(result4.prompt.type === "confirmation");
		const result5 = await api.submitPrompt({
			name: "email2",
			value: true,
			state: result4.state,
		});
		assert("success" in result5);
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
		const result1 = await api.signIn();
		const result2 = await api.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		const result3 = await api.submitPrompt({
			name: "password",
			value: "foo",
			state: result2.state,
		});
		assert("tokens" in result3);
		// sequence("email", "password") has no path to an end without "password", enrolled "email2" or not.
		const rejected = await assertRejects(
			() =>
				api.unenroll({
					name: "password",
					access_token: result3.tokens.access_token,
				}),
			AuthDanceError,
		);
		assertEquals(rejected.code, "WOULD_LOCK_OUT");
		const identity = await storage.getIdentity(result3.identity.id);
		assert(
			identity?.components.find((c) => c.kind === "challenge" && c.component === "password"),
		);
	});
	it("should unenroll a component a choice makes optional", async () => {
		// "email2" alone is an alternative to the email + password path, so "password" becomes droppable.
		const api = new AuthDanceApi({
			...apiOptions,
			choreography: choice(sequence("email", "password"), "email2"),
		});
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
		const result1 = await api.signIn();
		const result2 = await api.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		const result3 = await api.submitPrompt({
			name: "password",
			value: "foo",
			state: result2.state,
		});
		assert("tokens" in result3);
		const result4 = await api.unenroll({
			name: "password",
			access_token: result3.tokens.access_token,
		});
		assert(result4.prompt.kind === "input");
		assert(result4.prompt.type === "confirmation");
		const result5 = await api.submitPrompt({
			name: "password",
			value: true,
			state: result4.state,
		});
		assert("success" in result5);
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
		const result1 = await api.signIn();
		const result2 = await api.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		const result3 = await api.submitPrompt({
			name: "password",
			value: "foo",
			state: result2.state,
		});
		assert("tokens" in result3);
		// A second session, to show the deletion takes every session with it and not just the calling one.
		const other1 = await api.signIn();
		const other2 = await api.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: other1.state,
		});
		assert("state" in other2);
		const other3 = await api.submitPrompt({
			name: "password",
			value: "foo",
			state: other2.state,
		});
		assert("tokens" in other3);
		const result4 = await api.delete({
			access_token: result3.tokens.access_token,
		});
		assert("state" in result4);
		assert(result4.prompt.kind === "input");
		assert(result4.prompt.type === "confirmation");
		const result5 = await api.submitPrompt({
			name: "identity",
			value: true,
			state: result4.state,
		});
		assert("success" in result5);
		assert(result5.success);
		assertEquals(await storage.getIdentity(result3.identity.id), undefined);
		// No token outlives the identity it was minted for: both sessions are gone, so neither access token
		// resolves to anything any more. Which code that surfaces as is the provider's business — MemoryKvProvider
		// rejects on a missing key instead of resolving undefined, so it comes out UNKNOWN rather than
		// SESSION_NOT_FOUND — hence only the rejection itself is asserted.
		assertEquals(await storage.listSession(result3.identity.id), []);
		await assertRejects(
			() => api.signOut(other3.tokens.access_token),
			AuthDanceError,
		);
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
		const result1 = await api.signIn();
		const result2 = await api.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		const result3 = await api.submitPrompt({
			name: "password",
			value: "foo",
			state: result2.state,
		});
		assert("tokens" in result3);
		const result4 = await api.delete({
			access_token: result3.tokens.access_token,
		});
		// Anything other than an outright `true` leaves the identity where it is — the gate is a confirmation,
		// not a truthiness check.
		const rejected = await assertRejects(
			() =>
				api.submitPrompt({
					name: "identity",
					value: "yes",
					state: result4.state,
				}),
			AuthDanceError,
		);
		assertEquals(rejected.code, "CONFIRMATION_REQUIRED");
		assert(await storage.getIdentity(identity.id));
	});
	it("should require a fresh sign-in to delete the identity", async () => {
		const identity = await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
		// Deleting is destructive and irreversible, so it sits behind the same elevated window as enroll.
		const strictApi = new AuthDanceApi({
			...apiOptions,
			durations: { elevated: 0 },
		});
		const result1 = await strictApi.signIn();
		const result2 = await strictApi.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		const result3 = await strictApi.submitPrompt({
			name: "password",
			value: "foo",
			state: result2.state,
		});
		assert("tokens" in result3);
		const rejected = await assertRejects(
			() => strictApi.delete({ access_token: result3.tokens.access_token }),
			AuthDanceError,
		);
		assertEquals(rejected.code, "FRESH_SIGN_IN_REQUIRED");
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
		const result1 = await api.signIn();
		const result2 = await api.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		const result3 = await api.submitPrompt({
			name: "password",
			value: "foo",
			state: result2.state,
		});
		assert("tokens" in result3);
		const result4 = await api.rotate({
			name: "password",
			access_token: result3.tokens.access_token,
		});
		assert("state" in result4);
		assert(result4.prompt.kind === "input");
		assert(result4.prompt.type === "password");
		const result5 = await api.submitPrompt({
			name: "password",
			value: "bar",
			state: result4.state,
		});
		assert("success" in result5);
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
		const result1 = await api.signIn();
		const result2 = await api.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		const result3 = await api.submitPrompt({
			name: "password",
			value: "foo",
			state: result2.state,
		});
		assert("tokens" in result3);
		const result4 = await api.rotate({
			name: "email",
			access_token: result3.tokens.access_token,
		});
		assert("state" in result4);
		assert(result4.prompt.kind === "input");
		assert(result4.prompt.type === "otp");
		assert(result4.prompt.sendable);
		const sent1 = await api.sendValidation({
			name: "email",
			locale: "en",
			state: result4.state,
		});
		assert(sent1.success);
		const code1 = channelEmail.messages[0].content["text/x-code"];
		assert(code1);
		const result5 = await api.submitValidation({
			name: "email",
			value: code1,
			state: result4.state,
		});
		assert("state" in result5);
		const result6 = await api.submitPrompt({
			name: "email",
			value: "john.doe2@example.com",
			state: result5.state,
		});
		assert("state" in result6);
		assert(result6.prompt.kind === "input");
		assert(result6.prompt.type === "otp");
		assert(result6.prompt.sendable);
		const sent2 = await api.sendValidation({
			name: "email",
			locale: "en",
			state: result6.state,
		});
		assert(sent2.success);
		const code2 = channelEmail.messages[1].content["text/x-code"];
		assert(code2);
		const result7 = await api.submitValidation({
			name: "email",
			value: code2,
			state: result6.state,
		});
		assert("success" in result7);
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
		// The recovery names what the owner lost, not what they can still prove. sequence("email", "password")
		// leaves "email" as the only component that both resolves an identity and proves control of it, so the
		// choice of one collapses to that component's own prompt.
		const result1 = await api.recover({ name: "password" });
		assert(result1.prompt.kind === "input");
		assert(result1.prompt.name === "email");
		assert(result1.prompt.type === "email");
		const result2 = await api.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		assert(result2.prompt.kind === "input");
		assert(result2.prompt.type === "otp");
		assert(result2.prompt.sendable);
		const sent = await api.sendValidation({
			name: "email",
			locale: "en",
			state: result2.state,
		});
		assert(sent.success);
		assert(channelEmail.messages.length === 1);
		const code = channelEmail.messages[0].content["text/x-code"];
		assert(code);
		const result3 = await api.submitValidation({
			name: "email",
			value: code,
			state: result2.state,
		});
		assert("state" in result3);
		assert(result3.prompt.kind === "input");
		assert(result3.prompt.type === "password");
		const result4 = await api.submitPrompt({
			name: "password",
			value: "bar",
			state: result3.state,
		});
		assert("success" in result4);
		assert(result4.success);
		const identity2 = await storage.getIdentity(identity1.id);
		const passwordComponent1 = identity1.components.find((c) => c.kind === "challenge" && c.component === "password");
		const passwordComponent2 = identity2?.components.find((c) => c.kind === "challenge" && c.component === "password");
		assert(passwordComponent1?.data?.hash !== passwordComponent2?.data?.hash);
	});
	it("should offer every component a recovery can be proven through", async () => {
		// Two components of this choreography identify and verify on their own, so the owner picks which one of
		// them to prove — and the recovery runs through the one they picked, not through the first on offer.
		const api = new AuthDanceApi({
			...apiOptions,
			choreography: sequence(choice("email", "email2"), "password"),
		});
		const identity1 = await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await email2.getIdentityComponent(
				"email2",
				"john.doe2@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
		const result1 = await api.recover({ name: "password" });
		assert(result1.prompt.kind === "choice");
		assertEquals(
			result1.prompt.components.map((p) => (p.kind === "input" ? p.name : null)),
			["email", "email2"],
		);
		const result2 = await api.submitPrompt({
			name: "email2",
			value: "john.doe2@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		assert(result2.prompt.kind === "input");
		assert(result2.prompt.type === "otp");
		// The code goes to the channel of the component that was picked, and nothing reaches the other one.
		const sent = await api.sendValidation({ name: "email2", locale: "en", state: result2.state });
		assert(sent.success);
		assertEquals(channelEmail.messages.length, 0);
		assertEquals(channelEmail2.messages.length, 1);
		const code = channelEmail2.messages[0].content["text/x-code"];
		assert(code);
		const result3 = await api.submitValidation({
			name: "email2",
			value: code,
			state: result2.state,
		});
		assert("state" in result3);
		assert(result3.prompt.kind === "input");
		assert(result3.prompt.type === "password");
		const result4 = await api.submitPrompt({
			name: "password",
			value: "bar",
			state: result3.state,
		});
		assert("success" in result4);
		assert(result4.success);
		const identity2 = await storage.getIdentity(identity1.id);
		const passwordComponent1 = identity1.components.find((c) => c.kind === "challenge" && c.component === "password");
		const passwordComponent2 = identity2?.components.find((c) => c.kind === "challenge" && c.component === "password");
		assert(passwordComponent1?.data?.hash !== passwordComponent2?.data?.hash);
	});
	it("should not identify a recovery through a component it did not offer", async () => {
		await johnDoe();
		const result1 = await api.recover({ name: "password" });
		// "password" is the component being recovered, and it identifies nobody anyway. Answering the choice with
		// it does not start the recovery from it.
		const rejected = await assertRejects(
			() =>
				api.submitPrompt({
					name: "password",
					value: "foo",
					state: result1.state,
				}),
			AuthDanceError,
		);
		assertEquals(rejected.code, "COMPONENT_NOT_IN_CHOREOGRAPHY");
	});
	it("should not recover a component the caller has nothing left to identify through", async () => {
		// "email" is the only component of sequence("email", "password") that identifies and verifies on its own,
		// and it is the one being recovered — so there is no one left to prove they own the account.
		const rejected = await assertRejects(
			() => api.recover({ name: "email" }),
			AuthDanceError,
		);
		assertEquals(rejected.code, "COMPONENT_NOT_RECOVERABLE");
	});
	it("should not recover a component the choreography does not know", async () => {
		// "email2" is a declared component, but no step of sequence("email", "password") asks for it, so a
		// recovery has nothing to reset.
		const rejected = await assertRejects(
			() => api.recover({ name: "email2" }),
			AuthDanceError,
		);
		assertEquals(rejected.code, "COMPONENT_NOT_RECOVERABLE");
	});
	it("should not recover a component that is not declared at all", async () => {
		const rejected = await assertRejects(
			() => api.recover({ name: "totp" }),
			AuthDanceError,
		);
		assertEquals(rejected.code, "UNKNOWN_COMPONENT");
	});
	it("should keep the original sign-in date when refreshing tokens", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
		const result1 = await api.signIn();
		const result2 = await api.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		const result3 = await api.submitPrompt({
			name: "password",
			value: "foo",
			state: result2.state,
		});
		assert("tokens" in result3);
		const refreshed = await api.refreshToken(result3.tokens.refresh_token);
		const signedInAt = decodeJwt(result3.tokens.access_token).auth_time;
		assertEquals(typeof signedInAt, "number");
		// Refreshing extends how long the session may be used, never how recently its holder proved who they are.
		assertEquals(
			decodeJwt(refreshed.tokens.access_token).auth_time,
			signedInAt,
		);
		assertEquals(
			decodeJwt(refreshed.tokens.refresh_token).auth_time,
			signedInAt,
		);
	});
	it("should require a fresh sign-in for a sensitive action once the elevated window has elapsed", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
		// elevated_duration: 0 makes any sign-in — even this instant's — already too old.
		const strictApi = new AuthDanceApi({
			...apiOptions,
			durations: { elevated: 0 },
		});
		const result1 = await strictApi.signIn();
		const result2 = await strictApi.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		const result3 = await strictApi.submitPrompt({
			name: "password",
			value: "foo",
			state: result2.state,
		});
		assert("tokens" in result3);
		const rejected = await assertRejects(
			() =>
				strictApi.enroll({
					name: "email2",
					access_token: result3.tokens.access_token,
				}),
			AuthDanceError,
		);
		assertEquals(rejected.code, "FRESH_SIGN_IN_REQUIRED");
		// The session itself stays perfectly usable — only the sensitive action is gated.
		const signedOut = await strictApi.signOut(result3.tokens.access_token);
		assert(signedOut.success);
	});
	it("should not let a refresh renew the elevated window", async () => {
		await seedIdentity({ name: "John Doe" }, async (seed) => [
			...await email.getIdentityComponent(
				"email",
				"john.doe@example.com",
				true,
			),
			...await password.getIdentityComponent("password", "foo", true, seed("password")),
		]);
		const strictApi = new AuthDanceApi({
			...apiOptions,
			durations: { elevated: 0 },
		});
		const result1 = await strictApi.signIn();
		const result2 = await strictApi.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		const result3 = await strictApi.submitPrompt({
			name: "password",
			value: "foo",
			state: result2.state,
		});
		assert("tokens" in result3);
		const refreshed = await strictApi.refreshToken(
			result3.tokens.refresh_token,
		);
		const rejected = await assertRejects(
			() =>
				strictApi.subscribe({
					name: "sms",
					access_token: refreshed.tokens.access_token,
				}),
			AuthDanceError,
		);
		assertEquals(rejected.code, "FRESH_SIGN_IN_REQUIRED");
	});
	it("should give each flow its own state duration", async () => {
		const perFlowApi = new AuthDanceApi({
			...apiOptions,
			durations: { sign_in: 30, recover: 15 * 60 },
		});
		const secondsFromNow = (expireAt: Date) => Math.round((expireAt.getTime() - Date.now()) / 1000);
		assertEquals(secondsFromNow((await perFlowApi.signIn()).expireAt), 30);
		assertEquals(
			secondsFromNow((await perFlowApi.recover({ name: "password" })).expireAt),
			15 * 60,
		);
		// A flow left unconfigured keeps the 5 minute default.
		assertEquals(secondsFromNow((await perFlowApi.signUp()).expireAt), 5 * 60);
	});
	it("should reject an access token carrying no sign-in date", async () => {
		const forged = await new SignJWT({})
			.setProtectedHeader({ alg: "HS256" })
			.setIssuer("acme")
			.setIssuedAt()
			.setExpirationTime(new Date(Date.now() + 60_000))
			.setSubject("st_whatever")
			.sign(decode(apiOptions.secret));
		const rejected = await assertRejects(() => api.signOut(forged), AuthDanceError);
		assertEquals(rejected.code, "INVALID_ACCESS_TOKEN");
	});
	it("should read a state back under the issuer it was minted with", async () => {
		await johnDoe();
		// The issuer travels as the `iss` claim of the state, the way it does on the minted tokens, because the
		// library hands the configured issuer to jose and jose checks the claim. An issuer that only reached the
		// protected header left that claim unset, and every flow of a deployment that configured one then failed
		// on its second call with INVALID_STATE.
		const issuedApi = new AuthDanceApi({ ...apiOptions, tokens: { issuer: "auth-dance-demo" } });
		const result1 = await issuedApi.signIn();
		const result2 = await issuedApi.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		assert(result2.prompt.kind === "input");
		assert(result2.prompt.type === "password");
		// And the check is a real one: the same state under another issuer does not decrypt.
		const otherApi = new AuthDanceApi({ ...apiOptions, tokens: { issuer: "somebody-else" } });
		const rejected = await assertRejects(
			() =>
				otherApi.submitPrompt({
					name: "email",
					value: "john.doe@example.com",
					state: result1.state,
				}),
			AuthDanceError,
		);
		assertEquals(rejected.code, "INVALID_STATE");
	});
	it("should reject a forged state without reaching the flow", async () => {
		const rejected = await assertRejects(
			() =>
				api.submitPrompt({
					name: "email",
					value: "john.doe@example.com",
					state: "not-a-jwt",
				}),
			AuthDanceError,
		);
		assertEquals(rejected.code, "INVALID_STATE");
	});
	it("should surface an unexpected failure as UNKNOWN, not as a business error", async () => {
		// A provider blowing up is not a business rule: it must come out with no business error code so the
		// caller maps it to a 500 instead of quietly treating it as a rejected credential.
		const boom = new TypeError("kv is down");
		const brokenKv: AuthDanceKvProvider = {
			get: () => Promise.reject(boom),
			list: () => Promise.reject(boom),
			set: () => Promise.reject(boom),
			unset: () => Promise.reject(boom),
		};
		const brokenApi = new AuthDanceApi({
			...apiOptions,
			storage: new AuthDanceStorage({
				identity: new MemoryIdentityProvider(),
				kv: brokenKv,
				rate_limiter: new MemoryRateLimiterProvider(),
			}),
		});
		const result1 = await brokenApi.signUp();
		const result2 = await brokenApi.submitPrompt({
			name: "email",
			value: "john.doe@example.com",
			state: result1.state,
		});
		assert("state" in result2);
		// OtpAuthDanceComponent.sendPrompt writes the code to KV and does not catch — unlike EmailAuthDanceComponent,
		// which swallows storage faults into a plain "not verified" and so surfaces as a business error.
		const thrown = await assertRejects(
			() =>
				brokenApi.sendValidation({
					name: "email",
					locale: "en",
					state: result2.state,
				}),
			AuthDanceError,
		);
		assertEquals(thrown.code, "UNKNOWN");
		assertEquals(thrown.cause, boom);
	});

	// These buckets are keyed on the identity or session a call is attributable to, so they cover individual
	// abuse only. Spreading the same abuse over many identities is bucketed per address at the edge instead —
	// see app.test.ts.
	describe("rate limit", () => {
		function limitedApi(options: Pick<AuthDanceApiOptions, "durations" | "limits">): AuthDanceApi {
			return new AuthDanceApi({ ...apiOptions, ...options });
		}

		it("should stop guessing a password once the verify bucket is exhausted", async () => {
			const api = limitedApi({
				limits: { identity: { verify: { limit: 2, window: 60 } } },
			});
			await johnDoe();
			const result1 = await api.signIn();
			// The identification resolves the identity; every guess after it is attributable to that identity,
			// which is exactly the step brute-forcing a password lives on.
			const result2 = await api.submitPrompt({
				name: "email",
				value: "john.doe@example.com",
				state: result1.state,
			});
			assert("state" in result2);
			for (let attempt = 0; attempt < 2; attempt++) {
				const wrong = await assertRejects(
					() =>
						api.submitPrompt({
							name: "password",
							value: "nope",
							state: result2.state,
						}),
					AuthDanceError,
				);
				assertEquals(wrong.code, "INVALID_PROMPT_VALUE");
			}
			const blocked = await assertRejects(
				() =>
					api.submitPrompt({
						name: "password",
						value: "nope",
						state: result2.state,
					}),
				AuthDanceError,
			);
			assertEquals(blocked.code, "RATE_LIMITED");
			// The bucket is consumed before the value is looked at, so the correct password fares no better —
			// which is the point: an exhausted bucket must not be a way to tell a right guess from a wrong one.
			const stillBlocked = await assertRejects(
				() =>
					api.submitPrompt({
						name: "password",
						value: "foo",
						state: result2.state,
					}),
				AuthDanceError,
			);
			assertEquals(stillBlocked.code, "RATE_LIMITED");
		});

		it("should not bucket a step no identity is attributable to yet", async () => {
			const api = limitedApi({
				limits: { identity: { verify: { limit: 1, window: 60 } } },
			});
			// Probing for addresses resolves nothing, so there is no subject to bucket on and the tightest
			// possible per-identity limit never fires. Only the per-address bucket can stop this.
			for (let attempt = 0; attempt < 4; attempt++) {
				const result = await api.signIn();
				const rejected = await assertRejects(
					() =>
						api.submitPrompt({
							name: "email",
							value: `nobody${attempt}@example.com`,
							state: result.state,
						}),
					AuthDanceError,
				);
				assertEquals(rejected.code, "INVALID_PROMPT_VALUE");
			}
		});

		it("should stop starting management flows once the manage bucket is exhausted", async () => {
			const api = limitedApi({
				limits: { identity: { manage: { limit: 1, window: 60 } } },
			});
			await johnDoe();
			const result1 = await api.signIn();
			const result2 = await api.submitPrompt({
				name: "email",
				value: "john.doe@example.com",
				state: result1.state,
			});
			assert("state" in result2);
			const result3 = await api.submitPrompt({
				name: "password",
				value: "foo",
				state: result2.state,
			});
			assert("tokens" in result3);
			const access_token = result3.tokens.access_token;
			const enrolled = await api.enroll({ name: "email2", access_token });
			assert(enrolled.state);
			// One bucket for every management flow, keyed on the session: hopping to another flow does not
			// hand the same session a fresh allowance.
			const blocked = await assertRejects(
				() => api.unenroll({ name: "password", access_token }),
				AuthDanceError,
			);
			assertEquals(blocked.code, "RATE_LIMITED");
		});

		it("should stop draining a channel once the send bucket is exhausted", async () => {
			const api = limitedApi({
				limits: { identity: { send: { limit: 1, window: 60 } } },
			});
			await johnDoe();
			const result1 = await api.signIn();
			const result2 = await api.submitPrompt({
				name: "email",
				value: "john.doe@example.com",
				state: result1.state,
			});
			assert("state" in result2);
			// The bucket is on sending, not on the flow: rotating "email" sends an OTP to prove control, and the
			// second request for it is refused rather than putting another message on the channel.
			const result3 = await api.submitPrompt({
				name: "password",
				value: "foo",
				state: result2.state,
			});
			assert("tokens" in result3);
			const rotating = await api.rotate({
				name: "email",
				access_token: result3.tokens.access_token,
			});
			const sent = await api.sendValidation({
				name: "email",
				locale: "en",
				state: rotating.state,
			});
			assert(sent.success);
			assertEquals(channelEmail.messages.length, 1);
			const blocked = await assertRejects(
				() =>
					api.sendValidation({
						name: "email",
						locale: "en",
						state: rotating.state,
					}),
				AuthDanceError,
			);
			assertEquals(blocked.code, "RATE_LIMITED");
			assertEquals(channelEmail.messages.length, 1);
		});

		it("should keep the retryAfter hint out of the serialised error", async () => {
			const api = limitedApi({
				limits: { identity: { refresh: { limit: 1, window: 60 } } },
			});
			await johnDoe();
			const result1 = await api.signIn();
			const result2 = await api.submitPrompt({
				name: "email",
				value: "john.doe@example.com",
				state: result1.state,
			});
			assert("state" in result2);
			const result3 = await api.submitPrompt({
				name: "password",
				value: "foo",
				state: result2.state,
			});
			assert("tokens" in result3);
			await api.refreshToken(result3.tokens.refresh_token);
			const blocked = await assertRejects(
				() => api.refreshToken(result3.tokens.refresh_token),
				AuthDanceError,
			);
			assertEquals(blocked.code, "RATE_LIMITED");
			assertEquals(JSON.stringify(blocked), '{"code":"RATE_LIMITED"}');
		});
	});

	// A hook is how a deployment learns that something changed: it publishes an event, writes an audit record, or
	// warns the owner. What matters is therefore which hook fires, in which order, and with what on it — not that
	// something fired at all. Every suite below reads the whole lifecycle of one flow off the same recorder.
	describe("hooks", () => {
		interface HookRecord {
			hook: string;
			flow: string;
			identityId: string;
			name?: string;
			sessionId?: string;
		}

		function recorder(): { records: HookRecord[]; hooks: AuthDanceApiHooks } {
			const records: HookRecord[] = [];
			const identityHook = (hook: string) => (event: AuthDanceIdentityEvent): void => {
				records.push({ hook, flow: event.flow, identityId: event.identity.id, name: event.name });
			};
			const sessionHook = (hook: string) => (event: AuthDanceSessionEvent): void => {
				records.push({ hook, flow: event.flow, identityId: event.identity.id, sessionId: event.session.id });
			};
			return {
				records,
				hooks: {
					onIdentityCreated: identityHook("onIdentityCreated"),
					onIdentityUpdated: identityHook("onIdentityUpdated"),
					onIdentityDeleted: identityHook("onIdentityDeleted"),
					onSessionCreated: sessionHook("onSessionCreated"),
					onSessionRefreshed: sessionHook("onSessionRefreshed"),
					onSessionDeleted: sessionHook("onSessionDeleted"),
				},
			};
		}

		function recordingApi(): { records: HookRecord[]; api: AuthDanceApi } {
			const { records, hooks } = recorder();
			return { records, api: new AuthDanceApi({ ...apiOptions, hooks }) };
		}

		it("should report a sign-up as a new identity and then its first session", async () => {
			const { records, api } = recordingApi();
			const result1 = await api.signUp();
			const result2 = await api.submitPrompt({
				name: "email",
				value: "john.doe@example.com",
				state: result1.state,
			});
			assert("state" in result2);
			await api.sendValidation({ name: "email", locale: "en", state: result2.state });
			const code = channelEmail.messages[0].content["text/x-code"];
			assert(code);
			const result3 = await api.submitValidation({
				name: "email",
				value: code,
				state: result2.state,
			});
			assert("state" in result3);
			// Storage holds nothing until the choreography completes, so a half-walked sign-up reports nothing
			// either. A hook never names an identity a later step could still reject.
			assertEquals(records, []);
			const result4 = await api.submitPrompt({
				name: "password",
				value: "bar",
				state: result3.state,
			});
			assert("tokens" in result4);
			// The identity exists before the session that signs it in, and both name the flow that produced them.
			assertEquals(records.map((r) => r.hook), ["onIdentityCreated", "onSessionCreated"]);
			assertEquals(records.map((r) => r.flow), ["sign-up", "sign-up"]);
			assertEquals(records[0].identityId, result4.identity.id);
			assertEquals(records[1].sessionId, result4.session.id);
		});

		it("should report a sign-in as a session alone", async () => {
			const { records, api } = recordingApi();
			await johnDoe();
			const signedIn = await signInAsJohnDoe(api);
			// A sign-in reads an identity and changes nothing on it, so no identity hook fires for one.
			assertEquals(records.map((r) => r.hook), ["onSessionCreated"]);
			assertEquals(records[0].flow, "sign-in");
			assertEquals(records[0].sessionId, signedIn.session.id);
			assertEquals(records[0].identityId, signedIn.identity.id);
		});

		it("should report a refresh on the session the sign-in created", async () => {
			const { records, api } = recordingApi();
			await johnDoe();
			const signedIn = await signInAsJohnDoe(api);
			const refreshed = await api.refreshToken(signedIn.tokens.refresh_token);
			// A refresh mints a new pair of tokens on the session that already exists. It creates none, so the
			// hook that reports it is not the hook that reports a sign-in.
			assertEquals(records.map((r) => r.hook), ["onSessionCreated", "onSessionRefreshed"]);
			assertEquals(records[1].flow, "refresh");
			assertEquals(records[1].sessionId, signedIn.session.id);
			assertEquals(refreshed.session.id, signedIn.session.id);
		});

		it("should report every session a sign-out destroys", async () => {
			const { records, api } = recordingApi();
			await johnDoe();
			const first = await signInAsJohnDoe(api);
			const second = await signInAsJohnDoe(api);
			const signedOut = await api.signOut(first.tokens.access_token, true);
			assert(signedOut.success);
			// One event for each session, not one for the sweep: a listener sees the same event whichever way a
			// session ended.
			const deleted = records.filter((r) => r.hook === "onSessionDeleted");
			assertEquals(deleted.map((r) => r.flow), ["sign-out", "sign-out"]);
			assertEquals(
				deleted.map((r) => r.sessionId).sort(),
				[first.session.id, second.session.id].sort(),
			);
		});

		it("should report an enroll with the component it added", async () => {
			const { records, api } = recordingApi();
			await johnDoe();
			const signedIn = await signInAsJohnDoe(api);
			const enrolling = await api.enroll({
				name: "email2",
				access_token: signedIn.tokens.access_token,
			});
			const collected = await api.submitPrompt({
				name: "email2",
				value: "john.doe2@example.com",
				state: enrolling.state,
			});
			assert("state" in collected);
			await api.sendValidation({ name: "email2", locale: "en", state: collected.state });
			const code = channelEmail2.messages[0].content["text/x-code"];
			assert(code);
			const done = await api.submitValidation({
				name: "email2",
				value: code,
				state: collected.state,
			});
			assert("success" in done);
			const updated = records.filter((r) => r.hook === "onIdentityUpdated");
			assertEquals(updated.length, 1);
			assertEquals(updated[0].flow, "enroll");
			assertEquals(updated[0].name, "email2");
			assertEquals(updated[0].identityId, signedIn.identity.id);
		});

		it("should report a subscribe with the channel it added", async () => {
			const { records, api } = recordingApi();
			await johnDoe();
			const signedIn = await signInAsJohnDoe(api);
			const subscribing = await api.subscribe({
				name: "sms",
				access_token: signedIn.tokens.access_token,
			});
			const collected = await api.submitPrompt({
				name: "sms",
				value: "5551234567",
				state: subscribing.state,
			});
			assert("state" in collected);
			await api.sendValidation({ name: "email", locale: "en", state: collected.state });
			const code = channelEmail.messages[0].content["text/x-code"];
			assert(code);
			const done = await api.submitValidation({
				name: "sms",
				value: code,
				state: collected.state,
			});
			assert("success" in done);
			const updated = records.filter((r) => r.hook === "onIdentityUpdated");
			assertEquals(updated.length, 1);
			assertEquals(updated[0].flow, "subscribe");
			// A channel names itself the same way a component does, so one field carries both.
			assertEquals(updated[0].name, "sms");
		});

		it("should report an unenroll with the component it removed", async () => {
			const { records, api } = recordingApi();
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
			const signedIn = await signInAsJohnDoe(api);
			const unenrolling = await api.unenroll({
				name: "email2",
				access_token: signedIn.tokens.access_token,
			});
			const done = await api.submitPrompt({
				name: "email2",
				value: true,
				state: unenrolling.state,
			});
			assert("success" in done);
			const updated = records.filter((r) => r.hook === "onIdentityUpdated");
			assertEquals(updated.length, 1);
			assertEquals(updated[0].flow, "unenroll");
			assertEquals(updated[0].name, "email2");
		});

		it("should report a recovery one time, and mint no session for it", async () => {
			const { records, api } = recordingApi();
			await johnDoe();
			const result1 = await api.recover({ name: "password" });
			const result2 = await api.submitPrompt({
				name: "email",
				value: "john.doe@example.com",
				state: result1.state,
			});
			assert("state" in result2);
			await api.sendValidation({ name: "email", locale: "en", state: result2.state });
			const code = channelEmail.messages[0].content["text/x-code"];
			assert(code);
			const result3 = await api.submitValidation({
				name: "email",
				value: code,
				state: result2.state,
			});
			assert("state" in result3);
			const result4 = await api.submitPrompt({
				name: "password",
				value: "bar",
				state: result3.state,
			});
			assert("success" in result4);
			// Proving control of one component is not a sign-in, so a recovery reports no session at all. The one
			// identity event names the component it reset, not the email the caller proved along the way.
			assertEquals(records.map((r) => r.hook), ["onIdentityUpdated"]);
			assertEquals(records[0].flow, "recover");
			assertEquals(records[0].name, "password");
		});

		it("should report every session of a delete before the identity itself", async () => {
			const { records, api } = recordingApi();
			await johnDoe();
			const first = await signInAsJohnDoe(api);
			const second = await signInAsJohnDoe(api);
			const deleting = await api.delete({ access_token: first.tokens.access_token });
			const done = await api.submitPrompt({
				name: "identity",
				value: true,
				state: deleting.state,
			});
			assert("success" in done);
			assertEquals(records.map((r) => r.hook), [
				"onSessionCreated",
				"onSessionCreated",
				"onSessionDeleted",
				"onSessionDeleted",
				"onIdentityDeleted",
			]);
			assertEquals(
				records.slice(2, 4).map((r) => r.sessionId).sort(),
				[first.session.id, second.session.id].sort(),
			);
			// The identity comes last and carries the record as it stood one moment before the delete, because
			// storage holds nothing to read by the time the hook runs.
			assertEquals(records[4].flow, "delete");
			assertEquals(records[4].identityId, first.identity.id);
			assertEquals(await storage.getIdentity(first.identity.id), undefined);
		});

		it("should await a hook before it answers the caller", async () => {
			let published = false;
			const api = new AuthDanceApi({
				...apiOptions,
				hooks: {
					onSessionCreated: async () => {
						await new Promise((resolve) => setTimeout(resolve, 10));
						published = true;
					},
				},
			});
			await johnDoe();
			await signInAsJohnDoe(api);
			// A hook that publishes an event finishes before the caller reads the tokens, so a deployment can
			// order that event against the response it belongs to.
			assert(published);
		});

		it("should not fail a flow when a hook rejects", async () => {
			const boom = new Error("the queue is down");
			const errors: AuthDanceHookErrorEvent[] = [];
			const api = new AuthDanceApi({
				...apiOptions,
				hooks: {
					onSessionCreated: () => Promise.reject(boom),
					onError: (event) => {
						errors.push(event);
					},
				},
			});
			await johnDoe();
			// The tokens are minted before the hook runs. Surfacing a listener that is down as a failed sign-in
			// would tell the caller their tokens are worthless when they are not.
			const signedIn = await signInAsJohnDoe(api);
			assert(signedIn.tokens.access_token);
			assertEquals(errors.length, 1);
			assertEquals(errors[0].hook, "onSessionCreated");
			assertEquals(errors[0].cause, boom);
		});

		it("should keep a rejecting onError out of the flow too", async () => {
			const api = new AuthDanceApi({
				...apiOptions,
				hooks: {
					onSessionCreated: () => Promise.reject(new Error("the queue is down")),
					onError: () => Promise.reject(new Error("the log is down as well")),
				},
			});
			await johnDoe();
			// Nowhere left to report to, and still not the business of the sign-in.
			const signedIn = await signInAsJohnDoe(api);
			assert(signedIn.tokens.access_token);
		});
	});
});
