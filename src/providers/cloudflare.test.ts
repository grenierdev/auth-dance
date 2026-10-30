import { deepEqual, ok, rejects } from "node:assert";
import { readFileSync } from "node:fs";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import { beforeEach, describe, it, vi } from "vitest";
import { AuthDanceApi } from "../api.ts";
import { sequence } from "../choreography.ts";
import { EmailAuthDanceComponent } from "../components/email.ts";
import { OtpAuthDanceComponent } from "../components/otp.ts";
import { PasswordAuthDanceComponent, pbkdf2PasswordHasher } from "../components/password.ts";
import { AuthDanceError, InvalidPromptValueError } from "../error.ts";
import { TEST_ISSUER, TEST_SIGNING_KEYS } from "../fixtures.test.ts";
import { ksuid } from "../id.ts";
import type { AuthDanceIdentity } from "../identity.ts";
import { testOauth2ClientProvider } from "../provider.test.ts";
import { AuthDanceStorage } from "../storage.ts";
import { CloudflareD1Oauth2ClientProvider, CloudflareSendMailAuthDanceChannel } from "./cloudflare.ts";
import { MemoryAuthDanceChannel, MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "./memory.ts";

// The module extends `DurableObject`, which only the Workers runtime provides.
vi.mock("cloudflare:workers", () => ({ DurableObject: class {} }));

// A D1 binding on an in-memory SQLite database that runs `sqlite.sql`. It covers the statement methods the
// providers call: `bind`, `first`, `all` and `run`.
function sqliteD1(): D1Database {
	const db = new DatabaseSync(":memory:");
	db.exec(readFileSync(new URL("./sqlite.sql", import.meta.url), "utf8"));
	const statement = (sql: string, params: SQLInputValue[]) => ({
		bind: (...values: SQLInputValue[]) => statement(sql, values),
		first: async () => db.prepare(sql).get(...params) ?? null,
		all: async () => ({ results: db.prepare(sql).all(...params) }),
		run: async () => {
			db.prepare(sql).run(...params);
			return { success: true };
		},
	});
	return { prepare: (sql: string) => statement(sql, []) } as unknown as D1Database;
}

describe("CloudflareD1Oauth2ClientProvider", () => {
	testOauth2ClientProvider(() => new CloudflareD1Oauth2ClientProvider(sqliteD1()));
});

// What the `SendEmail` binding received.
function sendEmailStub(): { sent: Array<{ to: string }>; binding: SendEmail } {
	const sent: Array<{ to: string }> = [];
	const binding = {
		send: async (message: { to: string }) => {
			sent.push(message);
			return { messageId: "msg_1" };
		},
	} as unknown as SendEmail;
	return { sent, binding };
}

describe("CloudflareSendMailAuthDanceChannel", () => {
	let sent: Array<{ to: string }>;
	let channel: CloudflareSendMailAuthDanceChannel;

	beforeEach(() => {
		const stub = sendEmailStub();
		sent = stub.sent;
		channel = new CloudflareSendMailAuthDanceChannel(stub.binding, { from: "auth@example.com" });
	});

	it("should store one address in lower case", async () => {
		deepEqual(await channel.getIdentityChannel("mail", " Victim@Example.com "), {
			kind: "channel",
			component: "mail",
			confirmed: false,
			data: { email: "victim@example.com" },
		});
	});

	it("should refuse a recipient that is not one address", async () => {
		for (const value of ["victim@example.com\r\nBcc: other@example.com", "a@b@example.com", ["a@x.io"], { to: "a@x.io" }, 42]) {
			await rejects(() => channel.getIdentityChannel("mail", value), InvalidPromptValueError);
		}
	});

	it("should refuse to deliver to a stored recipient with a line break", async () => {
		await rejects(() =>
			channel.sendMessage({
				recipient: { kind: "channel", component: "mail", confirmed: true, data: { email: "victim@example.com\r\nBcc: other@example.com" } },
				subject: "Your one-time code",
				content: { "text/plain": "123456" },
			}),
		);
		deepEqual(sent, []);
	});

	it("should deliver to a recipient subscribed under a name other than email", async () => {
		const storage = new AuthDanceStorage({
			identity: new MemoryIdentityProvider(),
			kv: new MemoryKvProvider(),
			rate_limiter: new MemoryRateLimiterProvider(),
		});
		const email = new EmailAuthDanceComponent({ channel: "email", challenge: "otp" });
		const password = new PasswordAuthDanceComponent("tQ3vX9pL2mR7wK5nB8cF1hJ4dG6sA0zE", pbkdf2PasswordHasher(1));
		const api = new AuthDanceApi({
			channels: { email: new MemoryAuthDanceChannel("email"), mail: channel },
			choreography: sequence("email", "password"),
			components: { email, password, otp: new OtpAuthDanceComponent({ channel: "email" }) },
			secret: "zdJXI1jwuXW8A19fns0E_B4HSYm7AUHLGlU9WLo8mxs",
			keys: TEST_SIGNING_KEYS,
			tokens: { issuer: TEST_ISSUER },
			storage,
		});
		const identity: AuthDanceIdentity = { id: ksuid("id_"), data: {}, components: [] };
		identity.components = [
			...(await email.getIdentityComponent("email", "john.doe@example.com", true)),
			...(await password.getIdentityComponent("password", "foo", true, {
				storage,
				stateId: "st_seed",
				name: "password",
				flow: "sign-up",
				identity,
			})),
		];
		await storage.setIdentity(identity);

		const result1 = await api.signIn();
		const result2 = await api.submitPrompt({ name: "email", value: "john.doe@example.com", state: result1.state });
		ok("state" in result2);
		const result3 = await api.submitPrompt({ name: "password", value: "foo", state: result2.state });
		ok("tokens" in result3);
		const started = await api.subscribe({ name: "mail", access_token: result3.tokens.access_token });
		const result4 = await api.submitPrompt({ name: "mail", value: "John.Doe@Work.example", state: started.state });
		ok("state" in result4);
		await api.sendPrompt({ name: "mail", locale: "en", state: result4.state });
		deepEqual(
			sent.map((message) => message.to),
			["john.doe@work.example"],
		);
		await rejects(
			() => api.submitPrompt({ name: "mail", value: "a\r\nb", state: started.state }),
			(error) => error instanceof AuthDanceError && error.code === "INVALID_PROMPT_VALUE",
		);
	});
});
