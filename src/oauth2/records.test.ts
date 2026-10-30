import { deepEqual, ok, rejects, throws } from "node:assert";
import { beforeEach, describe, it } from "vitest";
import { MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "../providers/memory.ts";
import { AuthDanceStorage } from "../storage.ts";
import {
	type AuthorizationRequest,
	clientSessionRecords,
	codeRecords,
	consentRecords,
	loginRecords,
	randomToken,
	rememberedConsentRecords,
	sha256,
} from "./records.ts";

const request: AuthorizationRequest = {
	client_id: "cli_test",
	redirect_uri: "https://app.example.com/callback",
	redirect_uri_given: true,
	scope: ["profile"],
	state: "xyz",
	code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
};

describe("records", () => {
	let kv: MemoryKvProvider;
	let storage: AuthDanceStorage;

	beforeEach(() => {
		kv = new MemoryKvProvider();
		storage = new AuthDanceStorage({ identity: new MemoryIdentityProvider(), kv, rate_limiter: new MemoryRateLimiterProvider() });
	});

	it("should hash with SHA-256 in base64url", async () => {
		deepEqual(await sha256("abc"), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
	});
	it("should make random tokens of 32 bytes", () => {
		const a = randomToken();
		ok(/^[A-Za-z0-9_-]{43}$/.test(a));
		ok(a !== randomToken());
	});
	it("should write and read each record under its key space", async () => {
		const login = {
			request,
			request_url: "https://auth.example.com/authorize?x",
			endpoint: "https://auth.example.com/authorize",
			accepted: { identityId: "id_1", sessionId: "ses_1", authTime: 1 },
		};
		const consent = {
			request,
			endpoint: login.endpoint,
			login: { identityId: "id_1", sessionId: "ses_1", authTime: 1 },
			verifier: await sha256("verifier"),
			accepted: { grant_scope: ["profile"], remember: false },
		};
		const code = {
			session_id: "ses_2",
			auth_time: 1,
			client_id: "cli_test",
			redirect_uri: request.redirect_uri,
			redirect_uri_given: true,
			code_challenge: request.code_challenge,
		};
		await loginRecords.set(storage, ["ch_1"], login, 600);
		await consentRecords.set(storage, ["ch_2"], consent, 600);
		await codeRecords.set(storage, [await sha256("code")], code, 60);
		await clientSessionRecords.set(storage, ["cli_test", "ses_2"], { identityId: "id_1" }, 86400);
		await rememberedConsentRecords.set(storage, ["id_1", "cli_test"], { scopes: ["profile"], grantedAt: 2 });
		deepEqual(await loginRecords.get(storage, ["ch_1"]), login);
		deepEqual(await consentRecords.get(storage, ["ch_2"]), consent);
		deepEqual(await codeRecords.get(storage, [await sha256("code")]), code);
		deepEqual(await clientSessionRecords.get(storage, ["cli_test", "ses_2"]), { identityId: "id_1" });
		deepEqual(await rememberedConsentRecords.get(storage, ["id_1", "cli_test"]), { scopes: ["profile"], grantedAt: 2 });
		deepEqual((await kv.list("oauth2/")).sort(), [
			"oauth2/client-sessions/cli_test/ses_2",
			`oauth2/code/${await sha256("code")}`,
			"oauth2/consent/ch_2",
			"oauth2/consents/id_1/cli_test",
			"oauth2/login/ch_1",
		]);
	});
	it("should forget a record after its time to live", async () => {
		await rememberedConsentRecords.set(storage, ["id_1", "cli_test"], { scopes: ["profile"], grantedAt: 2 }, 0);
		deepEqual(await rememberedConsentRecords.get(storage, ["id_1", "cli_test"]), undefined);
	});
	it("should refuse a value that does not match the schema, on write and on read", async () => {
		await rejects(() => codeRecords.set(storage, ["c_1"], { session_id: "ses_1" } as never));
		deepEqual(await kv.list("oauth2/"), []);
		await kv.set("oauth2/code/c_2", JSON.stringify({ session_id: "ses_2" }));
		await rejects(() => codeRecords.get(storage, ["c_2"]));
	});
	it("should refuse a key segment that is empty, holds a slash, or comes in the wrong count", () => {
		throws(() => loginRecords.key([""]), TypeError);
		throws(() => loginRecords.key(["../session/ses_1"]), TypeError);
		throws(() => loginRecords.key(["a", "b"]), TypeError);
		throws(() => clientSessionRecords.key(["cli_1"]), TypeError);
		deepEqual(clientSessionRecords.key(["cli_1", "ses_1"]), "oauth2/client-sessions/cli_1/ses_1");
	});
	it("should list the sessions of one client", async () => {
		await clientSessionRecords.set(storage, ["cli_1", "ses_a"], { identityId: "id_a" });
		await clientSessionRecords.set(storage, ["cli_1", "ses_b"], { identityId: "id_b" });
		await clientSessionRecords.set(storage, ["cli_10", "ses_c"], { identityId: "id_c" });
		deepEqual((await clientSessionRecords.list(storage, ["cli_1"])).sort(), ["ses_a", "ses_b"]);
		await clientSessionRecords.unset(storage, ["cli_1", "ses_a"]);
		deepEqual(await clientSessionRecords.list(storage, ["cli_1"]), ["ses_b"]);
	});
});
