import { deepEqual, ok, rejects } from "node:assert";
import { decodeJwt } from "jose/jwt/decode";
import { afterEach, beforeEach, describe, it, vi } from "vitest";
import { RateLimitedError } from "../error.ts";
import { TEST_ISSUER, type TestIdp, testIdp } from "../fixtures.test.ts";
import type { AuthDanceTokenResponse } from "../response.ts";
import type { AuthDanceOauth2ApiOptions } from "./api.ts";
import type { AuthDanceOauth2Client } from "./client.ts";
import { InvalidClientError } from "./error.ts";

const REDIRECT_URI = "https://app.example.com/callback";

describe("introspection", () => {
	let env: TestIdp;
	let app: AuthDanceOauth2Client;
	let appSecret: string;
	let resourceServer: AuthDanceOauth2Client;
	let other: AuthDanceOauth2Client;
	let owner: { access_token: string; refresh_token: string; identityId: string };
	let tokens: AuthDanceTokenResponse;

	async function confidential(overrides: Partial<AuthDanceOauth2Client> = {}): Promise<{ client: AuthDanceOauth2Client; secret: string }> {
		const created = await env.idp.oauth2.clients.createClient({
			redirect_uris: [REDIRECT_URI],
			grant_types: ["authorization_code", "refresh_token", "client_credentials"],
			scope: "profile email reports",
		});
		ok(created.client_secret);
		const client = { ...created.client, ...overrides };
		await env.idp.oauth2.clients.updateClient(client);
		return { client, secret: created.client_secret };
	}

	function basic(client: AuthDanceOauth2Client, secret: string): string {
		return `Basic ${btoa(`${client.client_id}:${secret}`)}`;
	}

	async function exchange(): Promise<AuthDanceTokenResponse> {
		const { code, verifier } = await env.issueCode(app, owner.access_token, "profile email");
		return env.idp.oauth2.token({
			params: [
				["grant_type", "authorization_code"],
				["code", code],
				["code_verifier", verifier],
				["redirect_uri", REDIRECT_URI],
			],
			authorization: basic(app, appSecret),
		});
	}

	async function setup(options: Partial<AuthDanceOauth2ApiOptions> = {}): Promise<void> {
		env = testIdp({ oauth2: { introspection: { username: (identity) => identity.data?.email as string | undefined }, ...options } });
		({ client: app, secret: appSecret } = await confidential());
		({ client: resourceServer } = await confidential({ introspect: true }));
		({ client: other } = await confidential());
		owner = await env.signUp();
		tokens = await exchange();
	}

	beforeEach(async () => {
		await setup();
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	it("should describe an active access token with every claim it carries", async () => {
		const answer = await env.idp.oauth2.introspect(app, tokens.access_token);
		const claims = decodeJwt(tokens.access_token);
		deepEqual(answer, { ...claims, active: true, token_type: "Bearer", username: "alice@example.com" });
		deepEqual([answer.sub, answer.scope, answer.iss, answer.name], [owner.identityId, "profile email", TEST_ISSUER, "Alice"]);
		ok(typeof answer.sid === "string" && typeof answer.auth_time === "number");
	});
	it("should describe a refresh token, and the one a refresh replaced while the session lasts", async () => {
		const answer = await env.idp.oauth2.introspect(app, tokens.refresh_token ?? "");
		deepEqual(
			[answer.active, answer.token_type, answer.scope, answer.client_id, answer.sub, answer.sid],
			[true, "refresh_token", "profile email", app.client_id, owner.identityId, decodeJwt(tokens.access_token).sid],
		);
		// The refresh token ends with its session, `durations.refresh` after the consent.
		const session = await env.auth.api.storage.getSession(String(answer.sid));
		deepEqual(answer.exp, Math.floor(Date.parse(session?.expireAt ?? "") / 1000));
		deepEqual([answer.username, answer.name], ["alice@example.com", undefined]);
		const refreshed = await env.idp.oauth2.token({
			params: [
				["grant_type", "refresh_token"],
				["refresh_token", tokens.refresh_token ?? ""],
			],
			authorization: basic(app, appSecret),
		});
		deepEqual((await env.idp.oauth2.introspect(app, tokens.refresh_token ?? "")).active, true);
		deepEqual((await env.idp.oauth2.introspect(app, refreshed.refresh_token ?? "")).active, true);
	});
	it("should read both types whatever the hint says", async () => {
		for (const hint of ["refresh_token", "access_token", "unknown", undefined]) {
			deepEqual((await env.idp.oauth2.introspect(app, tokens.access_token, hint)).token_type, "Bearer");
			deepEqual((await env.idp.oauth2.introspect(app, tokens.refresh_token ?? "", hint)).token_type, "refresh_token");
		}
	});
	it("should answer inactive for an expired access token", async () => {
		vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 301_000 });
		deepEqual(await env.idp.oauth2.introspect(app, tokens.access_token), { active: false });
	});
	it("should answer inactive once the grant is revoked", async () => {
		const { code, verifier } = await env.issueCode(app, owner.access_token, "profile");
		const params: [string, string][] = [
			["grant_type", "authorization_code"],
			["code", code],
			["code_verifier", verifier],
			["redirect_uri", REDIRECT_URI],
		];
		const first = await env.idp.oauth2.token({ params, authorization: basic(app, appSecret) });
		// A second use of the code revokes its grant.
		await rejects(() => env.idp.oauth2.token({ params, authorization: basic(app, appSecret) }));
		deepEqual(await env.idp.oauth2.introspect(app, first.access_token), { active: false });
		deepEqual(await env.idp.oauth2.introspect(app, first.refresh_token ?? ""), { active: false });
	});
	it("should keep the tokens of a grant active through a sign-out, and not once the identity is gone", async () => {
		await env.auth.api.signOut(owner.access_token);
		deepEqual((await env.idp.oauth2.introspect(app, tokens.access_token)).active, true);
		await env.auth.api.storage.deleteIdentity(owner.identityId);
		deepEqual(await env.idp.oauth2.introspect(app, tokens.access_token), { active: false });
		deepEqual(await env.idp.oauth2.introspect(app, tokens.refresh_token ?? ""), { active: false });
	});
	it("should show a client its own tokens, and a resource server every token", async () => {
		deepEqual(await env.idp.oauth2.introspect(other, tokens.access_token), { active: false });
		deepEqual(await env.idp.oauth2.introspect(other, tokens.refresh_token ?? ""), { active: false });
		deepEqual((await env.idp.oauth2.introspect(resourceServer, tokens.access_token)).active, true);
		deepEqual((await env.idp.oauth2.introspect(resourceServer, tokens.refresh_token ?? "")).active, true);
	});
	it("should describe the tokens of a dance to a resource server only, and never call garbage active", async () => {
		const answer = await env.idp.oauth2.introspect(resourceServer, owner.access_token);
		deepEqual([answer.active, answer.client_id, answer.sub], [true, TEST_ISSUER, owner.identityId]);
		deepEqual(await env.idp.oauth2.introspect(app, owner.access_token), { active: false });
		for (const token of ["garbage", "", "gnt_x.y", `${tokens.refresh_token}.x`]) {
			deepEqual(await env.idp.oauth2.introspect(resourceServer, token), { active: false }, token);
		}
	});
	it("should describe a client credentials token, with no username", async () => {
		const machine = await env.idp.oauth2.token({ params: [["grant_type", "client_credentials"]], authorization: basic(app, appSecret) });
		const answer = await env.idp.oauth2.introspect(app, machine.access_token);
		deepEqual([answer.active, answer.sub, answer.username, answer.auth_time], [true, app.client_id, undefined, undefined]);
	});
	it("should refuse a public client", async () => {
		const { client: spa } = await env.idp.oauth2.clients.createClient({
			redirect_uris: [REDIRECT_URI],
			token_endpoint_auth_method: "none",
			scope: "profile",
		});
		await rejects(() => env.idp.oauth2.introspect(spa, tokens.access_token), InvalidClientError);
	});
	it("should count the introspections of each client", async () => {
		await setup({ limits: { client: { introspect: { limit: 1, window: 60 } } } });
		await env.idp.oauth2.introspect(app, tokens.access_token);
		await rejects(() => env.idp.oauth2.introspect(app, tokens.access_token), RateLimitedError);
		await env.idp.oauth2.introspect(resourceServer, tokens.access_token);
	});
});
