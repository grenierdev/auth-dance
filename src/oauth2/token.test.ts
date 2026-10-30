import { deepEqual, ok, rejects } from "node:assert";
import { decodeProtectedHeader } from "jose/decode/protected_header";
import { decodeJwt } from "jose/jwt/decode";
import { afterEach, beforeEach, describe, it, vi } from "vitest";
import type { AuthDanceApiOptions } from "../api.ts";
import { AuthDanceError } from "../error.ts";
import { TEST_ISSUER, type TestIdp, testIdp } from "../fixtures.test.ts";
import type { AuthDanceTokenResponse } from "../response.ts";
import type { AuthDanceSession } from "../session.ts";
import type { AuthDanceOauth2Api, AuthDanceOauth2HookErrorEvent } from "./api.ts";
import type { AuthDanceOauth2Client } from "./client.ts";
import {
	type AuthDanceOauth2Error,
	InvalidClientError,
	InvalidGrantError,
	InvalidRequestError,
	InvalidScopeError,
	ServerError,
	UnauthorizedClientError,
	UnsupportedGrantTypeError,
} from "./error.ts";
import { randomToken, sha256 } from "./records.ts";

const REDIRECT_URI = "https://app.example.com/callback";

function basic(id: string, secret: string): string {
	return `Basic ${btoa(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`)}`;
}

describe("token endpoint", () => {
	let env: TestIdp;
	let oauth2: AuthDanceOauth2Api;
	let client: AuthDanceOauth2Client;
	let secret: string;
	let owner: { access_token: string; refresh_token: string; identityId: string };
	let events: { created: AuthDanceSession[]; revoked: AuthDanceSession[]; errors: AuthDanceOauth2HookErrorEvent[] };

	async function setup(tokens: Partial<AuthDanceApiOptions["tokens"]> = {}): Promise<void> {
		events = { created: [], revoked: [], errors: [] };
		env = testIdp({
			api: { tokens },
			oauth2: {
				hooks: {
					onGrantCreated: ({ session }) => {
						events.created.push(session);
					},
					onGrantRevoked: ({ session }) => {
						events.revoked.push(session);
					},
					onError: (event) => {
						events.errors.push(event);
					},
				},
			},
		});
		oauth2 = env.idp.oauth2;
		const created = await oauth2.clients.createClient({
			redirect_uris: [REDIRECT_URI],
			grant_types: ["authorization_code", "refresh_token", "client_credentials"],
			scope: "profile email reports",
		});
		ok(created.client_secret);
		({ client } = created);
		secret = created.client_secret;
		owner = await env.signUp();
	}

	// Runs the authorization endpoint in process, with the login and the consent accepted, and returns the code.
	async function authorize(
		target: AuthDanceOauth2Client = client,
		scope = "profile email",
		params: Record<string, string> = {},
	): Promise<{ code: string; verifier: string }> {
		const verifier = randomToken();
		const step = async (entries: [string, string][]) =>
			new URL((await oauth2.authorize({ params: entries, endpoint: `${TEST_ISSUER}/authorize` })).location);
		const login = await step(
			Object.entries({
				client_id: target.client_id,
				redirect_uri: REDIRECT_URI,
				response_type: "code",
				scope,
				code_challenge: await sha256(verifier),
				code_challenge_method: "S256",
				...params,
			}),
		);
		const answer = await oauth2.acceptLoginRequest(login.searchParams.get("login_challenge") ?? "", { access_token: owner.access_token });
		const consent = await step([...new URL(answer.redirect_to).searchParams]);
		const back = await oauth2.acceptConsentRequest(consent.searchParams.get("consent_challenge") ?? "", { grant_scope: scope.split(" ") });
		const callback = await step([...new URL(back.redirect_to).searchParams]);
		return { code: callback.searchParams.get("code") ?? "", verifier };
	}

	function token(params: Record<string, string> | [string, string][], authorization?: string): Promise<AuthDanceTokenResponse> {
		return oauth2.token({ params: Array.isArray(params) ? params : Object.entries(params), authorization });
	}

	function exchange(code: string, verifier: string, extra: Record<string, string> = {}): Promise<AuthDanceTokenResponse> {
		return token(
			{ grant_type: "authorization_code", code, code_verifier: verifier, redirect_uri: REDIRECT_URI, ...extra },
			basic(client.client_id, secret),
		);
	}

	function refresh(refresh_token: string, extra: Record<string, string> = {}): Promise<AuthDanceTokenResponse> {
		return token({ grant_type: "refresh_token", refresh_token, ...extra }, basic(client.client_id, secret));
	}

	async function fails<T extends AuthDanceOauth2Error>(fn: () => Promise<unknown>, type: new (...args: never[]) => T): Promise<void> {
		await rejects(fn, (error) => error instanceof type);
	}

	// A failure of the core, by its code.
	async function failsWith(fn: () => Promise<unknown>, code: string): Promise<void> {
		await rejects(fn, (error) => error instanceof AuthDanceError && error.code === code);
	}

	beforeEach(async () => {
		await setup();
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	describe("authorization_code", () => {
		it("should mint the access token and the refresh token of a dance, for the client", async () => {
			const { code, verifier } = await authorize();
			const response = await exchange(code, verifier);
			deepEqual([response.token_type, response.expires_in, response.scope], ["Bearer", 300, "profile email"]);
			deepEqual(decodeProtectedHeader(response.access_token).typ, "at+jwt");
			deepEqual(decodeProtectedHeader(response.refresh_token ?? "").typ, "rt+jwt");
			const claims = decodeJwt(response.access_token);
			deepEqual(
				[claims.iss, claims.sub, claims.aud, claims.client_id, claims.scope, claims.name, claims.email],
				[TEST_ISSUER, owner.identityId, TEST_ISSUER, client.client_id, "profile email", "Alice", "alice@example.com"],
			);
			deepEqual(claims.exp, (claims.iat ?? 0) + 300);
			// The sign-in behind the consent sets `auth_time`, as for the token of the dance.
			deepEqual(claims.auth_time, decodeJwt(owner.access_token).auth_time);
			ok(typeof claims.jti === "string");
			deepEqual(
				events.created.map((session) => session.id),
				[claims.sid],
			);
			const [session] = events.created;
			deepEqual([session.client_id, session.scopes, session.identityId], [client.client_id, ["profile", "email"], owner.identityId]);
			ok(session.id !== decodeJwt(owner.access_token).sid);
			const verified = await env.auth.api.verifyAccessToken(response.access_token, { session: true });
			deepEqual(
				[verified.subject, verified.client_id, verified.scope, verified.session_id],
				[owner.identityId, client.client_id, ["profile", "email"], claims.sid],
			);
		});
		it("should send no refresh token to a client without the refresh_token grant type", async () => {
			await oauth2.clients.updateClient({ ...client, grant_types: ["authorization_code"] });
			const { code, verifier } = await authorize();
			deepEqual((await exchange(code, verifier)).refresh_token, undefined);
		});
		it("should accept client_secret_post and a public client with none", async () => {
			await oauth2.clients.updateClient({ ...client, token_endpoint_auth_method: "client_secret_post" });
			const first = await authorize();
			await token({
				grant_type: "authorization_code",
				code: first.code,
				code_verifier: first.verifier,
				redirect_uri: REDIRECT_URI,
				client_id: client.client_id,
				client_secret: secret,
			});
			const { client: spa } = await oauth2.clients.createClient({
				redirect_uris: [REDIRECT_URI],
				token_endpoint_auth_method: "none",
				scope: "profile",
			});
			const second = await authorize(spa, "profile");
			const response = await token({
				grant_type: "authorization_code",
				code: second.code,
				code_verifier: second.verifier,
				redirect_uri: REDIRECT_URI,
				client_id: spa.client_id,
			});
			deepEqual(decodeJwt(response.access_token).client_id, spa.client_id);
		});
		it("should refuse a missing, unknown or expired code", async () => {
			const { code, verifier } = await authorize();
			await fails(
				() => token({ grant_type: "authorization_code", code_verifier: verifier }, basic(client.client_id, secret)),
				InvalidRequestError,
			);
			await fails(() => token({ grant_type: "authorization_code", code }, basic(client.client_id, secret)), InvalidRequestError);
			await fails(() => exchange(randomToken(), verifier), InvalidGrantError);
			vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 61_000 });
			await fails(() => exchange(code, verifier), InvalidGrantError);
		});
		it("should revoke the grant when a code comes a second time", async () => {
			const { code, verifier } = await authorize();
			const first = await exchange(code, verifier);
			await fails(() => exchange(code, verifier), InvalidGrantError);
			deepEqual(events.revoked.length, 1);
			await fails(() => refresh(first.refresh_token ?? ""), InvalidGrantError);
			await failsWith(() => env.auth.api.verifyAccessToken(first.access_token, { session: true }), "SESSION_NOT_FOUND");
		});
		it("should refuse the code of another client, a redirect URI that differs, and a wrong verifier", async () => {
			const { client: other, client_secret: otherSecret } = await oauth2.clients.createClient({
				redirect_uris: [REDIRECT_URI],
				scope: "profile",
			});
			const a = await authorize();
			await fails(
				() =>
					token(
						{ grant_type: "authorization_code", code: a.code, code_verifier: a.verifier, redirect_uri: REDIRECT_URI },
						basic(other.client_id, otherSecret ?? ""),
					),
				InvalidGrantError,
			);
			const b = await authorize();
			await fails(() => exchange(b.code, b.verifier, { redirect_uri: "https://app.example.com/other" }), InvalidGrantError);
			const c = await authorize();
			await fails(
				() => token({ grant_type: "authorization_code", code: c.code, code_verifier: c.verifier }, basic(client.client_id, secret)),
				InvalidGrantError,
			);
			const d = await authorize();
			await fails(() => exchange(d.code, randomToken()), InvalidGrantError);
			const e = await authorize();
			await fails(() => exchange(e.code, "short"), InvalidGrantError);
		});
		it("should accept no redirect_uri when the request carried none", async () => {
			await oauth2.clients.updateClient({ ...client, redirect_uris: [REDIRECT_URI] });
			const verifier = randomToken();
			const step = async (entries: [string, string][]) =>
				new URL((await oauth2.authorize({ params: entries, endpoint: `${TEST_ISSUER}/authorize` })).location);
			const login = await step([
				["client_id", client.client_id],
				["response_type", "code"],
				["code_challenge", await sha256(verifier)],
				["code_challenge_method", "S256"],
			]);
			const answer = await oauth2.acceptLoginRequest(login.searchParams.get("login_challenge") ?? "", { access_token: owner.access_token });
			const consent = await step([...new URL(answer.redirect_to).searchParams]);
			const back = await oauth2.acceptConsentRequest(consent.searchParams.get("consent_challenge") ?? "", { grant_scope: ["profile"] });
			const code = (await step([...new URL(back.redirect_to).searchParams])).searchParams.get("code") ?? "";
			await token({ grant_type: "authorization_code", code, code_verifier: verifier }, basic(client.client_id, secret));
		});
		it("should keep the grant of a code through a sign-out of the session that signed in for it", async () => {
			const { code, verifier } = await authorize();
			await env.auth.api.signOut(owner.access_token);
			deepEqual((await oauth2.listGrants(owner.identityId)).length, 1);
			ok((await exchange(code, verifier)).refresh_token);
		});
	});

	describe("refresh_token", () => {
		it("should give a new refresh token, and keep the old one valid until the session ends", async () => {
			const { code, verifier } = await authorize();
			const first = await exchange(code, verifier);
			const second = await refresh(first.refresh_token ?? "");
			ok(second.refresh_token);
			deepEqual(decodeJwt(second.access_token).sid, decodeJwt(first.access_token).sid);
			await refresh(first.refresh_token ?? "");
			await refresh(second.refresh_token);
			deepEqual(events.revoked, []);
		});
		it("should refuse garbage, a forged refresh token and an access token, and revoke nothing", async () => {
			const { code, verifier } = await authorize();
			const first = await exchange(code, verifier);
			const [header, payload, signature] = (first.refresh_token ?? "").split(".");
			const forged = `${header}.${payload}.${signature.slice(0, 10)}${signature[10] === "A" ? "B" : "A"}${signature.slice(11)}`;
			for (const value of ["garbage", forged, first.access_token, `${randomToken()}.${randomToken()}`]) {
				await fails(() => refresh(value), InvalidGrantError);
			}
			deepEqual(events.revoked, []);
			await refresh(first.refresh_token ?? "");
		});
		it("should refuse the refresh token of a dance, which belongs to the issuer", async () => {
			await fails(() => refresh(owner.refresh_token), InvalidGrantError);
			await env.auth.api.refreshToken(owner.refresh_token);
		});
		it("should refuse the refresh token of another client", async () => {
			const { code, verifier } = await authorize();
			const first = await exchange(code, verifier);
			const { client: other, client_secret: otherSecret } = await oauth2.clients.createClient({
				redirect_uris: [REDIRECT_URI],
				grant_types: ["authorization_code", "refresh_token"],
				scope: "profile",
			});
			await fails(
				() => token({ grant_type: "refresh_token", refresh_token: first.refresh_token ?? "" }, basic(other.client_id, otherSecret ?? "")),
				InvalidGrantError,
			);
		});
		it("should narrow the scope of one access token, and refuse a wider one", async () => {
			const { code, verifier } = await authorize();
			const first = await exchange(code, verifier);
			const narrow = await refresh(first.refresh_token ?? "", { scope: "profile" });
			deepEqual([narrow.scope, decodeJwt(narrow.access_token).email], ["profile", undefined]);
			// RFC 6749 §6: the refresh token keeps the scopes the owner granted.
			deepEqual(decodeJwt(narrow.refresh_token ?? "").scope, "profile email");
			const full = await refresh(narrow.refresh_token ?? "");
			deepEqual(full.scope, "profile email");
			await fails(() => refresh(full.refresh_token ?? "", { scope: "profile reports" }), InvalidScopeError);
		});
		it("should keep the grant through a sign-out of every session of a dance, and end it with the identity", async () => {
			const { code, verifier } = await authorize();
			const first = await exchange(code, verifier);
			await env.auth.api.signOut(owner.access_token, true);
			const second = await refresh(first.refresh_token ?? "");
			deepEqual(events.revoked, []);
			// The identity goes, and the grant with it.
			await env.auth.api.storage.deleteIdentity(owner.identityId);
			await fails(() => refresh(second.refresh_token ?? ""), InvalidGrantError);
		});
	});

	describe("client_credentials", () => {
		it("should mint an access token for the client itself, with no refresh token", async () => {
			const response = await token({ grant_type: "client_credentials", scope: "reports" }, basic(client.client_id, secret));
			deepEqual([response.refresh_token, response.scope], [undefined, "reports"]);
			const claims = decodeJwt(response.access_token);
			deepEqual([claims.sub, claims.client_id, claims.auth_time, claims.sid], [client.client_id, client.client_id, undefined, undefined]);
			const verified = await env.auth.api.verifyAccessToken(response.access_token);
			deepEqual(verified.subject, client.client_id);
			// Nothing is stored, so no session can vouch for the token, and no grant event fires.
			await failsWith(() => env.auth.api.verifyAccessToken(response.access_token, { session: true }), "INVALID_ACCESS_TOKEN");
			deepEqual(events.created, []);
		});
		it("should take every scope of the client by default, and refuse more", async () => {
			deepEqual((await token({ grant_type: "client_credentials" }, basic(client.client_id, secret))).scope, "profile email reports");
			await fails(() => token({ grant_type: "client_credentials", scope: "admin" }, basic(client.client_id, secret)), InvalidScopeError);
		});
		it("should refuse a public client", async () => {
			const { client: spa } = await oauth2.clients.createClient({
				redirect_uris: [REDIRECT_URI],
				token_endpoint_auth_method: "none",
				grant_types: ["client_credentials"],
				scope: "reports",
			});
			await fails(() => token({ grant_type: "client_credentials", client_id: spa.client_id }), UnauthorizedClientError);
		});
	});

	describe("the request", () => {
		it("should refuse a repeated parameter, a missing or unsupported grant type, and a grant type the client lacks", async () => {
			const auth = basic(client.client_id, secret);
			await fails(
				() =>
					token(
						[
							["grant_type", "client_credentials"],
							["scope", "reports"],
							["scope", "profile"],
						],
						auth,
					),
				InvalidRequestError,
			);
			await fails(() => token({ scope: "reports" }, auth), InvalidRequestError);
			await fails(() => token({ grant_type: "password", username: "a", password: "b" }, auth), UnsupportedGrantTypeError);
			await fails(() => token({ grant_type: "urn:ietf:params:oauth:grant-type:device_code" }, auth), UnsupportedGrantTypeError);
			await oauth2.clients.updateClient({ ...client, grant_types: ["authorization_code"] });
			await fails(() => token({ grant_type: "client_credentials" }, auth), UnauthorizedClientError);
		});
		it("should refuse a client that does not authenticate", async () => {
			await fails(() => token({ grant_type: "client_credentials" }, basic(client.client_id, "wrong")), InvalidClientError);
			await fails(() => token({ grant_type: "client_credentials" }, basic("cli_missing", secret)), InvalidClientError);
			await fails(
				() => token({ grant_type: "client_credentials", client_id: client.client_id, client_secret: secret }),
				InvalidClientError,
			);
			await fails(
				() => token({ grant_type: "client_credentials", client_secret: secret }, basic(client.client_id, secret)),
				InvalidRequestError,
			);
			await fails(() => token({ grant_type: "client_credentials" }), InvalidClientError);
		});
	});

	describe("claims", () => {
		it("should put the claims of the mapper in the access token", async () => {
			await setup({
				claims: ({ client_id, defaults, grant_type }) => ({ ...defaults, reports: { tenant: { client_id, grant_type } } }),
			});
			const response = await token({ grant_type: "client_credentials", scope: "reports" }, basic(client.client_id, secret));
			deepEqual(decodeJwt(response.access_token).tenant, { client_id: client.client_id, grant_type: "client_credentials" });
		});
		it("should answer server_error and report to onError when the mapper fails", async () => {
			const failure = new Error("tenant service down");
			// The dance of `setup` mints through the same mapper, so it fails for the client only.
			await setup({
				claims: ({ grant_type, defaults }) => {
					if (grant_type === "client_credentials") {
						throw failure;
					}
					return defaults;
				},
			});
			await fails(() => token({ grant_type: "client_credentials", scope: "reports" }, basic(client.client_id, secret)), ServerError);
			deepEqual(events.errors, [{ source: "claims", cause: failure }]);
		});
	});

	describe("access tokens", () => {
		it("should take a per-client audience", async () => {
			await oauth2.clients.updateClient({ ...client, audience: "https://api.example.com" });
			const response = await token({ grant_type: "client_credentials", scope: "reports" }, basic(client.client_id, secret));
			deepEqual(decodeJwt(response.access_token).aud, "https://api.example.com");
			await env.auth.api.verifyAccessToken(response.access_token, { audience: "https://api.example.com" });
			await failsWith(() => env.auth.api.verifyAccessToken(response.access_token), "INVALID_ACCESS_TOKEN");
		});
		it("should verify the token of a dance and the token of a client alike", async () => {
			const { code, verifier } = await authorize();
			const response = await exchange(code, verifier);
			deepEqual((await env.auth.api.verifyAccessToken(owner.access_token)).client_id, TEST_ISSUER);
			deepEqual((await env.auth.api.verifyAccessToken(response.access_token)).client_id, client.client_id);
		});
		it("should refuse a refresh token, a forged token and an expired token", async () => {
			const { code, verifier } = await authorize();
			const issued = await exchange(code, verifier);
			await failsWith(() => env.auth.api.verifyAccessToken(issued.refresh_token ?? ""), "INVALID_ACCESS_TOKEN");
			await failsWith(() => env.auth.api.verifyAccessToken("garbage"), "INVALID_ACCESS_TOKEN");
			const response = await token({ grant_type: "client_credentials", scope: "reports" }, basic(client.client_id, secret));
			const [header, payload, signature] = response.access_token.split(".");
			const forged = `${signature.slice(0, 10)}${signature[10] === "A" ? "B" : "A"}${signature.slice(11)}`;
			await failsWith(() => env.auth.api.verifyAccessToken(`${header}.${payload}.${forged}`), "INVALID_ACCESS_TOKEN");
			vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 301_000 });
			await failsWith(() => env.auth.api.verifyAccessToken(response.access_token), "INVALID_ACCESS_TOKEN");
		});
		it("should let a client with account manage the account, and refuse a client without it", async () => {
			await oauth2.clients.updateClient({ ...client, scope: "profile account" });
			const without = await exchange(...(Object.values(await authorize(client, "profile")) as [string, string]));
			await failsWith(() => env.auth.api.delete({ access_token: without.access_token }), "INSUFFICIENT_SCOPE");
			const withAccount = await exchange(...(Object.values(await authorize(client, "profile account")) as [string, string]));
			ok("state" in (await env.auth.api.delete({ access_token: withAccount.access_token })));
			// A sign-out with the token of the client ends the session of its grant, not the session of the dance.
			await env.auth.api.signOut(withAccount.access_token);
			await failsWith(() => env.auth.api.verifyAccessToken(withAccount.access_token, { session: true }), "SESSION_NOT_FOUND");
			await env.auth.api.verifyAccessToken(owner.access_token, { session: true });
		});
	});
});
