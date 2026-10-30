import { deepEqual, ok, rejects } from "node:assert";
import { decodeJwt } from "jose/jwt/decode";
import { afterEach, beforeEach, describe, it, vi } from "vitest";
import { TEST_CONSENT_PAGE, TEST_ISSUER, type TestIdp, testIdp } from "../fixtures.test.ts";
import type { AuthDanceTokenResponse } from "../response.ts";
import type { AuthDanceSession } from "../session.ts";
import type { AuthDanceOauth2Client } from "./client.ts";
import { InsufficientScopeError, InvalidGrantError, InvalidTokenError } from "./error.ts";
import { randomToken, rememberedConsentRecords, sha256 } from "./records.ts";

const REDIRECT_URI = "https://app.example.com/callback";

describe("revocation", () => {
	let env: TestIdp;
	let app: AuthDanceOauth2Client;
	let appSecret: string;
	let other: AuthDanceOauth2Client;
	let owner: { access_token: string; refresh_token: string; identityId: string };
	let tokens: AuthDanceTokenResponse;
	let revoked: AuthDanceSession[];

	async function confidential(): Promise<{ client: AuthDanceOauth2Client; secret: string }> {
		const created = await env.idp.oauth2.clients.createClient({
			redirect_uris: [REDIRECT_URI],
			grant_types: ["authorization_code", "refresh_token", "client_credentials"],
			scope: "profile email reports",
		});
		ok(created.client_secret);
		return { client: created.client, secret: created.client_secret };
	}

	function basic(client: AuthDanceOauth2Client, secret: string): string {
		return `Basic ${btoa(`${client.client_id}:${secret}`)}`;
	}

	async function exchange(client = app, secret = appSecret, scope = "profile email"): Promise<AuthDanceTokenResponse> {
		const { code, verifier } = await env.issueCode(client, owner.access_token, scope);
		return env.idp.oauth2.token({
			params: [
				["grant_type", "authorization_code"],
				["code", code],
				["code_verifier", verifier],
				["redirect_uri", REDIRECT_URI],
			],
			authorization: basic(client, secret),
		});
	}

	async function refresh(token: string): Promise<AuthDanceTokenResponse> {
		return env.idp.oauth2.token({
			params: [
				["grant_type", "refresh_token"],
				["refresh_token", token],
			],
			authorization: basic(app, appSecret),
		});
	}

	// After a revocation, the refresh token fails and introspection calls both tokens inactive.
	async function expectRevoked(response: AuthDanceTokenResponse): Promise<void> {
		await rejects(() => refresh(response.refresh_token ?? ""), InvalidGrantError);
		deepEqual(await env.idp.oauth2.introspect(app, response.access_token), { active: false });
		deepEqual(await env.idp.oauth2.introspect(app, response.refresh_token ?? ""), { active: false });
	}

	async function expectActive(response: AuthDanceTokenResponse): Promise<void> {
		deepEqual((await env.idp.oauth2.introspect(app, response.access_token)).active, true);
	}

	beforeEach(async () => {
		revoked = [];
		env = testIdp({
			oauth2: {
				hooks: {
					onGrantRevoked: ({ session }) => {
						revoked.push(session);
					},
				},
			},
		});
		({ client: app, secret: appSecret } = await confidential());
		({ client: other } = await confidential());
		owner = await env.signUp();
		tokens = await exchange();
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	it("should revoke the whole session of the grant with its refresh token", async () => {
		await env.idp.oauth2.revoke(app, tokens.refresh_token ?? "");
		await expectRevoked(tokens);
		deepEqual(
			revoked.map((session) => [session.client_id, session.id]),
			[[app.client_id, decodeJwt(tokens.access_token).sid]],
		);
	});
	it("should revoke the session with an older refresh token of the same session", async () => {
		const rotated = await refresh(tokens.refresh_token ?? "");
		await env.idp.oauth2.revoke(app, tokens.refresh_token ?? "", "refresh_token");
		await expectRevoked(rotated);
	});
	it("should revoke the grant with an access token, live or expired", async () => {
		await env.idp.oauth2.revoke(app, tokens.access_token, "access_token");
		await expectRevoked(tokens);
		const second = await exchange();
		vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 301_000 });
		await env.idp.oauth2.revoke(app, second.access_token);
		vi.useRealTimers();
		await expectRevoked(second);
	});
	it("should do nothing for a token of another client, a token that is not valid, or a second revocation", async () => {
		await env.idp.oauth2.revoke(other, tokens.refresh_token ?? "");
		await env.idp.oauth2.revoke(other, tokens.access_token);
		for (const token of ["garbage", "", owner.access_token, `${(tokens.refresh_token ?? "").split(".")[0]}.${randomToken()}`]) {
			await env.idp.oauth2.revoke(app, token);
		}
		await expectActive(tokens);
		deepEqual(revoked, []);
		await env.idp.oauth2.revoke(app, tokens.refresh_token ?? "");
		await env.idp.oauth2.revoke(app, tokens.refresh_token ?? "");
		deepEqual(revoked.length, 1);
	});
	it("should let a public client revoke its own tokens", async () => {
		const { client: spa } = await env.idp.oauth2.clients.createClient({
			redirect_uris: [REDIRECT_URI],
			token_endpoint_auth_method: "none",
			grant_types: ["authorization_code", "refresh_token"],
			scope: "profile",
		});
		const { code, verifier } = await env.issueCode(spa, owner.access_token, "profile");
		const spaTokens = await env.idp.oauth2.token({
			params: [
				["grant_type", "authorization_code"],
				["code", code],
				["code_verifier", verifier],
				["redirect_uri", REDIRECT_URI],
				["client_id", spa.client_id],
			],
		});
		await env.idp.oauth2.revoke(spa, spaTokens.refresh_token ?? "");
		deepEqual(revoked.length, 1);
	});

	describe("by the identity and by the admin", () => {
		it("should list the grants of an identity, and revoke one by id, never the session of a dance", async () => {
			const { client: second, secret } = await confidential();
			const secondTokens = await exchange(second, secret, "profile");
			// Two grants of one second come in any order.
			const grants = (await env.idp.oauth2.listGrants(owner.identityId)).sort((a, b) => a.scopes.length - b.scopes.length);
			deepEqual(
				grants.map((grant) => [grant.client_id, grant.scopes]),
				[
					[second.client_id, ["profile"]],
					[app.client_id, ["profile", "email"]],
				],
			);
			ok(grants.every((grant) => !("refresh" in grant)));
			await env.idp.oauth2.revokeGrant(grants[0].id);
			deepEqual(
				(await env.idp.oauth2.listGrants(owner.identityId)).map((grant) => grant.client_id),
				[app.client_id],
			);
			deepEqual(await env.idp.oauth2.introspect(second, secondTokens.access_token), { active: false });
			deepEqual(await env.idp.oauth2.listGrants("../x"), []);
			await env.idp.oauth2.revokeGrant("not-a-grant");
			await env.idp.oauth2.revokeGrant(String(decodeJwt(owner.access_token).sid));
			await env.auth.api.verifyAccessToken(owner.access_token, { session: true });
		});
		it("should list the grants of the owner of an access token, with the public record of each client", async () => {
			const grants = await env.idp.oauth2.listOwnGrants(owner.access_token);
			deepEqual(
				grants.map((grant) => [grant.client_id, grant.scopes, grant.client?.client_id, grant.identityId]),
				[[app.client_id, ["profile", "email"], app.client_id, owner.identityId]],
			);
			ok(grants[0].client && !("client_secret_hash" in grants[0].client));
			// A token without `account` reads nothing, nor does a token that is not valid or whose session ended.
			const profileOnly = await env.auth.api.refreshToken(owner.refresh_token, { scope: ["profile"] });
			await rejects(() => env.idp.oauth2.listOwnGrants(profileOnly.tokens.access_token), InsufficientScopeError);
			await rejects(() => env.idp.oauth2.listOwnGrants(tokens.refresh_token ?? ""), InvalidTokenError);
			await env.auth.api.signOut(owner.access_token);
			await rejects(() => env.idp.oauth2.listOwnGrants(owner.access_token), InvalidTokenError);
		});
		it("should let the owner revoke one of their grants, and forget the consent they kept for its client", async () => {
			const [grant] = await env.idp.oauth2.listGrants(owner.identityId);
			await rememberedConsentRecords.set(env.idp.oauth2.storage, [owner.identityId, app.client_id], { scopes: ["profile"], grantedAt: 1 });
			await env.idp.oauth2.revokeOwnGrant(owner.access_token, grant.id);
			await expectRevoked(tokens);
			deepEqual(
				revoked.map((session) => session.id),
				[grant.id],
			);
			deepEqual(await rememberedConsentRecords.get(env.idp.oauth2.storage, [owner.identityId, app.client_id]), undefined);
			deepEqual(await env.idp.oauth2.listOwnGrants(owner.access_token), []);
		});
		it("should revoke nothing for a grant of another owner, the session of a dance or an unknown id", async () => {
			const bob = await env.signUp("bob@example.com");
			await env.issueCode(app, bob.access_token, "profile");
			const [bobGrant] = await env.idp.oauth2.listGrants(bob.identityId);
			for (const id of [bobGrant.id, String(decodeJwt(owner.access_token).sid), "ses_unknown", "../x"]) {
				await env.idp.oauth2.revokeOwnGrant(owner.access_token, id);
			}
			deepEqual(revoked, []);
			await expectActive(tokens);
			deepEqual((await env.idp.oauth2.listGrants(bob.identityId)).length, 1);
			await env.auth.api.verifyAccessToken(owner.access_token, { session: true });
			const profileOnly = await env.auth.api.refreshToken(owner.refresh_token, { scope: ["profile"] });
			await rejects(() => env.idp.oauth2.revokeOwnGrant(profileOnly.tokens.access_token, bobGrant.id), InsufficientScopeError);
		});
		it("should list a grant without a client once the client is gone from the store alone", async () => {
			await env.idp.oauth2.clients.deleteClient(app.client_id);
			const [grant] = await env.idp.oauth2.listGrants(owner.identityId);
			deepEqual([grant.client_id, grant.client], [app.client_id, undefined]);
		});
		it("should revoke every grant of a client and forget the remembered consent", async () => {
			const extra = await exchange();
			// Remember the consent through one more request.
			const verifier = randomToken();
			const step = async (params: [string, string][]) =>
				new URL((await env.idp.oauth2.authorize({ params, endpoint: `${TEST_ISSUER}/authorize` })).location);
			const request: [string, string][] = [
				["client_id", app.client_id],
				["redirect_uri", REDIRECT_URI],
				["response_type", "code"],
				["scope", "profile"],
				["code_challenge", await sha256(verifier)],
				["code_challenge_method", "S256"],
			];
			const answerLogin = async () => {
				const login = await step(request);
				const answer = await env.idp.oauth2.acceptLoginRequest(login.searchParams.get("login_challenge") ?? "", {
					access_token: owner.access_token,
				});
				return step([...new URL(answer.redirect_to).searchParams]);
			};
			const consent = await answerLogin();
			const back = await env.idp.oauth2.acceptConsentRequest(consent.searchParams.get("consent_challenge") ?? "", {
				grant_scope: ["profile"],
				remember: true,
			});
			await step([...new URL(back.redirect_to).searchParams]);
			ok((await answerLogin()).searchParams.has("code"));

			await env.idp.oauth2.revokeClientGrants(owner.identityId, app.client_id);
			await expectRevoked(tokens);
			await expectRevoked(extra);
			deepEqual(await env.idp.oauth2.listGrants(owner.identityId), []);
			// The consent page shows again.
			const again = await answerLogin();
			deepEqual(again.origin + again.pathname, TEST_CONSENT_PAGE);
		});
		it("should revoke every grant of a client before it deletes the client", async () => {
			const machine = await env.idp.oauth2.token({ params: [["grant_type", "client_credentials"]], authorization: basic(app, appSecret) });
			await env.idp.oauth2.deleteClient(app.client_id);
			deepEqual(await env.idp.oauth2.clients.getClient(app.client_id), undefined);
			deepEqual(revoked.length, 1);
			await rejects(() => env.auth.api.verifyAccessToken(tokens.access_token, { session: true }));
			// A token of client credentials has no session: its signature holds until `exp`, and introspection calls it
			// inactive at once.
			await env.auth.api.verifyAccessToken(machine.access_token);
			const resourceServer = { ...other, introspect: true };
			deepEqual(await env.idp.oauth2.introspect(resourceServer, machine.access_token), { active: false });
		});
	});
});
