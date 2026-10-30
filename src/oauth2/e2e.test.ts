import { deepEqual, ok, rejects } from "node:assert";
import * as oauth from "oauth4webapi";
import { afterEach, beforeEach, describe, it, vi } from "vitest";
import { AuthDanceClient } from "../client.ts";
import { lastCode, TEST_CONSENT_PAGE, TEST_ISSUER, TEST_LOGIN_PAGE, TestBrowser, type TestIdp, testIdp } from "../fixtures.test.ts";

const REDIRECT_URI = "https://app.example.com/callback";
const SPA_REDIRECT_URI = "http://127.0.0.1:5173/callback";
const DEVICE_PAGE = "https://login.example.com/device";

// The interop suite: a third-party client built on oauth4webapi runs each flow against the in-process `fetch`. It checks
// PKCE, `iss` in the authorization response (RFC 9207), the error formats and the access token format (RFC 9068).
describe("oauth4webapi interop", () => {
	let env: TestIdp;
	let as: oauth.AuthorizationServer;
	let options: { [oauth.customFetch]: typeof fetch; [oauth.allowInsecureRequests]: true };
	let confidential: oauth.Client;
	let secret: string;
	let spa: oauth.Client;

	beforeEach(async () => {
		env = testIdp({ oauth2: { ui: { login: TEST_LOGIN_PAGE, consent: TEST_CONSENT_PAGE, device: DEVICE_PAGE } } });
		options = {
			[oauth.customFetch]: async (url, init) => env.idp.fetch(new Request(url, init)),
			[oauth.allowInsecureRequests]: true,
		};
		const issuer = new URL(TEST_ISSUER);
		as = await oauth.processDiscoveryResponse(issuer, await oauth.discoveryRequest(issuer, { ...options, algorithm: "oauth2" }));
		const created = await env.idp.oauth2.clients.createClient({
			redirect_uris: [REDIRECT_URI],
			grant_types: ["authorization_code", "refresh_token", "client_credentials"],
			scope: "profile email reports",
		});
		ok(created.client_secret);
		confidential = { client_id: created.client.client_id };
		secret = created.client_secret;
		const { client } = await env.idp.oauth2.clients.createClient({
			redirect_uris: ["http://127.0.0.1/callback"],
			token_endpoint_auth_method: "none",
			grant_types: ["authorization_code", "refresh_token"],
			scope: "profile",
		});
		spa = { client_id: client.client_id, token_endpoint_auth_method: "none" };
		await env.signUp("alice@example.com", { name: "Alice", email: "alice@example.com" });
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	// The login page: it reads the request, signs the owner in with a dance against the core app, and accepts.
	async function loginApp(page: URL): Promise<string> {
		deepEqual(page.origin + page.pathname, TEST_LOGIN_PAGE);
		const challenge = page.searchParams.get("login_challenge") ?? "";
		await env.idp.oauth2.getLoginRequest(challenge);
		const client = new AuthDanceClient({ baseUrl: "http://localhost", fetch: env.auth.fetch });
		using dance = await client.signIn();
		while (!dance.done) {
			if (dance.current?.type === "email") {
				await dance.submitPrompt("alice@example.com");
			} else {
				await dance.sendPrompt();
				await dance.submitPrompt(lastCode(env.channel));
			}
		}
		const { redirect_to } = await env.idp.oauth2.acceptLoginRequest(challenge, { access_token: client.tokens?.access_token ?? "" });
		return redirect_to;
	}

	// The consent page: it grants every requested scope.
	async function consentApp(page: URL): Promise<string> {
		deepEqual(page.origin + page.pathname, TEST_CONSENT_PAGE);
		const challenge = page.searchParams.get("consent_challenge") ?? "";
		const request = await env.idp.oauth2.getConsentRequest(challenge);
		const { redirect_to } = await env.idp.oauth2.acceptConsentRequest(challenge, { grant_scope: request.requested_scope });
		return redirect_to;
	}

	// The browser of the owner: the client sends it to the authorization endpoint, and it comes back with the response.
	async function authorize(
		client: oauth.Client,
		redirectUri: string,
		scope: string,
	): Promise<{ callback: URL; verifier: string; state: string }> {
		const verifier = oauth.generateRandomCodeVerifier();
		const state = oauth.generateRandomState();
		const url = new URL(as.authorization_endpoint ?? "");
		url.searchParams.set("client_id", client.client_id);
		url.searchParams.set("redirect_uri", redirectUri);
		url.searchParams.set("response_type", "code");
		url.searchParams.set("scope", scope);
		url.searchParams.set("state", state);
		url.searchParams.set("code_challenge", await oauth.calculatePKCECodeChallenge(verifier));
		url.searchParams.set("code_challenge_method", "S256");
		const browser = new TestBrowser(env.idp.fetch);
		const login = await browser.redirect(url.href);
		const consent = await browser.redirect(await loginApp(login));
		const callback = await browser.redirect(await consentApp(consent));
		return { callback, verifier, state };
	}

	it("should discover the server", () => {
		deepEqual(as.issuer, TEST_ISSUER);
		deepEqual(as.code_challenge_methods_supported, ["S256"]);
		ok(as.authorization_response_iss_parameter_supported);
		deepEqual(as.device_authorization_endpoint, `${TEST_ISSUER}/device_authorization`);
	});
	it("should run the device flow of a public client, RFC 8628", async () => {
		const { client: created } = await env.idp.oauth2.clients.createClient({
			token_endpoint_auth_method: "none",
			grant_types: ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
			scope: "profile",
		});
		const tv: oauth.Client = { client_id: created.client_id, token_endpoint_auth_method: "none" };
		const device = await oauth.processDeviceAuthorizationResponse(
			as,
			tv,
			await oauth.deviceAuthorizationRequest(as, tv, oauth.None(), { scope: "profile" }, options),
		);
		const poll = async () =>
			oauth.processDeviceCodeResponse(as, tv, await oauth.deviceCodeGrantRequest(as, tv, oauth.None(), device.device_code, options));
		await rejects(poll, (error) => error instanceof oauth.ResponseBodyError && error.error === "authorization_pending");

		// The owner scans the QR code of verification_uri_complete on a phone, and lands on the device page with the code
		// filled in.
		const browser = new TestBrowser(env.idp.fetch);
		const page = await browser.redirect(device.verification_uri_complete ?? "");
		deepEqual(page.origin + page.pathname, DEVICE_PAGE);
		const challenge = page.searchParams.get("device_challenge") ?? "";
		const { user_code } = await env.idp.oauth2.getDeviceRequest(challenge);
		deepEqual(user_code, device.user_code);
		const { redirect_to } = await env.idp.oauth2.acceptDeviceRequest(challenge, { user_code: device.user_code });
		const login = await browser.redirect(redirect_to);
		const consent = await browser.redirect(await loginApp(login));
		const done = await browser.redirect(await consentApp(consent));
		deepEqual(done.href, `${DEVICE_PAGE}?device_status=approved`);

		vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + (device.interval ?? 5) * 1000 });
		const tokens = await poll();
		deepEqual([tokens.token_type, tokens.scope], ["bearer", "profile"]);
		const claims = await oauth.validateJwtAccessToken(
			as,
			new Request("https://api.example.com/me", { headers: { authorization: `Bearer ${tokens.access_token}` } }),
			// A client with no `audience` gets tokens for the issuer, like the tokens of a dance.
			TEST_ISSUER,
			options,
		);
		deepEqual([claims.client_id, claims.name], [tv.client_id, "Alice"]);
	});
	it("should run the code flow of a confidential client, refresh, and end the session with a revocation", async () => {
		const auth = oauth.ClientSecretBasic(secret);
		const { callback, verifier, state } = await authorize(confidential, REDIRECT_URI, "profile email");
		const params = oauth.validateAuthResponse(as, confidential, callback, state);
		const tokens = await oauth.processAuthorizationCodeResponse(
			as,
			confidential,
			await oauth.authorizationCodeGrantRequest(as, confidential, auth, params, REDIRECT_URI, verifier, options),
		);
		deepEqual([tokens.token_type, tokens.scope], ["bearer", "profile email"]);
		ok(tokens.refresh_token);

		// A resource server checks the access token with RFC 9068 and the JWK Set of the metadata.
		const claims = await oauth.validateJwtAccessToken(
			as,
			new Request("https://api.example.com/reports", { headers: { authorization: `Bearer ${tokens.access_token}` } }),
			TEST_ISSUER,
			options,
		);
		deepEqual([claims.client_id, claims.scope, claims.name], [confidential.client_id, "profile email", "Alice"]);

		const refreshed = await oauth.processRefreshTokenResponse(
			as,
			confidential,
			await oauth.refreshTokenGrantRequest(as, confidential, auth, tokens.refresh_token, options),
		);
		ok(refreshed.refresh_token && refreshed.refresh_token !== tokens.refresh_token);

		// The old refresh token stays valid until its session ends. A revocation of either one ends the session, and both
		// stop working.
		await oauth.processRefreshTokenResponse(
			as,
			confidential,
			await oauth.refreshTokenGrantRequest(as, confidential, auth, tokens.refresh_token, options),
		);
		await oauth.processRevocationResponse(await oauth.revocationRequest(as, confidential, auth, refreshed.refresh_token, options));
		for (const token of [tokens.refresh_token, refreshed.refresh_token]) {
			await rejects(
				async () =>
					oauth.processRefreshTokenResponse(as, confidential, await oauth.refreshTokenGrantRequest(as, confidential, auth, token, options)),
				(error) => error instanceof oauth.ResponseBodyError && error.error === "invalid_grant",
			);
		}
	});
	it("should introspect a token for a resource server", async () => {
		const { client: rs, client_secret: rsSecret } = await env.idp.oauth2.clients.createClient({
			grant_types: ["client_credentials"],
			scope: "reports",
		});
		ok(rsSecret);
		await env.idp.oauth2.clients.updateClient({ ...rs, introspect: true });
		const resourceServer: oauth.Client = { client_id: rs.client_id };
		const { callback, verifier, state } = await authorize(confidential, REDIRECT_URI, "profile");
		const params = oauth.validateAuthResponse(as, confidential, callback, state);
		const tokens = await oauth.processAuthorizationCodeResponse(
			as,
			confidential,
			await oauth.authorizationCodeGrantRequest(as, confidential, oauth.ClientSecretBasic(secret), params, REDIRECT_URI, verifier, options),
		);
		const introspect = async (token: string, hint: string) =>
			oauth.processIntrospectionResponse(
				as,
				resourceServer,
				await oauth.introspectionRequest(as, resourceServer, oauth.ClientSecretBasic(rsSecret), token, {
					...options,
					additionalParameters: { token_type_hint: hint },
				}),
			);
		const access = await introspect(tokens.access_token, "access_token");
		deepEqual([access.active, access.client_id, access.scope, access.token_type], [true, confidential.client_id, "profile", "Bearer"]);
		deepEqual((await introspect(tokens.refresh_token ?? "", "refresh_token")).token_type, "refresh_token");
		deepEqual(await introspect("garbage", "access_token"), { active: false });
	});
	it("should revoke a refresh token, and end the grant", async () => {
		const auth = oauth.ClientSecretBasic(secret);
		const { callback, verifier, state } = await authorize(confidential, REDIRECT_URI, "profile");
		const params = oauth.validateAuthResponse(as, confidential, callback, state);
		const tokens = await oauth.processAuthorizationCodeResponse(
			as,
			confidential,
			await oauth.authorizationCodeGrantRequest(as, confidential, auth, params, REDIRECT_URI, verifier, options),
		);
		ok(tokens.refresh_token);
		await oauth.processRevocationResponse(
			await oauth.revocationRequest(as, confidential, auth, tokens.refresh_token, {
				...options,
				additionalParameters: { token_type_hint: "refresh_token" },
			}),
		);
		await rejects(
			async () =>
				oauth.processRefreshTokenResponse(
					as,
					confidential,
					await oauth.refreshTokenGrantRequest(as, confidential, auth, tokens.refresh_token ?? "", options),
				),
			(error) => error instanceof oauth.ResponseBodyError && error.error === "invalid_grant",
		);
	});
	it("should register a client, then run the code flow with it", async () => {
		env = testIdp({ oauth2: { registration: { authorize: (token) => token === "initial" } } });
		await env.signUp("alice@example.com", { name: "Alice", email: "alice@example.com" });
		const issuer = new URL(TEST_ISSUER);
		as = await oauth.processDiscoveryResponse(issuer, await oauth.discoveryRequest(issuer, { ...options, algorithm: "oauth2" }));
		ok(as.registration_endpoint);
		const registered = await oauth.processDynamicClientRegistrationResponse(
			await oauth.dynamicClientRegistrationRequest(
				as,
				{ redirect_uris: [REDIRECT_URI], grant_types: ["authorization_code", "refresh_token"], scope: "profile", client_name: "Dynamic" },
				{ ...options, initialAccessToken: "initial" },
			),
		);
		const client: oauth.Client = { client_id: registered.client_id };
		const { callback, verifier, state } = await authorize(client, REDIRECT_URI, "profile");
		const tokens = await oauth.processAuthorizationCodeResponse(
			as,
			client,
			await oauth.authorizationCodeGrantRequest(
				as,
				client,
				oauth.ClientSecretBasic(String(registered.client_secret)),
				oauth.validateAuthResponse(as, client, callback, state),
				REDIRECT_URI,
				verifier,
				options,
			),
		);
		deepEqual([tokens.scope, typeof tokens.refresh_token], ["profile", "string"]);
	});
	it("should run the code flow of a public client on a loopback redirect URI", async () => {
		const { callback, verifier, state } = await authorize(spa, SPA_REDIRECT_URI, "profile");
		deepEqual(callback.origin, "http://127.0.0.1:5173");
		const params = oauth.validateAuthResponse(as, spa, callback, state);
		const tokens = await oauth.processAuthorizationCodeResponse(
			as,
			spa,
			await oauth.authorizationCodeGrantRequest(as, spa, oauth.None(), params, SPA_REDIRECT_URI, verifier, options),
		);
		deepEqual(tokens.scope, "profile");
	});
	it("should refuse a code with the wrong verifier, and a code used twice", async () => {
		const auth = oauth.ClientSecretBasic(secret);
		const { callback, verifier, state } = await authorize(confidential, REDIRECT_URI, "profile");
		const params = oauth.validateAuthResponse(as, confidential, callback, state);
		const exchange = async (codeVerifier: string) =>
			oauth.processAuthorizationCodeResponse(
				as,
				confidential,
				await oauth.authorizationCodeGrantRequest(as, confidential, auth, params, REDIRECT_URI, codeVerifier, options),
			);
		await rejects(
			() => exchange(oauth.generateRandomCodeVerifier()),
			(error) => error instanceof oauth.ResponseBodyError && error.error === "invalid_grant",
		);
		// The first exchange marked the code used, so the right verifier now ends the grant.
		await rejects(
			() => exchange(verifier),
			(error) => error instanceof oauth.ResponseBodyError && error.error === "invalid_grant",
		);
	});
	it("should hand a rejected login to the client with iss", async () => {
		const state = oauth.generateRandomState();
		const url = new URL(as.authorization_endpoint ?? "");
		for (const [name, value] of Object.entries({
			client_id: confidential.client_id,
			redirect_uri: REDIRECT_URI,
			response_type: "code",
			scope: "profile",
			state,
			code_challenge: await oauth.calculatePKCECodeChallenge(oauth.generateRandomCodeVerifier()),
			code_challenge_method: "S256",
		})) {
			url.searchParams.set(name, value);
		}
		const browser = new TestBrowser(env.idp.fetch);
		const login = await browser.redirect(url.href);
		const { redirect_to } = await env.idp.oauth2.rejectLoginRequest(login.searchParams.get("login_challenge") ?? "", {
			error: "access_denied",
		});
		const callback = await browser.redirect(redirect_to);
		ok(callback.searchParams.has("iss"));
		await rejects(
			async () => oauth.validateAuthResponse(as, confidential, callback, state),
			(error) => error instanceof oauth.AuthorizationResponseError && error.error === "access_denied",
		);
	});
	it("should mint a client credentials token, and refuse a wrong secret", async () => {
		const credentials = async (auth: oauth.ClientAuth, scope?: string) =>
			oauth.processClientCredentialsResponse(
				as,
				confidential,
				await oauth.clientCredentialsGrantRequest(as, confidential, auth, new URLSearchParams(scope ? { scope } : {}), options),
			);
		// The client registered client_secret_basic, so client_secret_post fails, with no Basic challenge.
		await rejects(
			() => credentials(oauth.ClientSecretPost(secret), "reports"),
			(error) => error instanceof oauth.ResponseBodyError && error.status === 401 && error.error === "invalid_client",
		);
		const basic = await credentials(oauth.ClientSecretBasic(secret), "reports");
		deepEqual([basic.scope, basic.refresh_token], ["reports", undefined]);
		// A wrong secret over Basic answers 401 with a Basic challenge.
		await rejects(
			() => credentials(oauth.ClientSecretBasic("wrong")),
			(error) => error instanceof oauth.WWWAuthenticateChallengeError && error.status === 401,
		);
	});
});
