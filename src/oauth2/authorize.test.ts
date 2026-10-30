import { deepEqual, ok, rejects } from "node:assert";
import { beforeEach, describe, it } from "vitest";
import { TEST_CONSENT_PAGE, TEST_ISSUER, TEST_LOGIN_PAGE, type TestIdp, testIdp } from "../fixtures.test.ts";
import type { AuthDanceOauth2Api, AuthDanceOauth2ApiOptions } from "./api.ts";
import type { AuthDanceOauth2Client } from "./client.ts";
import { InvalidRequestError } from "./error.ts";
import { codeRecords, loginRecords, randomToken, sha256 } from "./records.ts";

const ENDPOINT = `${TEST_ISSUER}/authorize`;
const REDIRECT_URI = "https://app.example.com/callback";

// One browser, and the authorization endpoint called in process.
class Browser {
	oauth2: AuthDanceOauth2Api;

	constructor(oauth2: AuthDanceOauth2Api) {
		this.oauth2 = oauth2;
	}

	async authorize(params: Record<string, string> | [string, string][] | string): Promise<URL> {
		const entries =
			typeof params === "string" ? [...new URL(params).searchParams] : Array.isArray(params) ? params : Object.entries(params);
		return new URL((await this.oauth2.authorize({ params: entries, endpoint: ENDPOINT })).location);
	}
}

describe("authorization endpoint", () => {
	let env: TestIdp;
	let oauth2: AuthDanceOauth2Api;
	let client: AuthDanceOauth2Client;
	let owner: { access_token: string; identityId: string };
	let browser: Browser;
	let verifier: string;
	let request: Record<string, string>;

	async function setup(options: Partial<AuthDanceOauth2ApiOptions> = {}): Promise<void> {
		env = testIdp({ oauth2: options });
		oauth2 = env.idp.oauth2;
		({ client } = await oauth2.clients.createClient({
			redirect_uris: [REDIRECT_URI, "https://app.example.com/other"],
			grant_types: ["authorization_code", "refresh_token"],
			scope: "profile email",
			client_name: "App",
		}));
		owner = await env.signUp();
		browser = new Browser(oauth2);
		verifier = randomToken();
		request = {
			client_id: client.client_id,
			redirect_uri: REDIRECT_URI,
			response_type: "code",
			scope: "profile email",
			state: "s-1",
			code_challenge: await sha256(verifier),
			code_challenge_method: "S256",
		};
	}

	async function toConsent(params: Record<string, string> = request): Promise<string> {
		const login = await browser.authorize(params);
		const { redirect_to } = await oauth2.acceptLoginRequest(login.searchParams.get("login_challenge") ?? "", {
			access_token: owner.access_token,
		});
		const consent = await browser.authorize(redirect_to);
		deepEqual(consent.origin + consent.pathname, TEST_CONSENT_PAGE);
		return consent.searchParams.get("consent_challenge") ?? "";
	}

	function expectError(location: URL, error: string): void {
		deepEqual(location.origin + location.pathname, REDIRECT_URI);
		deepEqual(location.searchParams.get("error"), error, location.href);
		deepEqual(location.searchParams.get("state"), "s-1");
		deepEqual(location.searchParams.get("iss"), TEST_ISSUER);
		ok(!location.searchParams.has("code"));
	}

	beforeEach(async () => {
		await setup();
	});

	it("should run a request through login and consent to a code", async () => {
		const login = await browser.authorize(request);
		deepEqual(login.origin + login.pathname, TEST_LOGIN_PAGE);
		const challenge = login.searchParams.get("login_challenge") ?? "";

		const loginRequest = await oauth2.getLoginRequest(challenge);
		deepEqual(loginRequest.requested_scope, ["profile", "email"]);
		deepEqual(loginRequest.client.client_name, "App");
		ok(!("client_secret_hash" in loginRequest.client));
		ok(loginRequest.request_url.startsWith(`${ENDPOINT}?client_id=`));

		const { redirect_to } = await oauth2.acceptLoginRequest(challenge, { access_token: owner.access_token });
		ok(redirect_to.startsWith(`${ENDPOINT}?login_verifier=`));
		const consent = await browser.authorize(redirect_to);
		const consentChallenge = consent.searchParams.get("consent_challenge") ?? "";
		deepEqual(await oauth2.getConsentRequest(consentChallenge), {
			challenge: consentChallenge,
			client: loginRequest.client,
			requested_scope: ["profile", "email"],
			subject: owner.identityId,
			skip: false,
		});

		const back = await oauth2.acceptConsentRequest(consentChallenge, { grant_scope: ["profile"] });
		const callback = await browser.authorize(back.redirect_to);
		deepEqual(callback.origin + callback.pathname, REDIRECT_URI);
		deepEqual(callback.searchParams.get("state"), "s-1");
		deepEqual(callback.searchParams.get("iss"), TEST_ISSUER);
		const code = await codeRecords.get(oauth2.storage, [await sha256(callback.searchParams.get("code") ?? "")]);
		ok(code);
		const session = await oauth2.storage.getSession(code.session_id);
		deepEqual([session?.client_id, session?.scopes], [client.client_id, ["profile"]]);
	});
	it("should take the scope of the client and its one redirect URI by default", async () => {
		await oauth2.clients.updateClient({ ...client, redirect_uris: [REDIRECT_URI] });
		const { redirect_uri: _uri, scope: _scope, ...rest } = request;
		const login = await browser.authorize(rest);
		const record = await loginRecords.get(oauth2.storage, [login.searchParams.get("login_challenge") ?? ""]);
		deepEqual(record?.request, {
			client_id: client.client_id,
			redirect_uri: REDIRECT_URI,
			redirect_uri_given: false,
			scope: ["profile", "email"],
			state: "s-1",
			code_challenge: request.code_challenge,
		});
	});
	it("should send the code to the port the request gave for a loopback redirect URI", async () => {
		await oauth2.clients.updateClient({ ...client, redirect_uris: ["http://127.0.0.1/callback"] });
		const challenge = await toConsent({ ...request, redirect_uri: "http://127.0.0.1:51004/callback" });
		const { redirect_to } = await oauth2.acceptConsentRequest(challenge, { grant_scope: ["profile"] });
		deepEqual((await browser.authorize(redirect_to)).origin, "http://127.0.0.1:51004");
	});

	describe("errors it cannot send to the client", () => {
		it("should throw for a missing or unknown client and a redirect URI that does not match", async () => {
			const { client_id: _id, ...noClient } = request;
			const { redirect_uri: _uri, ...noRedirect } = request;
			for (const params of [
				noClient,
				{ ...request, client_id: "cli_missing" },
				{ ...request, redirect_uri: "https://evil.example.com/callback" },
				{ ...request, redirect_uri: `${REDIRECT_URI}/more` },
				noRedirect,
				[...Object.entries(request), ["client_id", client.client_id]] as [string, string][],
				[...Object.entries(request), ["redirect_uri", REDIRECT_URI]] as [string, string][],
			]) {
				await rejects(() => browser.authorize(params), InvalidRequestError, JSON.stringify(params));
			}
		});
		it("should send them to ui.error when it is set", async () => {
			await setup({ ui: { login: TEST_LOGIN_PAGE, consent: TEST_CONSENT_PAGE, error: "https://login.example.com/error" } });
			const page = await browser.authorize({ ...request, client_id: "cli_missing" });
			deepEqual(page.origin + page.pathname, "https://login.example.com/error");
			deepEqual(page.searchParams.get("error"), "invalid_request");
			deepEqual(page.searchParams.get("error_description"), "client_id names no client");
		});
	});

	describe("errors it sends to the client", () => {
		it("should send each RFC 6749 error with state and iss", async () => {
			const { response_type: _type, ...noType } = request;
			const { code_challenge: _challenge, ...noChallenge } = request;
			const { code_challenge_method: _method, ...noMethod } = request;
			const cases: [Record<string, string> | [string, string][], string][] = [
				[[...Object.entries(request), ["scope", "profile"]], "invalid_request"],
				[noType, "invalid_request"],
				[{ ...request, response_type: "token" }, "unsupported_response_type"],
				[{ ...request, response_type: "code id_token" }, "unsupported_response_type"],
				[noChallenge, "invalid_request"],
				[noMethod, "invalid_request"],
				[{ ...request, code_challenge_method: "plain" }, "invalid_request"],
				[{ ...request, code_challenge: "too-short" }, "invalid_request"],
				[{ ...request, scope: "profile admin" }, "invalid_scope"],
				[{ ...request, scope: "reports" }, "invalid_scope"],
			];
			for (const [params, error] of cases) {
				expectError(await browser.authorize(params), error);
			}
			await oauth2.clients.updateClient({ ...client, grant_types: ["client_credentials"], response_types: [] });
			expectError(await browser.authorize(request), "unauthorized_client");
		});
		it("should ignore an unknown parameter, and the parameters left for OpenID Connect", async () => {
			const login = await browser.authorize({ ...request, nonce: "n", prompt: "login", max_age: "60", extra: "x" });
			deepEqual(login.origin + login.pathname, TEST_LOGIN_PAGE);
		});
	});

	describe("the login answer", () => {
		it("should refuse a verifier that is not valid, and a verifier used twice", async () => {
			const login = await browser.authorize(request);
			const { redirect_to } = await oauth2.acceptLoginRequest(login.searchParams.get("login_challenge") ?? "", {
				access_token: owner.access_token,
			});
			const verifierParam = new URL(redirect_to).searchParams.get("login_verifier") ?? "";
			const [challenge] = verifierParam.split(".");
			for (const value of ["garbage", `${challenge}.${randomToken()}`, `${challenge}/x.${randomToken()}`]) {
				await rejects(() => browser.authorize({ login_verifier: value }), InvalidRequestError, value);
			}
			await browser.authorize(redirect_to);
			await rejects(() => browser.authorize(redirect_to), InvalidRequestError);
		});
		it("should continue from any browser, because the pages own the browser", async () => {
			const login = await browser.authorize(request);
			const { redirect_to } = await oauth2.acceptLoginRequest(login.searchParams.get("login_challenge") ?? "", {
				access_token: owner.access_token,
			});
			const consent = await new Browser(oauth2).authorize(redirect_to);
			deepEqual(consent.origin + consent.pathname, TEST_CONSENT_PAGE);
		});
		it("should send a rejected login to the client with its error", async () => {
			const login = await browser.authorize(request);
			const { redirect_to } = await oauth2.rejectLoginRequest(login.searchParams.get("login_challenge") ?? "", {
				error: "login_required",
				error_description: 'the owner "left"',
			});
			const callback = await browser.authorize(redirect_to);
			expectError(callback, "login_required");
			deepEqual(callback.searchParams.get("error_description"), "the owner left");
		});
		it("should refuse an answer that is not valid", async () => {
			const challenge = (await browser.authorize(request)).searchParams.get("login_challenge") ?? "";
			await rejects(() => oauth2.acceptLoginRequest(challenge, { access_token: "not-a-token" }), InvalidRequestError);
			await rejects(() => oauth2.acceptLoginRequest(challenge, {} as { access_token: string }), InvalidRequestError);
			await rejects(() => oauth2.rejectLoginRequest(challenge, { error: 'bad"code' }), InvalidRequestError);
			await rejects(() => oauth2.getLoginRequest(randomToken()), InvalidRequestError);
			await rejects(() => oauth2.getLoginRequest("../session/x"), InvalidRequestError);
			await oauth2.acceptLoginRequest(challenge, { access_token: owner.access_token });
			await rejects(() => oauth2.acceptLoginRequest(challenge, { access_token: owner.access_token }), InvalidRequestError);
		});
		it("should refuse the access token of a session that ended", async () => {
			const challenge = (await browser.authorize(request)).searchParams.get("login_challenge") ?? "";
			await env.auth.api.signOut(owner.access_token);
			await rejects(() => oauth2.acceptLoginRequest(challenge, { access_token: owner.access_token }), InvalidRequestError);
		});
		it("should skip consent for a first-party client", async () => {
			await oauth2.clients.updateClient({ ...client, skip_consent: true });
			const login = await browser.authorize(request);
			const { redirect_to } = await oauth2.acceptLoginRequest(login.searchParams.get("login_challenge") ?? "", {
				access_token: owner.access_token,
			});
			const callback = await browser.authorize(redirect_to);
			ok(callback.searchParams.has("code"));
		});
	});

	describe("the consent answer", () => {
		it("should send a rejected consent to the client", async () => {
			const challenge = await toConsent();
			const { redirect_to } = await oauth2.rejectConsentRequest(challenge, { error: "access_denied" });
			expectError(await browser.authorize(redirect_to), "access_denied");
		});
		it("should grant only requested scopes, one time", async () => {
			const challenge = await toConsent();
			await rejects(() => oauth2.acceptConsentRequest(challenge, { grant_scope: ["reports"] }), InvalidRequestError);
			await oauth2.acceptConsentRequest(challenge, { grant_scope: ["profile", "profile"] });
			await rejects(() => oauth2.acceptConsentRequest(challenge, { grant_scope: ["profile"] }), InvalidRequestError);
		});
		it("should remember a consent, and skip it for the same scopes", async () => {
			const challenge = await toConsent();
			const { redirect_to } = await oauth2.acceptConsentRequest(challenge, { grant_scope: ["profile", "email"], remember: true });
			ok((await browser.authorize(redirect_to)).searchParams.has("code"));
			// The same scopes skip the consent page.
			const login = await browser.authorize({ ...request, scope: "profile" });
			const answer = await oauth2.acceptLoginRequest(login.searchParams.get("login_challenge") ?? "", { access_token: owner.access_token });
			ok((await browser.authorize(answer.redirect_to)).searchParams.has("code"));
		});
	});
});
