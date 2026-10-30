import { deepEqual, ok, rejects, throws } from "node:assert";
import { decodeJwt } from "jose/jwt/decode";
import { afterEach, beforeEach, describe, it, vi } from "vitest";
import { TEST_CONSENT_PAGE, TEST_ISSUER, TEST_LOGIN_PAGE, type TestIdp, testIdp } from "../fixtures.test.ts";
import type { AuthDanceOauth2Api, AuthDanceOauth2ApiOptions, AuthDanceOauth2DeviceAuthorization } from "./api.ts";
import { type AuthDanceOauth2Client, DEVICE_CODE_GRANT_TYPE, parseClientMetadata } from "./client.ts";
import { formatUserCode, generateUserCode, normalizeUserCode } from "./device.ts";
import {
	type AuthDanceOauth2Error,
	AuthorizationPendingError,
	DeviceAccessDeniedError,
	ExpiredTokenError,
	InvalidClientError,
	InvalidGrantError,
	InvalidRequestError,
	InvalidScopeError,
	InvalidUserCodeError,
	SlowDownError,
	UnauthorizedClientError,
	UnsupportedGrantTypeError,
} from "./error.ts";
import { deviceChallengeRecords, userCodeRecords } from "./records.ts";

const DEVICE_PAGE = "https://login.example.com/device";
const ENDPOINT = `${TEST_ISSUER}/authorize`;
const VERIFICATION_URI = `${TEST_ISSUER}/device`;
const UI = { login: TEST_LOGIN_PAGE, consent: TEST_CONSENT_PAGE, device: DEVICE_PAGE };

describe("user code", () => {
	it("should draw 8 characters of the base-20 alphabet", () => {
		for (let i = 0; i < 200; i++) {
			ok(/^[BCDFGHJKLMNPQRSTVWXZ]{8}$/.test(generateUserCode()));
		}
	});
	it("should show a code as XXXX-XXXX", () => {
		deepEqual(formatUserCode("BCDFGHJK"), "BCDF-GHJK");
	});
	it("should ignore case, dashes and spaces", () => {
		for (const typed of ["BCDF-GHJK", "bcdf-ghjk", " bcdf ghjk ", "BCDFGHJK"]) {
			deepEqual(normalizeUserCode(typed), "BCDFGHJK", typed);
		}
	});
	it("should refuse a code of another length, with a vowel, or that is not a string", () => {
		for (const typed of ["BCDF-GHJ", "BCDF-GHJKL", "ABCD-EFGH", "", 12345678, undefined, "B".repeat(65)]) {
			deepEqual(normalizeUserCode(typed), undefined, String(typed));
		}
	});
});

describe("device authorization grant", () => {
	let env: TestIdp;
	let oauth2: AuthDanceOauth2Api;
	let tv: AuthDanceOauth2Client;
	let owner: { access_token: string; identityId: string };

	async function setup(options: Partial<AuthDanceOauth2ApiOptions> = {}): Promise<void> {
		env = testIdp({ oauth2: { ui: UI, ...options } });
		oauth2 = env.idp.oauth2;
		({ client: tv } = await oauth2.clients.createClient({
			token_endpoint_auth_method: "none",
			grant_types: [DEVICE_CODE_GRANT_TYPE, "refresh_token"],
			scope: "profile email",
			client_name: "TV",
		}));
		owner = await env.signUp();
	}

	function start(params: Record<string, string> = {}, client = tv): Promise<AuthDanceOauth2DeviceAuthorization> {
		return oauth2.deviceAuthorization({
			params: Object.entries({ client_id: client.client_id, scope: "profile", ...params }),
			verification_uri: VERIFICATION_URI,
		});
	}

	function poll(device_code: string, client = tv) {
		return oauth2.token({ params: Object.entries({ grant_type: DEVICE_CODE_GRANT_TYPE, device_code, client_id: client.client_id }) });
	}

	// The browser of the owner at the authorization endpoint.
	async function browse(location: string): Promise<URL> {
		return new URL((await oauth2.authorize({ params: [...new URL(location).searchParams], endpoint: ENDPOINT })).location);
	}

	// The owner opens the verification URI and types the user code. Returns the device challenge and the login page.
	async function enter(userCode: string, query: Record<string, string> = {}): Promise<{ challenge: string; login: URL }> {
		const page = new URL(
			(await oauth2.startDeviceVerification({ params: Object.entries(query), endpoint: ENDPOINT, verification_uri: VERIFICATION_URI }))
				.location,
		);
		deepEqual(page.origin + page.pathname, DEVICE_PAGE);
		const challenge = page.searchParams.get("device_challenge") ?? "";
		const { redirect_to } = await oauth2.acceptDeviceRequest(challenge, { user_code: userCode });
		const login = await browse(redirect_to);
		deepEqual(login.origin + login.pathname, TEST_LOGIN_PAGE);
		return { challenge, login };
	}

	// The login page accepts. Returns the consent challenge.
	async function toConsent(login: URL): Promise<string> {
		const challenge = login.searchParams.get("login_challenge") ?? "";
		const { redirect_to } = await oauth2.acceptLoginRequest(challenge, { access_token: owner.access_token });
		const consent = await browse(redirect_to);
		deepEqual(consent.origin + consent.pathname, TEST_CONSENT_PAGE);
		return consent.searchParams.get("consent_challenge") ?? "";
	}

	// The whole flow on the browser side, accepted. Returns where the browser lands.
	async function approve(userCode: string, grant_scope = ["profile"]): Promise<URL> {
		const { login } = await enter(userCode);
		const consent = await toConsent(login);
		return browse((await oauth2.acceptConsentRequest(consent, { grant_scope })).redirect_to);
	}

	async function fails<T extends AuthDanceOauth2Error>(fn: () => Promise<unknown>, type: new (...args: never[]) => T): Promise<void> {
		await rejects(fn, (error) => error instanceof type);
	}

	// Moves the clock forward, for the interval and the expiry.
	function wait(seconds: number): void {
		vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + seconds * 1000 });
	}

	beforeEach(async () => {
		await setup();
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	describe("options", () => {
		it("should announce the endpoint and the grant type only when ui.device opens them", async () => {
			const open = oauth2.metadata(TEST_ISSUER);
			deepEqual(open.device_authorization_endpoint, `${TEST_ISSUER}/device_authorization`);
			ok(open.grant_types_supported.includes(DEVICE_CODE_GRANT_TYPE));
			await setup({ ui: { login: TEST_LOGIN_PAGE, consent: TEST_CONSENT_PAGE } });
			const closed = oauth2.metadata(TEST_ISSUER);
			deepEqual(closed.device_authorization_endpoint, undefined);
			ok(!closed.grant_types_supported.includes(DEVICE_CODE_GRANT_TYPE));
			deepEqual(oauth2.device, undefined);
		});
		it("should refuse a device page, a verification URI or an interval that is not valid", () => {
			throws(() => testIdp({ oauth2: { ui: { ...UI, device: "/device" } } }), TypeError);
			throws(() => testIdp({ oauth2: { ui: UI, device: { verification_uri: "http://example.com/go" } } }), TypeError);
			for (const interval of [0, -5, 1.5]) {
				throws(() => testIdp({ oauth2: { ui: UI, device: { interval } } }), TypeError, String(interval));
			}
		});
		it("should refuse every device route while the grant is closed", async () => {
			await setup({ ui: { login: TEST_LOGIN_PAGE, consent: TEST_CONSENT_PAGE } });
			await fails(() => start(), InvalidRequestError);
			await fails(
				() => oauth2.startDeviceVerification({ params: [], endpoint: ENDPOINT, verification_uri: VERIFICATION_URI }),
				InvalidRequestError,
			);
			await fails(() => poll("x".repeat(43)), UnsupportedGrantTypeError);
		});
	});

	describe("device authorization endpoint", () => {
		it("should answer a device code, a user code and the verification URIs, RFC 8628 §3.2", async () => {
			const answer = await start();
			ok(/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/.test(answer.user_code));
			ok(answer.device_code.length >= 43);
			deepEqual(
				[answer.verification_uri, answer.verification_uri_complete, answer.expires_in, answer.interval],
				[VERIFICATION_URI, `${VERIFICATION_URI}?user_code=${answer.user_code}`, 600, 5],
			);
		});
		it("should take the verification URI, the interval and the lifetime of the options", async () => {
			await setup({ device: { verification_uri: "https://example.com/go", interval: 8 }, durations: { device: 900 } });
			const answer = await start();
			deepEqual(
				[answer.verification_uri, answer.verification_uri_complete, answer.expires_in, answer.interval],
				["https://example.com/go", `https://example.com/go?user_code=${answer.user_code}`, 900, 8],
			);
		});
		it("should authenticate a confidential client", async () => {
			const { client, client_secret } = await oauth2.clients.createClient({ grant_types: [DEVICE_CODE_GRANT_TYPE], scope: "profile" });
			ok(client_secret);
			await fails(() => start({}, client), InvalidClientError);
			const answer = await oauth2.deviceAuthorization({
				params: [["scope", "profile"]],
				authorization: `Basic ${btoa(`${client.client_id}:${client_secret}`)}`,
				verification_uri: VERIFICATION_URI,
			});
			ok(answer.device_code);
		});
		it("should refuse a client without the device code grant type, and a scope it may not ask for", async () => {
			const { client } = await oauth2.clients.createClient({
				redirect_uris: ["https://app.example.com/callback"],
				token_endpoint_auth_method: "none",
				scope: "profile",
			});
			await fails(() => start({}, client), UnauthorizedClientError);
			await fails(() => start({ scope: "reports" }), InvalidScopeError);
			await fails(() => start({ scope: "unknown" }), InvalidScopeError);
		});
		it("should refuse a repeated parameter", async () => {
			await fails(
				() =>
					oauth2.deviceAuthorization({
						params: [
							["client_id", tv.client_id],
							["scope", "profile"],
							["scope", "email"],
						],
						verification_uri: VERIFICATION_URI,
					}),
				InvalidRequestError,
			);
		});
	});

	describe("verification", () => {
		it("should run the login and the consent pages, then hand the device its tokens", async () => {
			const { device_code, user_code } = await start({ scope: "profile email" });
			await fails(() => poll(device_code), AuthorizationPendingError);

			const { login } = await enter(user_code);
			const request = await oauth2.getLoginRequest(login.searchParams.get("login_challenge") ?? "");
			deepEqual(
				[request.client.client_id, request.requested_scope, request.user_code, request.request_url],
				[tv.client_id, ["profile", "email"], user_code, VERIFICATION_URI],
			);
			const consent = await toConsent(login);
			const consentRequest = await oauth2.getConsentRequest(consent);
			deepEqual([consentRequest.user_code, consentRequest.skip], [user_code, false]);
			const done = await browse((await oauth2.acceptConsentRequest(consent, { grant_scope: ["profile"] })).redirect_to);
			deepEqual(done.href, `${DEVICE_PAGE}?device_status=approved`);

			wait(5);
			const tokens = await poll(device_code);
			deepEqual(tokens.scope, "profile");
			const claims = decodeJwt(tokens.access_token);
			deepEqual([claims.sub, claims.client_id, claims.name], [owner.identityId, tv.client_id, "Alice"]);
			ok(tokens.refresh_token);
			const refreshed = await oauth2.token({
				params: Object.entries({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: tv.client_id }),
			});
			ok(refreshed.access_token);
		});
		it("should fill in the user code of verification_uri_complete", async () => {
			const { user_code } = await start();
			const page = new URL(
				(
					await oauth2.startDeviceVerification({
						params: [["user_code", user_code.toLowerCase()]],
						endpoint: ENDPOINT,
						verification_uri: VERIFICATION_URI,
					})
				).location,
			);
			deepEqual(await oauth2.getDeviceRequest(page.searchParams.get("device_challenge") ?? ""), {
				challenge: page.searchParams.get("device_challenge"),
				user_code,
			});
		});
		it("should take a user code in lower case, with no dash", async () => {
			const { user_code } = await start();
			await enter(user_code.toLowerCase().replace("-", " "));
		});
		it("should ask for consent even for a first-party client, and after a remembered consent", async () => {
			await oauth2.clients.updateClient({ ...tv, skip_consent: true });
			const first = await start();
			const { login } = await enter(first.user_code);
			const consent = await toConsent(login);
			await oauth2.acceptConsentRequest(consent, { grant_scope: ["profile"], remember: true });
			const second = await start();
			await toConsent((await enter(second.user_code)).login);
		});
		it("should tell the device page about a wrong user code, then end the challenge after five", async () => {
			const { user_code } = await start();
			const page = new URL(
				(await oauth2.startDeviceVerification({ params: [], endpoint: ENDPOINT, verification_uri: VERIFICATION_URI })).location,
			);
			const challenge = page.searchParams.get("device_challenge") ?? "";
			for (let i = 0; i < 4; i++) {
				await fails(() => oauth2.acceptDeviceRequest(challenge, { user_code: "BCDF-GHJK" }), InvalidUserCodeError);
			}
			await rejects(
				() => oauth2.acceptDeviceRequest(challenge, { user_code: "nonsense" }),
				(error) => error instanceof InvalidRequestError && !(error instanceof InvalidUserCodeError),
			);
			deepEqual(await deviceChallengeRecords.get(oauth2.storage, [challenge]), undefined);
			await fails(() => oauth2.acceptDeviceRequest(challenge, { user_code }), InvalidRequestError);
		});
		it("should refuse a device challenge that was already answered", async () => {
			const { user_code } = await start();
			const page = new URL(
				(await oauth2.startDeviceVerification({ params: [], endpoint: ENDPOINT, verification_uri: VERIFICATION_URI })).location,
			);
			const challenge = page.searchParams.get("device_challenge") ?? "";
			const { redirect_to } = await oauth2.acceptDeviceRequest(challenge, { user_code });
			await fails(() => oauth2.acceptDeviceRequest(challenge, { user_code }), InvalidRequestError);
			await fails(() => oauth2.getDeviceRequest(challenge), InvalidRequestError);
			await browse(redirect_to);
			await fails(() => browse(redirect_to), InvalidRequestError);
		});
		it("should free the user code once the device is approved", async () => {
			const { user_code } = await start();
			await approve(user_code);
			deepEqual(await userCodeRecords.get(oauth2.storage, [user_code.replace("-", "")]), undefined);
			await fails(() => enter(user_code), InvalidUserCodeError);
		});
		it("should let only the first of two browsers approve one user code", async () => {
			const { user_code } = await start();
			const first = await enter(user_code);
			const second = await enter(user_code);
			const secondConsent = await toConsent(second.login);
			await browse((await oauth2.acceptConsentRequest(secondConsent, { grant_scope: ["profile"] })).redirect_to);
			const firstConsent = await toConsent(first.login);
			const late = await browse((await oauth2.acceptConsentRequest(firstConsent, { grant_scope: ["profile"] })).redirect_to);
			deepEqual([late.searchParams.get("device_status"), late.searchParams.get("error")], ["denied", "invalid_request"]);
		});
	});

	describe("polling", () => {
		it("should answer slow_down to a device that polls too fast, and add 5 seconds to its interval", async () => {
			const { device_code } = await start();
			await fails(() => poll(device_code), AuthorizationPendingError);
			await rejects(
				() => poll(device_code),
				(error) => error instanceof SlowDownError && error.description === "wait 10 seconds between two polls",
			);
			wait(6);
			await fails(() => poll(device_code), SlowDownError);
			wait(6 + 16);
			await fails(() => poll(device_code), AuthorizationPendingError);
		});
		it("should answer access_denied once the owner denies the consent", async () => {
			const { device_code, user_code } = await start();
			const consent = await toConsent((await enter(user_code)).login);
			const done = await browse((await oauth2.rejectConsentRequest(consent, { error: "access_denied" })).redirect_to);
			deepEqual([done.searchParams.get("device_status"), done.searchParams.get("error")], ["denied", "access_denied"]);
			await rejects(
				() => poll(device_code),
				(error) => error instanceof DeviceAccessDeniedError && error.status === 400 && error.error === "access_denied",
			);
		});
		it("should deny the device when the login page refuses", async () => {
			const refused = await start();
			const { login } = await enter(refused.user_code);
			const { redirect_to } = await oauth2.rejectLoginRequest(login.searchParams.get("login_challenge") ?? "", { error: "login_required" });
			const done = await browse(redirect_to);
			deepEqual(done.searchParams.get("error"), "login_required");
			await fails(() => poll(refused.device_code), DeviceAccessDeniedError);
		});
		it("should answer expired_token once the device code expires", async () => {
			const { device_code, user_code } = await start();
			wait(601);
			await fails(() => poll(device_code), ExpiredTokenError);
			await fails(() => enter(user_code), InvalidUserCodeError);
		});
		it("should refuse an approval that comes after the expiry", async () => {
			// The consent challenge outlives the device code here, so the late approval reaches the device record.
			await setup({ durations: { device: 60 } });
			const { device_code, user_code } = await start();
			const consent = await toConsent((await enter(user_code)).login);
			wait(61);
			const late = await browse((await oauth2.acceptConsentRequest(consent, { grant_scope: ["profile"] })).redirect_to);
			deepEqual(late.searchParams.get("error"), "expired_token");
			await fails(() => poll(device_code), ExpiredTokenError);
		});
		it("should refuse an unknown device code, and the device code of another client", async () => {
			const { device_code } = await start();
			const { client: other } = await oauth2.clients.createClient({
				token_endpoint_auth_method: "none",
				grant_types: [DEVICE_CODE_GRANT_TYPE],
				scope: "profile",
			});
			await fails(() => poll("x".repeat(43)), InvalidGrantError);
			await fails(() => poll(device_code, other), InvalidGrantError);
		});
		it("should refuse a second exchange, and revoke the grant", async () => {
			const { device_code, user_code } = await start();
			await approve(user_code);
			const tokens = await poll(device_code);
			const { sid } = decodeJwt(tokens.access_token);
			ok(await oauth2.storage.getSession(String(sid)));
			await fails(() => poll(device_code), InvalidGrantError);
			deepEqual(await oauth2.storage.getSession(String(sid)), undefined);
		});
		it("should give the tokens after a sign-out of the session behind the approval, and refuse them once the grant is revoked", async () => {
			const approved = await start();
			await approve(approved.user_code);
			await env.auth.api.signOut(owner.access_token);
			ok((await poll(approved.device_code)).refresh_token);
			const revoked = await start();
			owner = await env.signUp("bob@example.com");
			await approve(revoked.user_code);
			for (const grant of await oauth2.listGrants(owner.identityId)) {
				await oauth2.revokeGrant(grant.id);
			}
			await fails(() => poll(revoked.device_code), InvalidGrantError);
		});
	});

	describe("client metadata", () => {
		it("should register a device client, with refresh_token and no redirect URI", () => {
			const metadata = parseClientMetadata(
				{ token_endpoint_auth_method: "none", grant_types: [DEVICE_CODE_GRANT_TYPE, "refresh_token"] },
				{ scope: ["profile"], registered_by: "dynamic" },
			);
			deepEqual(
				[metadata.grant_types, metadata.response_types, metadata.redirect_uris],
				[[DEVICE_CODE_GRANT_TYPE, "refresh_token"], [], []],
			);
		});
	});
});
