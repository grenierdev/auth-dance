// This file exports fixtures the test files share. It holds no test, and vitest.config.ts leaves it out.
import { AuthDanceApi, type AuthDanceApiOptions } from "./api.ts";
import { sequence } from "./choreography.ts";
import { AuthDanceClient } from "./client.ts";
import { EmailAuthDanceComponent } from "./components/email.ts";
import { OtpAuthDanceComponent } from "./components/otp.ts";
import { generateSigningKey } from "./keys.ts";
import { type AuthDance, createAuthDance } from "./mod.ts";
import type { AuthDanceOauth2Client } from "./oauth2/client.ts";
import { randomToken, sha256 } from "./oauth2/records.ts";
import { type AuthDanceOauth2, type AuthDanceOauth2ApiOptions, type AuthDanceOauth2AppOptions, createAuthDanceOauth2 } from "./oauth2.ts";
import {
	createAuthDanceMemoryOauth2ClientStorage,
	MemoryAuthDanceChannel,
	MemoryIdentityProvider,
	MemoryKvProvider,
	MemoryRateLimiterProvider,
} from "./providers/memory.ts";
import { AuthDanceStorage } from "./storage.ts";

/** The issuer of every test instance. `http:` passes for `localhost`. */
export const TEST_ISSUER = "http://localhost";

/** One ES256 key. Each test file that imports it generates it one time, so the suites stay fast. */
export const TEST_SIGNING_KEYS = [await generateSigningKey()];

/** The flow state key of the core: openssl rand -base64 32 | tr '+/' '-_' | tr -d '=' */
export const TEST_SECRET = "zdJXI1jwuXW8A19fns0E_B4HSYm7AUHLGlU9WLo8mxs";

/** A core API on memory storage, with an email and one-time code dance, the shared key, `issuer` and `scopes`. */
export function testCoreApi(issuer: string = TEST_ISSUER, scopes?: AuthDanceApiOptions["tokens"]["scopes"]): AuthDanceApi {
	return new AuthDanceApi({
		channels: { email: new MemoryAuthDanceChannel("email") },
		choreography: sequence("email", "otp"),
		components: {
			email: new EmailAuthDanceComponent({ channel: "email", challenge: "otp" }),
			otp: new OtpAuthDanceComponent({ channel: "email" }),
		},
		secret: TEST_SECRET,
		keys: TEST_SIGNING_KEYS,
		tokens: { issuer, scopes },
		storage: new AuthDanceStorage({
			identity: new MemoryIdentityProvider(),
			kv: new MemoryKvProvider(),
			rate_limiter: new MemoryRateLimiterProvider(),
		}),
	});
}

/** A confidential client record with every required field. `overrides` replaces any of them. */
export function testOauth2Client(overrides: Partial<AuthDanceOauth2Client> = {}): AuthDanceOauth2Client {
	return {
		client_id: "cli_test",
		client_secret_hash: "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
		client_secret_expires_at: 0,
		client_id_issued_at: 1_700_000_000,
		redirect_uris: ["https://app.example.com/callback"],
		token_endpoint_auth_method: "client_secret_basic",
		grant_types: ["authorization_code", "refresh_token"],
		response_types: ["code"],
		scope: "profile email",
		...overrides,
	};
}

/** The pages of the oauth2 test instances. Nothing serves them: a test reads the challenge off the redirect. */
export const TEST_LOGIN_PAGE = "https://login.example.com/login";
export const TEST_CONSENT_PAGE = "https://login.example.com/consent";

/** The last one-time code a memory channel took. */
export function lastCode(channel: MemoryAuthDanceChannel): string {
	const code = (channel.messages.at(-1)?.content as Record<string, string> | undefined)?.["text/x-code"];
	if (!code) {
		throw new Error("the channel took no one-time code");
	}
	return code;
}

/** A core instance and an authorization server on top of it, on memory storage. */
export interface TestIdp {
	auth: AuthDance;
	idp: AuthDanceOauth2;
	/** Where the core delivers each one-time code. */
	channel: MemoryAuthDanceChannel;
	/** Signs up an owner with a dance against `auth.fetch`, sets `data` on the identity, and returns its tokens. */
	signUp(email?: string, data?: Record<string, unknown>): Promise<{ access_token: string; refresh_token: string; identityId: string }>;
	/**
	 * Runs the authorization endpoint in process for a client and the first of its redirect URIs, accepts the login with
	 * `access_token` and the consent with every scope of `scope`, and returns the code and its verifier.
	 */
	issueCode(client: AuthDanceOauth2Client, access_token: string, scope: string): Promise<{ code: string; verifier: string }>;
}

/** The scopes of the `TestIdp` core. */
export const TEST_SCOPES = {
	profile: { description: "Your name", claims: ["name"] },
	email: { description: "Your email address", claims: ["email"] },
	reports: { description: "The reports" },
};

/**
 * Builds a `TestIdp`. `api` replaces any option of the core, `api.tokens` merged into the default. `oauth2` and `app`
 * replace any option of the authorization server.
 */
export function testIdp(
	options: {
		api?: Partial<Omit<AuthDanceApiOptions, "tokens">> & { tokens?: Partial<AuthDanceApiOptions["tokens"]> };
		oauth2?: Partial<AuthDanceOauth2ApiOptions>;
		app?: AuthDanceOauth2AppOptions;
	} = {},
): TestIdp {
	const channel = new MemoryAuthDanceChannel("email");
	const auth = createAuthDance({
		api: {
			channels: { email: channel },
			choreography: sequence("email", "otp"),
			components: {
				email: new EmailAuthDanceComponent({ channel: "email", challenge: "otp" }),
				otp: new OtpAuthDanceComponent({ channel: "email" }),
			},
			secret: TEST_SECRET,
			keys: TEST_SIGNING_KEYS,
			storage: new AuthDanceStorage({
				identity: new MemoryIdentityProvider(),
				kv: new MemoryKvProvider(),
				rate_limiter: new MemoryRateLimiterProvider(),
			}),
			...options.api,
			tokens: { issuer: TEST_ISSUER, scopes: TEST_SCOPES, ...options.api?.tokens },
		},
	});
	const idp = createAuthDanceOauth2({
		oauth2: {
			api: auth.api,
			clients: createAuthDanceMemoryOauth2ClientStorage(),
			issuer: TEST_ISSUER,
			ui: { login: TEST_LOGIN_PAGE, consent: TEST_CONSENT_PAGE },
			...options.oauth2,
		},
		app: options.app,
	});
	async function signUp(email = "alice@example.com", data: Record<string, unknown> = { name: "Alice", email }) {
		const client = new AuthDanceClient({ baseUrl: "http://localhost", fetch: auth.fetch });
		using dance = await client.signUp();
		while (!dance.done) {
			if (dance.current?.type === "email") {
				await dance.submitPrompt(email);
			} else {
				await dance.sendPrompt();
				await dance.submitPrompt(lastCode(channel));
			}
		}
		const access_token = client.tokens?.access_token;
		const refresh_token = client.tokens?.refresh_token;
		const identityId = client.identity?.id;
		if (!access_token || !refresh_token || !identityId) {
			throw new Error("the dance minted no tokens");
		}
		const identity = await auth.api.storage.getIdentity(identityId);
		if (identity) {
			await auth.api.storage.setIdentity({ ...identity, data });
		}
		return { access_token, refresh_token, identityId };
	}
	async function issueCode(client: AuthDanceOauth2Client, access_token: string, scope: string) {
		const verifier = randomToken();
		const step = async (params: [string, string][]) =>
			new URL((await idp.oauth2.authorize({ params, endpoint: `${TEST_ISSUER}/authorize` })).location);
		const login = await step([
			["client_id", client.client_id],
			["redirect_uri", client.redirect_uris[0]],
			["response_type", "code"],
			["scope", scope],
			["code_challenge", await sha256(verifier)],
			["code_challenge_method", "S256"],
		]);
		const answer = await idp.oauth2.acceptLoginRequest(login.searchParams.get("login_challenge") ?? "", { access_token });
		const consent = await step([...new URL(answer.redirect_to).searchParams]);
		const back = await idp.oauth2.acceptConsentRequest(consent.searchParams.get("consent_challenge") ?? "", {
			grant_scope: scope.split(" "),
		});
		const code = (await step([...new URL(back.redirect_to).searchParams])).searchParams.get("code");
		if (!code) {
			throw new Error("the authorization endpoint issued no code");
		}
		return { code, verifier };
	}
	return { auth, idp, channel, signUp, issueCode };
}

/** A browser. It sends each request to one `fetch`, and does not follow a redirect on its own. */
export class TestBrowser {
	#fetch: (request: Request) => Response | Promise<Response>;

	constructor(fetch: (request: Request) => Response | Promise<Response>) {
		this.#fetch = fetch;
	}

	/** Sends a request. */
	async request(url: string, init: RequestInit = {}): Promise<Response> {
		return this.#fetch(new Request(url, { ...init, redirect: "manual" }));
	}

	/** Sends a GET, expects a 303, and returns where it points. */
	async redirect(url: string, init?: RequestInit): Promise<URL> {
		const response = await this.request(url, init);
		const location = response.headers.get("location");
		if (response.status !== 303 || !location) {
			throw new Error(`expected a 303 from ${url}, got ${response.status}: ${await response.text()}`);
		}
		return new URL(location);
	}
}
