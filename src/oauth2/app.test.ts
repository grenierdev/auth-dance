import { deepEqual, ok } from "node:assert";
import { beforeEach, describe, it } from "vitest";
import { TEST_CONSENT_PAGE, TEST_LOGIN_PAGE, TestBrowser, type TestIdp, testCoreApi, testIdp } from "../fixtures.test.ts";
import { type AuthDanceOauth2, createAuthDanceOauth2 } from "../oauth2.ts";
import { createAuthDanceMemoryOauth2ClientStorage } from "../providers/memory.ts";
import type { AuthDanceOauth2AddressRateLimits } from "./api.ts";
import type { AuthDanceOauth2AppOptions } from "./app.ts";
import type { AuthDanceOauth2Client } from "./client.ts";
import { InvalidClientError } from "./error.ts";
import { randomToken, sha256 } from "./records.ts";

type Json = any;

function idp(
	options: { issuer?: string; app?: AuthDanceOauth2AppOptions; limits?: AuthDanceOauth2AddressRateLimits } = {},
): AuthDanceOauth2 {
	const api = testCoreApi(options.issuer, { profile: { description: "Your name", claims: ["name"] } });
	return createAuthDanceOauth2({
		oauth2: {
			api,
			clients: createAuthDanceMemoryOauth2ClientStorage(),
			issuer: api.issuer,
			ui: { login: "https://login.example.com/login", consent: "https://login.example.com/consent" },
			limits: { address: options.limits },
		},
		app: options.app,
	});
}

async function get(server: AuthDanceOauth2, path: string, headers: Record<string, string> = {}): Promise<[Response, Json]> {
	const response = await server.fetch(new Request(`http://localhost${path}`, { headers }));
	const text = await response.text();
	return [response, response.headers.get("content-type")?.startsWith("application/json") ? JSON.parse(text) : text];
}

describe("AuthDanceOauth2App", () => {
	it("should serve the metadata at the root, with no-store", async () => {
		const [response, metadata] = await get(idp(), "/.well-known/oauth-authorization-server");
		deepEqual(response.status, 200);
		deepEqual(response.headers.get("cache-control"), "no-store");
		deepEqual(response.headers.get("pragma"), "no-cache");
		deepEqual(metadata.issuer, "http://localhost");
		deepEqual(metadata.authorization_endpoint, "http://localhost/authorize");
		deepEqual(metadata.jwks_uri, "http://localhost/jwks.json");
	});
	it("should keep the metadata at the root under a base path, and put the endpoints under it", async () => {
		const server = idp({ app: { basePath: "/oauth2" } });
		const [response, metadata] = await get(server, "/.well-known/oauth-authorization-server");
		deepEqual(response.status, 200);
		deepEqual([metadata.token_endpoint, metadata.jwks_uri], ["http://localhost/oauth2/token", "http://localhost/oauth2/jwks.json"]);
		deepEqual((await get(server, "/oauth2/.well-known/oauth-authorization-server"))[0].status, 404);
		deepEqual((await get(server, "/oauth2/jwks.json"))[0].status, 200);
		deepEqual((await get(server, "/jwks.json"))[0].status, 404);
	});
	// RFC 8414 §3.1: the well-known segment goes between the host and the path of the issuer.
	it("should serve the metadata of an issuer with a path after the well-known segment", async () => {
		const server = idp({ issuer: "http://localhost/tenant", app: { basePath: "/tenant" } });
		const [response, metadata] = await get(server, "/.well-known/oauth-authorization-server/tenant");
		deepEqual(response.status, 200);
		deepEqual([metadata.issuer, metadata.token_endpoint], ["http://localhost/tenant", "http://localhost/tenant/token"]);
		deepEqual((await get(server, "/.well-known/oauth-authorization-server"))[0].status, 404);
		deepEqual((await get(server, "/.well-known/oauth-authorization-server/other"))[0].status, 404);
	});
	it("should serve the public keys", async () => {
		const server = idp();
		const [response, jwks] = await get(server, "/jwks.json");
		deepEqual(response.status, 200);
		deepEqual(jwks, server.oauth2.jwks());
		ok(!("d" in jwks.keys[0]));
	});
	it("should answer an oauth2 error with its status, its code and a Basic challenge for a Basic request", async () => {
		const server = idp();
		server.app.get("/fail", () => {
			throw new InvalidClientError('wrong "secret"');
		});
		const [basic, body] = await get(server, "/fail", { authorization: "Basic Y2xpX3Rlc3Q6eA==" });
		deepEqual(basic.status, 401);
		deepEqual(body, { error: "invalid_client", error_description: "wrong secret" });
		deepEqual(basic.headers.get("www-authenticate"), 'Basic realm="oauth2"');
		deepEqual(basic.headers.get("cache-control"), "no-store");
		const [post] = await get(server, "/fail");
		deepEqual(post.status, 401);
		deepEqual(post.headers.get("www-authenticate"), null);
	});
	it("should answer any other failure with server_error and no detail", async () => {
		const server = idp();
		server.app.get("/boom", () => {
			throw new TypeError("kv is down");
		});
		const [response, body] = await get(server, "/boom");
		deepEqual(response.status, 500);
		deepEqual(body, { error: "server_error" });
	});
	it("should count every request against the per-address bucket", async () => {
		const server = idp({ limits: { request: { limit: 1, window: 60 } } });
		const headers = { "x-forwarded-for": "203.0.113.7" };
		deepEqual((await get(server, "/jwks.json", headers))[0].status, 200);
		const [response, body] = await get(server, "/.well-known/oauth-authorization-server", headers);
		deepEqual(response.status, 429);
		deepEqual(body.error, "temporarily_unavailable");
		deepEqual((await get(server, "/jwks.json", { "x-forwarded-for": "203.0.113.8" }))[0].status, 200);
	});
	it("should document both routes in the OpenAPI document", async () => {
		const { paths } = await idp({ app: { basePath: "/oauth2" } }).generateOpenAPISchema();
		ok(paths?.["/.well-known/oauth-authorization-server"]?.get);
		ok(paths?.["/oauth2/jwks.json"]?.get);
		ok(paths?.["/oauth2/grants"]?.get);
		ok(paths?.["/oauth2/grants/{id}"]?.delete);
	});
});

describe("AuthDanceOauth2App grants route", () => {
	it("should list the grants of the owner of a bearer token that holds account", async () => {
		const env = testIdp();
		const owner = await env.signUp();
		const { client } = await env.idp.oauth2.clients.createClient({
			redirect_uris: ["https://app.example.com/callback"],
			token_endpoint_auth_method: "none",
			scope: "profile",
			client_name: "Reports",
		});
		await env.issueCode(client, owner.access_token, "profile");
		const list = (authorization?: string) =>
			env.idp.fetch(new Request("http://localhost/grants", { headers: authorization ? { authorization } : {} }));

		const listed = await list(`Bearer ${owner.access_token}`);
		deepEqual([listed.status, listed.headers.get("cache-control")], [200, "no-store"]);
		const { grants } = (await listed.json()) as Json;
		deepEqual(
			grants.map((grant: Json) => [grant.client_id, grant.client.client_name, grant.scopes]),
			[[client.client_id, "Reports", ["profile"]]],
		);

		for (const authorization of [undefined, "Bearer garbage", `Basic ${btoa("a:b")}`]) {
			const refused = await list(authorization);
			deepEqual(
				[refused.status, ((await refused.json()) as Json).error, refused.headers.get("www-authenticate")],
				[401, "invalid_token", 'Bearer error="invalid_token"'],
			);
		}
		const profileOnly = await env.auth.api.refreshToken(owner.refresh_token, { scope: ["profile"] });
		const narrow = await list(`Bearer ${profileOnly.tokens.access_token}`);
		deepEqual(
			[narrow.status, ((await narrow.json()) as Json).error, narrow.headers.get("www-authenticate")],
			[403, "insufficient_scope", 'Bearer error="insufficient_scope"'],
		);

		const revoke = (id: string, authorization?: string) =>
			env.idp.fetch(new Request(`http://localhost/grants/${id}`, { method: "DELETE", headers: authorization ? { authorization } : {} }));
		deepEqual((await revoke(grants[0].id)).status, 401);
		deepEqual((await revoke(grants[0].id, `Bearer ${profileOnly.tokens.access_token}`)).status, 403);
		const revoked = await revoke(grants[0].id, `Bearer ${owner.access_token}`);
		deepEqual([revoked.status, await revoked.text()], [204, ""]);
		deepEqual(((await (await list(`Bearer ${owner.access_token}`)).json()) as Json).grants, []);
		// An id that names nothing gets the same answer.
		deepEqual((await revoke("ses_unknown", `Bearer ${owner.access_token}`)).status, 204);
	});
});

describe("AuthDanceOauth2App routes", () => {
	const REDIRECT_URI = "https://app.example.com/callback";
	let env: TestIdp;
	let browser: TestBrowser;
	let client: AuthDanceOauth2Client;
	let secret: string;
	let owner: { access_token: string; identityId: string };

	async function setup(options: Parameters<typeof testIdp>[0] = {}): Promise<void> {
		env = testIdp(options);
		browser = new TestBrowser(env.idp.fetch);
		const created = await env.idp.oauth2.clients.createClient({
			redirect_uris: [REDIRECT_URI],
			grant_types: ["authorization_code", "refresh_token", "client_credentials"],
			scope: "profile email reports",
		});
		ok(created.client_secret);
		client = created.client;
		secret = created.client_secret;
		owner = await env.signUp();
	}

	async function authorizeUrl(base = "http://localhost/authorize", target = client): Promise<{ url: string; verifier: string }> {
		const verifier = randomToken();
		const params = new URLSearchParams({
			client_id: target.client_id,
			redirect_uri: target.redirect_uris[0],
			response_type: "code",
			scope: "profile",
			state: "s-1",
			code_challenge: await sha256(verifier),
			code_challenge_method: "S256",
		});
		return { url: `${base}?${params}`, verifier };
	}

	async function tokenRequest(params: Record<string, string>, headers: Record<string, string> = {}): Promise<Response> {
		return env.idp.fetch(
			new Request("http://localhost/token", {
				method: "POST",
				headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
				body: new URLSearchParams(params),
			}),
		);
	}

	function basic(id = client.client_id, value = secret): Record<string, string> {
		return { authorization: `Basic ${btoa(`${id}:${value}`)}` };
	}

	beforeEach(async () => {
		await setup();
	});

	it("should run the code flow over HTTP, and set no cookie", async () => {
		const { url, verifier } = await authorizeUrl();
		const first = await browser.request(url);
		deepEqual([first.status, first.headers.getSetCookie()], [303, []]);
		const login = new URL(first.headers.get("location") ?? "");
		deepEqual(login.origin + login.pathname, TEST_LOGIN_PAGE);

		const answer = await env.idp.oauth2.acceptLoginRequest(login.searchParams.get("login_challenge") ?? "", {
			access_token: owner.access_token,
		});
		const consent = await browser.redirect(answer.redirect_to);
		deepEqual(consent.origin + consent.pathname, TEST_CONSENT_PAGE);
		const back = await env.idp.oauth2.acceptConsentRequest(consent.searchParams.get("consent_challenge") ?? "", {
			grant_scope: ["profile"],
		});
		const callback = await browser.redirect(back.redirect_to);
		deepEqual(callback.origin + callback.pathname, REDIRECT_URI);

		const response = await tokenRequest(
			{
				grant_type: "authorization_code",
				code: callback.searchParams.get("code") ?? "",
				code_verifier: verifier,
				redirect_uri: REDIRECT_URI,
			},
			basic(),
		);
		deepEqual(response.status, 200);
		deepEqual([response.headers.get("cache-control"), response.headers.get("pragma")], ["no-store", "no-cache"]);
		const tokens = (await response.json()) as Json;
		deepEqual([tokens.token_type, tokens.scope], ["Bearer", "profile"]);
	});
	it("should take POST /authorize with a form body, and refuse another body", async () => {
		const { url } = await authorizeUrl();
		const [, query] = url.split("?");
		const form = await browser.request("http://localhost/authorize", {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: query,
		});
		deepEqual(form.status, 303);
		ok(form.headers.get("location")?.startsWith(TEST_LOGIN_PAGE));
		const json = await browser.request("http://localhost/authorize", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(Object.fromEntries(new URLSearchParams(query))),
		});
		deepEqual(json.status, 400);
		ok(json.headers.get("content-type")?.startsWith("text/html"));
	});
	it("should serve the authorization endpoint under a base path", async () => {
		await setup({ app: { basePath: "/oauth2" } });
		const { url } = await authorizeUrl("http://localhost/oauth2/authorize");
		const response = await browser.request(url);
		deepEqual(response.status, 303);
		ok(response.headers.get("location")?.startsWith(TEST_LOGIN_PAGE));
	});
	it("should show an HTML page that no frame can hold for an error it cannot send to the client", async () => {
		const response = await browser.request("http://localhost/authorize?client_id=cli_missing&response_type=code");
		deepEqual(response.status, 400);
		deepEqual(response.headers.get("x-frame-options"), "DENY");
		ok(response.headers.get("content-security-policy")?.includes("frame-ancestors 'none'"));
		deepEqual(response.headers.get("cache-control"), "no-store");
		const html = await response.text();
		ok(html.includes("invalid_request") && html.includes("client_id names no client"));
	});
	it("should answer token errors in the RFC 6749 format", async () => {
		const json = await env.idp.fetch(
			new Request("http://localhost/token", {
				method: "POST",
				headers: { "content-type": "application/json", ...basic() },
				body: JSON.stringify({ grant_type: "client_credentials" }),
			}),
		);
		deepEqual([json.status, ((await json.json()) as Json).error], [400, "invalid_request"]);
		const wrong = await tokenRequest({ grant_type: "client_credentials" }, basic(client.client_id, "wrong"));
		deepEqual([wrong.status, ((await wrong.json()) as Json).error], [401, "invalid_client"]);
		deepEqual(wrong.headers.get("www-authenticate"), 'Basic realm="oauth2"');
		deepEqual(wrong.headers.get("cache-control"), "no-store");
		const password = await tokenRequest({ grant_type: "password", username: "a", password: "b" }, basic());
		deepEqual([password.status, ((await password.json()) as Json).error], [400, "unsupported_grant_type"]);
	});
	it("should let a public client read the token response from the origin of its redirect URI", async () => {
		const { client: spa } = await env.idp.oauth2.clients.createClient({
			redirect_uris: ["https://spa.example.com/callback"],
			token_endpoint_auth_method: "none",
			scope: "profile",
		});
		const params = { grant_type: "authorization_code", code: randomToken(), code_verifier: randomToken(), client_id: spa.client_id };
		const own = await tokenRequest(params, { origin: "https://spa.example.com" });
		deepEqual(own.status, 400);
		deepEqual([own.headers.get("access-control-allow-origin"), own.headers.get("vary")], ["https://spa.example.com", "Origin"]);
		const evil = await tokenRequest(params, { origin: "https://evil.example.com" });
		deepEqual(evil.headers.get("access-control-allow-origin"), null);
		const confidential = await tokenRequest(
			{ grant_type: "client_credentials", client_id: client.client_id, client_secret: "x" },
			{ origin: "https://app.example.com" },
		);
		deepEqual(confidential.headers.get("access-control-allow-origin"), null);
	});
	it("should count the token requests and the secret checks of an address", async () => {
		await setup({ oauth2: { limits: { address: { token: { limit: 2, window: 60 }, client_auth: { limit: 1, window: 60 } } } } });
		deepEqual((await tokenRequest({ grant_type: "client_credentials" }, basic())).status, 200);
		// The right secret, past the secret bucket.
		deepEqual((await tokenRequest({ grant_type: "client_credentials" }, basic())).status, 429);
		deepEqual((await tokenRequest({ grant_type: "client_credentials", client_id: client.client_id })).status, 429);
	});

	describe("admin routes", () => {
		beforeEach(async () => {
			await setup({ app: { admin: { authorize: (c) => c.req.header("x-admin") === "yes" } } });
		});

		async function admin(method: string, path: string, body?: unknown, allowed = true): Promise<Response> {
			return env.idp.fetch(
				new Request(`http://localhost${path}`, {
					method,
					headers: { "content-type": "application/json", ...(allowed ? { "x-admin": "yes" } : {}) },
					body: body === undefined ? undefined : JSON.stringify(body),
				}),
			);
		}

		it("should run the login and the consent of a request", async () => {
			const { url } = await authorizeUrl();
			const login = await browser.redirect(url);
			const challenge = login.searchParams.get("login_challenge") ?? "";
			const read = (await (await admin("GET", `/admin/login?login_challenge=${challenge}`)).json()) as Json;
			deepEqual([read.challenge, read.requested_scope, read.client.client_id], [challenge, ["profile"], client.client_id]);
			const accepted = (await (
				await admin("PUT", `/admin/login/accept?login_challenge=${challenge}`, { access_token: owner.access_token })
			).json()) as Json;
			const consent = await browser.redirect(accepted.redirect_to);
			const consentChallenge = consent.searchParams.get("consent_challenge") ?? "";
			deepEqual(
				((await (await admin("GET", `/admin/consent?consent_challenge=${consentChallenge}`)).json()) as Json).subject,
				owner.identityId,
			);
			const granted = (await (
				await admin("PUT", `/admin/consent/accept?consent_challenge=${consentChallenge}`, { grant_scope: ["profile"] })
			).json()) as Json;
			ok((await browser.redirect(granted.redirect_to)).searchParams.has("code"));
		});
		it("should reject a login over the admin routes", async () => {
			const { url } = await authorizeUrl();
			const challenge = (await browser.redirect(url)).searchParams.get("login_challenge") ?? "";
			const rejected = (await (
				await admin("PUT", `/admin/login/reject?login_challenge=${challenge}`, { error: "access_denied" })
			).json()) as Json;
			deepEqual((await browser.redirect(rejected.redirect_to)).searchParams.get("error"), "access_denied");
		});
		it("should refuse a request that authorize refuses, a missing challenge, and a body that is not valid", async () => {
			const refused = await admin("GET", `/admin/login?login_challenge=${randomToken()}`, undefined, false);
			deepEqual([refused.status, ((await refused.json()) as Json).error], [403, "access_denied"]);
			deepEqual((await admin("GET", "/admin/login")).status, 400);
			const { url } = await authorizeUrl();
			const challenge = (await browser.redirect(url)).searchParams.get("login_challenge") ?? "";
			deepEqual((await admin("PUT", `/admin/login/accept?login_challenge=${challenge}`, { access_token: 42 })).status, 400);
			deepEqual((await admin("PUT", `/admin/consent/accept?consent_challenge=${challenge}`, { grant_scope: ["profile"] })).status, 400);
		});
		it("should document the routes in the OpenAPI document", async () => {
			const { paths } = await env.idp.generateOpenAPISchema();
			ok(paths?.["/authorize"]?.get && paths["/authorize"].post && paths["/token"]?.post);
			ok(paths?.["/admin/login"]?.get && paths["/admin/login/accept"]?.put && paths["/admin/consent/reject"]?.put);
		});
	});
});

describe("AuthDanceOauth2App introspection route", () => {
	let env: TestIdp;
	let client: AuthDanceOauth2Client;
	let secret: string;
	let token: string;

	async function post(path: string, params: Record<string, string>, headers: Record<string, string> = {}): Promise<Response> {
		return env.idp.fetch(
			new Request(`http://localhost${path}`, {
				method: "POST",
				headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
				body: new URLSearchParams(params),
			}),
		);
	}

	beforeEach(async () => {
		env = testIdp({ oauth2: { limits: { address: { introspect: { limit: 3, window: 60 } } } } });
		const created = await env.idp.oauth2.clients.createClient({ grant_types: ["client_credentials"], scope: "reports" });
		ok(created.client_secret);
		client = created.client;
		secret = created.client_secret;
		const response = await post(
			"/token",
			{ grant_type: "client_credentials" },
			{ authorization: `Basic ${btoa(`${client.client_id}:${secret}`)}` },
		);
		token = ((await response.json()) as Json).access_token;
	});

	it("should describe a token to an authenticated client, with no-store", async () => {
		const response = await post("/introspect", { token }, { authorization: `Basic ${btoa(`${client.client_id}:${secret}`)}` });
		deepEqual(response.status, 200);
		deepEqual(response.headers.get("cache-control"), "no-store");
		const body = (await response.json()) as Json;
		deepEqual([body.active, body.token_type, body.client_id], [true, "Bearer", client.client_id]);
	});
	it("should answer RFC 6749 errors for a missing token and a client that does not authenticate", async () => {
		await env.idp.oauth2.clients.updateClient({ ...client, token_endpoint_auth_method: "client_secret_post" });
		const missing = await post("/introspect", { client_id: client.client_id, client_secret: secret });
		deepEqual([missing.status, ((await missing.json()) as Json).error], [400, "invalid_request"]);
		const wrong = await post("/introspect", { token, client_id: client.client_id, client_secret: "wrong" });
		deepEqual([wrong.status, ((await wrong.json()) as Json).error], [401, "invalid_client"]);
		const anonymous = await post("/introspect", { token });
		deepEqual(anonymous.status, 401);
	});
	it("should count the introspections of an address", async () => {
		await env.idp.oauth2.clients.updateClient({ ...client, token_endpoint_auth_method: "client_secret_post" });
		const params = { token, client_id: client.client_id, client_secret: secret };
		for (let i = 0; i < 3; i++) {
			deepEqual((await post("/introspect", params, { "x-forwarded-for": "203.0.113.9" })).status, 200);
		}
		deepEqual((await post("/introspect", params, { "x-forwarded-for": "203.0.113.9" })).status, 429);
	});
	it("should announce the endpoint in the metadata", async () => {
		const metadata = (await (await env.idp.fetch(new Request("http://localhost/.well-known/oauth-authorization-server"))).json()) as Json;
		deepEqual(
			[metadata.introspection_endpoint, metadata.introspection_endpoint_auth_methods_supported],
			["http://localhost/introspect", ["client_secret_basic", "client_secret_post"]],
		);
	});
});

describe("AuthDanceOauth2App revocation route", () => {
	let env: TestIdp;
	let client: AuthDanceOauth2Client;
	let secret: string;
	let spa: AuthDanceOauth2Client;

	async function send(
		method: string,
		path: string,
		params?: Record<string, string>,
		headers: Record<string, string> = {},
	): Promise<Response> {
		return env.idp.fetch(
			new Request(`http://localhost${path}`, {
				method,
				headers: params === undefined ? headers : { "content-type": "application/x-www-form-urlencoded", ...headers },
				body: params === undefined ? undefined : new URLSearchParams(params),
			}),
		);
	}

	function basic(): Record<string, string> {
		return { authorization: `Basic ${btoa(`${client.client_id}:${secret}`)}` };
	}

	beforeEach(async () => {
		env = testIdp();
		const created = await env.idp.oauth2.clients.createClient({ grant_types: ["client_credentials"], scope: "reports" });
		ok(created.client_secret);
		client = created.client;
		secret = created.client_secret;
		({ client: spa } = await env.idp.oauth2.clients.createClient({
			redirect_uris: ["https://spa.example.com/callback"],
			token_endpoint_auth_method: "none",
			scope: "profile",
		}));
	});

	it("should revoke a token and answer 200 with an empty body", async () => {
		client = { ...client, redirect_uris: ["https://app.example.com/callback"], grant_types: ["authorization_code", "client_credentials"] };
		await env.idp.oauth2.clients.updateClient({ ...client, scope: "profile reports" });
		const owner = await env.signUp();
		const { code, verifier } = await env.issueCode(client, owner.access_token, "profile");
		const issued = await send(
			"POST",
			"/token",
			{ grant_type: "authorization_code", code, code_verifier: verifier, redirect_uri: "https://app.example.com/callback" },
			basic(),
		);
		const token = ((await issued.json()) as Json).access_token;
		const response = await send("POST", "/revoke", { token, token_type_hint: "access_token" }, basic());
		deepEqual([response.status, await response.text()], [200, ""]);
		deepEqual((await env.idp.oauth2.introspect(client, token)).active, false);
		// A token that is not valid gets the same answer, and so does a token of client credentials, which has no session.
		deepEqual((await send("POST", "/revoke", { token: "garbage" }, basic())).status, 200);
		const machine = ((await (await send("POST", "/token", { grant_type: "client_credentials" }, basic())).json()) as Json).access_token;
		deepEqual((await send("POST", "/revoke", { token: machine }, basic())).status, 200);
		deepEqual((await env.idp.oauth2.introspect(client, machine)).active, true);
	});
	it("should answer RFC 6749 errors for a missing token and a client that does not authenticate", async () => {
		const missing = await send("POST", "/revoke", {}, basic());
		deepEqual([missing.status, ((await missing.json()) as Json).error], [400, "invalid_request"]);
		const wrong = await send("POST", "/revoke", { token: "x" }, { authorization: `Basic ${btoa(`${client.client_id}:wrong`)}` });
		deepEqual([wrong.status, wrong.headers.get("www-authenticate")], [401, 'Basic realm="oauth2"']);
	});
	it("should let a public client revoke from the origin of its redirect URI", async () => {
		const response = await send("POST", "/revoke", { token: "x", client_id: spa.client_id }, { origin: "https://spa.example.com" });
		deepEqual([response.status, response.headers.get("access-control-allow-origin")], [200, "https://spa.example.com"]);
		const evil = await send("POST", "/revoke", { token: "x", client_id: spa.client_id }, { origin: "https://evil.example.com" });
		deepEqual(evil.headers.get("access-control-allow-origin"), null);
	});
	it("should answer the CORS preflight of /token and /revoke for the origin of a public client only", async () => {
		for (const path of ["/token", "/revoke"]) {
			const allowed = await send("OPTIONS", path, undefined, {
				origin: "https://spa.example.com",
				"access-control-request-method": "POST",
			});
			deepEqual(allowed.status, 204);
			deepEqual(
				[allowed.headers.get("access-control-allow-origin"), allowed.headers.get("access-control-allow-methods")],
				["https://spa.example.com", "POST"],
			);
			const refused = await send("OPTIONS", path, undefined, {
				origin: "https://evil.example.com",
				"access-control-request-method": "POST",
			});
			deepEqual([refused.status, refused.headers.get("access-control-allow-origin")], [204, null]);
		}
	});
	it("should find the origin of a public client past the first page of clients", async () => {
		for (let i = 0; i < 105; i++) {
			await env.idp.oauth2.clients.createClient({ grant_types: ["client_credentials"], scope: "reports" });
		}
		const late = await env.idp.oauth2.clients.createClient({
			redirect_uris: ["https://late.example.com/callback"],
			token_endpoint_auth_method: "none",
			scope: "profile",
		});
		// The highest id, so the client sits on the second page.
		await env.idp.oauth2.clients.updateClient({ ...late.client, client_id: "cli_zzz" });
		await env.idp.oauth2.clients.deleteClient(late.client.client_id);
		deepEqual((await env.idp.oauth2.clients.listClients()).at(-1)?.client_id, "cli_zzz");
		const response = await send("OPTIONS", "/revoke", undefined, { origin: "https://late.example.com" });
		deepEqual(response.headers.get("access-control-allow-origin"), "https://late.example.com");
	});
	it("should announce the endpoint in the metadata", async () => {
		const metadata = (await (await send("GET", "/.well-known/oauth-authorization-server")).json()) as Json;
		deepEqual(
			[metadata.revocation_endpoint, metadata.revocation_endpoint_auth_methods_supported],
			["http://localhost/revoke", ["client_secret_basic", "client_secret_post", "none"]],
		);
	});
});

describe("AuthDanceOauth2App registration route", () => {
	async function register(env: TestIdp, body: unknown, headers: Record<string, string> = {}): Promise<Response> {
		return env.idp.fetch(
			new Request("http://localhost/register", {
				method: "POST",
				headers: { "content-type": "application/json", ...headers },
				body: typeof body === "string" ? body : JSON.stringify(body),
			}),
		);
	}

	const body = { redirect_uris: ["https://app.example.com/callback"], client_name: "App" };

	it("should answer 404 while registration is closed", async () => {
		const env = testIdp();
		deepEqual((await register(env, body)).status, 404);
		const metadata = (await (await env.idp.fetch(new Request("http://localhost/.well-known/oauth-authorization-server"))).json()) as Json;
		ok(!("registration_endpoint" in metadata));
	});
	it("should register a client with 201 and no-store when registration is open", async () => {
		const env = testIdp({ oauth2: { registration: {} } });
		const response = await register(env, body);
		deepEqual([response.status, response.headers.get("cache-control")], [201, "no-store"]);
		const answer = (await response.json()) as Json;
		ok(answer.client_id && answer.client_secret);
		const metadata = (await (await env.idp.fetch(new Request("http://localhost/.well-known/oauth-authorization-server"))).json()) as Json;
		deepEqual(metadata.registration_endpoint, "http://localhost/register");
	});
	it("should check the initial access token", async () => {
		const env = testIdp({ oauth2: { registration: { authorize: (token) => token === "letmein" } } });
		const attempts: Record<string, string>[] = [{}, { authorization: "Bearer wrong" }, { authorization: "Basic bGV0bWVpbg==" }];
		for (const headers of attempts) {
			const refused = await register(env, body, headers);
			deepEqual([refused.status, ((await refused.json()) as Json).error], [401, "invalid_token"]);
			deepEqual(refused.headers.get("www-authenticate"), 'Bearer error="invalid_token"');
		}
		deepEqual((await register(env, body, { authorization: "Bearer letmein" })).status, 201);
	});
	it("should answer the RFC 7591 errors", async () => {
		const env = testIdp({ oauth2: { registration: {} } });
		const cases: [unknown, string][] = [
			["not json", "invalid_client_metadata"],
			[{ ...body, grant_types: ["password"] }, "invalid_client_metadata"],
			[{ redirect_uris: ["http://app.example.com/callback"] }, "invalid_redirect_uri"],
			[{ ...body, software_statement: "eyJ..." }, "unapproved_software_statement"],
		];
		for (const [request, error] of cases) {
			const response = await register(env, request);
			deepEqual([response.status, ((await response.json()) as Json).error], [400, error], JSON.stringify(request));
		}
		const form = await env.idp.fetch(
			new Request("http://localhost/register", {
				method: "POST",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				body: "client_name=App",
			}),
		);
		deepEqual(((await form.json()) as Json).error, "invalid_client_metadata");
	});
	it("should count the registrations of an address", async () => {
		const env = testIdp({ oauth2: { registration: {}, limits: { address: { register: { limit: 2, window: 3600 } } } } });
		deepEqual((await register(env, body)).status, 201);
		deepEqual((await register(env, "not json")).status, 400);
		deepEqual((await register(env, body)).status, 429);
	});
});

describe("AuthDanceOauth2App device routes", () => {
	const DEVICE_PAGE = "https://login.example.com/device";
	const ui = { login: TEST_LOGIN_PAGE, consent: TEST_CONSENT_PAGE, device: DEVICE_PAGE };

	async function startDevice(env: TestIdp, client_id: string): Promise<Response> {
		return env.idp.fetch(
			new Request("http://localhost/device_authorization", {
				method: "POST",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({ client_id, scope: "profile" }),
			}),
		);
	}

	async function deviceClient(env: TestIdp): Promise<string> {
		const { client } = await env.idp.oauth2.clients.createClient({
			token_endpoint_auth_method: "none",
			grant_types: ["urn:ietf:params:oauth:grant-type:device_code"],
			scope: "profile",
		});
		return client.client_id;
	}

	it("should answer 404 while ui.device does not open the grant", async () => {
		const env = testIdp();
		deepEqual((await startDevice(env, await deviceClient(env))).status, 404);
		deepEqual((await env.idp.fetch(new Request("http://localhost/device"))).status, 404);
		const metadata = (await (await env.idp.fetch(new Request("http://localhost/.well-known/oauth-authorization-server"))).json()) as Json;
		ok(!("device_authorization_endpoint" in metadata));
	});
	it("should start a device authorization, and send the verification URI to the device page", async () => {
		const env = testIdp({ oauth2: { ui }, app: { admin: { authorize: () => true } } });
		const response = await startDevice(env, await deviceClient(env));
		deepEqual([response.status, response.headers.get("cache-control")], [200, "no-store"]);
		const answer = (await response.json()) as Json;
		deepEqual(answer.verification_uri, "http://localhost/device");
		const browser = new TestBrowser(env.idp.fetch);
		const page = await browser.redirect(answer.verification_uri_complete);
		deepEqual(page.origin + page.pathname, DEVICE_PAGE);
		const challenge = page.searchParams.get("device_challenge") ?? "";
		const read = (await (await env.idp.fetch(new Request(`http://localhost/admin/device?device_challenge=${challenge}`))).json()) as Json;
		deepEqual(read.user_code, answer.user_code);
		const accepted = await env.idp.fetch(
			new Request(`http://localhost/admin/device/accept?device_challenge=${challenge}`, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ user_code: answer.user_code }),
			}),
		);
		const login = await browser.redirect(((await accepted.json()) as Json).redirect_to);
		deepEqual(login.origin + login.pathname, TEST_LOGIN_PAGE);
	});
	it("should answer the device errors at the token endpoint with 400", async () => {
		const env = testIdp({ oauth2: { ui } });
		const client_id = await deviceClient(env);
		const { device_code } = (await (await startDevice(env, client_id)).json()) as Json;
		const poll = () =>
			env.idp.fetch(
				new Request("http://localhost/token", {
					method: "POST",
					headers: { "content-type": "application/x-www-form-urlencoded" },
					body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code, client_id }),
				}),
			);
		for (const error of ["authorization_pending", "slow_down"]) {
			const response = await poll();
			deepEqual([response.status, ((await response.json()) as Json).error], [400, error]);
		}
	});
	it("should count the visits of an address to the verification URI", async () => {
		const env = testIdp({ oauth2: { ui, limits: { address: { device: { limit: 2, window: 60 } } } } });
		deepEqual((await env.idp.fetch(new Request("http://localhost/device"))).status, 303);
		deepEqual((await env.idp.fetch(new Request("http://localhost/device"))).status, 303);
		deepEqual((await env.idp.fetch(new Request("http://localhost/device"))).status, 429);
	});
	it("should document the device routes in the OpenAPI document", async () => {
		const { paths } = await testIdp({ oauth2: { ui }, app: { admin: { authorize: () => true } } }).idp.generateOpenAPISchema();
		ok(paths?.["/device_authorization"]?.post && paths["/device"]?.get);
		ok(paths?.["/admin/device"]?.get && paths["/admin/device/accept"]?.put);
	});
});
