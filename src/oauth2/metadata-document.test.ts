import { deepEqual, equal, ok, rejects, throws } from "node:assert";
import { afterEach, beforeEach, describe, it, vi } from "vitest";
import { TEST_ISSUER, TestBrowser, type TestIdp, testIdp } from "../fixtures.test.ts";
import type { AuthDanceOauth2ApiOptions } from "./api.ts";
import type { AuthDanceOauth2Client } from "./client.ts";
import { InvalidClientError, InvalidRequestError, TemporarilyUnavailableError } from "./error.ts";
import {
	type AuthDanceOauth2ClientIdMetadataDocumentOptions,
	cacheLifetime,
	checkClientIdUrl,
	fetchClientIdMetadataDocument,
	isSpecialUseHost,
	parseClientIdMetadataDocument,
} from "./metadata-document.ts";
import { randomToken, sha256 } from "./records.ts";

const CLIENT = "https://client.example.com/oauth/client.json";
const LOOPBACK = "http://127.0.0.1:3000/callback";
const WEB = "https://client.example.com/callback";

// The example document of MCP 2025-11-25, with a scope and a redirect URI on the host of the client id.
const DOCUMENT = {
	client_id: CLIENT,
	client_name: "Example MCP Client",
	client_uri: "https://example.com",
	logo_uri: "https://client.example.com/logo.png",
	redirect_uris: [LOOPBACK, WEB],
	grant_types: ["authorization_code", "refresh_token"],
	response_types: ["code"],
	token_endpoint_auth_method: "none",
	scope: "profile email",
};

function json(body: unknown, headers: Record<string, string> = {}, status = 200): Response {
	return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}

// The body of a JSON answer of the server.
async function read(response: Response): Promise<Record<string, unknown>> {
	return (await response.json()) as Record<string, unknown>;
}

const PARSE = { scope: ["profile", "email"], device: false, fetchedAt: 1_700_000_000 };

describe("checkClientIdUrl", () => {
	it("should accept an https URL with a path, a port and a query", () => {
		for (const url of [CLIENT, "https://client.example.com:8443/client", "https://client.example.com/client?v=1"]) {
			equal(checkClientIdUrl(url, TEST_ISSUER).href, url);
		}
	});
	it("should refuse what draft §3 forbids, and any form the server would have to normalize", () => {
		for (const url of [
			"http://client.example.com/client",
			"HTTPS://client.example.com/client",
			"https://user:pass@client.example.com/client",
			"https://client.example.com/client#top",
			"https://client.example.com/",
			"https://client.example.com",
			"https://client.example.com/a/../client",
			"https://client.example.com/a/./client",
			"https://client.example.com/a/%2e%2e/client",
			"https://client.example.com:443/client",
			"https://Client.Example.com/client",
			`https://client.example.com/${"a".repeat(2048)}`,
			"cli_123",
		]) {
			throws(
				() => checkClientIdUrl(url, TEST_ISSUER),
				(error) => error instanceof InvalidClientError && !error.description?.includes(url),
				url,
			);
		}
	});
	it("should refuse the origin of the issuer, draft §10.1", () => {
		throws(() => checkClientIdUrl("https://auth.example.com/client", "https://auth.example.com"), InvalidClientError);
	});
	it("should refuse a special-use address and a local name, draft §10.7", () => {
		for (const host of [
			"127.0.0.1",
			"10.1.2.3",
			"172.16.0.1",
			"192.168.1.1",
			"169.254.169.254",
			"100.64.0.1",
			"0.0.0.0",
			"[::1]",
			"[::]",
			"[::ffff:127.0.0.1]",
			"[fe80::1]",
			"[fc00::1]",
			"[2001:db8::1]",
			"localhost",
			"api.localhost",
			"intranet",
			"printer.local",
			"db.internal",
			"router.home.arpa",
		]) {
			throws(() => checkClientIdUrl(`https://${host}/client`, TEST_ISSUER), InvalidClientError, host);
		}
	});
});

describe("isSpecialUseHost", () => {
	it("should let a public address and a public name pass", () => {
		for (const host of ["93.184.216.34", "[2606:4700::1111]", "client.example.com"]) {
			equal(isSpecialUseHost(host), false, host);
		}
	});
});

describe("cacheLifetime", () => {
	const lifetime = (headers: Record<string, string>) => cacheLifetime(new Headers(headers), 300, 86400);

	it("should read s-maxage before max-age, and take Age off", () => {
		equal(lifetime({ "cache-control": "public, max-age=3600" }), 3600);
		equal(lifetime({ "cache-control": "max-age=3600, s-maxage=7200" }), 7200);
		equal(lifetime({ "cache-control": "max-age=3600", age: "600" }), 3000);
	});
	it("should clamp to the bounds, and give the minimum to no-store and to no lifetime", () => {
		equal(lifetime({ "cache-control": "max-age=10" }), 300);
		equal(lifetime({ "cache-control": "max-age=999999" }), 86400);
		equal(lifetime({ "cache-control": "no-store" }), 300);
		equal(lifetime({ "cache-control": "no-cache, max-age=3600" }), 300);
		equal(lifetime({ expires: "Wed, 01 Jan 2031 00:00:00 GMT" }), 300);
		equal(lifetime({}), 300);
	});
});

describe("parseClientIdMetadataDocument", () => {
	const refused = (body: unknown) => throws(() => parseClientIdMetadataDocument(body, CLIENT, PARSE), InvalidClientError);

	it("should read the MCP example as a public client", () => {
		const client = parseClientIdMetadataDocument(DOCUMENT, CLIENT, PARSE);
		deepEqual(
			[client.client_id, client.token_endpoint_auth_method, client.grant_types, client.redirect_uris, client.scope],
			[CLIENT, "none", ["authorization_code", "refresh_token"], [LOOPBACK, WEB], "profile email"],
		);
		deepEqual([client.client_id_issued_at, client.registered_by, client.client_secret_hash], [1_700_000_000, undefined, undefined]);
	});
	it("should refuse a client_id that is not the URL, character for character", () => {
		refused({ ...DOCUMENT, client_id: `${CLIENT}/` });
		refused({ ...DOCUMENT, client_id: "https://client.example.com:443/oauth/client.json" });
		refused({ ...DOCUMENT, client_id: undefined });
	});
	it("should refuse a secret and every method based on a shared secret, draft §4.1", () => {
		refused({ ...DOCUMENT, client_secret: "s" });
		refused({ ...DOCUMENT, client_secret_expires_at: 0 });
		refused({ ...DOCUMENT, token_endpoint_auth_method: "client_secret_basic" });
		refused({ ...DOCUMENT, token_endpoint_auth_method: undefined, token_endpoint_auth_methods_supported: ["none", "client_secret_jwt"] });
	});
	it("should pick none from token_endpoint_auth_methods_supported, and assume it when both are absent, draft §5", () => {
		const { token_endpoint_auth_method: _method, ...bare } = DOCUMENT;
		equal(parseClientIdMetadataDocument(bare, CLIENT, PARSE).token_endpoint_auth_method, "none");
		const keyed = {
			...bare,
			token_endpoint_auth_methods_supported: ["private_key_jwt", "none"],
			jwks_uri: "https://client.example.com/jwks",
		};
		equal(parseClientIdMetadataDocument(keyed, CLIENT, PARSE).token_endpoint_auth_method, "none");
		refused({ ...bare, token_endpoint_auth_methods_supported: ["private_key_jwt"], jwks_uri: "https://client.example.com/jwks" });
		refused({ ...DOCUMENT, token_endpoint_auth_methods_supported: ["private_key_jwt"] });
		refused({ ...keyed, jwks: { keys: [] } });
	});
	it("should narrow grant_types to what the server supports, and refuse an empty result, draft §6", () => {
		const client = parseClientIdMetadataDocument(
			{ ...DOCUMENT, grant_types: ["authorization_code", "client_credentials", "implicit"] },
			CLIENT,
			PARSE,
		);
		deepEqual(client.grant_types, ["authorization_code"]);
		refused({ ...DOCUMENT, grant_types: ["client_credentials"] });
		refused({ ...DOCUMENT, grant_types: ["refresh_token"] });
		refused({ ...DOCUMENT, response_types: ["token"] });
		const device = {
			...DOCUMENT,
			grant_types: ["urn:ietf:params:oauth:grant-type:device_code"],
			response_types: [],
			redirect_uris: undefined,
		};
		refused(device);
		deepEqual(parseClientIdMetadataDocument(device, CLIENT, { ...PARSE, device: true }).response_types, []);
	});
	it("should narrow scope to the ceiling, and default to it", () => {
		equal(parseClientIdMetadataDocument({ ...DOCUMENT, scope: "profile reports account" }, CLIENT, PARSE).scope, "profile");
		equal(parseClientIdMetadataDocument({ ...DOCUMENT, scope: undefined }, CLIENT, PARSE).scope, "profile email");
	});
	it("should require redirect_uris with authorization_code, and check each one", () => {
		refused({ ...DOCUMENT, redirect_uris: undefined });
		refused({ ...DOCUMENT, redirect_uris: ["http://evil.example.com/callback"] });
		refused({ ...DOCUMENT, redirect_uris: ["javascript:alert(1)"] });
	});
	it("should ignore a software statement, and never put a value of the document in the description", () => {
		ok(parseClientIdMetadataDocument({ ...DOCUMENT, software_statement: "eyJ" }, CLIENT, PARSE));
		throws(
			() => parseClientIdMetadataDocument({ ...DOCUMENT, client_uri: "http://<script>/" }, CLIENT, PARSE),
			(error) => error instanceof InvalidClientError && !error.description?.includes("<script>"),
		);
	});
	it("should refuse a body that is not an object", () => {
		for (const body of [null, [], "x", 1]) {
			refused(body);
		}
	});
});

describe("fetchClientIdMetadataDocument", () => {
	const url = new URL(CLIENT);
	const options = (fetch: (request: Request) => Promise<Response>) => ({ fetch, timeout: 5, max_size: 5120 });

	it("should send a GET with Accept: application/json and no redirect, and parse the body", async () => {
		let sent: Request | undefined;
		const { body } = await fetchClientIdMetadataDocument(
			url,
			options(async (request) => {
				sent = request;
				return json(DOCUMENT);
			}),
		);
		deepEqual(body, DOCUMENT);
		deepEqual([sent?.method, sent?.url, sent?.headers.get("accept"), sent?.redirect], ["GET", CLIENT, "application/json", "manual"]);
		equal(sent?.headers.get("cookie"), null);
	});
	it("should refuse a redirect, without following it, draft §6", async () => {
		let calls = 0;
		await rejects(
			fetchClientIdMetadataDocument(
				url,
				options(async () => {
					calls++;
					return new Response(null, { status: 302, headers: { location: "https://169.254.169.254/latest" } });
				}),
			),
			InvalidClientError,
		);
		equal(calls, 1);
	});
	it("should refuse a document over max_size, with or without Content-Length, draft §10.11", async () => {
		const big = { ...DOCUMENT, client_name: "x".repeat(6000) };
		await rejects(
			fetchClientIdMetadataDocument(
				url,
				options(async () => json(big)),
			),
			InvalidClientError,
		);
		const stream = new ReadableStream<Uint8Array>({
			pull(controller) {
				controller.enqueue(new Uint8Array(1024).fill(32));
			},
		});
		await rejects(
			fetchClientIdMetadataDocument(
				url,
				options(async () => new Response(stream, { headers: { "content-type": "application/json" } })),
			),
			InvalidClientError,
		);
	});
	it("should end a fetch that takes longer than timeout as a transient failure", async () => {
		const hang = (request: Request) =>
			new Promise<Response>((_, reject) => request.signal.addEventListener("abort", () => reject(request.signal.reason)));
		await rejects(fetchClientIdMetadataDocument(url, { fetch: hang, timeout: 0.05, max_size: 5120 }), TemporarilyUnavailableError);
	});
	it("should call a 5xx, a 429 and a network error transient, and a 404 terminal", async () => {
		await rejects(
			fetchClientIdMetadataDocument(
				url,
				options(async () => json({}, {}, 503)),
			),
			TemporarilyUnavailableError,
		);
		await rejects(
			fetchClientIdMetadataDocument(
				url,
				options(async () => json({}, {}, 429)),
			),
			TemporarilyUnavailableError,
		);
		await rejects(
			fetchClientIdMetadataDocument(
				url,
				options(() => Promise.reject(new TypeError("fetch failed"))),
			),
			TemporarilyUnavailableError,
		);
		await rejects(
			fetchClientIdMetadataDocument(
				url,
				options(async () => json({}, {}, 404)),
			),
			InvalidClientError,
		);
	});
	it("should refuse a body that is not JSON, or not served as JSON, and quote none of it", async () => {
		await rejects(
			fetchClientIdMetadataDocument(
				url,
				options(async () => new Response("<html>secret</html>", { headers: { "content-type": "text/html" } })),
			),
			(error) => error instanceof InvalidClientError && !String(error.description).includes("secret"),
		);
		await rejects(
			fetchClientIdMetadataDocument(
				url,
				options(async () => new Response("{secret", { headers: { "content-type": "application/json" } })),
			),
			(error) => error instanceof InvalidClientError && !String(error.description).includes("secret") && error.cause === undefined,
		);
		const { body } = await fetchClientIdMetadataDocument(
			url,
			options(async () => new Response(JSON.stringify(DOCUMENT), { headers: { "content-type": "application/client-metadata+json" } })),
		);
		deepEqual(body, DOCUMENT);
	});
});

// The server, with a stub of the network: each URL answers what `documents` holds for it.
describe("client id metadata documents", () => {
	let env: TestIdp;
	let documents: Map<string, () => Response | Promise<Response>>;
	let fetched: string[];
	let owner: { access_token: string; refresh_token: string; identityId: string };

	const network = async (request: Request): Promise<Response> => {
		fetched.push(request.url);
		const answer = documents.get(request.url);
		return answer ? answer() : new Response("not found", { status: 404 });
	};

	async function setup(
		document: false | Partial<AuthDanceOauth2ClientIdMetadataDocumentOptions> = {},
		options: Partial<AuthDanceOauth2ApiOptions> = {},
	): Promise<void> {
		fetched = [];
		documents = new Map([[CLIENT, () => json(DOCUMENT, { "cache-control": "max-age=600" })]]);
		env = testIdp({
			oauth2: {
				client_id_metadata_document: document === false ? false : { fetch: network, scope: ["profile", "email"], ...document },
				registration: { scope: ["profile"] },
				...options,
			},
		});
		owner = await env.signUp();
	}

	beforeEach(async () => {
		await setup();
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	async function authorizeParams(redirectUri = LOOPBACK, scope = "profile", clientId = CLIENT) {
		const verifier = randomToken();
		const params: [string, string][] = [
			["client_id", clientId],
			["redirect_uri", redirectUri],
			["response_type", "code"],
			["scope", scope],
			["state", "s1"],
			["code_challenge", await sha256(verifier)],
			["code_challenge_method", "S256"],
		];
		return { params, verifier };
	}

	async function step(params: [string, string][]): Promise<URL> {
		return new URL((await env.idp.oauth2.authorize({ params, endpoint: `${TEST_ISSUER}/authorize` })).location);
	}

	async function tokenRequest(params: Record<string, string>, headers: Record<string, string> = {}): Promise<Response> {
		return await env.idp.fetch(
			new Request(`${TEST_ISSUER}/token`, {
				method: "POST",
				headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
				body: new URLSearchParams(params),
			}),
		);
	}

	// Runs the flow up to the code, and returns the code, its verifier and what the consent page read.
	async function issueCode(redirectUri = LOOPBACK) {
		const { params, verifier } = await authorizeParams(redirectUri);
		const login = await step(params);
		const loginChallenge = login.searchParams.get("login_challenge") ?? "";
		const loginRequest = await env.idp.oauth2.getLoginRequest(loginChallenge);
		const back = await env.idp.oauth2.acceptLoginRequest(loginChallenge, { access_token: owner.access_token });
		const consentPage = await step([...new URL(back.redirect_to).searchParams]);
		const challenge = consentPage.searchParams.get("consent_challenge") ?? "";
		ok(challenge, `expected the consent page, got ${consentPage.href}`);
		const consent = await env.idp.oauth2.getConsentRequest(challenge);
		const answer = await env.idp.oauth2.acceptConsentRequest(challenge, { grant_scope: consent.requested_scope, remember: true });
		const callback = await step([...new URL(answer.redirect_to).searchParams]);
		return { code: callback.searchParams.get("code") ?? "", verifier, callback, loginRequest, consent };
	}

	describe("with the option off", () => {
		beforeEach(async () => {
			await setup(false);
		});

		it("should not announce the support, and treat a URL as an unknown client id", async () => {
			const metadata = await read(await env.idp.fetch(new Request(`${TEST_ISSUER}/.well-known/oauth-authorization-server`)));
			ok(!("client_id_metadata_document_supported" in metadata));
			const { params } = await authorizeParams();
			await rejects(step(params), (error) => error instanceof InvalidRequestError && error.description === "client_id names no client");
			deepEqual(fetched, []);
		});
	});

	it("should announce the support beside the registration endpoint", async () => {
		const metadata = await read(await env.idp.fetch(new Request(`${TEST_ISSUER}/.well-known/oauth-authorization-server`)));
		deepEqual([metadata.client_id_metadata_document_supported, metadata.registration_endpoint], [true, `${TEST_ISSUER}/register`]);
		const registered = await env.idp.oauth2.registerClient({ redirect_uris: [WEB], token_endpoint_auth_method: "none" });
		ok(registered.client_id.startsWith("cli_"));
	});

	it("should run the code flow, then refresh, list and revoke the grant, with a URL client id", async () => {
		const { code, verifier, callback, loginRequest, consent } = await issueCode();
		deepEqual([callback.origin + callback.pathname, callback.searchParams.get("state")], [LOOPBACK, "s1"]);
		// The consent page learns that the identity comes from a URL, and why to show it with care.
		deepEqual(consent.client_id_metadata_document, {
			hostname: "client.example.com",
			redirect_uri: LOOPBACK,
			warnings: ["loopback_redirect_uri", "client_uri_on_other_host"],
		});
		deepEqual(loginRequest.client_id_metadata_document, consent.client_id_metadata_document);
		deepEqual([consent.client.client_name, consent.skip], ["Example MCP Client", false]);
		deepEqual(fetched, [CLIENT]);

		const tokens = await tokenRequest({
			grant_type: "authorization_code",
			client_id: CLIENT,
			code,
			code_verifier: verifier,
			redirect_uri: LOOPBACK,
		});
		equal(tokens.status, 200);
		const { access_token, refresh_token } = (await read(tokens)) as Record<string, string>;
		const verified = await env.auth.api.verifyAccessToken(access_token, { session: true });
		// `aud` stays the issuer: a client of a document can never set `audience`.
		deepEqual([verified.client_id, verified.claims.aud], [CLIENT, TEST_ISSUER]);

		const refreshed = await tokenRequest({ grant_type: "refresh_token", client_id: CLIENT, refresh_token });
		equal(refreshed.status, 200);
		const next = (await read(refreshed)) as Record<string, string>;

		const grants = await env.idp.oauth2.listOwnGrants(owner.access_token);
		deepEqual(
			grants.map((grant) => [grant.client_id, grant.client?.client_name]),
			[[CLIENT, "Example MCP Client"]],
		);
		// The document is gone, and so is its copy in the cache: revocation needs none of it.
		documents.clear();
		await env.idp.oauth2.storage.unsetKv(`oauth2/client-metadata/${await sha256(CLIENT)}`);
		const before = fetched.length;
		const revoked = await env.idp.fetch(
			new Request(`${TEST_ISSUER}/grants/${grants[0].id}`, {
				method: "DELETE",
				headers: { authorization: `Bearer ${owner.access_token}` },
			}),
		);
		equal(revoked.status, 204);
		equal(fetched.length, before);
		const again = await tokenRequest({ grant_type: "refresh_token", client_id: CLIENT, refresh_token: next.refresh_token });
		equal(again.status, 401);
		deepEqual((await read(again)).error, "invalid_client");
	});

	it("should revoke a token at /revoke with no fetch of the document", async () => {
		const { code, verifier } = await issueCode();
		const { refresh_token } = (await read(
			await tokenRequest({ grant_type: "authorization_code", client_id: CLIENT, code, code_verifier: verifier, redirect_uri: LOOPBACK }),
		)) as Record<string, string>;
		documents.clear();
		vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 3600 * 1000 });
		const before = fetched.length;
		const response = await env.idp.fetch(
			new Request(`${TEST_ISSUER}/revoke`, {
				method: "POST",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({ client_id: CLIENT, token: refresh_token }),
			}),
		);
		equal(response.status, 200);
		equal(fetched.length, before);
		deepEqual(await env.idp.oauth2.listGrants(owner.identityId), []);
	});

	it("should refuse client authentication for a client of a document, draft §5", async () => {
		const { code, verifier } = await issueCode();
		const response = await tokenRequest(
			{ grant_type: "authorization_code", code, code_verifier: verifier, redirect_uri: LOOPBACK },
			{ authorization: `Basic ${btoa(`${encodeURIComponent(CLIENT)}:secret`)}` },
		);
		equal(response.status, 401);
		equal((await read(response)).error, "invalid_client");
	});

	it("should refuse a redirect URI the document does not list, with no redirect to it", async () => {
		const { params } = await authorizeParams("https://evil.example.com/callback");
		await rejects(step(params), InvalidRequestError);
		const browser = new TestBrowser(env.idp.fetch);
		const url = new URL(`${TEST_ISSUER}/authorize`);
		for (const [name, value] of params) {
			url.searchParams.set(name, value);
		}
		const response = await browser.request(url.href);
		deepEqual([response.status, response.headers.get("location")], [400, null]);
	});

	it("should keep the loopback port exception of RFC 8252 §7.3", async () => {
		const { params } = await authorizeParams("http://127.0.0.1:49152/callback");
		ok((await step(params)).searchParams.get("login_challenge"));
	});

	it("should show an error page, never a redirect, for a document that fails", async () => {
		documents.set(CLIENT, () => json({ ...DOCUMENT, client_secret: "oops" }));
		const { params } = await authorizeParams();
		const url = new URL(`${TEST_ISSUER}/authorize`);
		for (const [name, value] of params) {
			url.searchParams.set(name, value);
		}
		const response = await new TestBrowser(env.idp.fetch).request(url.href);
		deepEqual([response.status, response.headers.get("location")], [400, null]);
		const page = await response.text();
		ok(page.includes("invalid_client") && !page.includes("oops"));
	});

	it("should answer a fetch failure at the token endpoint with 503, and a bad document with invalid_client", async () => {
		documents.set(CLIENT, () => json({}, {}, 502));
		const unavailable = await tokenRequest({ grant_type: "refresh_token", client_id: CLIENT, refresh_token: "x" });
		equal(unavailable.status, 503);
		documents.set(CLIENT, () => json({ ...DOCUMENT, client_id: "https://other.example.com/client.json" }));
		const mismatch = await tokenRequest({ grant_type: "refresh_token", client_id: CLIENT, refresh_token: "x" });
		deepEqual([mismatch.status, (await read(mismatch)).error], [401, "invalid_client"]);
	});

	it("should refuse a private address and a non-https client id with no fetch", async () => {
		for (const clientId of [
			"https://127.0.0.1/client.json",
			"https://169.254.169.254/latest/meta-data",
			"http://client.example.com/client.json",
		]) {
			const { params } = await authorizeParams(LOOPBACK, "profile", clientId);
			await rejects(step(params), (error) => error instanceof InvalidClientError || error instanceof InvalidRequestError, clientId);
		}
		deepEqual(fetched, []);
	});

	it("should let the integrator refuse a URL with allow", async () => {
		await setup({ allow: (url) => url.hostname.endsWith(".trusted.example") });
		const { params } = await authorizeParams();
		await rejects(step(params), InvalidClientError);
		deepEqual(fetched, []);
	});

	it("should cache a document for its lifetime, then fetch it again", async () => {
		const { params } = await authorizeParams();
		await step(params);
		await step(params);
		deepEqual(fetched, [CLIENT]);
		vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 601 * 1000 });
		await step(params);
		deepEqual(fetched, [CLIENT, CLIENT]);
	});

	it("should hold a document no-store for min_ttl, and no longer than max_ttl", async () => {
		await setup({ cache: { min_ttl: 120, max_ttl: 900 } });
		documents.set(CLIENT, () => json(DOCUMENT, { "cache-control": "no-store" }));
		const { params } = await authorizeParams();
		await step(params);
		vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 100 * 1000 });
		await step(params);
		equal(fetched.length, 1);
		vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 30 * 1000 });
		documents.set(CLIENT, () => json(DOCUMENT, { "cache-control": "max-age=999999" }));
		await step(params);
		equal(fetched.length, 2);
		vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 901 * 1000 });
		await step(params);
		equal(fetched.length, 3);
	});

	it("should serve a stale copy on a transient failure, and drop it on a terminal one, draft §6.1", async () => {
		const { params } = await authorizeParams();
		await step(params);
		vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 601 * 1000 });
		documents.set(CLIENT, () => Promise.reject(new TypeError("fetch failed")));
		ok((await step(params)).searchParams.get("login_challenge"));
		documents.set(CLIENT, () => new Response("gone", { status: 404 }));
		await rejects(step(params), InvalidClientError);
		documents.set(CLIENT, () => Promise.reject(new TypeError("fetch failed")));
		await rejects(step(params), TemporarilyUnavailableError);
	});

	it("should never cache a document that fails", async () => {
		documents.set(CLIENT, () => json({ ...DOCUMENT, redirect_uris: [] }));
		const { params } = await authorizeParams();
		await rejects(step(params), InvalidClientError);
		await rejects(step(params), InvalidClientError);
		equal(fetched.length, 2);
	});

	it("should revoke the grants of a client whose document names another client id, draft §6.1", async () => {
		const { code, verifier } = await issueCode();
		const { refresh_token } = (await read(
			await tokenRequest({ grant_type: "authorization_code", client_id: CLIENT, code, code_verifier: verifier, redirect_uri: LOOPBACK }),
		)) as Record<string, string>;
		ok(refresh_token);
		documents.set(CLIENT, () => json({ ...DOCUMENT, client_id: "https://attacker.example.com/client.json" }));
		vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 601 * 1000 });
		const response = await tokenRequest({ grant_type: "refresh_token", client_id: CLIENT, refresh_token });
		equal(response.status, 401);
		deepEqual(await env.idp.oauth2.listGrants(owner.identityId), []);
	});

	it("should narrow the scope of the document to the ceiling", async () => {
		documents.set(CLIENT, () => json({ ...DOCUMENT, scope: "profile reports" }));
		const { params } = await authorizeParams(LOOPBACK, "reports");
		const answer = await step(params);
		deepEqual([answer.origin + answer.pathname, answer.searchParams.get("error")], [LOOPBACK, "invalid_scope"]);
	});

	it("should skip the consent page only for an https redirect URI of a remembered client", async () => {
		await issueCode(WEB);
		const { params } = await authorizeParams(WEB);
		const login = await step(params);
		const challenge = login.searchParams.get("login_challenge") ?? "";
		const back = await env.idp.oauth2.acceptLoginRequest(challenge, { access_token: owner.access_token });
		ok((await step([...new URL(back.redirect_to).searchParams])).searchParams.get("code"));

		// A loopback redirect URI asks again, whatever the owner remembered: any local program can take the name.
		await issueCode(LOOPBACK);
		const loopback = await step((await authorizeParams(LOOPBACK)).params);
		const answer = await env.idp.oauth2.acceptLoginRequest(loopback.searchParams.get("login_challenge") ?? "", {
			access_token: owner.access_token,
		});
		ok((await step([...new URL(answer.redirect_to).searchParams])).searchParams.get("consent_challenge"));
	});

	it("should count each fetch in the bucket of the URL and of the address", async () => {
		await setup(
			{},
			{ limits: { client: { client_metadata: { limit: 2, window: 60 } }, address: { client_metadata: { limit: 1, window: 60 } } } },
		);
		documents.set(CLIENT, () => json({}, {}, 500));
		const { params } = await authorizeParams();
		const at = (address?: string) => env.idp.oauth2.authorize({ params, endpoint: `${TEST_ISSUER}/authorize`, address });
		await rejects(at("198.51.100.7"), TemporarilyUnavailableError);
		await rejects(at("198.51.100.7"), (error) => (error as Error).constructor.name === "RateLimitedError");
		await rejects(at("198.51.100.8"), TemporarilyUnavailableError);
		await rejects(at("198.51.100.9"), (error) => (error as Error).constructor.name === "RateLimitedError");
		equal(fetched.length, 2);
	});

	it("should prefer a stored client with the same URL id, draft §9.2", async () => {
		const stored: AuthDanceOauth2Client = {
			client_id: CLIENT,
			client_secret_expires_at: 0,
			client_id_issued_at: 0,
			redirect_uris: ["https://stored.example.com/callback"],
			token_endpoint_auth_method: "none",
			grant_types: ["authorization_code"],
			response_types: ["code"],
			scope: "profile",
		};
		await env.idp.oauth2.clients.updateClient(stored);
		const { params } = await authorizeParams("https://stored.example.com/callback");
		ok((await step(params)).searchParams.get("login_challenge"));
		deepEqual(fetched, []);
	});

	it("should drop the document from the cache and revoke the grants on deleteClient", async () => {
		await issueCode();
		await env.idp.oauth2.deleteClient(CLIENT);
		deepEqual(await env.idp.oauth2.listGrants(owner.identityId), []);
		await step((await authorizeParams()).params);
		equal(fetched.length, 2);
	});
});
