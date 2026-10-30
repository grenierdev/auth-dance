import { deepEqual, ok, throws } from "node:assert";
import { describe, it } from "vitest";
import type { AuthDanceApi } from "../api.ts";
import { TEST_ISSUER, testCoreApi } from "../fixtures.test.ts";
import { createAuthDanceMemoryOauth2ClientStorage } from "../providers/memory.ts";
import { AuthDanceOauth2Api, type AuthDanceOauth2ApiOptions } from "./api.ts";

function options(api: AuthDanceApi = testCoreApi(), overrides: Partial<AuthDanceOauth2ApiOptions> = {}): AuthDanceOauth2ApiOptions {
	return {
		api,
		clients: createAuthDanceMemoryOauth2ClientStorage(),
		issuer: api.issuer,
		ui: { login: "https://login.example.com/login", consent: "https://login.example.com/consent" },
		...overrides,
	};
}

describe("AuthDanceOauth2Api", () => {
	it("should take the keys and the storage of the core api", () => {
		const api = testCoreApi();
		const oauth2 = new AuthDanceOauth2Api(options(api));
		deepEqual(oauth2.issuer, TEST_ISSUER);
		ok(oauth2.keys === api.keys);
		ok(oauth2.storage === api.storage);
		deepEqual(oauth2.jwks(), api.jwks());
	});
	it("should refuse an issuer that differs from the issuer of the core api", () => {
		throws(() => new AuthDanceOauth2Api(options(testCoreApi(), { issuer: "http://localhost/" })), TypeError);
		throws(() => new AuthDanceOauth2Api(options(testCoreApi(), { issuer: "https://other.example.com" })), TypeError);
	});
	it("should refuse a page URL that is not an absolute https URL", () => {
		const ui = { login: "https://login.example.com/login", consent: "https://login.example.com/consent" };
		for (const bad of ["/login", "login.example.com/login", "javascript:alert(1)", "http://login.example.com/login"]) {
			throws(() => new AuthDanceOauth2Api(options(testCoreApi(), { ui: { ...ui, login: bad } })), TypeError, bad);
			throws(() => new AuthDanceOauth2Api(options(testCoreApi(), { ui: { ...ui, consent: bad } })), TypeError, bad);
			throws(() => new AuthDanceOauth2Api(options(testCoreApi(), { ui: { ...ui, error: bad } })), TypeError, bad);
		}
		new AuthDanceOauth2Api(options(testCoreApi(), { ui: { login: "http://localhost:5173/login", consent: "http://127.0.0.1/consent" } }));
	});
	it("should describe the server in its metadata, with the scopes of the core", () => {
		const scopes = { profile: { description: "Your name", claims: ["name"] }, "email:read": { description: "Your email address" } };
		const oauth2 = new AuthDanceOauth2Api(options(testCoreApi(TEST_ISSUER, scopes)));
		deepEqual(oauth2.metadata("http://localhost/oauth2/"), {
			issuer: TEST_ISSUER,
			authorization_endpoint: "http://localhost/oauth2/authorize",
			token_endpoint: "http://localhost/oauth2/token",
			jwks_uri: "http://localhost/oauth2/jwks.json",
			scopes_supported: ["account", "profile", "email:read"],
			response_types_supported: ["code"],
			response_modes_supported: ["query"],
			grant_types_supported: ["authorization_code", "refresh_token", "client_credentials"],
			token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
			code_challenge_methods_supported: ["S256"],
			authorization_response_iss_parameter_supported: true,
			introspection_endpoint: "http://localhost/oauth2/introspect",
			introspection_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
			revocation_endpoint: "http://localhost/oauth2/revoke",
			revocation_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
		});
	});
});
