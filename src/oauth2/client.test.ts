import { deepEqual, ok, throws } from "node:assert";
import * as v from "valibot";
import { describe, it } from "vitest";
import { testOauth2Client } from "../fixtures.test.ts";
import {
	AuthDanceOauth2Client,
	isLanguageTag,
	isPublic,
	matchRedirectUri,
	parseClientMetadata,
	toPublicClient,
	validateRedirectUri,
} from "./client.ts";
import { InvalidClientMetadataError, InvalidRedirectUriError, UnapprovedSoftwareStatementError } from "./error.ts";

describe("validateRedirectUri", () => {
	it("should accept https, http on a loopback, and a private-use scheme with a dot", () => {
		for (const uri of [
			"https://app.example.com/callback",
			"https://app.example.com/callback?tenant=1",
			"http://127.0.0.1:8080/callback",
			"http://[::1]/callback",
			"http://localhost:3000/callback",
			"com.example.app:/oauth2redirect",
			"com.example.app://callback",
		]) {
			validateRedirectUri(uri);
		}
	});
	it("should refuse a relative URI, a fragment, http on a remote host, and the other schemes", () => {
		for (const uri of [
			"",
			"/callback",
			"app.example.com/callback",
			"https://app.example.com/callback#top",
			"https://app.example.com/callback#",
			"http://app.example.com/callback",
			"http://192.168.1.10/callback",
			"javascript:alert(1)",
			"data:text/html,hello",
			"file:///etc/passwd",
			"myapp:/callback",
		]) {
			throws(
				() => validateRedirectUri(uri),
				(error) => error instanceof InvalidRedirectUriError && error.error === "invalid_redirect_uri",
				uri,
			);
		}
	});
});

describe("matchRedirectUri", () => {
	const client = { redirect_uris: ["https://app.example.com/callback", "http://127.0.0.1:8080/callback", "http://[::1]/cb?x=1"] };

	it("should match a registered URI exactly", () => {
		ok(matchRedirectUri(client, "https://app.example.com/callback"));
	});
	it("should refuse anything that differs, with no pattern", () => {
		for (const uri of [
			"https://app.example.com/callback/",
			"https://app.example.com/callback/more",
			"https://app.example.com/callback?x=1",
			"https://app.example.com:8443/callback",
			"https://APP.example.com/callback",
			"https://app.example.com/callback#top",
		]) {
			ok(!matchRedirectUri(client, uri), uri);
		}
	});
	it("should let the port of a loopback URI change, and nothing else", () => {
		ok(matchRedirectUri(client, "http://127.0.0.1:51004/callback"));
		ok(matchRedirectUri(client, "http://127.0.0.1/callback"));
		ok(matchRedirectUri(client, "http://[::1]:9000/cb?x=1"));
		ok(!matchRedirectUri(client, "http://localhost:8080/callback"));
		ok(!matchRedirectUri(client, "http://127.0.0.1:8080/other"));
		ok(!matchRedirectUri(client, "http://[::1]:9000/cb?x=2"));
	});
});

describe("AuthDanceOauth2Client", () => {
	it("should parse a client", () => {
		const client = testOauth2Client({ localized: { "client_name#fr-CA": "Appli" } });
		deepEqual(v.parse(AuthDanceOauth2Client, client), client);
	});
	it("should hold a secret hash for a confidential client only", () => {
		throws(() => v.parse(AuthDanceOauth2Client, testOauth2Client({ client_secret_hash: undefined })));
		throws(() => v.parse(AuthDanceOauth2Client, testOauth2Client({ token_endpoint_auth_method: "none" })));
		v.parse(AuthDanceOauth2Client, testOauth2Client({ token_endpoint_auth_method: "none", client_secret_hash: undefined }));
	});
	it("should refuse a localized key that is not a field and a language tag", () => {
		throws(() => v.parse(AuthDanceOauth2Client, testOauth2Client({ localized: { client_name: "Appli" } })));
		throws(() => v.parse(AuthDanceOauth2Client, testOauth2Client({ localized: { "scope#fr": "x" } })));
	});
	it("should drop the secret hash and the server-side fields from the public client", () => {
		const client = testOauth2Client({ skip_consent: true, introspect: true, registered_by: "admin" });
		const publicClient = toPublicClient(client);
		for (const field of ["client_secret_hash", "skip_consent", "introspect", "registered_by"]) {
			ok(!(field in publicClient), field);
		}
		deepEqual(publicClient.client_id, client.client_id);
	});
	it("should name a client public by its method", () => {
		ok(isPublic({ token_endpoint_auth_method: "none" }));
		ok(!isPublic({ token_endpoint_auth_method: "client_secret_post" }));
	});
});

describe("isLanguageTag", () => {
	it("should accept the well-formed tags of RFC 5646", () => {
		for (const tag of [
			"fr",
			"fr-CA",
			"en-US",
			"zh-Hant-TW",
			"es-419",
			"sl-rozaj-biske",
			"de-CH-1901",
			"en-a-bbb-x-ccc",
			"x-private",
			"zh-cmn-Hans-CN",
		]) {
			ok(isLanguageTag(tag), tag);
		}
	});
	it("should refuse a tag that is not well formed", () => {
		for (const tag of ["", "f", "fr_CA", "fr-", "-fr", "fr-CA-", "toolonglanguage", "en-US-a", "fr CA", "fr-Latn-Latn-Latn"]) {
			ok(!isLanguageTag(tag), tag);
		}
	});
});

describe("parseClientMetadata", () => {
	const dynamic = { scope: ["profile", "email"], registered_by: "dynamic" } as const;
	const web = { redirect_uris: ["https://app.example.com/callback"] };

	function refused(body: unknown, error: new (...args: never[]) => Error, options: Parameters<typeof parseClientMetadata>[1] = dynamic) {
		throws(() => parseClientMetadata(body, options), error, JSON.stringify(body));
	}

	it("should fill the defaults of RFC 7591 §2", () => {
		deepEqual(parseClientMetadata(web, dynamic), {
			redirect_uris: ["https://app.example.com/callback"],
			token_endpoint_auth_method: "client_secret_basic",
			grant_types: ["authorization_code"],
			response_types: ["code"],
			scope: "profile email",
			registered_by: "dynamic",
		});
		deepEqual(parseClientMetadata({ grant_types: ["client_credentials"] }, dynamic).response_types, []);
	});
	it("should narrow the scope to the ceiling without an error", () => {
		deepEqual(parseClientMetadata({ ...web, scope: "email admin email" }, dynamic).scope, "email");
		deepEqual(parseClientMetadata({ ...web, scope: "admin" }, dynamic).scope, "");
	});
	it("should take the human-readable fields, in other languages too", () => {
		const metadata = parseClientMetadata(
			{
				...web,
				client_name: "App",
				"client_name#fr-CA": "Appli",
				client_uri: "https://app.example.com",
				"logo_uri#fr": "https://app.example.com/logo-fr.png",
				contacts: ["admin@example.com"],
				software_id: "app",
				software_version: "1.2",
				"scope#fr": "ignored, scope is not human-readable",
				unknown_member: true,
			},
			dynamic,
		);
		deepEqual(metadata.localized, { "client_name#fr-CA": "Appli", "logo_uri#fr": "https://app.example.com/logo-fr.png" });
		deepEqual([metadata.client_name, metadata.contacts, metadata.software_version], ["App", ["admin@example.com"], "1.2"]);
		ok(!("unknown_member" in metadata));
	});
	it("should refuse a member of the wrong type or value", () => {
		for (const body of [
			"not an object",
			[],
			null,
			{ ...web, token_endpoint_auth_method: "private_key_jwt" },
			{ ...web, grant_types: ["password"] },
			{ ...web, grant_types: [] },
			{ ...web, grant_types: "authorization_code" },
			{ ...web, response_types: ["token"] },
			{ ...web, client_name: 42 },
			{ ...web, contacts: "admin@example.com" },
			{ ...web, client_uri: "http://app.example.com" },
			{ ...web, policy_uri: "javascript:alert(1)" },
			{ ...web, "client_name#fr_CA": "Appli" },
			{ ...web, "client_name#fr": 42 },
			{ ...web, "tos_uri#fr": "http://app.example.com/tos" },
			{ ...web, jwks: { keys: [] } },
			{ ...web, jwks_uri: "https://app.example.com/jwks.json" },
		]) {
			refused(body, InvalidClientMetadataError);
		}
	});
	it("should check the rules between the fields", () => {
		refused({ ...web, response_types: [] }, InvalidClientMetadataError);
		refused({ grant_types: ["client_credentials"], response_types: ["code"] }, InvalidClientMetadataError);
		refused({ ...web, grant_types: ["refresh_token", "client_credentials"], response_types: [] }, InvalidClientMetadataError);
		refused({ grant_types: ["client_credentials"], token_endpoint_auth_method: "none" }, InvalidClientMetadataError);
		refused({ grant_types: ["authorization_code"] }, InvalidClientMetadataError);
		parseClientMetadata({ ...web, grant_types: ["authorization_code", "refresh_token"], token_endpoint_auth_method: "none" }, dynamic);
	});
	it("should refuse a redirect URI that does not pass, and a software statement", () => {
		refused({ redirect_uris: ["http://app.example.com/callback"] }, InvalidRedirectUriError);
		refused({ redirect_uris: ["https://app.example.com/callback#x"] }, InvalidRedirectUriError);
		refused({ ...web, software_statement: "eyJ..." }, UnapprovedSoftwareStatementError);
	});
	it("should take the fields only the server sets from an admin, and ignore them from a dynamic request", () => {
		const body = { ...web, skip_consent: true, introspect: true, audience: "https://api.example.com", registered_by: "admin" };
		const fromDynamic = parseClientMetadata(body, dynamic);
		deepEqual(
			[fromDynamic.skip_consent, fromDynamic.introspect, fromDynamic.audience, fromDynamic.registered_by],
			[undefined, undefined, undefined, "dynamic"],
		);
		const fromAdmin = parseClientMetadata(body, { scope: ["profile"], registered_by: "admin" });
		deepEqual(
			[fromAdmin.skip_consent, fromAdmin.introspect, fromAdmin.audience, fromAdmin.registered_by],
			[true, true, "https://api.example.com", "admin"],
		);
		refused({ ...web, skip_consent: "yes" }, InvalidClientMetadataError, { scope: [], registered_by: "admin" });
	});
});
