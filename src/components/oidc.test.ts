import { deepEqual, ok, rejects } from "node:assert";
import { encode as encodeBase64Url } from "jose/base64url";
import { afterEach, beforeEach, describe, it, vi } from "vitest";
import type { AuthDanceComponentContext } from "../component.ts";
import { InvalidPromptValueError } from "../error.ts";
import type { AuthDanceIdentityComponent } from "../identity.ts";
import type { AuthDancePromptInput } from "../prompt.ts";
import { MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "../providers/memory.ts";
import { AuthDanceStorage } from "../storage.ts";
import { AppleAuthDanceComponent } from "./oauth2/apple.ts";
import { GoogleAuthDanceComponent } from "./oauth2/google.ts";
import { MicrosoftAuthDanceComponent } from "./oauth2/microsoft.ts";
import { OidcAuthDanceComponent, type OidcAuthDanceComponentOptions } from "./oidc.ts";

const ISSUER = "https://idp.example/realms/staff";

const OPTIONS: OidcAuthDanceComponentOptions = {
	issuer: ISSUER,
	redirectUrl: "https://app.example/callback",
	clientId: "client id",
	clientSecret: "s3cret",
};

/** The discovery document of {@link ISSUER}. */
function discoveryDocument(): Record<string, unknown> {
	return {
		issuer: ISSUER,
		authorization_endpoint: `${ISSUER}/protocol/openid-connect/auth`,
		token_endpoint: `${ISSUER}/protocol/openid-connect/token`,
		token_endpoint_auth_methods_supported: ["private_key_jwt", "client_secret_basic", "client_secret_post"],
	};
}

/** An unsigned JWT. The component reads the ID token from the token endpoint, so it never checks the signature. */
function jwt(claims: Record<string, unknown>): string {
	const part = (value: unknown) => encodeBase64Url(new TextEncoder().encode(JSON.stringify(value)));
	return `${part({ alg: "none" })}.${part(claims)}.`;
}

/**
 * The OpenID Connect provider. It serves the discovery document of {@link ISSUER}, and issues codes bound to a PKCE
 * challenge and a `nonce`. Its token endpoint answers on any URL that ends with `/token`.
 */
function fakeIssuer() {
	const codes = new Map<string, { challenge: string; nonce: string | null; account: string; claims: Record<string, unknown> }>();
	const requests: Array<{ url: string; headers: Headers; body: URLSearchParams }> = [];
	const discoveries: string[] = [];
	const state = { document: discoveryDocument() as Record<string, unknown> | null, idToken: true };

	async function respond(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
		const url = String(input);
		if (url.endsWith("/.well-known/openid-configuration")) {
			discoveries.push(url);
			return state.document ? Response.json(state.document) : new Response("down", { status: 503 });
		}
		ok(url.endsWith("/token"), `unexpected fetch to ${url}`);
		const headers = new Headers(init?.headers);
		const body = new URLSearchParams(init?.body as URLSearchParams);
		requests.push({ url, headers, body });
		const issued = codes.get(body.get("code") ?? "");
		codes.delete(body.get("code") ?? "");
		const verifier = body.get("code_verifier") ?? "";
		const challenge = encodeBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
		if (!issued || issued.challenge !== challenge) {
			return Response.json({ error: "invalid_grant" }, { status: 400 });
		}
		const claims = {
			iss: ISSUER,
			aud: OPTIONS.clientId,
			sub: issued.account,
			exp: Math.floor(Date.now() / 1000) + 300,
			...(issued.nonce ? { nonce: issued.nonce } : {}),
			...issued.claims,
		};
		return Response.json({ access_token: "at", token_type: "Bearer", ...(state.idToken ? { id_token: jwt(claims) } : {}) });
	}

	return {
		state,
		requests,
		discoveries,
		fetch: vi.fn(respond),
		/** The owner signs in as `account`. `claims` replace claims of the ID token. Returns the query of the redirect. */
		authorize(prompt: AuthDancePromptInput, account: string, claims: Record<string, unknown> = {}): Record<string, string> {
			const url = new URL(prompt.options?.authorizationUrl as string);
			const code = `code_${codes.size}_${account}`;
			codes.set(code, { challenge: url.searchParams.get("code_challenge")!, nonce: url.searchParams.get("nonce"), account, claims });
			return { code, state: url.searchParams.get("state")! };
		},
	};
}

function storage(): AuthDanceStorage {
	return new AuthDanceStorage({
		identity: new MemoryIdentityProvider(),
		kv: new MemoryKvProvider(),
		rate_limiter: new MemoryRateLimiterProvider(),
	});
}

/** One step of a dance. Without `components` the context carries no identity, the way a sign-in does. */
function context(
	store: AuthDanceStorage,
	options: { flow?: string; components?: AuthDanceIdentityComponent[] } = {},
): AuthDanceComponentContext {
	return {
		storage: store,
		stateId: "st_test",
		name: "sso",
		flow: options.flow ?? "sign-in",
		identity: options.components && { id: "id_test", data: {}, components: options.components },
	};
}

describe("OidcAuthDanceComponent", () => {
	let issuer: ReturnType<typeof fakeIssuer>;

	beforeEach(() => {
		issuer = fakeIssuer();
		vi.stubGlobal("fetch", issuer.fetch);
	});
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	/** Links `account` to a stored identity through `component`. */
	async function seed(store: AuthDanceStorage, component: OidcAuthDanceComponent, account: string): Promise<string> {
		const ctx = context(store, { flow: "sign-up", components: [] });
		const query = issuer.authorize(await component.getPrompt(ctx), account);
		const components = await component.getIdentityComponent("sso", query, true, ctx);
		return (await store.createIdentity({}, components)).id;
	}

	it("should read the endpoints from the discovery document one time", async () => {
		const component = new OidcAuthDanceComponent(OPTIONS);
		const first = await component.getPrompt(context(storage()));
		await component.getPrompt(context(storage()));
		deepEqual(issuer.discoveries, [`${ISSUER}/.well-known/openid-configuration`]);
		deepEqual(first.type, "oauth2");
		const url = new URL(first.options?.authorizationUrl as string);
		deepEqual(url.origin + url.pathname, discoveryDocument().authorization_endpoint);
		deepEqual(url.searchParams.get("scope"), "openid");
		deepEqual(url.searchParams.get("nonce")?.length, 43);
		ok(url.searchParams.get("nonce") !== url.searchParams.get("state"));
	});

	it("should store sub, and resolve the identity that holds it", async () => {
		const store = storage();
		const component = new OidcAuthDanceComponent(OPTIONS);
		const id = await seed(store, component, "user-42");
		const identity = await store.getIdentity(id);
		deepEqual(identity?.components, [{ kind: "identification", component: "sso", identification: "user-42", confirmed: true }]);
		const ctx = context(store);
		deepEqual(await component.verifyPrompt(issuer.authorize(await component.getPrompt(ctx), "user-42"), ctx), id);
		const [request] = issuer.requests;
		deepEqual(request.url, discoveryDocument().token_endpoint);
		ok(request.headers.get("Authorization")?.startsWith("Basic "));
	});

	it("should take client_secret_post when the provider lists only that one", async () => {
		issuer.state.document = { ...discoveryDocument(), token_endpoint_auth_methods_supported: ["client_secret_post"] };
		const component = new OidcAuthDanceComponent(OPTIONS);
		await seed(storage(), component, "user-42");
		const [request] = issuer.requests;
		deepEqual(request.headers.has("Authorization"), false);
		deepEqual(request.body.get("client_secret"), OPTIONS.clientSecret);
	});

	it("should refuse a provider that takes neither client_secret_basic nor client_secret_post", async () => {
		issuer.state.document = { ...discoveryDocument(), token_endpoint_auth_methods_supported: ["private_key_jwt"] };
		const component = new OidcAuthDanceComponent(OPTIONS);
		await rejects(() => component.getPrompt(context(storage())), /private_key_jwt/);
	});

	it("should refuse a document that names another issuer, and read it again on the next prompt", async () => {
		const store = storage();
		issuer.state.document = { ...discoveryDocument(), issuer: "https://evil.example" };
		const component = new OidcAuthDanceComponent(OPTIONS);
		await rejects(() => component.getPrompt(context(store)), /another issuer/);
		// The failed read leaves no authorization behind.
		deepEqual(await store.getKv("oauth2/st_test/sso"), undefined);
		issuer.state.document = null;
		await rejects(() => component.getPrompt(context(store)), /503/);
		issuer.state.document = discoveryDocument();
		await component.getPrompt(context(store));
		deepEqual(issuer.discoveries.length, 3);
	});

	it("should drop the trailing slash before the path, and compare the issuer as written", async () => {
		issuer.state.document = { ...discoveryDocument(), issuer: "https://idp.example/tenant/" };
		const component = new OidcAuthDanceComponent({ ...OPTIONS, issuer: "https://idp.example/tenant/" });
		await component.getPrompt(context(storage()));
		deepEqual(issuer.discoveries, ["https://idp.example/tenant/.well-known/openid-configuration"]);
	});

	it("should skip the discovery document when the options give the endpoints", async () => {
		const component = new OidcAuthDanceComponent({
			...OPTIONS,
			endpoints: {
				authorizationUrl: "https://idp.example/authorize",
				tokenUrl: "https://idp.example/token",
				clientAuthentication: "client_secret_post",
			},
		});
		await seed(storage(), component, "user-42");
		deepEqual(issuer.discoveries, []);
		deepEqual(issuer.requests[0].url, "https://idp.example/token");
		deepEqual(issuer.requests[0].body.get("client_secret"), OPTIONS.clientSecret);
	});

	it("should take from the document only what the options leave out", async () => {
		const component = new OidcAuthDanceComponent({ ...OPTIONS, endpoints: { clientAuthentication: "client_secret_post" } });
		await seed(storage(), component, "user-42");
		deepEqual(issuer.discoveries.length, 1);
		deepEqual(issuer.requests[0].url, discoveryDocument().token_endpoint);
		deepEqual(issuer.requests[0].body.get("client_secret"), OPTIONS.clientSecret);
	});

	it("should refuse an ID token without the nonce of the authorization", async () => {
		const store = storage();
		const component = new OidcAuthDanceComponent(OPTIONS);
		await seed(store, component, "user-42");
		const ctx = context(store);
		deepEqual(await component.verifyPrompt(issuer.authorize(await component.getPrompt(ctx), "user-42", { nonce: "forged" }), ctx), false);
		deepEqual(await component.verifyPrompt(issuer.authorize(await component.getPrompt(ctx), "user-42", { nonce: undefined }), ctx), false);
		const collect = context(store, { flow: "sign-up", components: [] });
		const query = issuer.authorize(await component.getPrompt(collect), "user-43", { nonce: "forged" });
		await rejects(() => component.getIdentityComponent("sso", query, false, collect), InvalidPromptValueError);
	});

	it("should fail on an answer without an ID token, and on an ID token from another issuer or for another client", async () => {
		const store = storage();
		const component = new OidcAuthDanceComponent(OPTIONS);
		await seed(store, component, "user-42");
		const ctx = context(store);
		const other = issuer.authorize(await component.getPrompt(ctx), "user-42", { iss: "https://evil.example" });
		await rejects(() => component.verifyPrompt(other, ctx), /issuer/);
		const audience = issuer.authorize(await component.getPrompt(ctx), "user-42", { aud: "another client" });
		await rejects(() => component.verifyPrompt(audience, ctx), /not for this client/);
		issuer.state.idToken = false;
		await rejects(async () => component.verifyPrompt(issuer.authorize(await component.getPrompt(ctx), "user-42"), ctx), /openid scope/);
	});
});

describe("OpenID Connect providers", () => {
	let issuer: ReturnType<typeof fakeIssuer>;

	beforeEach(() => {
		issuer = fakeIssuer();
		vi.stubGlobal("fetch", issuer.fetch);
	});
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	/** Signs up `user-42` with `claims` in the ID token. Returns the identification the record holds. */
	async function signUp(component: OidcAuthDanceComponent, claims: Record<string, unknown>): Promise<string | undefined> {
		const ctx = context(storage(), { flow: "sign-up", components: [] });
		const query = issuer.authorize(await component.getPrompt(ctx), "user-42", claims);
		const [record] = await component.getIdentityComponent("sso", query, false, ctx);
		return record.kind === "identification" ? record.identification : undefined;
	}

	it("should point Google at fixed endpoints, and accept its two forms of iss", async () => {
		const component = new GoogleAuthDanceComponent(OPTIONS);
		const prompt = await component.getPrompt(context(storage()));
		const url = new URL(prompt.options?.authorizationUrl as string);
		deepEqual(url.origin + url.pathname, "https://accounts.google.com/o/oauth2/v2/auth");
		ok(url.searchParams.has("nonce"));
		for (const iss of ["https://accounts.google.com", "accounts.google.com"]) {
			deepEqual(await signUp(component, { iss }), "user-42");
		}
		await rejects(() => signUp(component, {}), /issuer/);
		deepEqual(issuer.discoveries, []);
	});

	it("should check the tenant of a Microsoft ID token", async () => {
		const tid = "72f988bf-86f1-41af-91ab-2d7cd011db47";
		const iss = `https://login.microsoftonline.com/${tid}/v2.0`;
		const organizations = new MicrosoftAuthDanceComponent({ ...OPTIONS, tenant: "organizations" });
		deepEqual(await signUp(organizations, { iss, tid }), "user-42");
		const consumers = "9188040d-6c67-4c5b-b112-36a304b66dad";
		await rejects(() => signUp(organizations, { iss: `https://login.microsoftonline.com/${consumers}/v2.0`, tid: consumers }), /issuer/);
		await rejects(() => signUp(organizations, { iss, tid: consumers }), /issuer/);
		deepEqual(issuer.discoveries, []);
	});

	it("should send Apple no scope by default, and a nonce", async () => {
		const { privateKey } = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
		const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", privateKey));
		const pem = `-----BEGIN PRIVATE KEY-----\n${btoa(String.fromCharCode(...pkcs8))}\n-----END PRIVATE KEY-----`;
		const component = new AppleAuthDanceComponent({ ...OPTIONS, teamId: "TEAM000000", keyId: "KEY0000000", privateKey: pem });
		const prompt = await component.getPrompt(context(storage()));
		const url = new URL(prompt.options?.authorizationUrl as string);
		deepEqual(url.searchParams.has("scope"), false);
		deepEqual(url.searchParams.get("response_mode"), "query");
		ok(url.searchParams.has("nonce"));
		deepEqual(await signUp(component, { iss: "https://appleid.apple.com" }), "user-42");
		deepEqual(issuer.discoveries, []);
	});
});
