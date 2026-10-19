import { deepEqual, ok, rejects } from "node:assert";
import { encode as encodeBase64Url } from "jose/base64url";
import { afterEach, beforeEach, describe, it, vi } from "vitest";
import { AuthDanceApi } from "../api.ts";
import { sequence } from "../choreography.ts";
import type { AuthDanceComponentContext } from "../component.ts";
import { IdentificationTakenError, InvalidPromptValueError } from "../error.ts";
import type { AuthDanceIdentityComponent } from "../identity.ts";
import type { AuthDancePromptInput } from "../prompt.ts";
import { MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "../providers/memory.ts";
import { AuthDanceStorage } from "../storage.ts";
import {
	OAuth2AuthDanceComponent,
	type OAuth2AuthDanceComponentOptions,
	type OAuth2Identification,
	type OAuth2TokenResponse,
} from "./oauth2.ts";

const OPTIONS: OAuth2AuthDanceComponentOptions = {
	authorizationUrl: "https://provider.example/authorize",
	tokenUrl: "https://provider.example/token",
	redirectUrl: "https://app.example/callback",
	clientId: "client id",
	clientSecret: "s3cret:&=",
	scope: "read:user",
};

/** A provider whose access token names the account: `at_<account>`. */
class TestOAuth2Component extends OAuth2AuthDanceComponent {
	#data: Record<string, unknown> | undefined;

	constructor(options: Partial<OAuth2AuthDanceComponentOptions> = {}, data?: Record<string, unknown>) {
		super({ ...OPTIONS, ...options });
		this.#data = data;
	}

	async retrieveIdentification(token: OAuth2TokenResponse): Promise<OAuth2Identification> {
		const identification = token.access_token.slice("at_".length);
		return this.#data ? { identification, data: this.#data } : { identification };
	}
}

/** The authorization server. It issues codes bound to a PKCE challenge, and each code works one time. */
function fakeProvider() {
	const codes = new Map<string, { challenge: string; redirectUri: string; account: string }>();
	const requests: Array<{ headers: Headers; body: URLSearchParams }> = [];
	let refuse = false;

	async function token(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
		ok(String(input) === OPTIONS.tokenUrl, `unexpected fetch to ${String(input)}`);
		const headers = new Headers(init?.headers);
		const body = new URLSearchParams(init?.body as URLSearchParams);
		requests.push({ headers, body });
		const issued = codes.get(body.get("code") ?? "");
		codes.delete(body.get("code") ?? "");
		const verifier = body.get("code_verifier") ?? "";
		const challenge = encodeBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
		if (refuse || !issued || issued.challenge !== challenge || issued.redirectUri !== body.get("redirect_uri")) {
			// GitHub answers a refused code with a 200.
			return Response.json({ error: "bad_verification_code" });
		}
		return Response.json({ access_token: `at_${issued.account}`, token_type: "bearer" });
	}

	return {
		requests,
		fetch: vi.fn(token),
		refuse() {
			refuse = true;
		},
		/** The owner signs in at the provider as `account`. Returns the query of the redirect as an object. */
		authorize(prompt: AuthDancePromptInput, account: string): Record<string, string> {
			const url = new URL(prompt.options?.authorizationUrl as string);
			const code = `code_${codes.size}_${account}`;
			codes.set(code, {
				challenge: url.searchParams.get("code_challenge")!,
				redirectUri: url.searchParams.get("redirect_uri")!,
				account,
			});
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
	options: { flow?: string; components?: AuthDanceIdentityComponent[]; id?: string } = {},
): AuthDanceComponentContext {
	return {
		storage: store,
		stateId: "st_test",
		name: "github",
		flow: options.flow ?? "sign-in",
		identity: options.components && { id: options.id ?? "id_test", data: {}, components: options.components },
	};
}

describe("OAuth2AuthDanceComponent", () => {
	let provider: ReturnType<typeof fakeProvider>;

	beforeEach(() => {
		provider = fakeProvider();
		vi.stubGlobal("fetch", provider.fetch);
	});
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	/** Links `account` to a stored identity. */
	async function seed(store: AuthDanceStorage, account: string, confirmed = true): Promise<string> {
		const component = new TestOAuth2Component();
		const ctx = context(store, { flow: "sign-up", components: [] });
		const query = provider.authorize(await component.getPrompt(ctx), account);
		const components = await component.getIdentityComponent("github", query, confirmed, ctx);
		return (await store.createIdentity({}, components)).id;
	}

	it("should build an authorization URL with state and a PKCE challenge", async () => {
		const component = new TestOAuth2Component({ parameters: { prompt: "consent", state: "forced" } });
		const prompt = await component.getPrompt(context(storage()));
		deepEqual(prompt.kind, "input");
		deepEqual(prompt.name, "github");
		deepEqual(prompt.type, "oauth2");
		deepEqual(prompt.sendable, false);
		deepEqual(prompt.options?.redirectUrl, OPTIONS.redirectUrl);
		const url = new URL(prompt.options?.authorizationUrl as string);
		deepEqual(url.origin + url.pathname, OPTIONS.authorizationUrl);
		deepEqual(url.searchParams.get("response_type"), "code");
		deepEqual(url.searchParams.get("client_id"), OPTIONS.clientId);
		deepEqual(url.searchParams.get("redirect_uri"), OPTIONS.redirectUrl);
		deepEqual(url.searchParams.get("scope"), OPTIONS.scope);
		deepEqual(url.searchParams.get("code_challenge_method"), "S256");
		deepEqual(url.searchParams.get("prompt"), "consent");
		// A parameter of the options never replaces the state the component checks.
		ok(url.searchParams.get("state") !== "forced");
		deepEqual(url.searchParams.get("state")?.length, 43);
		deepEqual(url.searchParams.get("code_challenge")?.length, 43);
	});

	it("should store the provider and the account id only, confirmed by the caller", async () => {
		const store = storage();
		const component = new TestOAuth2Component();
		const ctx = context(store, { flow: "sign-up", components: [] });
		const query = provider.authorize(await component.getPrompt(ctx), "42");
		const components = await component.getIdentityComponent("github", query, false, ctx);
		deepEqual(components, [{ kind: "identification", component: "github", identification: "42", confirmed: false }]);
	});

	it("should keep the data retrieveIdentification returns", async () => {
		const store = storage();
		const component = new TestOAuth2Component({}, { login: "octocat" });
		const ctx = context(store, { flow: "sign-up", components: [] });
		const query = provider.authorize(await component.getPrompt(ctx), "42");
		const [record] = await component.getIdentityComponent("github", query, false, ctx);
		deepEqual(record.data, { login: "octocat" });
	});

	it("should authenticate with client_secret_basic by default", async () => {
		const component = new TestOAuth2Component();
		const ctx = context(storage(), { flow: "sign-up", components: [] });
		await component.getIdentityComponent("github", provider.authorize(await component.getPrompt(ctx), "42"), false, ctx);
		const [request] = provider.requests;
		// RFC 6749 section 2.3.1 form-encodes both values before the base64.
		deepEqual(request.headers.get("Authorization"), `Basic ${btoa("client+id:s3cret%3A%26%3D")}`);
		deepEqual(request.headers.get("Accept"), "application/json");
		deepEqual(request.body.get("grant_type"), "authorization_code");
		deepEqual(request.body.has("client_secret"), false);
	});

	it("should authenticate with client_secret_post", async () => {
		const component = new TestOAuth2Component({ clientAuthentication: "client_secret_post" });
		const ctx = context(storage(), { flow: "sign-up", components: [] });
		await component.getIdentityComponent("github", provider.authorize(await component.getPrompt(ctx), "42"), false, ctx);
		const [request] = provider.requests;
		deepEqual(request.headers.has("Authorization"), false);
		deepEqual(request.body.get("client_id"), OPTIONS.clientId);
		deepEqual(request.body.get("client_secret"), OPTIONS.clientSecret);
	});

	it("should resolve the identity that holds the account", async () => {
		const store = storage();
		const id = await seed(store, "42");
		const component = new TestOAuth2Component();
		const ctx = context(store);
		const query = provider.authorize(await component.getPrompt(ctx), "42");
		deepEqual(await component.verifyPrompt(query, ctx), id);
	});

	it("should refuse an account nobody holds, and an unconfirmed one", async () => {
		const store = storage();
		await seed(store, "43", false);
		const component = new TestOAuth2Component();
		for (const account of ["42", "43"]) {
			const ctx = context(store);
			const query = provider.authorize(await component.getPrompt(ctx), account);
			deepEqual(await component.verifyPrompt(query, ctx), false);
		}
	});

	it("should refuse a state that does not match, and keep the authorization", async () => {
		const store = storage();
		const id = await seed(store, "42");
		const component = new TestOAuth2Component();
		const ctx = context(store);
		const query = provider.authorize(await component.getPrompt(ctx), "42");
		deepEqual(await component.verifyPrompt({ ...query, state: "forged" }, ctx), false);
		deepEqual(provider.fetch.mock.calls.length, 1);
		deepEqual(await component.verifyPrompt(query, ctx), id);
	});

	it("should answer one time", async () => {
		const store = storage();
		const id = await seed(store, "42");
		const component = new TestOAuth2Component();
		const ctx = context(store);
		const query = provider.authorize(await component.getPrompt(ctx), "42");
		deepEqual(await component.verifyPrompt(query, ctx), id);
		const calls = provider.fetch.mock.calls.length;
		deepEqual(await component.verifyPrompt(query, ctx), false);
		// The component refuses the replay itself, before the provider sees the code again.
		deepEqual(provider.fetch.mock.calls.length, calls);
	});

	it("should answer the last prompt only", async () => {
		const store = storage();
		const id = await seed(store, "42");
		const component = new TestOAuth2Component();
		const ctx = context(store);
		const first = provider.authorize(await component.getPrompt(ctx), "42");
		const second = provider.authorize(await component.getPrompt(ctx), "42");
		deepEqual(await component.verifyPrompt(first, ctx), false);
		deepEqual(await component.verifyPrompt(second, ctx), id);
	});

	it("should refuse an error answer, a value that does not read and a refused code", async () => {
		const store = storage();
		await seed(store, "42");
		const component = new TestOAuth2Component();
		const ctx = context(store);
		const { state } = provider.authorize(await component.getPrompt(ctx), "42");
		for (const value of [{ error: "access_denied", state }, "code", null, { code: "", state }]) {
			deepEqual(await component.verifyPrompt(value, ctx), false);
		}
		provider.refuse();
		const query = provider.authorize(await component.getPrompt(ctx), "42");
		deepEqual(await component.verifyPrompt(query, ctx), false);
		const collect = context(store, { flow: "sign-up", components: [] });
		const again = provider.authorize(await component.getPrompt(collect), "44");
		await rejects(() => component.getIdentityComponent("github", again, false, collect), InvalidPromptValueError);
	});

	it("should refuse to link an account another identity holds", async () => {
		const store = storage();
		const id = await seed(store, "42");
		const component = new TestOAuth2Component();
		const other = context(store, { flow: "enroll", components: [], id: "id_other" });
		const query = provider.authorize(await component.getPrompt(other), "42");
		await rejects(() => component.getIdentityComponent("github", query, false, other), IdentificationTakenError);
		// The identity that holds it may link it again, a rotate to the same account for one.
		const same = context(store, { flow: "rotate", components: [], id });
		const again = provider.authorize(await component.getPrompt(same), "42");
		deepEqual((await component.getIdentityComponent("github", again, false, same)).length, 1);
	});

	it("should refuse an empty identification", async () => {
		class EmptyOAuth2Component extends TestOAuth2Component {
			override async retrieveIdentification(): Promise<OAuth2Identification> {
				return { identification: "" };
			}
		}
		const component = new EmptyOAuth2Component();
		const ctx = context(storage());
		const query = provider.authorize(await component.getPrompt(ctx), "42");
		await rejects(() => component.verifyPrompt(query, ctx), InvalidPromptValueError);
	});

	it("should sign up and sign in through the api", async () => {
		const store = storage();
		const api = new AuthDanceApi({
			channels: {},
			choreography: sequence("github"),
			components: { github: new TestOAuth2Component() },
			secret: "zdJXI1jwuXW8A19fns0E_B4HSYm7AUHLGlU9WLo8mxs",
			storage: store,
		});
		const signUp = await api.signUp();
		ok(signUp.prompt.kind === "input" && signUp.prompt.type === "oauth2");
		const created = await api.submitPrompt({ name: "github", value: provider.authorize(signUp.prompt, "42"), state: signUp.state });
		ok("tokens" in created);
		const identity = await store.getIdentity(created.identity.id);
		deepEqual(identity?.components, [{ kind: "identification", component: "github", identification: "42", confirmed: true }]);

		const signIn = await api.signIn();
		ok(signIn.prompt.kind === "input");
		const signedIn = await api.submitPrompt({ name: "github", value: provider.authorize(signIn.prompt, "42"), state: signIn.state });
		ok("tokens" in signedIn);
		deepEqual(signedIn.identity.id, created.identity.id);
	});
});
