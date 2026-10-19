import { encode as encodeBase64Url } from "jose/base64url";
import { decodeJwt } from "jose/jwt/decode";
import type { AuthDanceComponent, AuthDanceComponentContext } from "../component.ts";
import { IdentificationTakenError, InvalidPromptValueError } from "../error.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent, AuthDanceIdentityIdentification } from "../identity.ts";
import type { AuthDancePromptInput } from "../prompt.ts";

/** Reads a value as a plain object. Returns `null` for anything else, an array included. */
function asObject(value: unknown): Record<string, unknown> | null {
	return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

/** Reads a value as a string that holds something. Returns `null` for anything else. */
function asText(value: unknown): string | null {
	return typeof value === "string" && value.length > 0 ? value : null;
}

/** Encodes one value the way `application/x-www-form-urlencoded` does, RFC 6749 appendix B. */
function formEncode(value: string): string {
	return new URLSearchParams({ v: value }).toString().slice(2);
}

/** What the component wrote to the key value store when it built the prompt of the authorization in progress. */
interface OAuth2Authorization {
	/** The `state` the authorization URL carried. The redirect must give it back. */
	state: string;
	/** The PKCE code verifier, RFC 7636. The authorization URL carried its SHA-256 hash. */
	verifier: string;
}

/**
 * The answer of the token endpoint, RFC 6749 section 5.1. The component reads only `access_token`, and it gives the
 * whole answer to {@link OAuth2AuthDanceComponent.retrieveIdentification}.
 */
export interface OAuth2TokenResponse {
	/** The token that opens the resources of the owner at the provider. */
	access_token: string;
	/** The type of the token, `bearer` for one. */
	token_type?: string;
	/** How long the access token stays valid, in seconds. */
	expires_in?: number;
	/** The token that gets a new access token. The component does not keep it. */
	refresh_token?: string;
	/** The scopes the provider granted, separated by spaces. */
	scope?: string;
	/** The OpenID Connect ID token, when the provider gives one. */
	id_token?: string;
	/** Any other field the provider adds. */
	[key: string]: unknown;
}

/** What {@link OAuth2AuthDanceComponent.retrieveIdentification} reads from the provider about the owner. */
export interface OAuth2Identification {
	/**
	 * The id of the account at the provider, for example the GitHub user id. It is the value that names the owner, so
	 * it must not change for the life of the account. An email address or a login name can change, so do not use one.
	 */
	identification: string;
	/**
	 * Data the record keeps in its private `data` bag, a display name for example. `/list-components` drops it. Omit it
	 * to keep only the id.
	 */
	data?: Record<string, unknown>;
}

/** Options for {@link OAuth2AuthDanceComponent}. Only `scope`, `parameters`, `clientAuthentication` and `ttl` have a default. */
export interface OAuth2AuthDanceComponentOptions {
	/** The authorization endpoint of the provider, `https://github.com/login/oauth/authorize` for one. */
	authorizationUrl: string;
	/** The token endpoint of the provider, `https://github.com/login/oauth/access_token` for one. */
	tokenUrl: string;
	/**
	 * The page of the client that the provider sends the owner back to. Register the same URL at the provider. The
	 * client reads the query of this page and submits it.
	 */
	redirectUrl: string;
	/** The client id the provider issued. */
	clientId: string;
	/**
	 * The client secret the provider issued. It stays on the server. Give a function for a secret that changes, the
	 * signed JWT of Apple for one. The component calls it before each exchange.
	 */
	clientSecret: string | (() => string | Promise<string>);
	/** The scopes the authorization asks for, separated by spaces. Without it the URL carries no `scope`. */
	scope?: string;
	/**
	 * More parameters for the authorization URL, `{ prompt: "select_account" }` for one. A parameter the component sets
	 * itself replaces the one of the same name here.
	 */
	parameters?: Record<string, string>;
	/**
	 * How the component authenticates to the token endpoint, RFC 6749 section 2.3.1. `client_secret_basic` sends the
	 * HTTP Basic header. `client_secret_post` sends the client id and the secret in the body.
	 * @defaultValue `"client_secret_basic"`
	 */
	clientAuthentication?: "client_secret_basic" | "client_secret_post";
	/**
	 * How long an authorization stays valid, in seconds. The state of the dance also expires, so the shorter of the two
	 * applies.
	 * @defaultValue `300`
	 */
	ttl?: number;
}

/**
 * The options every provider of `auth-dance/components/oauth2/*` takes. The provider sets the endpoints and the client
 * authentication itself.
 */
export type OAuth2ProviderOptions = Omit<OAuth2AuthDanceComponentOptions, "authorizationUrl" | "tokenUrl" | "clientAuthentication">;

/**
 * An account at an OAuth 2.0 provider as the step that resolves the identity, RFC 6749 with the authorization code
 * grant and PKCE, RFC 7636.
 *
 * The component is headless. It never answers an HTTP request of the provider, and the client moves the owner
 * between the two:
 *
 * 1. `getPrompt` gives a prompt of the type `oauth2`. `options.authorizationUrl` is the whole authorization URL, and
 *    `options.redirectUrl` is the page the provider sends the owner back to. The client keeps the dance, through an
 *    `AuthDanceClientChoreographyStore` over `sessionStorage` for example, and it sends the owner to
 *    `options.authorizationUrl`.
 * 2. The provider sends the owner back to `options.redirectUrl` with `code` and `state` in the query.
 * 3. The client reads the query into an object and submits it under the name of the step. The component checks
 *    `state`, exchanges `code` at the token endpoint, and calls {@link retrieveIdentification} with the answer.
 *
 * The prompt is the same in every flow. A `sign-in` and the first step of a `recover` look up the identity that holds
 * the account. A `sign-up`, an `enroll`, a `rotate` and the reset of a `recover` link the account.
 *
 * The record holds the name of the step and the id of the account at the provider, and nothing more unless
 * {@link retrieveIdentification} returns `data`. The component keeps no token. It gets the data when it links the
 * account, and a sign-in does not refresh it.
 *
 * An exchange that succeeds proves that the owner controls the account, so the component sets `proves` to `true`. It
 * confirms the account when it links it, and it is not `verifiable`.
 *
 * The component keeps one record in the key value store. `oauth2/<stateId>/<name>` holds the `state` and the PKCE code
 * verifier of the authorization in progress, for the time to live. `getPrompt` writes it, and a second call to
 * `getPrompt` replaces it, so only the last authorization URL the client read answers. A redirect that gives back the
 * correct `state` removes it, so one authorization answers one time.
 *
 * OAuth 2.0 says nothing standard about who the owner is, so a subclass implements {@link retrieveIdentification} for
 * one provider. `auth-dance/components/oauth2/*` ships `apple`, `facebook`, `github`, `gitlab`, `google`, `microsoft`
 * and `x`. A provider that speaks OpenID Connect reads `sub` with {@link readIdToken}.
 *
 * @example
 * ```ts
 * class GitHubAuthDanceComponent extends OAuth2AuthDanceComponent {
 *     constructor(options: { clientId: string; clientSecret: string; redirectUrl: string }) {
 *         super({
 *             ...options,
 *             authorizationUrl: "https://github.com/login/oauth/authorize",
 *             tokenUrl: "https://github.com/login/oauth/access_token",
 *         });
 *     }
 *
 *     async retrieveIdentification(token: OAuth2TokenResponse): Promise<OAuth2Identification> {
 *         const response = await fetch("https://api.github.com/user", {
 *             headers: { Authorization: `Bearer ${token.access_token}`, "User-Agent": "auth-dance" },
 *         });
 *         const user = await response.json();
 *         return { identification: String(user.id) };
 *     }
 * }
 * ```
 *
 * On the client, before the redirect and on the page at `options.redirectUrl`:
 *
 * ```ts
 * const store = webStorageStore<AuthDanceClientChoreographySnapshot>("auth-dance.dance", sessionStorage);
 * const dance = await client.signIn({ store });
 * await dance.choose("github");
 * location.assign(dance.current!.options!.authorizationUrl as string);
 *
 * // On the page at options.redirectUrl.
 * const resumed = await client.resume(store);
 * await resumed.submitPrompt(Object.fromEntries(new URLSearchParams(location.search)), { name: "github" });
 * ```
 */
export abstract class OAuth2AuthDanceComponent implements AuthDanceComponent {
	/** The record kind the component contributes to an identity. The account id resolves the owner on its own. */
	readonly kind: AuthDanceIdentityComponent["kind"] = "identification";
	/** The exchange already proves control of the account, so the component offers no verification. */
	readonly verifiable = false;
	/** `verifyPrompt` exchanges a code that only the provider issues, so an accepted value proves control. */
	readonly proves = true;

	#options: OAuth2AuthDanceComponentOptions;

	/**
	 * Keeps the endpoints of the provider and the credentials of the client.
	 *
	 * @param options The endpoints, the redirect URL and the client credentials. Every other key has a default.
	 */
	constructor(options: OAuth2AuthDanceComponentOptions) {
		this.#options = options;
	}

	/**
	 * Reads the account of the owner at the provider. The component calls this method after each exchange that
	 * succeeds, in every flow.
	 *
	 * Return the id of the account only, and the component stores only the name of the step and that id. Return
	 * `data` too to keep more about the account in the record.
	 *
	 * Throw {@link InvalidPromptValueError} to refuse the account. Any other error fails the request.
	 *
	 * @param token The answer of the token endpoint.
	 * @param context The context of the step.
	 * @returns The id of the account at the provider, and the data to keep.
	 */
	abstract retrieveIdentification(token: OAuth2TokenResponse, context: AuthDanceComponentContext): Promise<OAuth2Identification>;

	/**
	 * Reads the claims of the OpenID Connect ID token in the answer of the token endpoint, and checks `iss`, `aud` and
	 * `exp`. A provider that speaks OpenID Connect calls this method from {@link retrieveIdentification}, and reads
	 * `sub`.
	 *
	 * The method does not check the signature. The component reads the answer straight from the token endpoint over
	 * TLS, and OpenID Connect Core 1.0 section 3.1.3.7 accepts that in place of the signature.
	 * @param token The answer of the token endpoint. Without the `openid` scope it holds no ID token.
	 * @param issuer The `iss` the provider writes, or a function that returns `true` for claims with a correct `iss`.
	 * @returns The claims of the ID token.
	 * @throws {@link Error} When the answer holds no ID token, when the ID token does not read, and when `iss`, `aud`
	 * or `exp` fails its check.
	 */
	protected readIdToken(
		token: OAuth2TokenResponse,
		issuer: string | ((claims: Record<string, unknown>) => boolean),
	): Record<string, unknown> {
		if (typeof token.id_token !== "string") {
			throw new Error("the token response holds no id_token, ask for the openid scope");
		}
		const claims: Record<string, unknown> = decodeJwt(token.id_token);
		if (typeof issuer === "string" ? claims.iss !== issuer : !issuer(claims)) {
			throw new Error(`the id_token comes from the issuer ${String(claims.iss)}`);
		}
		const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
		// OpenID Connect Core 1.0 section 3.1.3.7: an ID token with more than one audience names the client in `azp`.
		if (!audience.includes(this.#options.clientId) || (audience.length > 1 && claims.azp !== this.#options.clientId)) {
			throw new Error("the id_token is not for this client");
		}
		// One minute of leeway for the clock of the provider.
		if (typeof claims.exp !== "number" || claims.exp * 1000 < Date.now() - 60_000) {
			throw new Error("the id_token has expired");
		}
		return claims;
	}

	// The key that holds the authorization in progress. One dance, one step, one authorization.
	#authorizationKey(context: AuthDanceComponentContext): string {
		return `oauth2/${context.stateId}/${context.name}`;
	}

	// The authorization the last prompt started. Returns `null` once the time to live passes.
	async #authorization(context: AuthDanceComponentContext): Promise<OAuth2Authorization | null> {
		const raw = await context.storage.getKv(this.#authorizationKey(context));
		if (!raw) {
			return null;
		}
		try {
			const parsed = asObject(JSON.parse(raw));
			const state = asText(parsed?.state);
			const verifier = asText(parsed?.verifier);
			return state && verifier ? { state, verifier } : null;
		} catch {
			return null;
		}
	}

	/**
	 * Describes the entry the client renders, under the component name, with the type `oauth2`.
	 *
	 * `options.authorizationUrl` carries `response_type=code`, the client id, the redirect URL, the scope, a new `state`
	 * and a new PKCE code challenge. The method keeps the `state` and the code verifier under `oauth2/<stateId>/<name>`,
	 * so a second call replaces the authorization of the first. `options.redirectUrl` is the page the provider sends the
	 * owner back to.
	 *
	 * The input is not sendable, because no channel delivers an authorization.
	 * @returns One input for the client to render.
	 */
	async getPrompt(context: AuthDanceComponentContext): Promise<AuthDancePromptInput> {
		const authorization: OAuth2Authorization = {
			state: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
			verifier: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
		};
		await context.storage.setKv(this.#authorizationKey(context), JSON.stringify(authorization), this.#options.ttl ?? 300);
		const challenge = encodeBase64Url(
			new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(authorization.verifier))),
		);
		const url = new URL(this.#options.authorizationUrl);
		for (const [key, value] of Object.entries(this.#options.parameters ?? {})) {
			url.searchParams.set(key, value);
		}
		url.searchParams.set("response_type", "code");
		url.searchParams.set("client_id", this.#options.clientId);
		url.searchParams.set("redirect_uri", this.#options.redirectUrl);
		if (this.#options.scope) {
			url.searchParams.set("scope", this.#options.scope);
		}
		url.searchParams.set("state", authorization.state);
		url.searchParams.set("code_challenge", challenge);
		url.searchParams.set("code_challenge_method", "S256");
		return {
			kind: "input",
			name: context.name,
			type: "oauth2",
			sendable: false,
			options: {
				authorizationUrl: url.toString(),
				redirectUrl: this.#options.redirectUrl,
			},
		};
	}

	// Exchanges the code at the token endpoint. Returns `null` when the provider refuses the code.
	async #requestToken(code: string, verifier: string): Promise<OAuth2TokenResponse | null> {
		const body = new URLSearchParams({
			grant_type: "authorization_code",
			code,
			redirect_uri: this.#options.redirectUrl,
			code_verifier: verifier,
		});
		// GitHub answers in a form encoding unless the request asks for JSON.
		const headers = new Headers({ "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" });
		const secret = typeof this.#options.clientSecret === "function" ? await this.#options.clientSecret() : this.#options.clientSecret;
		if ((this.#options.clientAuthentication ?? "client_secret_basic") === "client_secret_basic") {
			headers.set("Authorization", `Basic ${btoa(`${formEncode(this.#options.clientId)}:${formEncode(secret)}`)}`);
		} else {
			body.set("client_id", this.#options.clientId);
			body.set("client_secret", secret);
		}
		const response = await fetch(this.#options.tokenUrl, { method: "POST", headers, body });
		if (!response.ok) {
			return null;
		}
		// GitHub answers a refused code with a 200 and an `error` field, so the token decides.
		const token = asObject(await response.json().catch(() => null));
		return asText(token?.access_token) ? (token as OAuth2TokenResponse) : null;
	}

	// Checks the query of the redirect against the authorization in progress, exchanges the code, and reads the
	// account. Returns `null` for a value that does not read, an error answer of the provider, a `state` that does not
	// match, an expired authorization and a code the provider refuses.
	async #exchange(value: unknown, context: AuthDanceComponentContext): Promise<OAuth2Identification | null> {
		const query = asObject(value);
		const code = asText(query?.code);
		const state = asText(query?.state);
		if (!code || !state) {
			return null;
		}
		const authorization = await this.#authorization(context);
		if (!authorization || authorization.state !== state) {
			return null;
		}
		// The authorization answers one time, whatever the provider says about the code.
		await context.storage.unsetKv(this.#authorizationKey(context));
		const token = await this.#requestToken(code, authorization.verifier);
		if (!token) {
			return null;
		}
		const account = await this.retrieveIdentification(token, context);
		if (!asText(account?.identification)) {
			throw new InvalidPromptValueError(`${context.name} retrieveIdentification must return a non-empty identification`);
		}
		return account;
	}

	/**
	 * Turns the query of the redirect into the identification record the identity holds. The `sign-up`, `enroll`,
	 * `rotate` and `recover` flows call this method.
	 *
	 * `identification` holds the id of the account at the provider. `data` holds what
	 * {@link retrieveIdentification} returned under `data`, and the record has no `data` without it.
	 * @param component The component name the record carries.
	 * @param value The query of the redirect as an object, `{ code, state }` at least.
	 * @param confirmed Whether the record starts as confirmed.
	 * @returns One identification record.
	 * @throws {@link InvalidPromptValueError} When the value does not read, when the provider answered with an error,
	 * when `state` does not match the authorization in progress or it expired, and when the provider refuses the code.
	 * @throws {@link IdentificationTakenError} When the account already belongs to another identity.
	 */
	async getIdentityComponent(
		component: string,
		value: unknown,
		confirmed: boolean,
		context: AuthDanceComponentContext,
	): Promise<AuthDanceIdentityComponent[]> {
		const account = await this.#exchange(value, context);
		if (!account) {
			throw new InvalidPromptValueError(`${component} authorization does not match the authorization in progress`);
		}
		const owner = await context.storage.getIdentityByIdentification(component, account.identification).catch(() => undefined);
		if (owner && owner.id !== context.identity?.id) {
			throw new IdentificationTakenError(`${component} account already belongs to an identity`);
		}
		return [
			{
				kind: "identification",
				component,
				identification: account.identification,
				confirmed,
				...(account.data ? { data: account.data } : {}),
			},
		];
	}

	/**
	 * Checks the query of the redirect, and resolves the identity that holds the account.
	 *
	 * The method checks `state`, exchanges `code`, and looks up the id {@link retrieveIdentification} returns. The
	 * identity must hold a confirmed identification under `context.name` with that id.
	 * @param response The query of the redirect as an object, `{ code, state }` at least.
	 * @param context The context of the step.
	 * @returns The id of the identity that holds the account, or `false`. A value that does not read, an error answer of
	 * the provider, a `state` that does not match, a code the provider refuses and an account nobody holds give `false`.
	 */
	async verifyPrompt(response: unknown, context: AuthDanceComponentContext): Promise<boolean | AuthDanceIdentity["id"]> {
		const account = await this.#exchange(response, context);
		if (!account) {
			return false;
		}
		const identity = await context.storage.getIdentityByIdentification(context.name, account.identification).catch(() => undefined);
		const record = identity?.components.find(
			(c): c is AuthDanceIdentityIdentification =>
				c.kind === "identification" && c.component === context.name && c.identification === account.identification,
		);
		return identity && record?.confirmed ? identity.id : false;
	}
}
