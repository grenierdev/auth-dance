import { encode as encodeBase64Url } from "jose/base64url";
import { decodeJwt } from "jose/jwt/decode";
import type { AuthDanceComponentContext } from "../component.ts";
import {
	OAuth2AuthDanceComponent,
	type OAuth2Endpoints,
	type OAuth2Identification,
	type OAuth2ProviderOptions,
	type OAuth2TokenResponse,
} from "./oauth2.ts";

/** Options for {@link OidcAuthDanceComponent}. */
export interface OidcAuthDanceComponentOptions extends OAuth2ProviderOptions {
	/**
	 * The issuer identifier, `https://accounts.google.com` for one. The component reads the discovery document at
	 * `<issuer>/.well-known/openid-configuration`, and the ID token must carry the same value in `iss`. Write it the way
	 * the provider writes it, with the trailing slash when the provider writes one.
	 */
	issuer: string;
	/**
	 * The scopes the authorization asks for, separated by spaces. A scope you give must keep `openid`, or the answer
	 * holds no ID token.
	 * @defaultValue `"openid"`
	 */
	scope?: string;
	/**
	 * The endpoints of the issuer, and how the component authenticates to the token endpoint. The component reads what
	 * this leaves out from the discovery document. Give `authorizationUrl` and `tokenUrl` to skip the document.
	 *
	 * Without `clientAuthentication`, the component reads `token_endpoint_auth_methods_supported`. It takes
	 * `client_secret_basic` when the provider lists it or lists nothing, and `client_secret_post` when the provider lists
	 * only that one.
	 */
	endpoints?: Partial<OAuth2Endpoints>;
}

// OpenID Connect Discovery 1.0 section 3: without `token_endpoint_auth_methods_supported`, the provider takes
// `client_secret_basic`.
function clientAuthentication(issuer: string, supported: unknown): OAuth2Endpoints["clientAuthentication"] {
	if (!Array.isArray(supported) || supported.includes("client_secret_basic")) {
		return "client_secret_basic";
	}
	if (supported.includes("client_secret_post")) {
		return "client_secret_post";
	}
	throw new Error(`${issuer} takes neither client_secret_basic nor client_secret_post, only ${supported.join(", ")}`);
}

// Reads the endpoints from the discovery document, OpenID Connect Discovery 1.0 section 4. `given` wins over the
// document.
async function discover(issuer: string, given: Partial<OAuth2Endpoints>): Promise<OAuth2Endpoints> {
	// Section 4.1: the path goes after the issuer without its trailing slash.
	const response = await fetch(`${issuer.replace(/\/+$/, "")}/.well-known/openid-configuration`, {
		headers: { Accept: "application/json" },
	});
	if (!response.ok) {
		throw new Error(`the discovery document of ${issuer} answered ${response.status}`);
	}
	const document = (await response.json().catch(() => null)) as Record<string, unknown> | null;
	// Section 4.3: the document names the issuer exactly the way the component asked for it.
	if (typeof document !== "object" || document === null || document.issuer !== issuer) {
		throw new Error(`the discovery document of ${issuer} names another issuer`);
	}
	const authorizationUrl = given.authorizationUrl ?? document.authorization_endpoint;
	const tokenUrl = given.tokenUrl ?? document.token_endpoint;
	if (typeof authorizationUrl !== "string" || !authorizationUrl || typeof tokenUrl !== "string" || !tokenUrl) {
		throw new Error(`the discovery document of ${issuer} has no authorization_endpoint or token_endpoint`);
	}
	return {
		authorizationUrl,
		tokenUrl,
		clientAuthentication: given.clientAuthentication ?? clientAuthentication(issuer, document.token_endpoint_auth_methods_supported),
	};
}

// Reads the discovery document on the first call, and keeps the endpoints. A read that fails is not kept, so the next
// call reads the document again.
function discovery(issuer: string, given: Partial<OAuth2Endpoints>): () => Promise<OAuth2Endpoints> {
	let endpoints: Promise<OAuth2Endpoints> | undefined;
	return () => {
		endpoints ??= discover(issuer, given).catch((error: unknown) => {
			endpoints = undefined;
			throw error;
		});
		return endpoints;
	};
}

/**
 * An account at an OpenID Connect provider as the step that resolves the identity, OpenID Connect Core 1.0 with the
 * authorization code flow. The record holds `sub`, the id of the account at the issuer.
 *
 * The component is an {@link OAuth2AuthDanceComponent}. The prompt, the redirect and the exchange are the same, and the
 * prompt has the type `oauth2`. The component adds three things:
 *
 * - It reads the endpoints from the discovery document of the issuer, OpenID Connect Discovery 1.0. It reads the
 *   document on the first prompt, and keeps the endpoints for its life. After a read that fails, the next prompt reads
 *   the document again. Give `endpoints.authorizationUrl` and `endpoints.tokenUrl` to skip the document.
 * - It sends a new `nonce` with each authorization, and refuses an ID token that does not give it back.
 * - It reads `sub` from the ID token, and checks `iss`, `aud` and `exp`. The component reads the ID token straight from
 *   the token endpoint over TLS, so it does not check the signature, OpenID Connect Core 1.0 section 3.1.3.7.
 *
 * A `sub` names an account at one issuer only, and two issuers can give the same `sub` to two persons. Give each issuer
 * its own step name. The record keeps `sub` under that name, so a new name or a new issuer makes every linked account
 * unusable.
 *
 * Register a confidential client at the provider, give `redirectUrl` as its redirect URI, and allow the `openid`
 * scope.
 *
 * To keep more about the account, override {@link retrieveIdentification} and read {@link retrieveProfile}. Add
 * `email` or `profile` to `scope` for the claims of those scopes. To accept another `iss`, override
 * {@link checkIssuer}.
 *
 * @example
 * ```ts
 * const staff = new OidcAuthDanceComponent({
 *     issuer: "https://sso.example.com/realms/staff",
 *     clientId: "auth-dance",
 *     clientSecret: process.env.SSO_CLIENT_SECRET!,
 *     redirectUrl: "https://app.example.com/callback",
 * });
 * ```
 */
export class OidcAuthDanceComponent extends OAuth2AuthDanceComponent {
	#issuer: string;
	#clientId: string;

	/**
	 * Points the component at an issuer.
	 * @param options The issuer, the client credentials and the redirect URL. `scope` defaults to `openid`. Give
	 * `endpoints.authorizationUrl` and `endpoints.tokenUrl` to skip the discovery document.
	 */
	constructor(options: OidcAuthDanceComponentOptions) {
		const { issuer, endpoints = {}, ...rest } = options;
		const { authorizationUrl, tokenUrl } = endpoints;
		super({
			...rest,
			scope: rest.scope ?? "openid",
			endpoints: authorizationUrl && tokenUrl ? { ...endpoints, authorizationUrl, tokenUrl } : discovery(issuer, endpoints),
		});
		this.#issuer = issuer;
		this.#clientId = options.clientId;
	}

	/**
	 * Tells whether the ID token comes from the issuer.
	 *
	 * The method compares `iss` with `options.issuer`. A provider that writes more than one `iss` overrides it.
	 * @param claims The claims of the ID token.
	 * @returns `true` when `iss` names the issuer.
	 */
	protected checkIssuer(claims: Record<string, unknown>): boolean {
		return claims.iss === this.#issuer;
	}

	// The claims of the ID token, after the checks of OpenID Connect Core 1.0 section 3.1.3.7. The component reads the
	// ID token straight from the token endpoint over TLS, and the section accepts that in place of the signature.
	#claims(token: OAuth2TokenResponse): Record<string, unknown> {
		if (typeof token.id_token !== "string") {
			throw new Error("the token response holds no id_token, ask for the openid scope");
		}
		const claims: Record<string, unknown> = decodeJwt(token.id_token);
		if (!this.checkIssuer(claims)) {
			throw new Error(`the id_token comes from the issuer ${String(claims.iss)}`);
		}
		const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
		// An ID token with more than one audience names the client in `azp`.
		if (!audience.includes(this.#clientId) || (audience.length > 1 && claims.azp !== this.#clientId)) {
			throw new Error("the id_token is not for this client");
		}
		// One minute of leeway for the clock of the provider.
		if (typeof claims.exp !== "number" || claims.exp * 1000 < Date.now() - 60_000) {
			throw new Error("the id_token has expired");
		}
		return claims;
	}

	/**
	 * Gives a new `nonce` for the authorization URL, OpenID Connect Core 1.0 section 3.1.2.1. {@link verifyToken}
	 * refuses an ID token that does not give it back. A subclass that overrides this method keeps the `nonce` of
	 * `super`.
	 * @param _context The context of the step.
	 * @returns The `nonce`.
	 */
	protected override async getAuthorizationParameters(_context: AuthDanceComponentContext): Promise<Record<string, string>> {
		return { nonce: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))) };
	}

	/**
	 * Checks the ID token in the answer of the token endpoint: `iss` with {@link checkIssuer}, `aud`, `exp`, and the
	 * `nonce` of the authorization.
	 * @param token The answer of the token endpoint.
	 * @param parameters What {@link getAuthorizationParameters} gave for this authorization.
	 * @param _context The context of the step.
	 * @returns `false` when the ID token does not give back the `nonce` of the authorization.
	 * @throws {@link Error} When the answer holds no ID token, when the ID token does not read, and when `iss`, `aud` or
	 * `exp` fails its check.
	 */
	protected override async verifyToken(
		token: OAuth2TokenResponse,
		parameters: Record<string, string>,
		_context: AuthDanceComponentContext,
	): Promise<boolean> {
		const claims = this.#claims(token);
		return typeof parameters.nonce === "string" && claims.nonce === parameters.nonce;
	}

	/**
	 * Reads the claims of the ID token in the answer of the token endpoint. It checks `iss`, `aud` and `exp` the way
	 * {@link verifyToken} does.
	 * @param token The answer of the token endpoint.
	 * @returns The claims. `sub` holds the id of the account.
	 * @throws {@link Error} When the answer holds no ID token, when the ID token does not read, and when `iss`, `aud` or
	 * `exp` fails its check.
	 */
	protected async retrieveProfile(token: OAuth2TokenResponse): Promise<Record<string, unknown>> {
		return this.#claims(token);
	}

	/**
	 * Reads the id of the account.
	 * @param token The answer of the token endpoint.
	 * @returns `sub`, and no data.
	 * @throws {@link Error} When the answer holds no ID token, the ID token fails a check, or it has no `sub`.
	 */
	async retrieveIdentification(token: OAuth2TokenResponse, _context: AuthDanceComponentContext): Promise<OAuth2Identification> {
		const claims = await this.retrieveProfile(token);
		if (typeof claims.sub !== "string") {
			throw new Error(`the id_token of ${this.#issuer} has no sub`);
		}
		return { identification: claims.sub };
	}
}
