import { SignJWT } from "jose/jwt/sign";
import { importPKCS8 } from "jose/key/import";
import type { AuthDanceComponentContext } from "../../component.ts";
import {
	OAuth2AuthDanceComponent,
	type OAuth2AuthDanceComponentOptions,
	type OAuth2Identification,
	type OAuth2ProviderOptions,
	type OAuth2TokenResponse,
} from "../oauth2.ts";

/** Options for {@link AppleAuthDanceComponent}. Apple takes a signed JWT as the client secret, so no `clientSecret` here. */
export interface AppleAuthDanceComponentOptions extends Omit<OAuth2ProviderOptions, "clientSecret"> {
	/** The Services ID, `com.example.web` for one. It is the client id. */
	clientId: string;
	/** The 10-character Team ID of the developer account. */
	teamId: string;
	/** The 10-character id of the Sign in with Apple key. */
	keyId: string;
	/** The private key of the Sign in with Apple key, the content of the `.p8` file, in PKCS #8 PEM. */
	privateKey: string;
	/**
	 * The scopes the authorization asks for: `name`, `email`, or both. Without it, the authorization asks for none.
	 *
	 * Apple sends the answer of an authorization with a scope as an HTTP POST to `redirectUrl`, in a form encoding, and
	 * the component then sets `response_mode=form_post`. The page at `redirectUrl` must read that body, and a static page
	 * cannot. Apple sends the name in the `user` field of that body, never in the ID token.
	 */
	scope?: string;
}

// Signs a new client secret for each exchange, for five minutes, and imports the key one time.
function clientSecret(options: AppleAuthDanceComponentOptions): () => Promise<string> {
	let key: Promise<CryptoKey> | undefined;
	return async () => {
		key ??= importPKCS8(options.privateKey, "ES256");
		return new SignJWT({})
			.setProtectedHeader({ alg: "ES256", kid: options.keyId })
			.setIssuer(options.teamId)
			.setSubject(options.clientId)
			.setAudience("https://appleid.apple.com")
			.setIssuedAt()
			.setExpirationTime("5m")
			.sign(await key);
	};
}

// The options of the parent. The key stays in the closure of `clientSecret`, and out of the options.
function parentOptions(options: AppleAuthDanceComponentOptions): OAuth2AuthDanceComponentOptions {
	const { teamId: _teamId, keyId: _keyId, privateKey: _privateKey, ...rest } = options;
	return {
		...rest,
		clientSecret: clientSecret(options),
		authorizationUrl: "https://appleid.apple.com/auth/authorize",
		tokenUrl: "https://appleid.apple.com/auth/token",
		clientAuthentication: "client_secret_post",
		// Apple refuses `query` for an authorization with a scope.
		parameters: { response_mode: options.scope ? "form_post" : "query", ...options.parameters },
	};
}

/**
 * An Apple Account as the step that resolves the identity, through Sign in with Apple. The record holds `sub`, the id
 * of the account for the team. Every app of the same team reads the same `sub`.
 *
 * Make a Services ID with Sign in with Apple, register `redirectUrl` as a return URL, and make a Sign in with Apple
 * key. The component signs a new client secret with the key for each exchange.
 *
 * Without `scope`, Apple sends the owner back to `redirectUrl` with `code` and `state` in the query, the way every
 * other provider does.
 *
 * Apple does not document PKCE. The component sends the PKCE parameters all the same, and RFC 6749 tells a server to
 * ignore a parameter it does not know.
 *
 * To keep more about the account, override {@link retrieveIdentification} and read {@link retrieveProfile}. The ID
 * token carries `email` when the owner granted the `email` scope one time:
 *
 * @example
 * ```ts
 * class MyAppleAuthDanceComponent extends AppleAuthDanceComponent {
 *     async retrieveIdentification(token: OAuth2TokenResponse): Promise<OAuth2Identification> {
 *         const claims = await this.retrieveProfile(token);
 *         return { identification: claims.sub as string, data: { email: claims.email } };
 *     }
 * }
 * ```
 */
export class AppleAuthDanceComponent extends OAuth2AuthDanceComponent {
	/**
	 * Points the component at Apple.
	 * @param options The Services ID, the key that signs the client secret, and the redirect URL.
	 */
	constructor(options: AppleAuthDanceComponentOptions) {
		super(parentOptions(options));
	}

	/**
	 * Reads the claims of the ID token in the answer of the token endpoint. Apple has no endpoint for the account, so
	 * the ID token is all it tells.
	 * @returns The claims. `sub` holds the id of the account.
	 * @throws {@link Error} When the answer holds no ID token, or the ID token fails a check of `readIdToken`.
	 */
	protected async retrieveProfile(token: OAuth2TokenResponse): Promise<Record<string, unknown>> {
		return this.readIdToken(token, "https://appleid.apple.com");
	}

	/**
	 * Reads the id of the account.
	 * @returns `sub`, and no data.
	 * @throws {@link Error} When the answer holds no ID token, the ID token fails a check, or it has no `sub`.
	 */
	async retrieveIdentification(token: OAuth2TokenResponse, _context: AuthDanceComponentContext): Promise<OAuth2Identification> {
		const claims = await this.retrieveProfile(token);
		if (typeof claims.sub !== "string") {
			throw new Error("the Apple id_token has no sub");
		}
		return { identification: claims.sub };
	}
}
