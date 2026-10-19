import type { AuthDanceComponentContext } from "../../component.ts";
import { OAuth2AuthDanceComponent, type OAuth2Identification, type OAuth2ProviderOptions, type OAuth2TokenResponse } from "../oauth2.ts";

/** The two forms of `iss` that Google writes in an ID token. */
const ISSUERS = ["https://accounts.google.com", "accounts.google.com"];

/**
 * A Google account as the step that resolves the identity, through OpenID Connect. The record holds `sub`, the id of
 * the account. It stays the same when the owner changes the email address.
 *
 * Create an OAuth client ID of the type "Web application", and give one of its authorized redirect URIs as
 * `redirectUrl`.
 *
 * To keep more about the account, override {@link retrieveIdentification} and read {@link retrieveProfile}. Add
 * `email` or `profile` to `scope` for the claims of those scopes:
 *
 * @example
 * ```ts
 * class MyGoogleAuthDanceComponent extends GoogleAuthDanceComponent {
 *     async retrieveIdentification(token: OAuth2TokenResponse): Promise<OAuth2Identification> {
 *         const claims = await this.retrieveProfile(token);
 *         return { identification: claims.sub as string, data: { name: claims.name } };
 *     }
 * }
 * ```
 */
export class GoogleAuthDanceComponent extends OAuth2AuthDanceComponent {
	/**
	 * Points the component at Google.
	 * @param options The client credentials and the redirect URL. `scope` defaults to `openid`. A scope you give must
	 * keep `openid`, or the answer holds no ID token.
	 */
	constructor(options: OAuth2ProviderOptions) {
		super({
			...options,
			scope: options.scope ?? "openid",
			authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth",
			tokenUrl: "https://oauth2.googleapis.com/token",
			clientAuthentication: "client_secret_basic",
		});
	}

	/**
	 * Reads the claims of the ID token in the answer of the token endpoint.
	 * @returns The claims. `sub` holds the id of the account.
	 * @throws {@link Error} When the answer holds no ID token, or the ID token fails a check of `readIdToken`.
	 */
	protected async retrieveProfile(token: OAuth2TokenResponse): Promise<Record<string, unknown>> {
		return this.readIdToken(token, (claims) => ISSUERS.includes(claims.iss as string));
	}

	/**
	 * Reads the id of the account.
	 * @returns `sub`, and no data.
	 * @throws {@link Error} When the answer holds no ID token, the ID token fails a check, or it has no `sub`.
	 */
	async retrieveIdentification(token: OAuth2TokenResponse, _context: AuthDanceComponentContext): Promise<OAuth2Identification> {
		const claims = await this.retrieveProfile(token);
		if (typeof claims.sub !== "string") {
			throw new Error("the Google id_token has no sub");
		}
		return { identification: claims.sub };
	}
}
