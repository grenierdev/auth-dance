import type { OAuth2ProviderOptions } from "../oauth2.ts";
import { OidcAuthDanceComponent } from "../oidc.ts";

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
export class GoogleAuthDanceComponent extends OidcAuthDanceComponent {
	/**
	 * Points the component at Google.
	 * @param options The client credentials and the redirect URL. `scope` defaults to `openid`. A scope you give must
	 * keep `openid`, or the answer holds no ID token.
	 */
	constructor(options: OAuth2ProviderOptions) {
		super({
			...options,
			issuer: "https://accounts.google.com",
			endpoints: {
				authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth",
				tokenUrl: "https://oauth2.googleapis.com/token",
				clientAuthentication: "client_secret_basic",
			},
		});
	}

	/**
	 * Tells whether the ID token comes from Google. Google writes `iss` with `https://` and without it.
	 * @param claims The claims of the ID token.
	 * @returns `true` for the two forms.
	 */
	protected override checkIssuer(claims: Record<string, unknown>): boolean {
		return ISSUERS.includes(claims.iss as string);
	}
}
