import type { AuthDanceComponentContext } from "../../component.ts";
import { OAuth2AuthDanceComponent, type OAuth2Identification, type OAuth2ProviderOptions, type OAuth2TokenResponse } from "../oauth2.ts";

/**
 * An X account, formerly Twitter, as the step that resolves the identity. The record holds the numeric id of the
 * account, which stays the same when the owner changes the username.
 *
 * Turn on OAuth 2.0 in the user authentication settings of the app, select "Web App" so the app is a confidential
 * client, and give `redirectUrl` as its callback URI.
 *
 * To keep more about the account, override {@link retrieveIdentification} and read {@link retrieveProfile}:
 *
 * @example
 * ```ts
 * class MyXAuthDanceComponent extends XAuthDanceComponent {
 *     async retrieveIdentification(token: OAuth2TokenResponse): Promise<OAuth2Identification> {
 *         const profile = await this.retrieveProfile(token);
 *         return { identification: profile.id as string, data: { username: profile.username } };
 *     }
 * }
 * ```
 */
export class XAuthDanceComponent extends OAuth2AuthDanceComponent {
	/**
	 * Points the component at X.
	 * @param options The client credentials and the redirect URL. `scope` defaults to `users.read tweet.read`, the two
	 * scopes `GET /2/users/me` needs. A scope you give must keep both.
	 */
	constructor(options: OAuth2ProviderOptions) {
		super({
			...options,
			scope: options.scope ?? "users.read tweet.read",
			endpoints: {
				authorizationUrl: "https://x.com/i/oauth2/authorize",
				tokenUrl: "https://api.x.com/2/oauth2/token",
				clientAuthentication: "client_secret_basic",
			},
		});
	}

	/**
	 * Reads the account from `GET https://api.x.com/2/users/me`.
	 * @returns The `data` object of the answer. `id` holds the id of the account, and `username` the username.
	 * @throws {@link Error} When X refuses the call, or answers without `data`.
	 */
	protected async retrieveProfile(token: OAuth2TokenResponse): Promise<Record<string, unknown>> {
		const response = await fetch("https://api.x.com/2/users/me", { headers: { Authorization: `Bearer ${token.access_token}` } });
		if (!response.ok) {
			throw new Error(`X answered ${response.status} to GET /2/users/me`);
		}
		const body = (await response.json()) as { data?: Record<string, unknown> };
		if (typeof body.data !== "object" || body.data === null) {
			throw new Error("X answered GET /2/users/me without data");
		}
		return body.data;
	}

	/**
	 * Reads the id of the account.
	 * @returns The id of the account, and no data.
	 * @throws {@link Error} When X refuses the call, or answers without an id.
	 */
	async retrieveIdentification(token: OAuth2TokenResponse, _context: AuthDanceComponentContext): Promise<OAuth2Identification> {
		const profile = await this.retrieveProfile(token);
		if (typeof profile.id !== "string") {
			throw new Error("X answered GET /2/users/me without an id");
		}
		return { identification: profile.id };
	}
}
