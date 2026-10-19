import type { AuthDanceComponentContext } from "../../component.ts";
import { OAuth2AuthDanceComponent, type OAuth2Identification, type OAuth2ProviderOptions, type OAuth2TokenResponse } from "../oauth2.ts";

/**
 * A GitHub account as the step that resolves the identity. The record holds the numeric id of the account, which stays
 * the same when the owner changes the login name.
 *
 * Register an OAuth app or a GitHub App, and give its callback URL as `redirectUrl`. The id needs no scope.
 *
 * To keep more about the account, override {@link retrieveIdentification} and read {@link retrieveProfile}:
 *
 * @example
 * ```ts
 * class MyGitHubAuthDanceComponent extends GitHubAuthDanceComponent {
 *     async retrieveIdentification(token: OAuth2TokenResponse): Promise<OAuth2Identification> {
 *         const profile = await this.retrieveProfile(token);
 *         return { identification: String(profile.id), data: { login: profile.login } };
 *     }
 * }
 * ```
 */
export class GitHubAuthDanceComponent extends OAuth2AuthDanceComponent {
	/**
	 * Points the component at GitHub.
	 * @param options The client credentials and the redirect URL. Without `scope`, the authorization asks for none.
	 */
	constructor(options: OAuth2ProviderOptions) {
		super({
			...options,
			authorizationUrl: "https://github.com/login/oauth/authorize",
			tokenUrl: "https://github.com/login/oauth/access_token",
			clientAuthentication: "client_secret_post",
		});
	}

	/**
	 * Reads the account from `GET https://api.github.com/user`.
	 * @returns The body of the answer. `id` holds the id of the account, and `login` the login name.
	 * @throws {@link Error} When GitHub refuses the call.
	 */
	protected async retrieveProfile(token: OAuth2TokenResponse): Promise<Record<string, unknown>> {
		const response = await fetch("https://api.github.com/user", {
			headers: {
				Accept: "application/vnd.github+json",
				Authorization: `Bearer ${token.access_token}`,
				// The GitHub API refuses a request without a user agent.
				"User-Agent": "auth-dance",
				"X-GitHub-Api-Version": "2022-11-28",
			},
		});
		if (!response.ok) {
			throw new Error(`GitHub answered ${response.status} to GET /user`);
		}
		return (await response.json()) as Record<string, unknown>;
	}

	/**
	 * Reads the id of the account.
	 * @returns The id of the account in decimal, and no data.
	 * @throws {@link Error} When GitHub refuses the call, or answers without an id.
	 */
	async retrieveIdentification(token: OAuth2TokenResponse, _context: AuthDanceComponentContext): Promise<OAuth2Identification> {
		const profile = await this.retrieveProfile(token);
		if (typeof profile.id !== "number") {
			throw new Error("GitHub answered GET /user without an id");
		}
		return { identification: String(profile.id) };
	}
}
