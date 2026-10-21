import type { OAuth2ProviderOptions } from "../oauth2.ts";
import { OidcAuthDanceComponent } from "../oidc.ts";

/** Options for {@link GitLabAuthDanceComponent}. */
export interface GitLabAuthDanceComponentOptions extends OAuth2ProviderOptions {
	/**
	 * The URL of the GitLab instance. Give the URL of a GitLab Self-Managed instance here.
	 * @defaultValue `"https://gitlab.com"`
	 */
	baseUrl?: string;
}

/**
 * A GitLab account as the step that resolves the identity, through OpenID Connect. The record holds `sub`, the numeric
 * id of the account on the instance. It stays the same when the owner changes the username. The ID token must carry
 * the URL of the instance in `iss`.
 *
 * Add an application in the settings of a user, a group or the instance, give `redirectUrl` as its redirect URI, mark
 * it confidential, and select the `openid` scope.
 *
 * To keep more about the account, override {@link retrieveIdentification} and read {@link retrieveProfile}. Add
 * `profile` or `email` to `scope` for the claims of those scopes:
 *
 * @example
 * ```ts
 * class MyGitLabAuthDanceComponent extends GitLabAuthDanceComponent {
 *     async retrieveIdentification(token: OAuth2TokenResponse): Promise<OAuth2Identification> {
 *         const claims = await this.retrieveProfile(token);
 *         return { identification: claims.sub as string, data: { username: claims.nickname } };
 *     }
 * }
 * ```
 */
export class GitLabAuthDanceComponent extends OidcAuthDanceComponent {
	/**
	 * Points the component at a GitLab instance.
	 * @param options The client credentials, the redirect URL and the instance. `scope` defaults to `openid`. A scope
	 * you give must keep `openid`, or the answer holds no ID token.
	 */
	constructor(options: GitLabAuthDanceComponentOptions) {
		const baseUrl = (options.baseUrl ?? "https://gitlab.com").replace(/\/+$/, "");
		super({
			...options,
			issuer: baseUrl,
			endpoints: {
				authorizationUrl: `${baseUrl}/oauth/authorize`,
				tokenUrl: `${baseUrl}/oauth/token`,
				clientAuthentication: "client_secret_basic",
			},
		});
	}
}
