import type { AuthDanceComponentContext } from "../../component.ts";
import { OAuth2AuthDanceComponent, type OAuth2Identification, type OAuth2ProviderOptions, type OAuth2TokenResponse } from "../oauth2.ts";

/** The tenant id of every personal Microsoft account. */
const CONSUMERS_TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad";

/** Matches a tenant id. */
const TENANT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Options for {@link MicrosoftAuthDanceComponent}. */
export interface MicrosoftAuthDanceComponentOptions extends OAuth2ProviderOptions {
	/**
	 * Which accounts can sign in. `common` takes work, school and personal accounts. `organizations` takes work and
	 * school accounts. `consumers` takes personal accounts. A tenant id or a domain name takes the accounts of that one
	 * tenant.
	 * @defaultValue `"common"`
	 */
	tenant?: string;
}

/**
 * A Microsoft account as the step that resolves the identity, through OpenID Connect on the Microsoft identity
 * platform. The record holds `sub`, the id of the account for this application. The same person has another `sub` in
 * an application with another client id, so a new app registration makes every linked account unusable.
 *
 * Register an application in Microsoft Entra ID, add `redirectUrl` under the "Web" platform, and make a client
 * secret. The "Single-page application" platform does not work: the server redeems the code.
 *
 * To keep more about the account, override {@link retrieveIdentification} and read {@link retrieveProfile}. Add
 * `email` or `profile` to `scope` for the claims of those scopes:
 *
 * @example
 * ```ts
 * class MyMicrosoftAuthDanceComponent extends MicrosoftAuthDanceComponent {
 *     async retrieveIdentification(token: OAuth2TokenResponse): Promise<OAuth2Identification> {
 *         const claims = await this.retrieveProfile(token);
 *         return { identification: claims.sub as string, data: { name: claims.name } };
 *     }
 * }
 * ```
 */
export class MicrosoftAuthDanceComponent extends OAuth2AuthDanceComponent {
	#tenant: string;

	/**
	 * Points the component at the Microsoft identity platform.
	 * @param options The client credentials, the redirect URL and the tenant. `scope` defaults to `openid`. A scope you
	 * give must keep `openid`, or the answer holds no ID token.
	 */
	constructor(options: MicrosoftAuthDanceComponentOptions) {
		const tenant = options.tenant ?? "common";
		const base = `https://login.microsoftonline.com/${encodeURIComponent(tenant)}/oauth2/v2.0`;
		super({
			...options,
			scope: options.scope ?? "openid",
			authorizationUrl: `${base}/authorize`,
			tokenUrl: `${base}/token`,
			clientAuthentication: "client_secret_post",
		});
		this.#tenant = tenant.toLowerCase();
	}

	/**
	 * Reads the claims of the ID token in the answer of the token endpoint.
	 *
	 * Each tenant writes its own `iss`, so the method checks `iss` against `tid`, and `tid` against the tenant of the
	 * options.
	 * @returns The claims. `sub` holds the id of the account for this application, `oid` and `tid` the id of the
	 * account in its tenant.
	 * @throws {@link Error} When the answer holds no ID token, or the ID token fails a check of `readIdToken`.
	 */
	protected async retrieveProfile(token: OAuth2TokenResponse): Promise<Record<string, unknown>> {
		return this.readIdToken(token, (claims) => {
			const tid = claims.tid;
			if (typeof tid !== "string" || claims.iss !== `https://login.microsoftonline.com/${tid}/v2.0`) {
				return false;
			}
			if (this.#tenant === "consumers") {
				return tid === CONSUMERS_TENANT;
			}
			if (this.#tenant === "organizations") {
				return tid !== CONSUMERS_TENANT;
			}
			// A domain name is not in the ID token. The token endpoint of that tenant issued it, and that is enough.
			return !TENANT_ID.test(this.#tenant) || tid.toLowerCase() === this.#tenant;
		});
	}

	/**
	 * Reads the id of the account.
	 * @returns `sub`, and no data.
	 * @throws {@link Error} When the answer holds no ID token, the ID token fails a check, or it has no `sub`.
	 */
	async retrieveIdentification(token: OAuth2TokenResponse, _context: AuthDanceComponentContext): Promise<OAuth2Identification> {
		const claims = await this.retrieveProfile(token);
		if (typeof claims.sub !== "string") {
			throw new Error("the Microsoft id_token has no sub");
		}
		return { identification: claims.sub };
	}
}
