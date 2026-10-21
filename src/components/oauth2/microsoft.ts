import type { OAuth2ProviderOptions } from "../oauth2.ts";
import { OidcAuthDanceComponent } from "../oidc.ts";

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
 * To keep more about the account, override {@link retrieveIdentification} and read {@link retrieveProfile}. Its claims
 * also hold `oid` and `tid`, the id of the account in its tenant. Add `email` or `profile` to `scope` for the claims of
 * those scopes:
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
export class MicrosoftAuthDanceComponent extends OidcAuthDanceComponent {
	#tenant: string;

	/**
	 * Points the component at the Microsoft identity platform.
	 * @param options The client credentials, the redirect URL and the tenant. `scope` defaults to `openid`. A scope you
	 * give must keep `openid`, or the answer holds no ID token.
	 */
	constructor(options: MicrosoftAuthDanceComponentOptions) {
		const tenant = options.tenant ?? "common";
		const base = `https://login.microsoftonline.com/${encodeURIComponent(tenant)}`;
		super({
			...options,
			issuer: `${base}/v2.0`,
			endpoints: {
				authorizationUrl: `${base}/oauth2/v2.0/authorize`,
				tokenUrl: `${base}/oauth2/v2.0/token`,
				clientAuthentication: "client_secret_post",
			},
		});
		this.#tenant = tenant.toLowerCase();
	}

	/**
	 * Tells whether the ID token comes from the tenant of the options.
	 *
	 * Each tenant writes its own `iss`, so the method checks `iss` against `tid`, and `tid` against the tenant of the
	 * options.
	 * @param claims The claims of the ID token.
	 * @returns `true` when `iss` names the tenant in `tid`, and that tenant can sign in.
	 */
	protected override checkIssuer(claims: Record<string, unknown>): boolean {
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
	}
}
