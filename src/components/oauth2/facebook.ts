import { hex } from "@scure/base";
import type { AuthDanceComponentContext } from "../../component.ts";
import { OAuth2AuthDanceComponent, type OAuth2Identification, type OAuth2ProviderOptions, type OAuth2TokenResponse } from "../oauth2.ts";

/** Options for {@link FacebookAuthDanceComponent}. */
export interface FacebookAuthDanceComponentOptions extends OAuth2ProviderOptions {
	/**
	 * The Graph API version of the dialog, of the token endpoint and of `/me`. Meta keeps a version for about two years.
	 * @defaultValue `"v26.0"`
	 */
	version?: string;
}

/**
 * A Facebook account as the step that resolves the identity. The record holds the app-scoped id of the account: the
 * same person has another id in another Meta app.
 *
 * Add the Facebook Login product to a Meta app, and give one of its valid OAuth redirect URIs as `redirectUrl`. The id
 * needs no scope: Facebook always grants `public_profile`.
 *
 * Every call to `/me` carries `appsecret_proof`, so the component works when the app requires it.
 *
 * To keep more about the account, override {@link retrieveIdentification} and read {@link retrieveProfile} with the
 * fields you need:
 *
 * @example
 * ```ts
 * class MyFacebookAuthDanceComponent extends FacebookAuthDanceComponent {
 *     async retrieveIdentification(token: OAuth2TokenResponse): Promise<OAuth2Identification> {
 *         const profile = await this.retrieveProfile(token, "id,name");
 *         return { identification: profile.id as string, data: { name: profile.name } };
 *     }
 * }
 * ```
 */
export class FacebookAuthDanceComponent extends OAuth2AuthDanceComponent {
	#version: string;
	#clientSecret: OAuth2ProviderOptions["clientSecret"];

	/**
	 * Points the component at Facebook.
	 * @param options The client credentials, the redirect URL and the Graph API version. Without `scope`, the
	 * authorization asks for none.
	 */
	constructor(options: FacebookAuthDanceComponentOptions) {
		const version = options.version ?? "v26.0";
		super({
			...options,
			endpoints: {
				authorizationUrl: `https://www.facebook.com/${version}/dialog/oauth`,
				tokenUrl: `https://graph.facebook.com/${version}/oauth/access_token`,
				clientAuthentication: "client_secret_post",
			},
		});
		this.#version = version;
		this.#clientSecret = options.clientSecret;
	}

	/**
	 * Reads the account from `GET https://graph.facebook.com/<version>/me`.
	 * @param fields The fields of the account to read, separated by commas.
	 * @returns The body of the answer. `id` holds the app-scoped id of the account.
	 * @throws {@link Error} When Facebook refuses the call.
	 */
	protected async retrieveProfile(token: OAuth2TokenResponse, fields = "id"): Promise<Record<string, unknown>> {
		const secret = typeof this.#clientSecret === "function" ? await this.#clientSecret() : this.#clientSecret;
		const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
		// The HMAC-SHA256 of the access token under the app secret, in hex.
		const proof = hex.encode(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(token.access_token))));
		const url = new URL(`https://graph.facebook.com/${this.#version}/me`);
		url.searchParams.set("fields", fields);
		url.searchParams.set("appsecret_proof", proof);
		const response = await fetch(url, { headers: { Authorization: `Bearer ${token.access_token}` } });
		if (!response.ok) {
			throw new Error(`Facebook answered ${response.status} to GET /me`);
		}
		return (await response.json()) as Record<string, unknown>;
	}

	/**
	 * Reads the id of the account.
	 * @returns The app-scoped id of the account, and no data.
	 * @throws {@link Error} When Facebook refuses the call, or answers without an id.
	 */
	async retrieveIdentification(token: OAuth2TokenResponse, _context: AuthDanceComponentContext): Promise<OAuth2Identification> {
		const profile = await this.retrieveProfile(token);
		if (typeof profile.id !== "string") {
			throw new Error("Facebook answered GET /me without an id");
		}
		return { identification: profile.id };
	}
}
