import type { AuthDanceOauth2Client, AuthDanceOauth2ClientAuthMethod } from "./client.ts";
import { InvalidClientError, InvalidRequestError } from "./error.ts";
import type { AuthDanceOauth2ClientStorage } from "./storage.ts";

/** What one request presents to authenticate its client, RFC 6749 §2.3. */
export interface ClientCredentials {
	client_id: string;
	client_secret?: string;
	method: AuthDanceOauth2ClientAuthMethod;
}

// RFC 6749 Appendix B: application/x-www-form-urlencoded decoding, `+` included.
function formDecode(value: string): string {
	return decodeURIComponent(value.replace(/\+/g, " "));
}

function readBasic(authorization: string): { client_id: string; client_secret: string } {
	try {
		const decoded = new TextDecoder("utf-8", { fatal: true }).decode(
			Uint8Array.from(atob(authorization.slice(6).trim()), (c) => c.charCodeAt(0)),
		);
		const colon = decoded.indexOf(":");
		if (colon < 1) {
			throw new Error("no colon after a client id");
		}
		return { client_id: formDecode(decoded.slice(0, colon)), client_secret: formDecode(decoded.slice(colon + 1)) };
	} catch (cause) {
		throw new InvalidClientError("the Basic credentials are malformed", { cause });
	}
}

/**
 * Reads the client credentials of a request, RFC 6749 §2.3: `Authorization: Basic`, `client_id` and `client_secret`
 * in the body, or `client_id` alone for a public client. A header with another scheme counts as absent.
 *
 * @param authorization The `Authorization` header.
 * @param params The body parameters.
 * @throws InvalidRequestError when the request uses two methods at once, or names two client ids.
 * @throws InvalidClientError when the Basic credentials are malformed, or when the request names no client.
 */
export function readClientCredentials(authorization: string | undefined, params: Map<string, string>): ClientCredentials {
	const bodyId = params.get("client_id");
	const bodySecret = params.get("client_secret");
	if (authorization !== undefined && /^basic\s/i.test(authorization)) {
		if (bodySecret !== undefined) {
			throw new InvalidRequestError("the request uses Basic and client_secret at once");
		}
		const basic = readBasic(authorization);
		if (bodyId !== undefined && bodyId !== basic.client_id) {
			throw new InvalidRequestError("client_id differs from the client of the Basic credentials");
		}
		return { ...basic, method: "client_secret_basic" };
	}
	if (bodyId === undefined) {
		throw new InvalidClientError("the request names no client");
	}
	return bodySecret === undefined
		? { client_id: bodyId, method: "none" }
		: { client_id: bodyId, client_secret: bodySecret, method: "client_secret_post" };
}

/**
 * Authenticates a client with its credentials. The method must be the one the client registered, and the secret must
 * match its hash.
 *
 * @throws InvalidClientError for an unknown client, a method other than the registered one, or a wrong or expired
 * secret.
 */
export async function authenticateClient(
	clients: AuthDanceOauth2ClientStorage,
	credentials: ClientCredentials,
): Promise<AuthDanceOauth2Client> {
	const client = await clients.getClient(credentials.client_id);
	if (!client) {
		throw new InvalidClientError("the client is unknown");
	}
	if (client.token_endpoint_auth_method !== credentials.method) {
		throw new InvalidClientError(`the client authenticates with ${client.token_endpoint_auth_method}`);
	}
	if (credentials.method !== "none" && !(await clients.verifySecret(client, credentials.client_secret ?? ""))) {
		throw new InvalidClientError("the client secret is wrong or expired");
	}
	return client;
}
