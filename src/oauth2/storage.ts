import * as v from "valibot";
import { ksuid } from "../id.ts";
import { AuthDanceOauth2Client, type AuthDanceOauth2ClientMetadata, validateRedirectUri } from "./client.ts";
import { InvalidClientError, InvalidClientMetadataError } from "./error.ts";
import { constantTimeEqual, randomToken, sha256 } from "./records.ts";

/** The adapter that holds the registered clients. */
export interface AuthDanceOauth2ClientProvider {
	/**
	 * Read one client by id.
	 *
	 * @param clientId A ksuid with a `cli_` prefix.
	 * @returns The client, or `undefined` when the store holds no client under the id.
	 */
	get: (clientId: string) => Promise<AuthDanceOauth2Client | undefined>;
	/**
	 * Read one page of clients, in the order of `client_id`.
	 *
	 * @param cursor The `client_id` of the first client of the page. The page starts at the first id equal to it or
	 * after it. Without it, start at the first client.
	 * @param limit The number of clients to return at most. Without it, return every client from the cursor.
	 * @returns The clients of the page, or an empty array when the page matches none.
	 */
	list: (cursor?: string, limit?: number) => Promise<AuthDanceOauth2Client[]>;
	/** Write a whole client under `client.client_id`, and replace the record already stored there. */
	set: (client: AuthDanceOauth2Client) => Promise<void>;
	/** Delete one client by id. An id the store does not hold is not a failure. */
	delete: (clientId: string) => Promise<void>;
}

/**
 * The SHA-256 of a client secret, in base64url: the value of `client_secret_hash`. Use it to seed a client with a
 * secret you already hold.
 */
export function hashClientSecret(secret: string): Promise<string> {
	return sha256(secret);
}

/**
 * The storage layer of the registered clients. It creates the client id and the secret, keeps only the hash of the
 * secret, and checks each record before the adapter writes it.
 */
export class AuthDanceOauth2ClientStorage {
	#clients: AuthDanceOauth2ClientProvider;

	/** Builds a storage on one adapter. */
	constructor(options: { clients: AuthDanceOauth2ClientProvider }) {
		this.#clients = options.clients;
	}

	/**
	 * Creates a client with a fresh `cli_` ksuid, and fills the defaults of RFC 7591 §2. A confidential client gets a
	 * secret of 32 random bytes. The store keeps only its hash, so this call is the one time the secret is readable.
	 *
	 * @returns The stored client, and `client_secret` for a confidential client.
	 * @throws InvalidRedirectUriError when a redirect URI does not pass `validateRedirectUri`.
	 * @throws InvalidClientMetadataError when a field does not match the `AuthDanceOauth2Client` schema.
	 */
	async createClient(metadata: AuthDanceOauth2ClientMetadata): Promise<{ client: AuthDanceOauth2Client; client_secret?: string }> {
		const token_endpoint_auth_method = metadata.token_endpoint_auth_method ?? "client_secret_basic";
		const grant_types = metadata.grant_types ?? ["authorization_code"];
		const client_secret = token_endpoint_auth_method === "none" ? undefined : randomToken();
		const client: AuthDanceOauth2Client = {
			...metadata,
			client_id: ksuid("cli_"),
			client_secret_expires_at: metadata.client_secret_expires_at ?? 0,
			client_id_issued_at: Math.floor(Date.now() / 1000),
			redirect_uris: metadata.redirect_uris ?? [],
			token_endpoint_auth_method,
			grant_types,
			response_types: metadata.response_types ?? (grant_types.includes("authorization_code") ? ["code"] : []),
			registered_by: metadata.registered_by ?? "admin",
		};
		delete client.client_secret_hash;
		if (client_secret !== undefined) {
			client.client_secret_hash = await sha256(client_secret);
		}
		const stored = await this.#write(client);
		return client_secret === undefined ? { client: stored } : { client: stored, client_secret };
	}

	/** Reads one client by id. Returns `undefined` when no client holds the id. */
	getClient(clientId: string): Promise<AuthDanceOauth2Client | undefined> {
		return this.#clients.get(clientId);
	}

	/** Lists clients in the order of `client_id`, from the first id equal to `cursor` or after it. */
	listClients(cursor?: string, limit?: number): Promise<AuthDanceOauth2Client[]> {
		return this.#clients.list(cursor, limit);
	}

	/**
	 * Writes a whole client, and replaces the record stored under its id. The record goes through the same checks as
	 * `createClient`.
	 *
	 * @throws InvalidRedirectUriError when a redirect URI does not pass `validateRedirectUri`.
	 * @throws InvalidClientMetadataError when a field does not match the `AuthDanceOauth2Client` schema.
	 */
	async updateClient(client: AuthDanceOauth2Client): Promise<void> {
		await this.#write(client);
	}

	/** Deletes one client by id. An id the store does not hold is not a failure. */
	deleteClient(clientId: string): Promise<void> {
		return this.#clients.delete(clientId);
	}

	/**
	 * Replaces the secret of a confidential client. The old secret stops working at once.
	 *
	 * @param expiresAt When the new secret expires, in seconds since the epoch. @defaultValue `0`, which means never
	 * @returns The new secret. The store keeps only its hash, so this call is the one time it is readable.
	 * @throws InvalidClientError when no client holds the id, or when the client is public.
	 */
	async rotateSecret(clientId: string, expiresAt: number = 0): Promise<string> {
		const client = await this.#clients.get(clientId);
		if (!client?.client_secret_hash) {
			throw new InvalidClientError(undefined, { cause: new Error(`no confidential client ${clientId}`) });
		}
		const client_secret = randomToken();
		await this.#write({ ...client, client_secret_hash: await sha256(client_secret), client_secret_expires_at: expiresAt });
		return client_secret;
	}

	/**
	 * Checks a secret against the hash of the client. The comparison takes the same time whatever the input.
	 *
	 * @returns `false` for a wrong secret, for a public client, and for a secret past `client_secret_expires_at`.
	 */
	async verifySecret(client: AuthDanceOauth2Client, secret: string): Promise<boolean> {
		if (!client.client_secret_hash || typeof secret !== "string") {
			return false;
		}
		if (client.client_secret_expires_at !== 0 && client.client_secret_expires_at <= Date.now() / 1000) {
			return false;
		}
		return constantTimeEqual(await sha256(secret), client.client_secret_hash);
	}

	async #write(client: AuthDanceOauth2Client): Promise<AuthDanceOauth2Client> {
		const result = v.safeParse(AuthDanceOauth2Client, client);
		if (!result.success) {
			const [issue] = result.issues;
			const field = issue.path?.map((item) => item.key).join(".");
			throw new InvalidClientMetadataError(field ? `${field} is not valid` : issue.message, { cause: new v.ValiError(result.issues) });
		}
		for (const uri of result.output.redirect_uris) {
			validateRedirectUri(uri);
		}
		await this.#clients.set(result.output);
		return result.output;
	}
}
