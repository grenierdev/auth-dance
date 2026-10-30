import * as v from "valibot";
import { InvalidClientMetadataError, InvalidRedirectUriError, UnapprovedSoftwareStatementError } from "./error.ts";

/** The grant type of the device authorization grant, RFC 8628 §3.4. */
export const DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

/** The grant types the server supports, RFC 6749 §4.1, §4.4 and §6, and RFC 8628 §3.4. */
export type AuthDanceOauth2GrantType = "authorization_code" | "refresh_token" | "client_credentials" | typeof DEVICE_CODE_GRANT_TYPE;

/** How a client authenticates at the token endpoint, RFC 7591 §2. `none` is a public client. */
export type AuthDanceOauth2ClientAuthMethod = "client_secret_basic" | "client_secret_post" | "none";

/**
 * A registered client. The field names follow RFC 7591 §2, so the registration endpoint reads and returns them as they
 * are. The store never holds the secret, only its hash.
 */
export interface AuthDanceOauth2Client {
	/** The client id, a ksuid with a `cli_` prefix. */
	client_id: string;
	/** The SHA-256 of the secret, in base64url. A confidential client has one, and a public client has none. */
	client_secret_hash?: string;
	/** When the secret expires, in seconds since the epoch. `0` means never. */
	client_secret_expires_at: number;
	/** When the library created the client, in seconds since the epoch. */
	client_id_issued_at: number;
	/** The redirect URIs. An authorization request must name one of them exactly, except the port of a loopback URI. */
	redirect_uris: string[];
	/** How the client authenticates at the token endpoint. */
	token_endpoint_auth_method: AuthDanceOauth2ClientAuthMethod;
	/** The grant types the client may use. */
	grant_types: AuthDanceOauth2GrantType[];
	/** The response types the client may use. `code` is the only one. */
	response_types: "code"[];
	/** The scopes the client may ask for, separated by spaces. A request for more fails with `invalid_scope`. */
	scope: string;
	/** The name the consent page shows. */
	client_name?: string;
	/** The home page of the client. */
	client_uri?: string;
	/** The logo the consent page shows. */
	logo_uri?: string;
	/** The terms of service of the client. */
	tos_uri?: string;
	/** The privacy policy of the client. */
	policy_uri?: string;
	/** The people responsible for the client, often email addresses. */
	contacts?: string[];
	/** An id of the software, the same for every instance of it. */
	software_id?: string;
	/** The version of the software. */
	software_version?: string;
	/**
	 * The values in other languages, RFC 7591 §2.2. Each key is a field and a BCP 47 tag, for example
	 * `{ "client_name#fr-CA": "Mon application" }`.
	 */
	localized?: Record<string, string>;
	/** Set on the server only. True for a first-party client: the consent page never shows. */
	skip_consent?: boolean;
	/** Set on the server only. True for a resource server that may introspect the tokens of other clients. */
	introspect?: boolean;
	/** Set on the server only. Whether an administrator or the registration endpoint created the client. */
	registered_by?: "admin" | "dynamic";
	/** Set on the server only. The `aud` of the access tokens of the client, a resource server. @defaultValue The client id */
	audience?: string;
}

// RFC 7591 §2.2: a field that can hold human-readable text, `#`, and a BCP 47 language tag.
const LOCALIZED_MEMBER = /^(client_name|client_uri|logo_uri|tos_uri|policy_uri)#[A-Za-z0-9]+(-[A-Za-z0-9]+)*$/;

/**
 * Parses and validates a registered client at runtime. A confidential client must hold a secret hash, and a public
 * client must hold none.
 */
export const AuthDanceOauth2Client: v.GenericSchema<AuthDanceOauth2Client> = v.pipe(
	v.object({
		client_id: v.string(),
		client_secret_hash: v.optional(v.string()),
		client_secret_expires_at: v.pipe(v.number(), v.integer(), v.minValue(0)),
		client_id_issued_at: v.pipe(v.number(), v.integer()),
		redirect_uris: v.array(v.string()),
		token_endpoint_auth_method: v.picklist(["client_secret_basic", "client_secret_post", "none"]),
		grant_types: v.array(v.picklist(["authorization_code", "refresh_token", "client_credentials", DEVICE_CODE_GRANT_TYPE])),
		response_types: v.array(v.literal("code")),
		scope: v.string(),
		client_name: v.optional(v.string()),
		client_uri: v.optional(v.string()),
		logo_uri: v.optional(v.string()),
		tos_uri: v.optional(v.string()),
		policy_uri: v.optional(v.string()),
		contacts: v.optional(v.array(v.string())),
		software_id: v.optional(v.string()),
		software_version: v.optional(v.string()),
		localized: v.optional(v.record(v.pipe(v.string(), v.regex(LOCALIZED_MEMBER)), v.string())),
		skip_consent: v.optional(v.boolean()),
		introspect: v.optional(v.boolean()),
		registered_by: v.optional(v.picklist(["admin", "dynamic"])),
		audience: v.optional(v.string()),
	}),
	v.check(
		(client) => (client.token_endpoint_auth_method === "none") === (client.client_secret_hash === undefined),
		"a confidential client holds a secret hash, and a public client holds none",
	),
	v.title("AuthDanceOauth2Client"),
	v.description("A registered OAuth 2.0 client, with the fields of RFC 7591 §2"),
);

/** A client without its secret hash and without the fields that only the server sets. */
export type AuthDanceOauth2ClientPublic = Omit<
	AuthDanceOauth2Client,
	"client_secret_hash" | "skip_consent" | "introspect" | "registered_by" | "audience"
>;

/** Removes the secret hash and the fields that only the server sets. */
export function toPublicClient(client: AuthDanceOauth2Client): AuthDanceOauth2ClientPublic {
	const {
		client_secret_hash: _hash,
		skip_consent: _skip,
		introspect: _introspect,
		registered_by: _by,
		audience: _audience,
		...rest
	} = client;
	return rest;
}

/**
 * The fields `AuthDanceOauth2ClientStorage.createClient` takes. The storage sets `client_id`, the secret and
 * `client_id_issued_at`, and fills the defaults of RFC 7591 §2.
 */
export interface AuthDanceOauth2ClientMetadata
	extends Omit<
		AuthDanceOauth2Client,
		| "client_id"
		| "client_secret_hash"
		| "client_id_issued_at"
		| "client_secret_expires_at"
		| "redirect_uris"
		| "token_endpoint_auth_method"
		| "grant_types"
		| "response_types"
	> {
	/** @defaultValue `[]` */
	redirect_uris?: string[];
	/** @defaultValue `"client_secret_basic"` */
	token_endpoint_auth_method?: AuthDanceOauth2ClientAuthMethod;
	/** @defaultValue `["authorization_code"]` */
	grant_types?: AuthDanceOauth2GrantType[];
	/** @defaultValue `["code"]` when `grant_types` holds `authorization_code`, and `[]` when it does not */
	response_types?: "code"[];
	/** When the secret expires, in seconds since the epoch. @defaultValue `0`, which means never */
	client_secret_expires_at?: number;
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Checks one redirect URI before the store keeps it. The URI is absolute and holds no fragment, RFC 6749 §3.1.2. Its
 * scheme is one of:
 *
 * - `https:`.
 * - `http:` on a loopback host, `127.0.0.1`, `[::1]` or `localhost`, RFC 8252 §7.3.
 * - A private-use scheme with a dot in it, for example `com.example.app:`, RFC 8252 §7.1.
 *
 * Every other scheme fails, `javascript:`, `data:` and `file:` among them.
 *
 * @throws InvalidRedirectUriError when the URI does not pass.
 */
export function validateRedirectUri(uri: string): void {
	const url = typeof uri === "string" ? URL.parse(uri) : null;
	if (!url) {
		throw new InvalidRedirectUriError("redirect_uri must be an absolute URI");
	}
	if (uri.includes("#")) {
		throw new InvalidRedirectUriError("redirect_uri must not hold a fragment");
	}
	if (url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname))) {
		return;
	}
	if (url.protocol === "http:") {
		throw new InvalidRedirectUriError("redirect_uri uses http: on a host that is not a loopback");
	}
	if (!url.protocol.slice(0, -1).includes(".")) {
		throw new InvalidRedirectUriError("redirect_uri must use https:, http: on a loopback, or a private-use scheme with a dot");
	}
}

// The host and the path of a loopback URI, without the port.
const LOOPBACK_URI = /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?([/?].*)?$/;

/**
 * Whether a redirect URI of a request matches one URI the client registered. The match is exact, character for
 * character, with no pattern, RFC 9700 §4.1.3. One exception: the port of a loopback URI can change, RFC 8252 §7.3.
 */
export function matchRedirectUri(client: Pick<AuthDanceOauth2Client, "redirect_uris">, uri: string): boolean {
	return client.redirect_uris.some((registered) => {
		if (registered === uri) {
			return true;
		}
		const a = LOOPBACK_URI.exec(registered);
		const b = LOOPBACK_URI.exec(uri);
		return a !== null && b !== null && a[1] === b[1] && (a[2] ?? "") === (b[2] ?? "");
	});
}

/** Whether the client is public: it has no secret, and it authenticates with `none`. */
export function isPublic(client: Pick<AuthDanceOauth2Client, "token_endpoint_auth_method">): boolean {
	return client.token_endpoint_auth_method === "none";
}

// RFC 5646 §2.1, without the grandfathered tags: language, script, region, variants, extensions and a private use part.
const LANGUAGE_TAG =
	/^(?:(?:[a-z]{2,3}(?:-[a-z]{3}){0,3}|[a-z]{4}|[a-z]{5,8})(?:-[a-z]{4})?(?:-(?:[a-z]{2}|[0-9]{3}))?(?:-(?:[a-z0-9]{5,8}|[0-9][a-z0-9]{3}))*(?:-[0-9a-wy-z](?:-[a-z0-9]{2,8})+)*(?:-x(?:-[a-z0-9]{1,8})+)?|x(?:-[a-z0-9]{1,8})+)$/i;

/** Whether a value is a well-formed BCP 47 language tag, RFC 5646 §2.1. The grandfathered tags of §2.2.8 fail. */
export function isLanguageTag(value: string): boolean {
	return LANGUAGE_TAG.test(value);
}

// The fields that hold text for the owner, and can hold one value for each language, RFC 7591 §2.2.
const LOCALIZABLE = new Set(["client_name", "client_uri", "logo_uri", "tos_uri", "policy_uri"]);
const URI_FIELDS = new Set(["client_uri", "logo_uri", "tos_uri", "policy_uri"]);
const GRANT_TYPES = new Set(["authorization_code", "refresh_token", "client_credentials", DEVICE_CODE_GRANT_TYPE]);
const AUTH_METHODS = new Set(["client_secret_basic", "client_secret_post", "none"]);

function refuse(description: string): InvalidClientMetadataError {
	return new InvalidClientMetadataError(description);
}

/**
 * Checks the rules between the fields of a client, RFC 7591 §2 and §2.1, on top of the schema. The page URIs use
 * `https:`, and each redirect URI passes `validateRedirectUri`.
 *
 * - `authorization_code` in `grant_types` comes with `code` in `response_types`, and the other way round.
 * - `refresh_token` comes with `authorization_code` or the device code grant type.
 * - `client_credentials` needs a confidential client.
 * - `authorization_code` needs at least one redirect URI.
 *
 * @throws InvalidClientMetadataError when a rule fails.
 * @throws InvalidRedirectUriError when a redirect URI does not pass.
 */
export function checkClientMetadata(metadata: AuthDanceOauth2ClientMetadata): void {
	const grantTypes = metadata.grant_types ?? ["authorization_code"];
	const responseTypes = metadata.response_types ?? (grantTypes.includes("authorization_code") ? ["code"] : []);
	const method = metadata.token_endpoint_auth_method ?? "client_secret_basic";
	if (grantTypes.includes("authorization_code") !== responseTypes.includes("code")) {
		throw refuse("grant_types holds authorization_code if and only if response_types holds code");
	}
	if (grantTypes.includes("refresh_token") && !grantTypes.includes("authorization_code") && !grantTypes.includes(DEVICE_CODE_GRANT_TYPE)) {
		throw refuse(`grant_types holds refresh_token only with authorization_code or ${DEVICE_CODE_GRANT_TYPE}`);
	}
	if (grantTypes.includes("client_credentials") && method === "none") {
		throw refuse("client_credentials needs a confidential client, not token_endpoint_auth_method none");
	}
	if (grantTypes.includes("authorization_code") && !metadata.redirect_uris?.length) {
		throw refuse("authorization_code needs at least one redirect URI");
	}
	for (const uri of metadata.redirect_uris ?? []) {
		validateRedirectUri(uri);
	}
	const pages: [string, string | undefined][] = [
		["client_uri", metadata.client_uri],
		["logo_uri", metadata.logo_uri],
		["tos_uri", metadata.tos_uri],
		["policy_uri", metadata.policy_uri],
		...Object.entries(metadata.localized ?? {}).filter(([key]) => URI_FIELDS.has(key.slice(0, key.indexOf("#")))),
	];
	for (const [name, uri] of pages) {
		if (uri !== undefined && URL.parse(uri)?.protocol !== "https:") {
			throw refuse(`${name} must be an https: URL`);
		}
	}
}

/**
 * Reads the client metadata of a registration request, RFC 7591 §2 and §3.1, and applies the defaults of §2.
 *
 * - `scope` narrows to `options.scope` without an error, and defaults to it.
 * - A `name#tag` member of a human-readable field needs a well-formed BCP 47 tag, and lands in `localized`.
 * - `jwks` and `jwks_uri` fail, because the server supports no `private_key_jwt`. `software_statement` fails with
 *   `unapproved_software_statement`.
 * - A member the server does not know is ignored, RFC 7591 §2.
 * - `skip_consent`, `introspect` and `audience` count only when `options.registered_by` is `admin`. A dynamic request
 *   that names them is not an error: the members are ignored.
 *
 * @throws InvalidClientMetadataError when a member has the wrong type or value, or a rule of `checkClientMetadata`
 * fails.
 * @throws InvalidRedirectUriError when a redirect URI does not pass `validateRedirectUri`.
 * @throws UnapprovedSoftwareStatementError when the request carries a software statement.
 */
export function parseClientMetadata(
	body: unknown,
	options: { scope: readonly string[]; registered_by: "admin" | "dynamic" },
): AuthDanceOauth2ClientMetadata {
	if (typeof body !== "object" || body === null || Array.isArray(body)) {
		throw refuse("the body must be a JSON object");
	}
	const input = body as Record<string, unknown>;
	if (input.software_statement !== undefined) {
		throw new UnapprovedSoftwareStatementError("the server accepts no software statement");
	}
	if (input.jwks !== undefined || input.jwks_uri !== undefined) {
		throw refuse("jwks and jwks_uri are not supported, because private_key_jwt is not");
	}
	const text = (name: string): string | undefined => {
		const value = input[name];
		if (value !== undefined && typeof value !== "string") {
			throw refuse(`${name} must be a string`);
		}
		return value;
	};
	const list = (name: string): string[] | undefined => {
		const value = input[name];
		if (value !== undefined && (!Array.isArray(value) || value.some((item) => typeof item !== "string"))) {
			throw refuse(`${name} must be an array of strings`);
		}
		return value === undefined ? undefined : [...new Set(value as string[])];
	};
	const flag = (name: string): boolean | undefined => {
		const value = input[name];
		if (value !== undefined && typeof value !== "boolean") {
			throw refuse(`${name} must be a boolean`);
		}
		return value;
	};

	const method = text("token_endpoint_auth_method") ?? "client_secret_basic";
	if (!AUTH_METHODS.has(method)) {
		throw refuse("token_endpoint_auth_method must be client_secret_basic, client_secret_post or none");
	}
	const grantTypes = list("grant_types") ?? ["authorization_code"];
	if (grantTypes.length === 0 || grantTypes.some((type) => !GRANT_TYPES.has(type))) {
		throw refuse(`grant_types must hold authorization_code, refresh_token, client_credentials or ${DEVICE_CODE_GRANT_TYPE}`);
	}
	const responseTypes = list("response_types") ?? (grantTypes.includes("authorization_code") ? ["code"] : []);
	if (responseTypes.some((type) => type !== "code")) {
		throw refuse("response_types may hold code only");
	}
	const requested = text("scope")
		?.split(" ")
		.filter((scope) => scope !== "");
	const scope = requested === undefined ? options.scope : [...new Set(requested)].filter((name) => options.scope.includes(name));

	const localized: Record<string, string> = {};
	for (const [key, value] of Object.entries(input)) {
		const separator = key.indexOf("#");
		if (separator < 0 || !LOCALIZABLE.has(key.slice(0, separator))) {
			continue;
		}
		if (!isLanguageTag(key.slice(separator + 1))) {
			throw refuse(`${key} does not end with a BCP 47 language tag`);
		}
		if (typeof value !== "string") {
			throw refuse(`${key} must be a string`);
		}
		localized[key] = value;
	}

	const metadata: AuthDanceOauth2ClientMetadata = {
		redirect_uris: list("redirect_uris") ?? [],
		token_endpoint_auth_method: method as AuthDanceOauth2ClientAuthMethod,
		grant_types: grantTypes as AuthDanceOauth2GrantType[],
		response_types: responseTypes as "code"[],
		scope: scope.join(" "),
		client_name: text("client_name"),
		client_uri: text("client_uri"),
		logo_uri: text("logo_uri"),
		tos_uri: text("tos_uri"),
		policy_uri: text("policy_uri"),
		contacts: list("contacts"),
		software_id: text("software_id"),
		software_version: text("software_version"),
		localized: Object.keys(localized).length > 0 ? localized : undefined,
		registered_by: options.registered_by,
		...(options.registered_by === "admin"
			? { skip_consent: flag("skip_consent"), introspect: flag("introspect"), audience: text("audience") }
			: {}),
	};
	for (const key of Object.keys(metadata) as (keyof AuthDanceOauth2ClientMetadata)[]) {
		if (metadata[key] === undefined) {
			delete metadata[key];
		}
	}
	checkClientMetadata(metadata);
	return metadata;
}
