import {
	type AuthDanceOauth2Client,
	type AuthDanceOauth2GrantType,
	DEVICE_CODE_GRANT_TYPE,
	parseClientMetadata,
	validateRedirectUri,
} from "./client.ts";
import { AuthDanceOauth2Error, InvalidClientError, TemporarilyUnavailableError } from "./error.ts";

/**
 * How the server takes a client that names itself with a URL, the OAuth Client ID Metadata Document of
 * draft-ietf-oauth-client-id-metadata-document-03. The server fetches the JSON document at the URL, and uses it as the
 * metadata of the client. No registration comes first.
 */
export interface AuthDanceOauth2ClientIdMetadataDocumentOptions {
	/**
	 * The most a client of a document may ask for. A document that asks for more narrows to it, with no error, as
	 * `registration.scope` does. List `account` here to let such a client ask to manage the account.
	 * @defaultValue Every scope the server knows but `account`
	 */
	scope?: string[];
	/**
	 * Decides whether the server may fetch a client id URL. It runs after the built-in checks, so it can only refuse
	 * more. Use it for a trust policy: an allowlist of hosts, or a refusal of the identifiers of the resource servers
	 * you trust, draft §10.1. A refusal answers `invalid_client`. @defaultValue Every URL that passes the built-in checks
	 */
	allow?: (url: URL) => boolean | Promise<boolean>;
	/**
	 * The function that sends the request for a document. The library builds the `Request`: `GET`, `Accept:
	 * application/json`, `redirect: "manual"`, no cookie, and a signal for `timeout`. Supply a function that resolves the
	 * host and refuses a special-use address before it connects, for example a Node `fetch` with an agent that checks
	 * each address. The built-in checks read only the text of the URL. @defaultValue `globalThis.fetch`
	 */
	fetch?: (request: Request) => Promise<Response>;
	/** How long the fetch of one document may take, the body included, in seconds. @defaultValue 5 */
	timeout?: number;
	/** The most bytes the server reads of one document. A larger document fails, draft §10.11. @defaultValue 5120 */
	max_size?: number;
	/**
	 * The bounds of the time the server keeps a document, in seconds, draft §6.2. The server reads `Cache-Control`
	 * (`s-maxage`, then `max-age`, less `Age`) and clamps the result to these bounds. A document with no lifetime, or
	 * with `no-store` or `no-cache`, stays `min_ttl`. Workers KV refuses a time to live under 60 seconds.
	 */
	cache?: {
		/** @defaultValue 300 */
		min_ttl?: number;
		/** @defaultValue 86400 */
		max_ttl?: number;
	};
}

/** Why the consent page shows a client of a document with more care. Each value is a fact, not a refusal. */
export type AuthDanceOauth2ClientIdentityWarning =
	/** The redirect URI of the request is on a host other than the host of the client id. */
	| "redirect_uri_on_other_host"
	/**
	 * The redirect URI of the request is on a loopback address. Any program on the device of the owner can listen on
	 * it, so a program can take the name of the client and get the code.
	 */
	| "loopback_redirect_uri"
	/** The redirect URI of the request uses a private-use scheme. Any app that claims the scheme can get the code. */
	| "private_use_redirect_uri"
	/**
	 * `client_uri` is on a host other than the host of the client id. This is common and allowed, draft §4.4: the
	 * client asserts `client_uri`, and the host of the client id is the only value the server checked.
	 */
	| "client_uri_on_other_host";

/**
 * What the login and the consent page read about a client that names itself with a URL. The server checked only one
 * thing about the client: that the document at `client_id` names that URL. `client_name`, `logo_uri` and `client_uri`
 * are what the client says about itself.
 */
export interface AuthDanceOauth2ClientIdMetadataDocumentInfo {
	/** The hostname of the client id. Show it next to the name of the client, draft §10.6. */
	hostname: string;
	/** The redirect URI of the request. Show its host, MCP 2025-11-25. Absent for a device. */
	redirect_uri?: string;
	/** Why the page should show the client with more care. */
	warnings: AuthDanceOauth2ClientIdentityWarning[];
}

/** The defaults of `AuthDanceOauth2ClientIdMetadataDocumentOptions`. */
export const ClientIdMetadataDocumentDefaults = {
	timeout: 5,
	max_size: 5120,
	min_ttl: 300,
	max_ttl: 86400,
} as const;

// The longest client id URL the server takes. The draft sets no limit. The URL goes in every token and every log line.
const MAX_URL_LENGTH = 2048;

// Names that never resolve to a public address: RFC 6761, RFC 6762, RFC 7686, RFC 8375, and `internal`.
const LOCAL_SUFFIXES = ["localhost", "local", "internal", "home.arpa", "localdomain", "invalid", "onion"];

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

// The special-use IPv4 blocks of RFC 6890 and the IANA registry, with the multicast and the reserved blocks.
const SPECIAL_IPV4: [number, number][] = [
	["0.0.0.0", 8],
	["10.0.0.0", 8],
	["100.64.0.0", 10],
	["127.0.0.0", 8],
	["169.254.0.0", 16],
	["172.16.0.0", 12],
	["192.0.0.0", 24],
	["192.0.2.0", 24],
	["192.88.99.0", 24],
	["192.168.0.0", 16],
	["198.18.0.0", 15],
	["198.51.100.0", 24],
	["203.0.113.0", 24],
	["224.0.0.0", 4],
	["240.0.0.0", 4],
].map(([base, bits]) => [ipv4Number(base as string) ?? 0, bits as number]);

function ipv4Number(value: string): number | undefined {
	const parts = IPV4.exec(value)?.slice(1).map(Number);
	if (!parts || parts.some((part) => part > 255)) {
		return undefined;
	}
	return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

// The eight 16-bit groups of an IPv6 address, as the URL parser writes it: lowercase hex, `::` at most once, no IPv4
// tail. `undefined` for any other text.
function ipv6Groups(value: string): number[] | undefined {
	const halves = value.split("::");
	if (halves.length > 2) {
		return undefined;
	}
	const read = (half: string) =>
		half === "" ? [] : half.split(":").map((group) => (/^[0-9a-f]{1,4}$/.test(group) ? parseInt(group, 16) : NaN));
	const head = read(halves[0]);
	const tail = halves.length === 2 ? read(halves[1]) : [];
	const groups = halves.length === 2 ? [...head, ...new Array(8 - head.length - tail.length).fill(0), ...tail] : head;
	return groups.length === 8 && groups.every((group) => Number.isInteger(group)) ? groups : undefined;
}

/**
 * Whether the host of a URL is a special-use address or a local name, so the server must not fetch it, draft §10.7. It
 * reads the text of the host only, as the URL parser writes it: it resolves no name.
 *
 * - An IPv4 address in a block of RFC 6890, or multicast, or reserved.
 * - An IPv6 address outside the global unicast block `2000::/3`, or in `2001::/23`, `2001:db8::/32` or `2002::/16`.
 * - A name with no dot, `localhost`, or a name under `localhost`, `local`, `internal`, `home.arpa`, `localdomain`,
 *   `invalid` or `onion`.
 */
export function isSpecialUseHost(hostname: string): boolean {
	const host = hostname.toLowerCase().replace(/\.$/, "");
	if (host.startsWith("[")) {
		const groups = ipv6Groups(host.slice(1, -1));
		if (!groups) {
			return true;
		}
		const [a, b] = groups;
		const global = (a & 0xe000) === 0x2000;
		return !global || (a === 0x2001 && b < 0x200) || (a === 0x2001 && b === 0xdb8) || a === 0x2002;
	}
	const ipv4 = ipv4Number(host);
	if (ipv4 !== undefined) {
		return ipv4 === 0xffffffff || SPECIAL_IPV4.some(([base, bits]) => ipv4 >>> (32 - bits) === base >>> (32 - bits));
	}
	if (/^[0-9.]+$/.test(host) || !host.includes(".")) {
		return true;
	}
	return LOCAL_SUFFIXES.some((suffix) => host === suffix || host.endsWith(`.${suffix}`));
}

/** Whether a client id has the shape of a client id URL, so the server reads it as one: it starts with `https://`. */
export function isClientIdUrl(clientId: string): boolean {
	return typeof clientId === "string" && clientId.startsWith("https://");
}

/**
 * Checks a client id URL before the server fetches it, draft §3 and §10.7. The URL:
 *
 * - Uses `https:`, and holds no userinfo and no fragment.
 * - Has a path other than `/`, with no `.` or `..` segment.
 * - Is in the form the URL parser writes: no default port, a lowercase host, no escape the parser changes. The draft
 *   forbids the server to normalize, and the server fetches the parsed URL, so a URL in another form can never match
 *   the `client_id` of its document.
 * - Is not on the origin of the issuer, draft §10.1, and its host is not special-use, see `isSpecialUseHost`.
 * - Holds 2048 characters at most.
 *
 * @returns The parsed URL.
 * @throws InvalidClientError when a rule fails. The description never repeats the URL.
 */
export function checkClientIdUrl(clientId: string, issuer: string): URL {
	const url = isClientIdUrl(clientId) && clientId.length <= MAX_URL_LENGTH ? URL.parse(clientId) : null;
	if (url?.protocol !== "https:") {
		throw new InvalidClientError("client_id is not an https URL of 2048 characters at most");
	}
	if (url.username !== "" || url.password !== "" || clientId.includes("#")) {
		throw new InvalidClientError("client_id must hold no userinfo and no fragment");
	}
	if (url.href !== clientId) {
		throw new InvalidClientError("client_id is not in normal form, or holds a dot segment");
	}
	if (url.pathname === "/") {
		throw new InvalidClientError("client_id must have a path other than /");
	}
	if (url.origin === new URL(issuer).origin) {
		throw new InvalidClientError("client_id is on the origin of the issuer");
	}
	if (isSpecialUseHost(url.hostname)) {
		throw new InvalidClientError("client_id is on a special-use address or a local name");
	}
	return url;
}

/**
 * The time to keep a document, in seconds, from its headers, draft §6.2. `s-maxage` comes before `max-age`, and `Age`
 * comes off. `no-store`, `no-cache` and a response with no lifetime give `min`. The result is between `min` and `max`.
 */
export function cacheLifetime(headers: Headers, min: number, max: number): number {
	const directives = new Map<string, string | undefined>();
	for (const part of (headers.get("cache-control") ?? "").split(",")) {
		const [name, value] = part.trim().split("=", 2);
		if (name) {
			directives.set(name.toLowerCase(), value?.replace(/^"|"$/g, ""));
		}
	}
	if (directives.has("no-store") || directives.has("no-cache")) {
		return min;
	}
	const seconds = (value: string | null | undefined) => (value != null && /^\d+$/.test(value) ? Number(value) : undefined);
	const maxAge = seconds(directives.get("s-maxage")) ?? seconds(directives.get("max-age"));
	if (maxAge === undefined) {
		return min;
	}
	return Math.min(max, Math.max(min, maxAge - (seconds(headers.get("age")) ?? 0)));
}

function isJsonMediaType(contentType: string | null): boolean {
	const mediaType = contentType?.split(";")[0].trim().toLowerCase() ?? "";
	return mediaType === "application/json" || /^application\/[a-z0-9!#$&^_.-]+\+json$/.test(mediaType);
}

// A terminal failure: the server got an answer, and the answer is not a valid document.
function refuse(description: string, cause?: unknown): InvalidClientError {
	return new InvalidClientError(description, cause === undefined ? undefined : { cause });
}

// A transient failure: the server got no answer, draft §6.1.
function unavailable(cause: unknown): TemporarilyUnavailableError {
	return new TemporarilyUnavailableError("the client metadata document could not be fetched", { cause });
}

/**
 * Fetches a client id metadata document, draft §6. It sends a `GET` with `Accept: application/json`, follows no
 * redirect, and reads `options.max_size` bytes at most.
 *
 * @returns The parsed JSON and the headers of the response.
 * @throws TemporarilyUnavailableError for a network failure, a timeout, a 429 or a 5xx: a transient failure.
 * @throws InvalidClientError for any other status but 200, a redirect among them, a media type other than JSON, a
 * body over the limit, and a body that is not JSON: a terminal failure. No description holds a byte of the response.
 */
export async function fetchClientIdMetadataDocument(
	url: URL,
	options: { fetch: (request: Request) => Promise<Response>; timeout: number; max_size: number },
): Promise<{ body: unknown; headers: Headers }> {
	const signal = AbortSignal.timeout(options.timeout * 1000);
	let response: Response;
	try {
		// No cookie and no other header: a server runtime keeps no cookie jar, and draft §11.1 asks for nothing more.
		response = await options.fetch(
			new Request(url.href, { method: "GET", headers: { accept: "application/json" }, redirect: "manual", signal }),
		);
	} catch (cause) {
		throw unavailable(cause);
	}
	if (response.status !== 200) {
		await response.body?.cancel().catch(() => undefined);
		const cause = new Error(`the document answered HTTP ${response.status}`);
		if (response.status === 429 || response.status >= 500) {
			throw unavailable(cause);
		}
		throw refuse("the client metadata document did not answer 200, or answered with a redirect", cause);
	}
	if (!isJsonMediaType(response.headers.get("content-type"))) {
		await response.body?.cancel().catch(() => undefined);
		throw refuse("the client metadata document is not served as JSON");
	}
	const length = Number(response.headers.get("content-length") ?? 0);
	if (length > options.max_size) {
		await response.body?.cancel().catch(() => undefined);
		throw refuse("the client metadata document is larger than the server reads");
	}
	const chunks: Uint8Array[] = [];
	let size = 0;
	const reader = response.body?.getReader();
	try {
		for (;;) {
			const chunk = reader ? await reader.read() : { done: true as const, value: undefined };
			if (chunk.done) {
				break;
			}
			size += chunk.value.byteLength;
			if (size > options.max_size) {
				await reader?.cancel().catch(() => undefined);
				throw refuse("the client metadata document is larger than the server reads");
			}
			chunks.push(chunk.value);
		}
	} catch (cause) {
		throw cause instanceof AuthDanceOauth2Error ? cause : unavailable(cause);
	}
	const bytes = new Uint8Array(size);
	let offset = 0;
	for (const chunk of chunks) {
		bytes.set(chunk, offset);
		offset += chunk.byteLength;
	}
	try {
		return { body: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)), headers: response.headers };
	} catch {
		// The cause stays empty: the error of the parser quotes the body.
		throw refuse("the client metadata document is not valid JSON");
	}
}

// The token endpoint methods based on a shared secret, draft §4.1.
const SECRET_METHODS = new Set(["client_secret_basic", "client_secret_post", "client_secret_jwt"]);

function stringList(value: unknown, name: string): string[] | undefined {
	if (value === undefined) {
		return undefined;
	}
	if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
		throw refuse(`${name} of the client metadata document must be an array of strings`);
	}
	return value as string[];
}

/**
 * Reads a client id metadata document into a client record, draft §4 to §6. The RFC 7591 checks of the registration
 * endpoint run on it, `parseClientMetadata`, with these rules on top:
 *
 * - `client_id` equals `clientId`, character for character.
 * - `client_secret` and `client_secret_expires_at` are absent, and no method based on a shared secret appears.
 * - `token_endpoint_auth_methods_supported` comes first, then `token_endpoint_auth_method`. When the two are present,
 *   the second is in the first. With neither, the method is `none`. The server supports `none` only, so a document
 *   without `none` fails. The default `client_secret_basic` of RFC 7591 never applies.
 * - `jwks` and `jwks_uri` are not both present. The server reads neither: it supports no `private_key_jwt`.
 * - `grant_types` narrows to what the server supports for a public client: `authorization_code`, `refresh_token`, and
 *   the device code grant type when `options.device` is true. An empty result fails. `response_types` narrows to
 *   `code`, and must keep it when `authorization_code` stays.
 * - `scope` narrows to `options.scope`, and defaults to it.
 * - `redirect_uris` is required with `authorization_code`, and each URI passes `validateRedirectUri`.
 * - `software_statement` is ignored: the server does not evaluate it, draft §4.3.
 *
 * @returns The client, public, with `client_id_issued_at` set to `fetchedAt`. The record has no `registered_by`.
 * @throws InvalidClientError when a rule fails. The description names the rule, never a value of the document.
 */
export function parseClientIdMetadataDocument(
	body: unknown,
	clientId: string,
	options: { scope: readonly string[]; device: boolean; fetchedAt: number },
): AuthDanceOauth2Client {
	if (typeof body !== "object" || body === null || Array.isArray(body)) {
		throw refuse("the client metadata document is not a JSON object");
	}
	const input = { ...(body as Record<string, unknown>) };
	if (input.client_id !== clientId) {
		throw refuse("the client_id of the client metadata document differs from its URL");
	}
	if (input.client_secret !== undefined || input.client_secret_expires_at !== undefined) {
		throw refuse("the client metadata document must not hold client_secret or client_secret_expires_at");
	}
	if (input.jwks !== undefined && input.jwks_uri !== undefined) {
		throw refuse("the client metadata document must not hold both jwks and jwks_uri");
	}
	const supported = stringList(input.token_endpoint_auth_methods_supported, "token_endpoint_auth_methods_supported");
	const single = input.token_endpoint_auth_method;
	if (single !== undefined && typeof single !== "string") {
		throw refuse("token_endpoint_auth_method of the client metadata document must be a string");
	}
	if (supported !== undefined && single !== undefined && !supported.includes(single)) {
		throw refuse("token_endpoint_auth_method is not in token_endpoint_auth_methods_supported");
	}
	const methods = supported ?? (single === undefined ? ["none"] : [single]);
	if (methods.some((method) => SECRET_METHODS.has(method))) {
		throw refuse("the client metadata document names a method based on a shared secret");
	}
	if (!methods.includes("none")) {
		throw refuse("the server supports none of the token endpoint authentication methods of the client");
	}

	const offered: string[] = ["authorization_code", "refresh_token", ...(options.device ? [DEVICE_CODE_GRANT_TYPE] : [])];
	const grantTypes = (stringList(input.grant_types, "grant_types") ?? ["authorization_code"]).filter((type) => offered.includes(type));
	if (!grantTypes.some((type) => type !== "refresh_token")) {
		throw refuse("the server supports none of the grant types of the client");
	}
	const code = grantTypes.includes("authorization_code");
	const responseTypes = stringList(input.response_types, "response_types") ?? (code ? ["code"] : []);
	if (code && !responseTypes.includes("code")) {
		throw refuse("the server supports none of the response types of the client");
	}

	for (const name of ["client_id", "jwks", "jwks_uri", "token_endpoint_auth_methods_supported", "software_statement"]) {
		delete input[name];
	}
	let metadata: ReturnType<typeof parseClientMetadata>;
	try {
		metadata = parseClientMetadata(
			{
				...input,
				token_endpoint_auth_method: "none",
				grant_types: grantTypes,
				response_types: code ? ["code"] : [],
			},
			{ scope: options.scope, registered_by: "dynamic" },
		);
	} catch (cause) {
		if (cause instanceof AuthDanceOauth2Error) {
			// The description of the parser names a member of the document, so it stays in `cause`, for the server log.
			throw refuse("the client metadata document is not valid client metadata", cause);
		}
		throw cause;
	}
	const { registered_by: _by, ...fields } = metadata;
	const client: AuthDanceOauth2Client = {
		...fields,
		client_id: clientId,
		client_secret_expires_at: 0,
		client_id_issued_at: options.fetchedAt,
		redirect_uris: metadata.redirect_uris ?? [],
		token_endpoint_auth_method: "none",
		grant_types: grantTypes as AuthDanceOauth2GrantType[],
		response_types: code ? ["code"] : [],
	};
	for (const uri of client.redirect_uris) {
		validateRedirectUri(uri);
	}
	return client;
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Describes the identity of a client of a document for the login and the consent page: the host of its client id,
 * the redirect URI of the request, and the warnings of `AuthDanceOauth2ClientIdentityWarning`.
 */
export function describeClientIdentity(
	client: Pick<AuthDanceOauth2Client, "client_id" | "client_uri">,
	redirectUri: string | undefined,
): AuthDanceOauth2ClientIdMetadataDocumentInfo {
	const hostname = new URL(client.client_id).hostname;
	const warnings: AuthDanceOauth2ClientIdentityWarning[] = [];
	if (redirectUri !== undefined) {
		const redirect = URL.parse(redirectUri);
		if (redirect?.protocol === "http:" && LOOPBACK_HOSTS.has(redirect.hostname)) {
			warnings.push("loopback_redirect_uri");
		} else if (redirect?.protocol === "https:") {
			if (redirect.hostname !== hostname) {
				warnings.push("redirect_uri_on_other_host");
			}
		} else {
			warnings.push("private_use_redirect_uri");
		}
	}
	if (client.client_uri !== undefined && URL.parse(client.client_uri)?.hostname !== hostname) {
		warnings.push("client_uri_on_other_host");
	}
	return { hostname, ...(redirectUri === undefined ? {} : { redirect_uri: redirectUri }), warnings };
}

/** Whether a redirect URI lets another program on the device of the owner take the code: a loopback or a private-use scheme. */
export function isDeviceLocalRedirectUri(redirectUri: string): boolean {
	const url = URL.parse(redirectUri);
	return url?.protocol !== "https:" || LOOPBACK_HOSTS.has(url.hostname);
}
