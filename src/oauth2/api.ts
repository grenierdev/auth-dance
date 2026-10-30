import type { Context } from "hono";
import {
	ACCESS_TOKEN_TYPE,
	type AuthDanceApi,
	type AuthDanceRateLimit,
	type AuthDanceToken,
	REFRESH_TOKEN_TYPE,
	readToken,
} from "../api.ts";
import { ACCOUNT_SCOPE, type AuthDanceGrantType } from "../claims.ts";
import {
	AuthDanceError,
	AuthDanceUnknownError,
	ClaimsMapperError,
	InsufficientScopeError as CoreInsufficientScopeError,
	RateLimitedError,
} from "../error.ts";
import type { AuthDanceIdentity } from "../identity.ts";
import type { AuthDanceKeys } from "../keys.ts";
import type { AuthDanceTokenResponse } from "../response.ts";
import type { AuthDanceSession } from "../session.ts";
import type { AuthDanceStorage } from "../storage.ts";
import {
	type AuthDanceOauth2Client,
	type AuthDanceOauth2ClientMetadata,
	type AuthDanceOauth2ClientPublic,
	checkClientMetadata,
	DEVICE_CODE_GRANT_TYPE,
	isPublic,
	matchRedirectUri,
	parseClientMetadata,
	toPublicClient,
} from "./client.ts";
import { authenticateClient, readClientCredentials } from "./client-auth.ts";
import { formatUserCode, generateUserCode, normalizeUserCode } from "./device.ts";
import {
	AuthDanceOauth2Error,
	AuthorizationPendingError,
	DeviceAccessDeniedError,
	ExpiredTokenError,
	InsufficientScopeError,
	InvalidClientError,
	InvalidGrantError,
	InvalidRequestError,
	InvalidScopeError,
	InvalidTokenError,
	InvalidUserCodeError,
	ServerError,
	SlowDownError,
	UnauthorizedClientError,
	UnsupportedGrantTypeError,
	UnsupportedResponseTypeError,
} from "./error.ts";
import { readParams } from "./params.ts";
import { isCodeChallenge, verifyCodeVerifier } from "./pkce.ts";
import {
	type AuthorizationRequest,
	type ConsentRecord,
	clientSessionRecords,
	codeRecords,
	consentRecords,
	constantTimeEqual,
	type DeviceChallengeRecord,
	type DeviceRecord,
	type DeviceRequest,
	deviceChallengeRecords,
	deviceRecords,
	isDeviceRequest,
	isRandomToken,
	type KvRecord,
	type LoginRecord,
	type LoginResult,
	loginRecords,
	randomToken,
	rememberedConsentRecords,
	sha256,
	userCodeRecords,
} from "./records.ts";
import type { AuthDanceOauth2ClientStorage } from "./storage.ts";

/** The buckets the oauth2 HTTP layer consumes. The HTTP layer keys each one on the address of the caller. */
export interface AuthDanceOauth2AddressRateLimits {
	/** Every request, whatever the route. @defaultValue `{ limit: 300, window: 60 }` */
	request?: AuthDanceRateLimit;
	/** The token endpoint, on top of `request`. @defaultValue `{ limit: 60, window: 60 }` */
	token?: AuthDanceRateLimit;
	/**
	 * Each check of a client secret, at any endpoint. A secret is 32 random bytes, so this bucket only matters for a
	 * secret that an administrator chose. @defaultValue `{ limit: 100, window: 300 }`
	 */
	client_auth?: AuthDanceRateLimit;
	/** The registration endpoint, on top of `request`. Each request counts. @defaultValue `{ limit: 10, window: 3600 }` */
	register?: AuthDanceRateLimit;
	/** The introspection endpoint, on top of `request`. @defaultValue `{ limit: 300, window: 60 }` */
	introspect?: AuthDanceRateLimit;
	/** The revocation endpoint, on top of `request`. @defaultValue `{ limit: 60, window: 60 }` */
	revoke?: AuthDanceRateLimit;
	/** The device authorization endpoint, on top of `request`. @defaultValue `{ limit: 60, window: 60 }` */
	device_authorization?: AuthDanceRateLimit;
	/**
	 * Each visit to the verification URI, on top of `request`. Each visit gives the device page a few tries at a user
	 * code, so this bucket bounds how fast one address can guess. @defaultValue `{ limit: 30, window: 60 }`
	 */
	device?: AuthDanceRateLimit;
}

/** The buckets `AuthDanceOauth2Api` consumes, keyed on the client that calls. */
export interface AuthDanceOauth2ClientRateLimits {
	/** Each introspection a client asks for, from any address. @defaultValue `{ limit: 600, window: 60 }` */
	introspect?: AuthDanceRateLimit;
}

/** What the library hands `onError` when a hook rejects, or when the `claims` mapper fails. */
export interface AuthDanceOauth2HookErrorEvent {
	/** The hook that rejected, or `claims` for the mapper. */
	source: Exclude<keyof AuthDanceOauth2Hooks, "onError"> | "claims";
	/** What the hook rejected with, what the mapper threw, or the rule the result of the mapper broke. */
	cause: unknown;
}

/**
 * The listeners the library calls after it changes a grant or a client. A grant is the session a consent creates for a
 * client. A hook that rejects never fails the request, and `onError` gets every rejection.
 */
export interface AuthDanceOauth2Hooks {
	/** A code exchange or a device poll minted the first tokens of the session of a consent. */
	onGrantCreated?(event: { session: AuthDanceSession }): void | Promise<void>;
	/**
	 * The library deleted the session of a consent: a revocation, a reused code, an identity that is gone, or a deleted
	 * client. A delete or a reset in the core reports to the `onSessionDeleted` hook of the core instead. A sign-out in
	 * the core leaves every grant.
	 */
	onGrantRevoked?(event: { session: AuthDanceSession }): void | Promise<void>;
	/** `registerClient` stored a new client, through the registration endpoint or a setup script. */
	onClientRegistered?(event: { client: AuthDanceOauth2ClientPublic }): void | Promise<void>;
	/** Another hook rejected, or the `claims` mapper failed. The library drops a rejection from this hook. */
	onError?(event: AuthDanceOauth2HookErrorEvent): void | Promise<void>;
}

/** Everything `AuthDanceOauth2Api` needs to act as an OAuth 2.0 authorization server. */
export interface AuthDanceOauth2ApiOptions {
	/**
	 * The core state machine. The oauth2 module mints and verifies every token with it, reads the scopes it knows, and
	 * keeps its records in `api.storage`.
	 */
	api: AuthDanceApi;
	/** The registered clients. */
	clients: AuthDanceOauth2ClientStorage;
	/**
	 * The issuer URL: the `iss` of every token and the base of the metadata document. It must equal the issuer of
	 * `api`. The constructor raises `TypeError` when it does not.
	 */
	issuer: string;
	/**
	 * The pages the integrator serves. The authorization endpoint sends the browser to `login` with
	 * `?login_challenge=`, and to `consent` with `?consent_challenge=`. It sends the browser to `error` with `?error=`
	 * and `&error_description=` for an error it cannot send to the client. Without `error`, the endpoint shows a plain
	 * HTML page. Each URL is `https:`, or `http:` on `localhost`, `127.0.0.1` or `[::1]`.
	 *
	 * `device` opens the device authorization grant, RFC 8628. The verification URI sends the browser to it with
	 * `?device_challenge=`, where the owner types the user code. At the end of the flow the browser comes back with
	 * `?device_status=approved`, or with `?device_status=denied`, `&error=` and `&error_description=`. Without `device`,
	 * the device endpoints answer 404 and the metadata does not announce them.
	 */
	ui: { login: string; consent: string; error?: string; device?: string };
	/**
	 * How long each record lasts, in seconds. The lifetime of a token comes from the `durations` of `api`, the same for a
	 * dance and for every client.
	 */
	durations?: {
		/** How long a login or a consent challenge stays valid. @defaultValue 600 */
		challenge?: number;
		/**
		 * How long an authorization code stays valid. RFC 6749 §4.1.2 asks for 10 minutes at most. Workers KV refuses a
		 * time to live under 60 seconds. @defaultValue 60
		 */
		code?: number;
		/** How long a device code and its user code stay valid, the `expires_in` of RFC 8628 §3.2. @defaultValue 600 */
		device?: number;
	};
	/** How the device authorization grant behaves, once `ui.device` opens it. */
	device?: AuthDanceOauth2DeviceOptions;
	/** The rate limit buckets. Any bucket you omit keeps its default. */
	limits?: {
		/** The per-address buckets the oauth2 HTTP layer consumes. `AuthDanceOauth2Api` never reads them. */
		address?: AuthDanceOauth2AddressRateLimits;
		/** The per-client buckets `AuthDanceOauth2Api` consumes. */
		client?: AuthDanceOauth2ClientRateLimits;
	};
	/**
	 * Opens the registration endpoint, RFC 7591. Without this option, or with `false`, the endpoint answers 404 and the
	 * metadata does not announce it. @defaultValue `false`
	 */
	registration?: false | AuthDanceOauth2RegistrationOptions;
	/** How the introspection endpoint describes a token. */
	introspection?: {
		/**
		 * Gives the `username` of an active token, RFC 7662 §2.2, from its identity. Without it the answer carries no
		 * `username`. A client credentials token has no identity, so it never gets one.
		 */
		username?: (identity: AuthDanceIdentity) => string | undefined | Promise<string | undefined>;
	};
	/** The listeners the library calls after it changes a grant or a client. @defaultValue No listener. */
	hooks?: AuthDanceOauth2Hooks;
}

/** How the device authorization grant behaves, RFC 8628. */
export interface AuthDanceOauth2DeviceOptions {
	/**
	 * The verification URI the device shows, RFC 8628 §3.2. Make it short, the owner types it. It must lead to the
	 * `/device` route with its query, by a redirect for example. @defaultValue The `/device` route of the app
	 */
	verification_uri?: string;
	/** How long the device waits between two polls of the token endpoint, in seconds. @defaultValue 5 */
	interval?: number;
}

/** The answer of the device authorization endpoint, RFC 8628 §3.2. */
export interface AuthDanceOauth2DeviceAuthorization {
	/** The code the device polls the token endpoint with. Only the device sees it. */
	device_code: string;
	/** The code the owner types on the verification URI, as XXXX-XXXX. */
	user_code: string;
	/** Where the owner goes, on another device. */
	verification_uri: string;
	/** The verification URI with the user code, for a QR code or a link. */
	verification_uri_complete: string;
	/** How long the codes stay valid, in seconds. */
	expires_in: number;
	/** How long the device waits between two polls, in seconds. */
	interval: number;
}

/** One request to the device authorization endpoint, as the HTTP layer reads it. */
export interface AuthDanceOauth2DeviceAuthorizationRequest {
	/** Each parameter of the form body, one pair for each occurrence. */
	params: [string, string][];
	/** The `Authorization` header. */
	authorization?: string;
	/** The verification URI of the app, the `/device` route. `device.verification_uri` replaces it in the answer. */
	verification_uri: string;
}

/** One visit to the verification URI, as the HTTP layer reads it. */
export interface AuthDanceOauth2DeviceVerificationRequest {
	/** Each parameter of the query, one pair for each occurrence. `user_code` fills in the device page. */
	params: [string, string][];
	/** The absolute URL of the authorization endpoint, without a query. */
	endpoint: string;
	/** The verification URI the owner opened. */
	verification_uri: string;
}

/** What the device page reads about one visit to the verification URI. */
export interface AuthDanceOauth2DeviceRequest {
	/** The device challenge. */
	challenge: string;
	/** The user code of `verification_uri_complete`, as XXXX-XXXX, for the page to fill in. */
	user_code?: string;
}

/** The authorization server metadata, RFC 8414 §2. */
export interface AuthDanceOauth2Metadata {
	issuer: string;
	authorization_endpoint: string;
	token_endpoint: string;
	jwks_uri: string;
	scopes_supported: string[];
	response_types_supported: string[];
	response_modes_supported: string[];
	grant_types_supported: string[];
	token_endpoint_auth_methods_supported: string[];
	code_challenge_methods_supported: string[];
	authorization_response_iss_parameter_supported: boolean;
	introspection_endpoint: string;
	introspection_endpoint_auth_methods_supported: string[];
	revocation_endpoint: string;
	revocation_endpoint_auth_methods_supported: string[];
	/** Present when `options.registration` opens the registration endpoint. */
	registration_endpoint?: string;
	/** Present when `ui.device` opens the device authorization grant, RFC 8628 §4. */
	device_authorization_endpoint?: string;
}

/** How the registration endpoint takes a new client, RFC 7591. */
export interface AuthDanceOauth2RegistrationOptions {
	/**
	 * Checks the initial access token of a request, the bearer token of its `Authorization` header, RFC 7591 §3. A
	 * request with no token, or with a token this function refuses, answers 401 with `invalid_token`. Without this
	 * function, anyone can register a client: the owner still sees the client name on the consent page, but a client can
	 * take a name that misleads.
	 */
	authorize?: (initialAccessToken: string, c: Context) => boolean | Promise<boolean>;
	/**
	 * Rewrites or refuses the metadata before the store keeps it. Throw an `AuthDanceOauth2Error`, an
	 * `InvalidClientMetadataError` for example, to refuse. The result goes through the same checks as the request, and
	 * the fields only the server sets drop out.
	 */
	policy?: (metadata: AuthDanceOauth2ClientMetadata) => AuthDanceOauth2ClientMetadata | Promise<AuthDanceOauth2ClientMetadata>;
	/**
	 * The most a registered client may ask for. A request for more narrows to it. List `account` here to let a
	 * registered client ask to manage the account. @defaultValue Every scope the server knows but `account`
	 */
	scope?: string[];
	/** How long a client secret stays valid, in seconds. `0` means it never expires. @defaultValue 0 */
	secret_lifetime?: number;
}

/**
 * The answer of the registration endpoint, RFC 7591 §3.2.1: every field the server registered, the defaults included,
 * with each value of `localized` as a member of its own, `client_name#fr-CA` for example. `client_secret` and
 * `client_secret_expires_at` are present for a confidential client only.
 */
export type AuthDanceOauth2ClientRegistration = Omit<AuthDanceOauth2ClientPublic, "localized" | "client_secret_expires_at"> & {
	client_secret?: string;
	client_secret_expires_at?: number;
	[localized: `${string}#${string}`]: string;
};

/**
 * The answer of the introspection endpoint, RFC 7662 §2.2. An inactive token gives `{ active: false }` and nothing
 * else. An active access token gives every claim it carries, the claims of the `claims` mapper included.
 */
export interface AuthDanceOauth2Introspection {
	active: boolean;
	scope?: string;
	client_id?: string;
	username?: string;
	/** `Bearer` for an access token, and `refresh_token` for a refresh token. */
	token_type?: "Bearer" | "refresh_token";
	exp?: number;
	iat?: number;
	nbf?: number;
	sub?: string;
	aud?: string | string[];
	iss?: string;
	jti?: string;
	/** The moment of the sign-in behind the session, in seconds since the epoch. */
	auth_time?: number;
	/** The session the token belongs to. Absent for client credentials. */
	sid?: string;
	[claim: string]: unknown;
}

/** A grant, for an account page: the session of a consent, with the public record of the client that holds it. */
export interface AuthDanceOauth2Grant extends AuthDanceSession {
	/** The client that holds the grant, without its secret hash. Absent once the client is gone. */
	client?: AuthDanceOauth2ClientPublic;
}

/** What the login page reads about one authorization request. */
export interface AuthDanceOauth2LoginRequest {
	/** The login challenge. */
	challenge: string;
	/** The client that asks for access. */
	client: AuthDanceOauth2ClientPublic;
	/** The scopes the client asks for. */
	requested_scope: string[];
	/** The URL of the authorization request, or the verification URI for a device. */
	request_url: string;
	/** The user code, as XXXX-XXXX, when a device asks for access, RFC 8628. */
	user_code?: string;
}

/** What the consent page reads about one authorization request. */
export interface AuthDanceOauth2ConsentRequest {
	/** The consent challenge. */
	challenge: string;
	/** The client that asks for access. */
	client: AuthDanceOauth2ClientPublic;
	/** The scopes the client asks for. */
	requested_scope: string[];
	/** The identity id of the owner who signed in. */
	subject: string;
	/**
	 * True when the owner already granted every requested scope to this client, and asked to remember it. Always false
	 * for a device: the owner confirms each device, RFC 8628 §5.4.
	 */
	skip: boolean;
	/** The user code, as XXXX-XXXX, when a device asks for access. The page asks the owner to check it on the device. */
	user_code?: string;
}

/** How a login or a consent page refuses a request: an RFC 6749 error code, and a text for the client. */
export interface AuthDanceOauth2Rejection {
	/** The error code, `access_denied` or `login_required` for example. Printable ASCII with no `"` and no `\`. */
	error: string;
	/** The text for the client. The characters RFC 6749 §5.2 forbids drop out. */
	error_description?: string;
}

/** Where a login or a consent page sends the browser next, with a redirect. */
export interface AuthDanceOauth2Redirect {
	/** The authorization endpoint, with the verifier of the answer. */
	redirect_to: string;
}

/** One request to the authorization endpoint, as the HTTP layer reads it. */
export interface AuthDanceOauth2AuthorizeRequest {
	/** Each parameter of the query or the form body, one pair for each occurrence. */
	params: [string, string][];
	/** The absolute URL of the authorization endpoint, without a query. */
	endpoint: string;
}

/** The answer of the authorization endpoint: a 303 redirect. */
export interface AuthDanceOauth2AuthorizeResult {
	/** Where the browser goes next. */
	location: string;
}

/** One request to the token endpoint, as the HTTP layer reads it. */
export interface AuthDanceOauth2TokenRequest {
	/** Each parameter of the form body, one pair for each occurrence. */
	params: [string, string][];
	/** The `Authorization` header. */
	authorization?: string;
}

// RFC 6749 §5.2: the characters of a scope token, RFC 6749 §3.3, with the space added.
const ERROR_CODE = /^[\x20-\x21\x23-\x5B\x5D-\x7E]+$/;

// A key segment of a record: an identity id or a client id, with no `/`.
const SEGMENT = /^[A-Za-z0-9_.~-]+$/;

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

const ClientRateLimits: Required<AuthDanceOauth2ClientRateLimits> = {
	introspect: { limit: 600, window: 60 },
};

const Durations: Required<NonNullable<AuthDanceOauth2ApiOptions["durations"]>> = {
	challenge: 600,
	code: 60,
	device: 600,
};

// RFC 8628 §3.2: without `interval`, the device waits 5 seconds. §3.5: each `slow_down` adds 5.
const DEVICE_INTERVAL = 5;
const SLOW_DOWN = 5;

// How many wrong user codes one visit to the verification URI may send before its challenge ends.
const USER_CODE_ATTEMPTS = 5;

function checkPageUrl(name: string, value: unknown): void {
	const url = typeof value === "string" ? URL.parse(value) : null;
	if (!url || !(url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname)))) {
		throw new TypeError(`${name} ${value} is not an absolute https: URL`);
	}
}

function scopeList(value: string | undefined): string[] | undefined {
	return value === undefined ? undefined : [...new Set(value.split(" ").filter((scope) => scope !== ""))];
}

// Adds query parameters, and keeps the query the URL already holds, RFC 6749 §3.1.2.
function withParams(base: string, params: Record<string, string | undefined>): string {
	const url = new URL(base);
	for (const [name, value] of Object.entries(params)) {
		if (value !== undefined) {
			url.searchParams.set(name, value);
		}
	}
	return url.href;
}

// A verifier is `<challenge>.<random>`. The record holds the SHA-256 of the random part.
function readVerifier(value: string): [string, string] | undefined {
	const [challenge, secret, ...rest] = value.split(".");
	return rest.length === 0 && isRandomToken(challenge) && isRandomToken(secret) ? [challenge, secret] : undefined;
}

function now(): number {
	return Math.floor(Date.now() / 1000);
}

// The error a login or a consent page answered with. The code passes as it is, and the description goes through the
// filter of every other description.
class RejectionError extends AuthDanceOauth2Error {
	readonly error: string;
	readonly status = 403;

	constructor(rejection: AuthDanceOauth2Rejection) {
		super(rejection.error_description);
		this.error = rejection.error;
	}
}

function checkRejection(rejection: AuthDanceOauth2Rejection): AuthDanceOauth2Rejection {
	if (typeof rejection?.error !== "string" || !ERROR_CODE.test(rejection.error)) {
		throw new InvalidRequestError("error must be an RFC 6749 error code");
	}
	if (rejection.error_description !== undefined && typeof rejection.error_description !== "string") {
		throw new InvalidRequestError("error_description must be a string");
	}
	return { error: rejection.error, error_description: rejection.error_description };
}

type GrantHandler = (client: AuthDanceOauth2Client, params: Map<string, string>) => Promise<AuthDanceTokenResponse>;

/**
 * The protocol logic of the OAuth 2.0 authorization server, with no HTTP. It wraps one `AuthDanceApi`: it verifies the
 * tokens of a dance with it, and keeps its records in `api.storage`.
 *
 * The authorization endpoint hands each request to pages the integrator hosts. The login page reads the request with
 * `getLoginRequest`, lets the owner dance against the core app, and answers with `acceptLoginRequest` or
 * `rejectLoginRequest`. The consent page does the same with the consent methods. Each answer gives the URL to send
 * the browser to.
 *
 * A consent creates a session for the client, a grant, and every code, access token and refresh token of the grant
 * belongs to that session. The core mints the tokens, so they are the tokens of a dance, with the scopes and the client
 * of the grant. A grant stands alone: a sign-out of the session that signed in for it leaves it. A revocation ends it,
 * and so do a delete and a reset in the core. It lasts `durations.refresh` of the core from its consent.
 */
export class AuthDanceOauth2Api {
	#options: AuthDanceOauth2ApiOptions;
	// One handler for each grant type, RFC 6749 §4.5 keeps room for more.
	#grants: ReadonlyMap<string, GrantHandler> = new Map<string, GrantHandler>([
		["authorization_code", (client, params) => this.#exchangeCode(client, params)],
		["refresh_token", (client, params) => this.#refresh(client, params)],
		["client_credentials", (client, params) => this.#clientCredentials(client, params)],
		[DEVICE_CODE_GRANT_TYPE, (client, params) => this.#exchangeDeviceCode(client, params)],
	]);

	/**
	 * Builds the authorization server and checks its options.
	 *
	 * @throws {TypeError} When `options.issuer` differs from the issuer of `options.api`, when a URL of `options.ui` or
	 * `device.verification_uri` is not an absolute `https:` URL, or when `device.interval` is not a positive integer.
	 */
	constructor(options: AuthDanceOauth2ApiOptions) {
		if (options.issuer !== options.api.issuer) {
			throw new TypeError(`issuer ${options.issuer} differs from the issuer of api, ${options.api.issuer}`);
		}
		checkPageUrl("ui.login", options.ui?.login);
		checkPageUrl("ui.consent", options.ui?.consent);
		if (options.ui.error !== undefined) {
			checkPageUrl("ui.error", options.ui.error);
		}
		if (options.ui.device !== undefined) {
			checkPageUrl("ui.device", options.ui.device);
		}
		if (options.device?.verification_uri !== undefined) {
			checkPageUrl("device.verification_uri", options.device.verification_uri);
		}
		const interval = options.device?.interval;
		if (interval !== undefined && !(Number.isInteger(interval) && interval > 0)) {
			throw new TypeError("device.interval must be a positive integer");
		}
		this.#options = options;
	}

	/** The issuer URL, the `iss` of every token. */
	get issuer(): string {
		return this.#options.issuer;
	}

	/** The keys that sign the tokens, the keys of `api`. */
	get keys(): AuthDanceKeys {
		return this.#options.api.keys;
	}

	/** The registered clients. */
	get clients(): AuthDanceOauth2ClientStorage {
		return this.#options.clients;
	}

	/** The storage of the core state machine, where the oauth2 records live under `oauth2/`. */
	get storage(): AuthDanceStorage {
		return this.#options.api.storage;
	}

	/** The options of the registration endpoint, or `undefined` when the endpoint is closed. */
	get registration(): AuthDanceOauth2RegistrationOptions | undefined {
		return this.#options.registration || undefined;
	}

	/** The options of the device authorization grant, or `undefined` when `ui.device` does not open it. */
	get device(): AuthDanceOauth2DeviceOptions | undefined {
		return this.#options.ui.device === undefined ? undefined : (this.#options.device ?? {});
	}

	/** The public JWK Set of the keys, RFC 7517 §5. */
	jwks(): { keys: JsonWebKey[] } {
		return this.keys.jwks();
	}

	/**
	 * The authorization server metadata, RFC 8414 §2.
	 *
	 * @param endpoint The absolute URL the routes sit under, for example `https://auth.example.com/oauth2`.
	 */
	metadata(endpoint: string): AuthDanceOauth2Metadata {
		const base = endpoint.replace(/\/+$/, "");
		return {
			issuer: this.#options.issuer,
			authorization_endpoint: `${base}/authorize`,
			token_endpoint: `${base}/token`,
			jwks_uri: `${base}/jwks.json`,
			scopes_supported: Object.keys(this.#options.api.scopes),
			response_types_supported: ["code"],
			response_modes_supported: ["query"],
			grant_types_supported: [
				"authorization_code",
				"refresh_token",
				"client_credentials",
				...(this.device ? [DEVICE_CODE_GRANT_TYPE] : []),
			],
			token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
			code_challenge_methods_supported: ["S256"],
			authorization_response_iss_parameter_supported: true,
			introspection_endpoint: `${base}/introspect`,
			introspection_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
			revocation_endpoint: `${base}/revoke`,
			revocation_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
			...(this.#options.registration ? { registration_endpoint: `${base}/register` } : {}),
			...(this.device ? { device_authorization_endpoint: `${base}/device_authorization` } : {}),
		};
	}

	/**
	 * Handles one request to the authorization endpoint, RFC 6749 §4.1.1. The query sets the mode:
	 *
	 * - `login_verifier`: the login page answered. Without consent to ask for, the browser goes to the client with a
	 *   code. Otherwise it goes to the consent page.
	 * - `consent_verifier`: the consent page answered. The browser goes to the client with a code. For a device, it goes
	 *   to the device page with `device_status`, and the device gets its tokens at its next poll.
	 * - `device_verifier`: the device page took a user code, RFC 8628 §3.3. The browser goes to the login page.
	 * - None of them: a new request. The browser goes to the login page.
	 *
	 * Once the client and the redirect URI are valid, every error goes to the client, with `state` and `iss`,
	 * RFC 9207. Each verifier works one time.
	 *
	 * The server sets no cookie. A verifier in the URL is all it needs to continue a request, so the login, the consent
	 * and the device pages own the browser: they decide whether the browser that comes back is the one that left, and
	 * whether a returning owner has to dance again.
	 *
	 * @returns Where to send the browser with a 303.
	 * @throws AuthDanceOauth2Error for an error the server cannot send to the client: an unknown client, a redirect URI
	 * that does not match, or a verifier that is not valid. With `ui.error`, the method returns a redirect to that
	 * page instead.
	 */
	async authorize(request: AuthDanceOauth2AuthorizeRequest): Promise<AuthDanceOauth2AuthorizeResult> {
		try {
			const { params, repeated } = readParams(request.params);
			const verifiers = ["login_verifier", "consent_verifier", "device_verifier"] as const;
			if (verifiers.some((name) => repeated.includes(name))) {
				throw new InvalidRequestError("a verifier appears more than once");
			}
			const given = verifiers.filter((name) => params.has(name));
			if (given.length > 1) {
				throw new InvalidRequestError("the request carries more than one verifier");
			}
			const loginVerifier = params.get("login_verifier");
			if (loginVerifier !== undefined) {
				return await this.#continueLogin(loginVerifier);
			}
			const consentVerifier = params.get("consent_verifier");
			if (consentVerifier !== undefined) {
				return await this.#continueConsent(consentVerifier);
			}
			const deviceVerifier = params.get("device_verifier");
			if (deviceVerifier !== undefined) {
				return await this.#continueDevice(deviceVerifier);
			}
			return await this.#startAuthorization(params, repeated, request);
		} catch (error) {
			const page = this.#options.ui.error;
			if (error instanceof AuthDanceOauth2Error && page !== undefined) {
				return { location: withParams(page, { error: error.error, error_description: error.description }) };
			}
			throw error;
		}
	}

	/**
	 * Reads the authorization request behind a login challenge, for the login page.
	 *
	 * @throws InvalidRequestError when the challenge is unknown or expired, or when the client no longer exists.
	 */
	async getLoginRequest(challenge: string): Promise<AuthDanceOauth2LoginRequest> {
		const record = await this.#challenge(loginRecords, challenge);
		const client = await this.#client(record.request.client_id);
		return {
			challenge,
			client: toPublicClient(client),
			requested_scope: record.request.scope,
			request_url: record.request_url,
			...(isDeviceRequest(record.request) ? { user_code: formatUserCode(record.request.user_code) } : {}),
		};
	}

	/**
	 * Accepts a login. The identity, the session and the `auth_time` come from the access token of the dance, never from
	 * the login page. A page that keeps the owner signed in hands over the access token of that session, and skips the
	 * dance. The grant the consent creates does not depend on that session.
	 *
	 * @param options `access_token` is an access token of the session the owner signed in with. It must hold `account`.
	 * @returns Where the login page sends the browser.
	 * @throws InvalidRequestError when the challenge is unknown, expired or already answered, or when the access token
	 * is missing, not valid, without `account`, or its session ended.
	 */
	async acceptLoginRequest(challenge: string, options: { access_token: string }): Promise<AuthDanceOauth2Redirect> {
		const record = await this.#challenge(loginRecords, challenge);
		this.#requireUnanswered(record);
		if (typeof options?.access_token !== "string") {
			throw new InvalidRequestError("access_token is required");
		}
		const verified = await this.#options.api
			.verifyAccessToken(options.access_token, { scope: ACCOUNT_SCOPE, session: true })
			.catch((cause: unknown) => {
				throw new InvalidRequestError("access_token is not valid, or its session ended", { cause });
			});
		if (verified.session_id === undefined || verified.auth_time === undefined) {
			throw new InvalidRequestError("access_token has no session");
		}
		const login: LoginResult = { identityId: verified.subject, sessionId: verified.session_id, authTime: verified.auth_time };
		return this.#answer(loginRecords, challenge, record, { accepted: login }, "login_verifier");
	}

	/**
	 * Refuses a login. The client gets the error.
	 *
	 * @throws InvalidRequestError when the challenge is unknown, expired or already answered, or when the error is not
	 * an RFC 6749 error code.
	 */
	async rejectLoginRequest(challenge: string, error: AuthDanceOauth2Rejection): Promise<AuthDanceOauth2Redirect> {
		const record = await this.#challenge(loginRecords, challenge);
		this.#requireUnanswered(record);
		return this.#answer(loginRecords, challenge, record, { rejected: checkRejection(error) }, "login_verifier");
	}

	/**
	 * Reads the authorization request behind a consent challenge, for the consent page.
	 *
	 * @throws InvalidRequestError when the challenge is unknown or expired, or when the client no longer exists.
	 */
	async getConsentRequest(challenge: string): Promise<AuthDanceOauth2ConsentRequest> {
		const record = await this.#challenge(consentRecords, challenge);
		const client = await this.#client(record.request.client_id);
		const remembered = await rememberedConsentRecords.get(this.storage, [record.login.identityId, client.client_id]);
		const device = isDeviceRequest(record.request);
		return {
			challenge,
			client: toPublicClient(client),
			requested_scope: record.request.scope,
			subject: record.login.identityId,
			skip: !device && remembered !== undefined && record.request.scope.every((scope) => remembered.scopes.includes(scope)),
			...(isDeviceRequest(record.request) ? { user_code: formatUserCode(record.request.user_code) } : {}),
		};
	}

	/**
	 * Accepts a consent. The client learns the granted scopes from the `scope` of the token response, RFC 6749 §5.1.
	 *
	 * @param options `grant_scope` holds the scopes the owner granted, some or all of the requested scopes. `remember`
	 * keeps the consent, so a later request for these scopes skips the consent page.
	 * @returns Where the consent page sends the browser.
	 * @throws InvalidRequestError when the challenge is unknown, expired or already answered, or when `grant_scope`
	 * holds a scope the client did not ask for.
	 */
	async acceptConsentRequest(challenge: string, options: { grant_scope: string[]; remember?: boolean }): Promise<AuthDanceOauth2Redirect> {
		const record = await this.#challenge(consentRecords, challenge);
		this.#requireUnanswered(record);
		const grantScope = [...new Set(options.grant_scope)];
		if (!Array.isArray(options.grant_scope) || grantScope.some((scope) => !record.request.scope.includes(scope))) {
			throw new InvalidRequestError("grant_scope must hold only requested scopes");
		}
		return this.#answer(
			consentRecords,
			challenge,
			record,
			{ accepted: { grant_scope: grantScope, remember: options.remember ?? false } },
			"consent_verifier",
		);
	}

	/**
	 * Refuses a consent. The client gets the error, `access_denied` in most cases.
	 *
	 * @throws InvalidRequestError when the challenge is unknown, expired or already answered, or when the error is not
	 * an RFC 6749 error code.
	 */
	async rejectConsentRequest(challenge: string, error: AuthDanceOauth2Rejection): Promise<AuthDanceOauth2Redirect> {
		const record = await this.#challenge(consentRecords, challenge);
		this.#requireUnanswered(record);
		return this.#answer(consentRecords, challenge, record, { rejected: checkRejection(error) }, "consent_verifier");
	}

	/**
	 * Handles one request to the token endpoint, RFC 6749 §3.2. It authenticates the client, RFC 6749 §2.3, then runs
	 * the grant type: `authorization_code` with PKCE, `refresh_token`, `client_credentials`, or the device code of
	 * RFC 8628 §3.4 once `ui.device` opens it. The core mints the tokens, so they are the tokens of a dance.
	 *
	 * @throws InvalidRequestError for a missing or repeated parameter.
	 * @throws InvalidClientError when the client authentication fails.
	 * @throws UnsupportedGrantTypeError for another grant type, `password` among them.
	 * @throws UnauthorizedClientError when the client may not use the grant type.
	 * @throws InvalidGrantError when the code or the refresh token is not valid, expired, used, or of another client,
	 * and when its session was revoked.
	 * @throws InvalidScopeError for a scope the refresh token or the client does not hold.
	 * @throws AuthorizationPendingError, SlowDownError, DeviceAccessDeniedError or ExpiredTokenError while a device
	 * polls, RFC 8628 §3.5.
	 * @throws ServerError when the `claims` mapper fails.
	 */
	async token(request: AuthDanceOauth2TokenRequest): Promise<AuthDanceTokenResponse> {
		const { params, repeated } = readParams(request.params);
		if (repeated.length > 0) {
			throw new InvalidRequestError(`${repeated[0]} appears more than once`);
		}
		const client = await authenticateClient(this.clients, readClientCredentials(request.authorization, params));
		const grantType = params.get("grant_type");
		if (grantType === undefined) {
			throw new InvalidRequestError("grant_type is missing");
		}
		const handler = this.#grants.get(grantType);
		if (!handler || (grantType === DEVICE_CODE_GRANT_TYPE && !this.device)) {
			throw new UnsupportedGrantTypeError(`grant_type ${grantType} is not supported`);
		}
		if (!(client.grant_types as string[]).includes(grantType)) {
			throw new UnauthorizedClientError(`the client may not use grant_type ${grantType}`);
		}
		return handler(client, params);
	}

	/**
	 * Handles one request to the device authorization endpoint, RFC 8628 §3.1. It authenticates the client as the token
	 * endpoint does, so a public client sends its `client_id` alone, and answers with a device code for the device and
	 * a user code for the owner, RFC 8628 §3.2.
	 *
	 * @throws InvalidRequestError for a repeated parameter, or when `ui.device` does not open the grant.
	 * @throws InvalidClientError when the client authentication fails.
	 * @throws UnauthorizedClientError when the client may not use the device code grant type.
	 * @throws InvalidScopeError for a scope the client may not ask for.
	 */
	async deviceAuthorization(request: AuthDanceOauth2DeviceAuthorizationRequest): Promise<AuthDanceOauth2DeviceAuthorization> {
		const device = this.device;
		if (!device) {
			throw new InvalidRequestError("the server does not open the device authorization grant");
		}
		const { params, repeated } = readParams(request.params);
		if (repeated.length > 0) {
			throw new InvalidRequestError(`${repeated[0]} appears more than once`);
		}
		const client = await authenticateClient(this.clients, readClientCredentials(request.authorization, params));
		if (!client.grant_types.includes(DEVICE_CODE_GRANT_TYPE)) {
			throw new UnauthorizedClientError("the client may not use the device code grant type");
		}
		const allowed = this.#clientScopes(client);
		const scope = scopeList(params.get("scope")) ?? allowed;
		if (scope.length === 0 || scope.some((name) => !allowed.includes(name))) {
			throw new InvalidScopeError("the scope is unknown, empty, or more than the client may ask for");
		}
		const expiresIn = this.#duration("device");
		const interval = device.interval ?? DEVICE_INTERVAL;
		const deviceCode = randomToken();
		const hash = await sha256(deviceCode);
		const userCode = await this.#newUserCode();
		await userCodeRecords.set(this.storage, [userCode], { device_code: hash }, expiresIn);
		await deviceRecords.set(
			this.storage,
			[hash],
			{ client_id: client.client_id, scope, user_code: userCode, expiresAt: now() + expiresIn, interval, status: "pending" },
			2 * expiresIn,
		);
		const verificationUri = device.verification_uri ?? request.verification_uri;
		return {
			device_code: deviceCode,
			user_code: formatUserCode(userCode),
			verification_uri: verificationUri,
			verification_uri_complete: withParams(verificationUri, { user_code: formatUserCode(userCode) }),
			expires_in: expiresIn,
			interval,
		};
	}

	/**
	 * Handles one visit to the verification URI, RFC 8628 §3.3. The browser goes to the device page with a device
	 * challenge. A `user_code` in the query, from `verification_uri_complete`, is kept for the page to fill in.
	 *
	 * @returns Where to send the browser with a 303.
	 * @throws InvalidRequestError when `ui.device` does not open the grant.
	 */
	async startDeviceVerification(request: AuthDanceOauth2DeviceVerificationRequest): Promise<{ location: string }> {
		const page = this.#options.ui.device;
		if (page === undefined) {
			throw new InvalidRequestError("the server does not open the device authorization grant");
		}
		const { params } = readParams(request.params);
		const challenge = randomToken();
		await deviceChallengeRecords.set(
			this.storage,
			[challenge],
			{
				endpoint: request.endpoint,
				verification_uri: request.verification_uri,
				user_code: normalizeUserCode(params.get("user_code")),
				attempts: 0,
			},
			this.#duration("challenge"),
		);
		return { location: withParams(page, { device_challenge: challenge }) };
	}

	/**
	 * Reads a device challenge, for the device page.
	 *
	 * @throws InvalidRequestError when the challenge is unknown, expired or already answered.
	 */
	async getDeviceRequest(challenge: string): Promise<AuthDanceOauth2DeviceRequest> {
		const record = await this.#deviceChallenge(challenge);
		return { challenge, ...(record.user_code === undefined ? {} : { user_code: formatUserCode(record.user_code) }) };
	}

	/**
	 * Takes the user code the owner typed on the device page, RFC 8628 §3.3. Case does not count, and a dash or a space
	 * drops out. The answer sends the browser to the login page, then to the consent page, which always shows for a
	 * device, RFC 8628 §5.4.
	 *
	 * @returns Where the device page sends the browser.
	 * @throws InvalidUserCodeError when the code names no pending device request. The page asks again.
	 * @throws InvalidRequestError when the challenge is unknown, expired or already answered, or after too many wrong
	 * codes, which end the challenge.
	 */
	async acceptDeviceRequest(challenge: string, options: { user_code: string }): Promise<AuthDanceOauth2Redirect> {
		const record = await this.#deviceChallenge(challenge);
		const userCode = normalizeUserCode(options?.user_code);
		const index = userCode === undefined ? undefined : await userCodeRecords.get(this.storage, [userCode]);
		const device = index === undefined ? undefined : await deviceRecords.get(this.storage, [index.device_code]);
		if (!index || !device || device.status !== "pending" || device.expiresAt <= now()) {
			const attempts = record.attempts + 1;
			if (attempts >= USER_CODE_ATTEMPTS) {
				await deviceChallengeRecords.unset(this.storage, [challenge]);
				throw new InvalidRequestError("too many wrong user codes");
			}
			await deviceChallengeRecords.set(this.storage, [challenge], { ...record, attempts }, this.#duration("challenge"));
			throw new InvalidUserCodeError("the user code is not valid, or has expired");
		}
		const verifier = randomToken();
		await deviceChallengeRecords.set(
			this.storage,
			[challenge],
			{ ...record, device_code: index.device_code, verifier: await sha256(verifier) },
			this.#duration("challenge"),
		);
		return { redirect_to: withParams(record.endpoint, { device_verifier: `${challenge}.${verifier}` }) };
	}

	/**
	 * Says whether a token is active, RFC 7662. It reads an access token or a refresh token, whatever the hint, and
	 * the hint only sets which comes first.
	 *
	 * A token is active while its signature, `typ`, `iss` and `exp` pass and the session it names exists. A token of
	 * client credentials has no session: it is active while its client exists. The tokens of a dance are tokens like
	 * any other, with the issuer as `client_id`.
	 *
	 * A client sees the tokens issued to itself. A client with `introspect: true`, a resource server, sees every token.
	 * A token the caller may not see answers `{ active: false }`, exactly like a token that is not valid, RFC 7662 §4.
	 *
	 * @param caller The client that asks, authenticated.
	 * @param token The token to describe.
	 * @param hint `access_token` or `refresh_token`. Any other value counts as absent.
	 * @throws InvalidClientError when the caller is a public client.
	 * @throws RateLimitedError when the `introspect` bucket of the caller is empty.
	 */
	async introspect(caller: AuthDanceOauth2Client, token: string, hint?: string): Promise<AuthDanceOauth2Introspection> {
		if (isPublic(caller)) {
			throw new InvalidClientError("a public client may not introspect a token");
		}
		const { limit, window } = this.#options.limits?.client?.introspect ?? ClientRateLimits.introspect;
		const { allowed, retryAfter } = await this.storage.consumeRateLimit(`introspect:${caller.client_id}`, limit, window * 1000);
		if (!allowed) {
			throw new RateLimitedError(retryAfter);
		}
		for (const typ of this.#tokenTypes(hint)) {
			const read = await this.#readToken(token, typ, false);
			if (read) {
				if (!this.#mayIntrospect(caller, read.client_id)) {
					return { active: false };
				}
				const identity = await this.#tokenIdentity(read);
				if (identity === null) {
					return { active: false };
				}
				const token_type = typ === ACCESS_TOKEN_TYPE ? "Bearer" : "refresh_token";
				return { ...read.claims, active: true, token_type, ...(await this.#username(identity)) };
			}
		}
		return { active: false };
	}

	/**
	 * Revokes the session of a token, RFC 7009. An access token or a refresh token ends its whole session, and every
	 * token of the session with it. An access token revokes even after `exp`: it is the one way to end a JWT before
	 * `exp`, and the revocation does no harm.
	 *
	 * The method does nothing, and does not say so, for a token of another client, a token that is not valid, a session
	 * already revoked, and a token of client credentials, which has no session to end, RFC 7009 §2.1 and §2.2. A
	 * resource server that only checks the signature still accepts an access token until `exp`. It sees the revocation
	 * through introspection, or the `verifyAccessToken` of the core with `session: true`.
	 *
	 * @param caller The client that asks, authenticated. A public client revokes its own tokens.
	 * @param token The token to revoke.
	 * @param hint `access_token` or `refresh_token`. It only sets which lookup runs first.
	 */
	async revoke(caller: AuthDanceOauth2Client, token: string, hint?: string): Promise<void> {
		for (const typ of this.#tokenTypes(hint)) {
			const read = await this.#readToken(token, typ, true);
			if (read) {
				if (read.client_id === caller.client_id && read.session_id !== undefined) {
					const session = await this.storage.getSession(read.session_id);
					if (session?.client_id === caller.client_id && session.identityId === read.subject) {
						await this.#revokeSession(session);
					}
				}
				return;
			}
		}
	}

	/**
	 * Lists the grants of one identity, oldest first: the sessions of the consents it gave, so the clients that have
	 * access to the account. The sessions of a dance are not grants.
	 *
	 * @returns Each grant with the public record of its client. An id with a `/` gives an empty list.
	 */
	async listGrants(identityId: string): Promise<AuthDanceOauth2Grant[]> {
		const grants = await this.#grantSessions(identityId);
		const clients = new Map<string, Promise<AuthDanceOauth2Client | undefined>>();
		for (const { client_id } of grants) {
			if (!clients.has(client_id)) {
				clients.set(client_id, this.clients.getClient(client_id));
			}
		}
		return Promise.all(
			grants.map(async (session) => {
				const client = await clients.get(session.client_id);
				return client ? { ...session, client: toPublicClient(client) } : session;
			}),
		);
	}

	/**
	 * Lists the grants of the owner an access token names, oldest first, for an account page. `GET /grants` runs it.
	 * The token needs `account` and a session that still exists: the token of a dance, or of a client the owner gave
	 * `account` to.
	 *
	 * @returns Each grant with the public record of its client.
	 * @throws InvalidTokenError when the access token is not valid, or its session ended.
	 * @throws InsufficientScopeError when the access token does not hold `account`.
	 */
	async listOwnGrants(access_token: string): Promise<AuthDanceOauth2Grant[]> {
		return this.listGrants(await this.#accountOwner(access_token));
	}

	/**
	 * Revokes one grant of the owner an access token names, for an account page. `DELETE /grants/{id}` runs it. The
	 * token needs `account` and a session that still exists. The method also forgets the consent the owner kept for the
	 * client of the grant, so the next request of that client asks for consent again. It fires `onGrantRevoked`.
	 *
	 * An id that names no grant of that owner does nothing, and does not say so: a grant of another owner, the session
	 * of a dance and an unknown id all get the same answer.
	 *
	 * @param grantId The id of the session of the grant, `id` in the list of `listOwnGrants`.
	 * @throws InvalidTokenError when the access token is not valid, or its session ended.
	 * @throws InsufficientScopeError when the access token does not hold `account`.
	 */
	async revokeOwnGrant(access_token: string, grantId: string): Promise<void> {
		const identityId = await this.#accountOwner(access_token);
		const session = SEGMENT.test(grantId) ? await this.storage.getSession(grantId) : undefined;
		if (session && session.identityId === identityId && session.client_id !== this.#options.api.clientId) {
			await this.#revokeSession(session);
			await rememberedConsentRecords.unset(this.storage, [identityId, session.client_id]);
		}
	}

	// The identity behind an access token that may manage the account: it holds `account`, and its session exists.
	async #accountOwner(access_token: string): Promise<string> {
		const token = await this.#options.api
			.verifyAccessToken(access_token, { scope: ACCOUNT_SCOPE, session: true })
			.catch((cause: unknown) => {
				if (cause instanceof CoreInsufficientScopeError) {
					throw new InsufficientScopeError("the access token does not hold account", { cause });
				}
				if (cause instanceof AuthDanceError) {
					throw new InvalidTokenError("the access token is not valid, or its session ended", { cause });
				}
				throw cause;
			});
		return token.subject;
	}

	/**
	 * Revokes one grant by the id of its session, and fires `onGrantRevoked`. An id that names no grant does nothing.
	 * The session of a dance is not a grant: end it with the `signOut` of the core.
	 */
	async revokeGrant(sessionId: string): Promise<void> {
		const session = SEGMENT.test(sessionId) ? await this.storage.getSession(sessionId) : undefined;
		if (session && session.client_id !== this.#options.api.clientId) {
			await this.#revokeSession(session);
		}
	}

	/**
	 * Revokes every grant one identity gave to one client, and forgets the consent the identity kept for that client, so
	 * the next request asks for consent again.
	 */
	async revokeClientGrants(identityId: string, clientId: string): Promise<void> {
		if (!SEGMENT.test(identityId) || !SEGMENT.test(clientId)) {
			return;
		}
		for (const session of await this.#grantSessions(identityId)) {
			if (session.client_id === clientId) {
				await this.#revokeSession(session);
			}
		}
		await rememberedConsentRecords.unset(this.storage, [identityId, clientId]);
	}

	/**
	 * Revokes every grant of a client, then deletes the client. `AuthDanceOauth2ClientStorage.deleteClient` deletes the
	 * client only: the access tokens of its grants stay valid until `exp`, and its refresh tokens until their sessions
	 * end. A token of client credentials stays valid until `exp`, and introspection calls it inactive at once.
	 */
	async deleteClient(clientId: string): Promise<void> {
		if (SEGMENT.test(clientId)) {
			for (const sessionId of await clientSessionRecords.list(this.storage, [clientId])) {
				await clientSessionRecords.unset(this.storage, [clientId, sessionId]);
				const session = SEGMENT.test(sessionId) ? await this.storage.getSession(sessionId) : undefined;
				if (session?.client_id === clientId) {
					await this.#revokeSession(session);
				}
			}
		}
		await this.clients.deleteClient(clientId);
	}

	/**
	 * Registers a client, RFC 7591 §3. The registration endpoint calls it with `registered_by: "dynamic"`. A setup
	 * script calls it with `registered_by: "admin"`: the same checks run, and the body can then set `skip_consent`,
	 * `introspect` and `audience`.
	 *
	 * A dynamic client asks for no more than `registration.scope`, goes through `registration.policy`, and gets a
	 * secret that expires after `registration.secret_lifetime`. It never gets the fields only the server sets.
	 *
	 * @param metadata The client metadata of the request, as JSON.
	 * @returns The registered client, with the secret for a confidential client. The store keeps only the hash of the
	 * secret, so this is the one time it is readable.
	 * @throws InvalidClientMetadataError, InvalidRedirectUriError or UnapprovedSoftwareStatementError when the
	 * metadata does not pass, and any error `registration.policy` throws.
	 */
	async registerClient(
		metadata: unknown,
		options: { registered_by?: "dynamic" | "admin" } = {},
	): Promise<AuthDanceOauth2ClientRegistration> {
		const registeredBy = options.registered_by ?? "dynamic";
		const known = Object.keys(this.#options.api.scopes);
		const registration = this.registration;
		const offered = registration?.scope ?? known.filter((scope) => scope !== ACCOUNT_SCOPE);
		const ceiling = registeredBy === "dynamic" ? offered.filter((scope) => known.includes(scope)) : known;
		let parsed = parseClientMetadata(metadata, { scope: ceiling, registered_by: registeredBy });
		if (registeredBy === "dynamic" && registration?.policy) {
			const { skip_consent: _skip, introspect: _introspect, audience: _audience, ...rewritten } = await registration.policy(parsed);
			parsed = { ...rewritten, registered_by: "dynamic" };
			checkClientMetadata(parsed);
		}
		const lifetime = registeredBy === "dynamic" ? (registration?.secret_lifetime ?? 0) : 0;
		const { client, client_secret } = await this.clients.createClient({
			...parsed,
			client_secret_expires_at: lifetime > 0 ? now() + lifetime : 0,
		});
		await this.#emit("onClientRegistered", { client: toPublicClient(client) });
		const { localized, client_secret_expires_at, ...fields } = toPublicClient(client);
		return {
			...fields,
			...localized,
			...(client_secret === undefined ? {} : { client_secret, client_secret_expires_at }),
		};
	}

	#duration(name: keyof typeof Durations): number {
		return this.#options.durations?.[name] ?? Durations[name];
	}

	// The sessions of the grants of one identity, oldest first. An id with a `/` gives an empty list.
	async #grantSessions(identityId: string): Promise<AuthDanceSession[]> {
		if (!SEGMENT.test(identityId)) {
			return [];
		}
		return (await this.storage.listSession(identityId))
			.filter((session) => session.client_id !== this.#options.api.clientId)
			.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
	}

	// The scopes of the client that the server still knows.
	#clientScopes(client: AuthDanceOauth2Client): string[] {
		const known = this.#options.api.scopes;
		return (scopeList(client.scope) ?? []).filter((scope) => Object.hasOwn(known, scope));
	}

	// Ends a request that failed after its client and its redirect URI passed. An authorization request sends the error
	// to the client, with `state` and `iss`. A device request records the denial for the next poll, and sends the browser
	// to the device page.
	async #fail(record: LoginRecord | ConsentRecord, error: AuthDanceOauth2Error): Promise<AuthDanceOauth2AuthorizeResult> {
		const { request } = record;
		if (isDeviceRequest(request)) {
			await this.#denyDevice(request, { error: error.error, error_description: error.description });
			return { location: this.#devicePage({ device_status: "denied", error: error.error, error_description: error.description }) };
		}
		const location = withParams(request.redirect_uri, {
			error: error.error,
			error_description: error.description,
			state: request.state,
			iss: this.issuer,
		});
		return { location };
	}

	#devicePage(params: Record<string, string | undefined>): string {
		return withParams(this.#options.ui.device ?? "", params);
	}

	// A user code that no pending request uses. Two requests at once could draw the same code, so the loop reads the
	// index first. With 2^34.5 codes, a second draw almost never runs.
	async #newUserCode(): Promise<string> {
		for (;;) {
			const code = generateUserCode();
			if (!(await userCodeRecords.get(this.storage, [code]))) {
				return code;
			}
		}
	}

	async #deviceChallenge(challenge: string): Promise<DeviceChallengeRecord> {
		const record = isRandomToken(challenge) ? await deviceChallengeRecords.get(this.storage, [challenge]) : undefined;
		if (!record || record.verifier !== undefined) {
			throw new InvalidRequestError("the device challenge is unknown, expired or already answered");
		}
		return record;
	}

	// The time to live left to a device record: it lasts twice `durations.device` from its start.
	#deviceTtl(record: DeviceRecord): number {
		return Math.max(1, record.expiresAt + this.#duration("device") - now());
	}

	// Records the denial of a pending device request, and frees its user code.
	async #denyDevice(request: DeviceRequest, rejected: AuthDanceOauth2Rejection): Promise<void> {
		const device = await deviceRecords.get(this.storage, [request.device_code]);
		if (device?.status !== "pending") {
			return;
		}
		await deviceRecords.set(this.storage, [request.device_code], { ...device, status: "denied", rejected }, this.#deviceTtl(device));
		await userCodeRecords.unset(this.storage, [device.user_code]);
	}

	async #client(clientId: string): Promise<AuthDanceOauth2Client> {
		const client = await this.clients.getClient(clientId);
		if (!client) {
			throw new InvalidRequestError("the client no longer exists");
		}
		return client;
	}

	async #challenge<T extends LoginRecord | ConsentRecord>(records: KvRecord<T>, challenge: string): Promise<T> {
		const record = isRandomToken(challenge) ? await records.get(this.storage, [challenge]) : undefined;
		if (!record) {
			throw new InvalidRequestError("the challenge is unknown or expired");
		}
		return record;
	}

	#requireUnanswered(record: LoginRecord | ConsentRecord): void {
		if (record.verifier !== undefined) {
			throw new InvalidRequestError("the challenge was already answered");
		}
	}

	async #answer<T extends LoginRecord | ConsentRecord>(
		records: KvRecord<T>,
		challenge: string,
		record: T,
		answer: Partial<T>,
		param: "login_verifier" | "consent_verifier",
	): Promise<AuthDanceOauth2Redirect> {
		const verifier = randomToken();
		await records.set(this.storage, [challenge], { ...record, ...answer, verifier: await sha256(verifier) }, this.#duration("challenge"));
		return { redirect_to: withParams(record.endpoint, { [param]: `${challenge}.${verifier}` }) };
	}

	// Loads the record a verifier names, and deletes it, so the verifier works one time.
	async #redeem<T extends { verifier?: string }>(records: KvRecord<T>, verifier: string): Promise<[string, T]> {
		const parts = readVerifier(verifier);
		const record = parts ? await records.get(this.storage, [parts[0]]) : undefined;
		if (!parts || !record?.verifier || !constantTimeEqual(await sha256(parts[1]), record.verifier)) {
			throw new InvalidRequestError("the verifier is not valid, or was already used");
		}
		await records.unset(this.storage, [parts[0]]);
		return [parts[0], record];
	}

	// Mode 1: a new authorization request.
	async #startAuthorization(
		params: Map<string, string>,
		repeated: string[],
		request: AuthDanceOauth2AuthorizeRequest,
	): Promise<AuthDanceOauth2AuthorizeResult> {
		// RFC 6749 §4.1.2.1: until the client and the redirect URI are valid, no error goes to the redirect URI.
		if (repeated.includes("client_id") || repeated.includes("redirect_uri")) {
			throw new InvalidRequestError("client_id and redirect_uri may appear one time only");
		}
		const clientId = params.get("client_id");
		if (clientId === undefined) {
			throw new InvalidRequestError("client_id is missing");
		}
		const client = await this.clients.getClient(clientId);
		if (!client) {
			throw new InvalidRequestError("client_id names no client");
		}
		const given = params.get("redirect_uri");
		let redirectUri: string;
		if (given !== undefined) {
			if (!matchRedirectUri(client, given)) {
				throw new InvalidRequestError("redirect_uri does not match a registered redirect URI");
			}
			redirectUri = given;
		} else if (client.redirect_uris.length === 1) {
			redirectUri = client.redirect_uris[0];
		} else {
			throw new InvalidRequestError("redirect_uri is missing, and the client has more than one");
		}

		const state = params.get("state");
		const fail = (error: AuthDanceOauth2Error): AuthDanceOauth2AuthorizeResult => ({
			location: withParams(redirectUri, { error: error.error, error_description: error.description, state, iss: this.issuer }),
		});
		if (repeated.length > 0) {
			return fail(new InvalidRequestError(`${repeated[0]} appears more than once`));
		}
		const responseType = params.get("response_type");
		if (responseType === undefined) {
			return fail(new InvalidRequestError("response_type is missing"));
		}
		if (responseType !== "code") {
			return fail(new UnsupportedResponseTypeError("only response_type=code is supported"));
		}
		if (!client.grant_types.includes("authorization_code")) {
			return fail(new UnauthorizedClientError("the client may not use the authorization code grant"));
		}
		const codeChallenge = params.get("code_challenge");
		if (!isCodeChallenge(codeChallenge) || params.get("code_challenge_method") !== "S256") {
			return fail(new InvalidRequestError("PKCE is required: code_challenge with code_challenge_method=S256"));
		}
		const allowed = this.#clientScopes(client);
		const scope = scopeList(params.get("scope")) ?? allowed;
		if (scope.length === 0 || scope.some((name) => !allowed.includes(name))) {
			return fail(new InvalidScopeError("the scope is unknown, empty, or more than the client may ask for"));
		}

		const authorization: AuthorizationRequest = {
			client_id: client.client_id,
			redirect_uri: redirectUri,
			redirect_uri_given: given !== undefined,
			scope,
			state,
			code_challenge: codeChallenge,
		};
		return this.#beginLogin(authorization, `${request.endpoint}?${new URLSearchParams(request.params)}`, request.endpoint);
	}

	// Stores the login challenge of a request, and sends the browser to the login page.
	async #beginLogin(
		request: AuthorizationRequest | DeviceRequest,
		requestUrl: string,
		endpoint: string,
	): Promise<AuthDanceOauth2AuthorizeResult> {
		const challenge = randomToken();
		await loginRecords.set(this.storage, [challenge], { request, request_url: requestUrl, endpoint }, this.#duration("challenge"));
		return { location: withParams(this.#options.ui.login, { login_challenge: challenge }) };
	}

	// Mode 4: the device page took a user code. The device request goes through the login and the consent pages.
	async #continueDevice(verifier: string): Promise<AuthDanceOauth2AuthorizeResult> {
		const [, record] = await this.#redeem(deviceChallengeRecords, verifier);
		const device = record.device_code === undefined ? undefined : await deviceRecords.get(this.storage, [record.device_code]);
		if (!record.device_code || !device || device.status !== "pending" || device.expiresAt <= now()) {
			throw new InvalidRequestError("the device request is no longer pending");
		}
		const client = await this.#client(device.client_id);
		const request: DeviceRequest = {
			client_id: client.client_id,
			scope: device.scope,
			device_code: record.device_code,
			user_code: device.user_code,
		};
		return this.#beginLogin(request, record.verification_uri, record.endpoint);
	}

	// Mode 2: the login page answered.
	async #continueLogin(verifier: string): Promise<AuthDanceOauth2AuthorizeResult> {
		const [, record] = await this.#redeem(loginRecords, verifier);
		if (record.rejected) {
			return this.#fail(record, new RejectionError(record.rejected));
		}
		if (!record.accepted) {
			throw new InvalidRequestError("the login challenge has no answer");
		}
		const { request } = record;
		const client = await this.#client(request.client_id);
		const remembered = await rememberedConsentRecords.get(this.storage, [record.accepted.identityId, client.client_id]);
		// RFC 8628 §5.4: a user code can come from someone else, so the owner confirms each device on the consent page.
		if (
			!isDeviceRequest(request) &&
			(client.skip_consent || (remembered && request.scope.every((scope) => remembered.scopes.includes(scope))))
		) {
			return this.#issueCode(record, request, record.accepted, request.scope, false);
		}
		const challenge = randomToken();
		await consentRecords.set(
			this.storage,
			[challenge],
			{ request: record.request, endpoint: record.endpoint, login: record.accepted },
			this.#duration("challenge"),
		);
		return { location: withParams(this.#options.ui.consent, { consent_challenge: challenge }) };
	}

	// Mode 3: the consent page answered.
	async #continueConsent(verifier: string): Promise<AuthDanceOauth2AuthorizeResult> {
		const [, record] = await this.#redeem(consentRecords, verifier);
		if (record.rejected) {
			return this.#fail(record, new RejectionError(record.rejected));
		}
		if (!record.accepted) {
			throw new InvalidRequestError("the consent challenge has no answer");
		}
		const { request } = record;
		if (isDeviceRequest(request)) {
			return this.#approveDevice(record, request, record.accepted.grant_scope, record.accepted.remember);
		}
		return this.#issueCode(record, request, record.login, record.accepted.grant_scope, record.accepted.remember);
	}

	// Creates the session of an accepted login and consent, the grant, and keeps the consent when the owner asked for
	// it. The grant stands alone: it does not depend on the session of the sign-in, and lasts `durations.refresh` of the
	// core from now.
	async #createSession(clientId: string, login: LoginResult, grantScope: string[], rememberConsent: boolean): Promise<AuthDanceSession> {
		const session = await this.storage.createSession({
			identityId: login.identityId,
			client_id: clientId,
			scopes: grantScope,
			expireAt: new Date(Date.now() + this.#options.api.sessionDuration * 1000),
		});
		await clientSessionRecords.set(
			this.storage,
			[clientId, session.id],
			{ identityId: login.identityId },
			this.#options.api.sessionDuration,
		);
		if (rememberConsent) {
			const remembered = await rememberedConsentRecords.get(this.storage, [login.identityId, clientId]);
			await rememberedConsentRecords.set(this.storage, [login.identityId, clientId], {
				scopes: [...new Set([...(remembered?.scopes ?? []), ...grantScope])],
				grantedAt: now(),
			});
		}
		return session;
	}

	// Approves a device request, RFC 8628 §3.3: the session waits in the device record for the next poll, and the
	// browser goes to the device page.
	async #approveDevice(
		record: ConsentRecord,
		request: DeviceRequest,
		grantScope: string[],
		rememberConsent: boolean,
	): Promise<AuthDanceOauth2AuthorizeResult> {
		const device = await deviceRecords.get(this.storage, [request.device_code]);
		if (device?.status !== "pending") {
			return this.#fail(record, new InvalidRequestError("the device request is no longer pending"));
		}
		if (device.expiresAt <= now()) {
			return this.#fail(record, new ExpiredTokenError("the device request has expired"));
		}
		const session = await this.#createSession(request.client_id, record.login, grantScope, rememberConsent);
		await deviceRecords.set(
			this.storage,
			[request.device_code],
			{ ...device, status: "approved", session_id: session.id, auth_time: record.login.authTime },
			this.#deviceTtl(device),
		);
		await userCodeRecords.unset(this.storage, [device.user_code]);
		return { location: this.#devicePage({ device_status: "approved" }) };
	}

	// Creates the session and the code, and sends the browser to the client, RFC 6749 §4.1.2 and RFC 9207.
	async #issueCode(
		_record: LoginRecord | ConsentRecord,
		request: AuthorizationRequest,
		login: LoginResult,
		grantScope: string[],
		rememberConsent: boolean,
	): Promise<AuthDanceOauth2AuthorizeResult> {
		const session = await this.#createSession(request.client_id, login, grantScope, rememberConsent);
		const code = randomToken();
		await codeRecords.set(
			this.storage,
			[await sha256(code)],
			{
				session_id: session.id,
				auth_time: login.authTime,
				client_id: request.client_id,
				redirect_uri: request.redirect_uri,
				redirect_uri_given: request.redirect_uri_given,
				code_challenge: request.code_challenge,
			},
			this.#duration("code"),
		);
		return { location: withParams(request.redirect_uri, { code, state: request.state, iss: this.issuer }) };
	}

	// RFC 6749 §4.1.3, with the PKCE check of RFC 7636 §4.6.
	async #exchangeCode(client: AuthDanceOauth2Client, params: Map<string, string>): Promise<AuthDanceTokenResponse> {
		const code = params.get("code");
		const verifier = params.get("code_verifier");
		if (code === undefined || verifier === undefined) {
			throw new InvalidRequestError("code and code_verifier are required");
		}
		const hash = await sha256(code);
		const record = await codeRecords.get(this.storage, [hash]);
		if (!record) {
			throw new InvalidGrantError("the code is not valid, or has expired");
		}
		// RFC 6749 §4.1.2: a second exchange shows that the code leaked, so the session ends.
		if (record.usedAt !== undefined) {
			await this.#revokeSessionById(record.session_id);
			throw new InvalidGrantError("the code was already used");
		}
		// The store has no compare-and-set. Two exchanges that both read the record before this write lands both pass.
		// On a store that is eventually consistent across locations, such as Workers KV, that window lasts up to about
		// 60 seconds between two locations. An adapter with a conditional write can close it later.
		await codeRecords.set(this.storage, [hash], { ...record, usedAt: now() }, this.#duration("code"));
		if (record.client_id !== client.client_id) {
			throw new InvalidGrantError("the code was issued to another client");
		}
		const redirectUri = params.get("redirect_uri");
		if (
			record.redirect_uri_given ? redirectUri !== record.redirect_uri : redirectUri !== undefined && redirectUri !== record.redirect_uri
		) {
			throw new InvalidGrantError("redirect_uri does not match the authorization request");
		}
		if (!(await verifyCodeVerifier(verifier, record.code_challenge))) {
			throw new InvalidGrantError("code_verifier does not match code_challenge");
		}
		return this.#mintFirst(client, record.session_id, record.auth_time, "authorization_code");
	}

	// RFC 8628 §3.4 and §3.5: the device polls until the owner approves or denies the request, or until it expires.
	async #exchangeDeviceCode(client: AuthDanceOauth2Client, params: Map<string, string>): Promise<AuthDanceTokenResponse> {
		const code = params.get("device_code");
		if (code === undefined) {
			throw new InvalidRequestError("device_code is missing");
		}
		const hash = await sha256(code);
		const device = await deviceRecords.get(this.storage, [hash]);
		if (!device || device.client_id !== client.client_id) {
			throw new InvalidGrantError("the device code is not valid");
		}
		// Like a code, a device code that works twice leaked, so the session ends.
		if (device.usedAt !== undefined) {
			if (device.session_id !== undefined) {
				await this.#revokeSessionById(device.session_id);
			}
			throw new InvalidGrantError("the device code was already used");
		}
		if (device.expiresAt <= now()) {
			throw new ExpiredTokenError("the device code has expired");
		}
		if (device.status === "denied") {
			throw new DeviceAccessDeniedError(device.rejected?.error_description ?? "the owner denied the request");
		}
		if (device.status === "pending") {
			const polledAt = now();
			const early = device.polledAt !== undefined && polledAt - device.polledAt < device.interval;
			const interval = early ? device.interval + SLOW_DOWN : device.interval;
			await deviceRecords.set(this.storage, [hash], { ...device, polledAt, interval }, this.#deviceTtl(device));
			throw early ? new SlowDownError(`wait ${interval} seconds between two polls`) : new AuthorizationPendingError();
		}
		// The store has no compare-and-set, as for a code: two polls that both read the record before this write lands both
		// pass.
		await deviceRecords.set(this.storage, [hash], { ...device, usedAt: now() }, this.#deviceTtl(device));
		if (device.session_id === undefined || device.auth_time === undefined) {
			throw new InvalidGrantError("the device request has no session");
		}
		return this.#mintFirst(client, device.session_id, device.auth_time, DEVICE_CODE_GRANT_TYPE);
	}

	// RFC 6749 §6. The core checks the refresh token and its session, and mints the new pair: a refresh token of a client
	// is a refresh token of a dance, with another `client_id`.
	async #refresh(client: AuthDanceOauth2Client, params: Map<string, string>): Promise<AuthDanceTokenResponse> {
		const token = params.get("refresh_token");
		if (token === undefined) {
			throw new InvalidRequestError("refresh_token is missing");
		}
		try {
			const refreshed = await this.#options.api.refreshToken(token, {
				client_id: client.client_id,
				scope: scopeList(params.get("scope")),
				audience: client.audience,
			});
			return refreshed.tokens;
		} catch (error) {
			throw await this.#tokenError(error);
		}
	}

	// RFC 6749 §4.4. A confidential client acts for itself: the token has no identity, no session and no refresh token,
	// and nothing is stored.
	async #clientCredentials(client: AuthDanceOauth2Client, params: Map<string, string>): Promise<AuthDanceTokenResponse> {
		if (isPublic(client)) {
			throw new UnauthorizedClientError("a public client may not use client_credentials");
		}
		const allowed = this.#clientScopes(client);
		const scope = scopeList(params.get("scope")) ?? allowed;
		if (scope.length === 0 || scope.some((name) => !allowed.includes(name))) {
			throw new InvalidScopeError("the scope is unknown, empty, or more than the client may ask for");
		}
		return this.#mint(client, { scopes: scope, grant_type: "client_credentials" });
	}

	// The first tokens of the session a code or a device code names.
	async #mintFirst(
		client: AuthDanceOauth2Client,
		sessionId: string,
		authTime: number,
		grantType: AuthDanceGrantType,
	): Promise<AuthDanceTokenResponse> {
		const session = await this.storage.getSession(sessionId);
		if (!session || session.client_id !== client.client_id) {
			throw new InvalidGrantError("the session of the grant was revoked");
		}
		const identity = await this.storage.getIdentity(session.identityId);
		if (!identity) {
			await this.#revokeSession(session);
			throw new InvalidGrantError("the identity behind the session is gone");
		}
		const response = await this.#mint(client, { scopes: session.scopes, grant_type: grantType, session, identity, authTime });
		await this.#emit("onGrantCreated", { session });
		return response;
	}

	// The core mints the tokens. A refresh token comes out for a client with the `refresh_token` grant type.
	async #mint(
		client: AuthDanceOauth2Client,
		options: {
			scopes: string[];
			grant_type: AuthDanceGrantType;
			session?: AuthDanceSession;
			identity?: AuthDanceIdentity;
			authTime?: number;
		},
	): Promise<AuthDanceTokenResponse> {
		try {
			const { tokens } = await this.#options.api.mintTokens({
				...options,
				client_id: client.client_id,
				audience: client.audience,
				refresh: client.grant_types.includes("refresh_token"),
			});
			return tokens;
		} catch (error) {
			throw await this.#tokenError(error);
		}
	}

	// The error of the core, as an RFC 6749 §5.2 error. A failure of the claims mapper reaches `onError`, and the client
	// sees `server_error`, with nothing internal.
	async #tokenError(error: unknown): Promise<unknown> {
		if (error instanceof ClaimsMapperError) {
			await this.#report({ source: "claims", cause: error.cause });
			return new ServerError(undefined, { cause: error.cause });
		}
		if (error instanceof CoreInsufficientScopeError) {
			return new InvalidScopeError("the scope must be some of the scopes of the refresh token");
		}
		if (error instanceof AuthDanceError && !(error instanceof RateLimitedError) && !(error instanceof AuthDanceUnknownError)) {
			return new InvalidGrantError("the refresh token is not valid, or its session ended", { cause: error });
		}
		return error;
	}

	// The token types to try, the hinted one first.
	#tokenTypes(hint: string | undefined): string[] {
		return hint === "refresh_token" ? [REFRESH_TOKEN_TYPE, ACCESS_TOKEN_TYPE] : [ACCESS_TOKEN_TYPE, REFRESH_TOKEN_TYPE];
	}

	// A token of this issuer of one type, for any audience. `undefined` when it does not pass. RFC 7009 §2.1 lets an
	// expired token revoke, so with `expired` the check of `exp` runs at the start of the epoch.
	async #readToken(token: string, typ: string, expired: boolean): Promise<AuthDanceToken | undefined> {
		const payload = await this.keys
			.verify(token, {
				issuer: this.issuer,
				typ,
				requiredClaims: ["sub", "client_id", "scope", "jti", "iat", "exp"],
				...(expired ? { currentDate: new Date(0) } : {}),
			})
			.catch(() => undefined);
		return payload && readToken(payload);
	}

	#mayIntrospect(caller: AuthDanceOauth2Client, clientId: string): boolean {
		return caller.client_id === clientId || caller.introspect === true;
	}

	// The identity of a live token, `undefined` for client credentials while the client exists, and `null` once the
	// session, the identity or the client is gone.
	async #tokenIdentity(token: AuthDanceToken): Promise<AuthDanceIdentity | undefined | null> {
		if (token.session_id === undefined) {
			return (await this.clients.getClient(token.client_id)) ? undefined : null;
		}
		const session = await this.storage.getSession(token.session_id);
		if (!session || session.identityId !== token.subject || session.client_id !== token.client_id) {
			return null;
		}
		return (await this.storage.getIdentity(session.identityId)) ?? null;
	}

	async #username(identity: AuthDanceIdentity | undefined): Promise<{ username?: string }> {
		const username = identity && (await this.#options.introspection?.username?.(identity));
		return typeof username === "string" ? { username } : {};
	}

	async #revokeSessionById(sessionId: string): Promise<void> {
		const session = await this.storage.getSession(sessionId);
		if (session) {
			await this.#revokeSession(session);
		}
	}

	// Deletes the session of a grant with its index entry.
	async #revokeSession(session: AuthDanceSession): Promise<void> {
		await this.storage.deleteSession(session.id);
		await clientSessionRecords.unset(this.storage, [session.client_id, session.id]);
		await this.#emit("onGrantRevoked", { session });
	}

	async #emit<TKey extends Exclude<keyof AuthDanceOauth2Hooks, "onError">>(
		hook: TKey,
		event: Parameters<NonNullable<AuthDanceOauth2Hooks[TKey]>>[0],
	): Promise<void> {
		const listener = this.#options.hooks?.[hook] as ((event: unknown) => void | Promise<void>) | undefined;
		if (!listener) {
			return;
		}
		try {
			await listener(event);
		} catch (cause) {
			await this.#report({ source: hook, cause });
		}
	}

	async #report(event: AuthDanceOauth2HookErrorEvent): Promise<void> {
		try {
			await this.#options.hooks?.onError?.(event);
		} catch {
			// Nowhere left to report to.
		}
	}
}

/** Builds an `AuthDanceOauth2Api`. Call it directly when you want the protocol logic without the HTTP layer. */
export function createAuthDanceOauth2Api(options: AuthDanceOauth2ApiOptions): AuthDanceOauth2Api {
	return new AuthDanceOauth2Api(options);
}
