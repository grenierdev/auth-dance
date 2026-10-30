import { encode } from "jose/base64url";
import * as v from "valibot";
import type { AuthDanceStorage } from "../storage.ts";

/** The SHA-256 of the UTF-8 bytes of a value, in base64url. The store keeps every code, token and secret as this hash. */
export async function sha256(value: string): Promise<string> {
	return encode(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
}

/** 32 random bytes in base64url, for a code, a token, a secret or a challenge. */
export function randomToken(): string {
	return encode(crypto.getRandomValues(new Uint8Array(32)));
}

/** Whether a value has the shape of `randomToken`: 43 base64url characters. */
export function isRandomToken(value: unknown): value is string {
	return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
}

/** Compares two hashes. The loop always runs over the full length, so the time does not tell where they differ. */
export function constantTimeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) {
		return false;
	}
	let difference = 0;
	for (let i = 0; i < a.length; i++) {
		difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
	}
	return difference === 0;
}

/** A validated authorization request, RFC 6749 §4.1.1, with the PKCE challenge of RFC 7636 §4.3. */
export interface AuthorizationRequest {
	client_id: string;
	/** Where the code goes: the `redirect_uri` of the request, or the one URI the client registered. */
	redirect_uri: string;
	/** Whether the request carried `redirect_uri`. The token request must then repeat it, RFC 6749 §4.1.3. */
	redirect_uri_given: boolean;
	scope: string[];
	state?: string;
	/** BASE64URL(SHA256(code_verifier)). The server supports `S256` only, so the method is not stored. */
	code_challenge: string;
}

const AuthorizationRequestSchema: v.GenericSchema<AuthorizationRequest> = v.object({
	client_id: v.string(),
	redirect_uri: v.string(),
	redirect_uri_given: v.boolean(),
	scope: v.array(v.string()),
	state: v.optional(v.string()),
	code_challenge: v.string(),
});

/**
 * A device authorization request, RFC 8628 §3.1, once the owner typed its user code. It goes through the same login and
 * consent pages as an authorization request, and ends on the device page instead of the redirect URI.
 */
export interface DeviceRequest {
	client_id: string;
	scope: string[];
	/** The SHA-256 of the device code: the key of the device record. */
	device_code: string;
	/** The user code, normalized, for the login and the consent page. */
	user_code: string;
}

const DeviceRequestSchema: v.GenericSchema<DeviceRequest> = v.object({
	client_id: v.string(),
	scope: v.array(v.string()),
	device_code: v.string(),
	user_code: v.string(),
});

/** Whether a challenge serves a device authorization request rather than an authorization request. */
export function isDeviceRequest(request: AuthorizationRequest | DeviceRequest): request is DeviceRequest {
	return "device_code" in request;
}

const RejectionSchema = v.object({ error: v.string(), error_description: v.optional(v.string()) });

/** A sign-in that answers a login challenge: the identity, its session, and the `auth_time` of the sign-in. */
export interface LoginResult {
	identityId: string;
	sessionId: string;
	/** The `auth_time` of the sign-in, in seconds since the epoch. */
	authTime: number;
}

const LoginResultSchema = v.object({ identityId: v.string(), sessionId: v.string(), authTime: v.number() });

/** The fields the login and the consent record share. */
interface ChallengeRecord {
	request: AuthorizationRequest | DeviceRequest;
	/** The URL of the authorization endpoint. A verifier sends the browser back to it. */
	endpoint: string;
	/** The SHA-256 of the random part of the verifier, once the page answered. Each verifier works one time. */
	verifier?: string;
	/** What the page refused, as an RFC error. */
	rejected?: { error: string; error_description?: string };
}

const ChallengeRecordFields = {
	request: v.union([AuthorizationRequestSchema, DeviceRequestSchema]),
	endpoint: v.string(),
	verifier: v.optional(v.string()),
	rejected: v.optional(RejectionSchema),
};

/** `oauth2/login/<challenge>`: an authorization request that waits for the login page. */
export interface LoginRecord extends ChallengeRecord {
	/** The URL of the authorization request, for the login page. */
	request_url: string;
	/** The sign-in the login page accepted. */
	accepted?: LoginResult;
}

const LoginRecordSchema: v.GenericSchema<LoginRecord> = v.object({
	...ChallengeRecordFields,
	request_url: v.string(),
	accepted: v.optional(LoginResultSchema),
});

/** `oauth2/consent/<challenge>`: an accepted login that waits for the consent page. */
export interface ConsentRecord extends ChallengeRecord {
	/** The sign-in that answered the login challenge. */
	login: LoginResult;
	/** What the consent page accepted. */
	accepted?: { grant_scope: string[]; remember: boolean };
}

const ConsentRecordSchema: v.GenericSchema<ConsentRecord> = v.object({
	...ChallengeRecordFields,
	login: LoginResultSchema,
	accepted: v.optional(v.object({ grant_scope: v.array(v.string()), remember: v.boolean() })),
});

/** `oauth2/code/<sha256>`: an authorization code, stored under its hash. */
export interface CodeRecord {
	/** The session the consent created. A second exchange of the code revokes it. */
	session_id: string;
	/** The moment of the sign-in behind the session, in seconds since the epoch: the `auth_time` of the tokens. */
	auth_time: number;
	client_id: string;
	redirect_uri: string;
	/** Whether the authorization request carried `redirect_uri`. */
	redirect_uri_given: boolean;
	code_challenge: string;
	/** When the first exchange of the code started, in seconds since the epoch. A second exchange revokes the session. */
	usedAt?: number;
}

const CodeRecordSchema: v.GenericSchema<CodeRecord> = v.object({
	session_id: v.string(),
	auth_time: v.number(),
	client_id: v.string(),
	redirect_uri: v.string(),
	redirect_uri_given: v.boolean(),
	code_challenge: v.string(),
	usedAt: v.optional(v.number()),
});

/** `oauth2/device/<sha256>`: a device authorization, RFC 8628 §3.2, stored under the hash of its device code. */
export interface DeviceRecord {
	client_id: string;
	scope: string[];
	/** The user code, normalized: the key of its `oauth2/user-code/` entry. */
	user_code: string;
	/** When the device code expires, in seconds since the epoch. The record lasts longer, to answer `expired_token`. */
	expiresAt: number;
	/** How long the device waits between two polls, in seconds. Each `slow_down` adds 5, RFC 8628 §3.5. */
	interval: number;
	/** When the device last polled while the request was pending, in seconds since the epoch. */
	polledAt?: number;
	/** `pending` until the owner approves or denies it on the device page. */
	status: "pending" | "approved" | "denied";
	/** The session an approval created. */
	session_id?: string;
	/** The moment of the sign-in behind the approval, in seconds since the epoch: the `auth_time` of the tokens. */
	auth_time?: number;
	/** Why the request was denied, as an RFC error. */
	rejected?: { error: string; error_description?: string };
	/** When the device first exchanged the approved code, in seconds since the epoch. A second exchange revokes the session. */
	usedAt?: number;
}

const DeviceRecordSchema: v.GenericSchema<DeviceRecord> = v.object({
	client_id: v.string(),
	scope: v.array(v.string()),
	user_code: v.string(),
	expiresAt: v.number(),
	interval: v.number(),
	polledAt: v.optional(v.number()),
	status: v.picklist(["pending", "approved", "denied"]),
	session_id: v.optional(v.string()),
	auth_time: v.optional(v.number()),
	rejected: v.optional(RejectionSchema),
	usedAt: v.optional(v.number()),
});

/** `oauth2/user-code/<user code>`: the device authorization a user code names, while it is pending. */
export interface UserCodeRecord {
	/** The SHA-256 of the device code. */
	device_code: string;
}

const UserCodeRecordSchema: v.GenericSchema<UserCodeRecord> = v.object({ device_code: v.string() });

/** `oauth2/device-challenge/<challenge>`: a visit to the verification URI that waits for the device page. */
export interface DeviceChallengeRecord {
	/** The URL of the authorization endpoint. The verifier sends the browser to it, to start the login. */
	endpoint: string;
	/** The verification URI the owner opened, for the login page. */
	verification_uri: string;
	/** The user code of `verification_uri_complete`, normalized, for the device page to fill in. */
	user_code?: string;
	/** How many wrong user codes the device page sent. The challenge ends at the limit. */
	attempts: number;
	/** The SHA-256 of the device code the owner's user code named, once the page answered. */
	device_code?: string;
	/** The SHA-256 of the random part of the verifier, once the page answered. */
	verifier?: string;
}

const DeviceChallengeRecordSchema: v.GenericSchema<DeviceChallengeRecord> = v.object({
	endpoint: v.string(),
	verification_uri: v.string(),
	user_code: v.optional(v.string()),
	attempts: v.number(),
	device_code: v.optional(v.string()),
	verifier: v.optional(v.string()),
});

/** `oauth2/client-sessions/<clientId>/<sessionId>`: one entry of the index of the sessions of a client. */
export interface ClientSessionRecord {
	identityId: string;
}

const ClientSessionRecordSchema: v.GenericSchema<ClientSessionRecord> = v.object({ identityId: v.string() });

/** `oauth2/consents/<identityId>/<clientId>`: the scopes an identity granted to a client, so the consent page can skip. */
export interface RememberedConsentRecord {
	scopes: string[];
	/** When the owner granted the scopes, in seconds since the epoch. */
	grantedAt: number;
}

const RememberedConsentRecordSchema: v.GenericSchema<RememberedConsentRecord> = v.object({
	scopes: v.array(v.string()),
	grantedAt: v.number(),
});

/**
 * One key space under `oauth2/`, with the schema of its values. A key is the prefix and a fixed count of segments. A
 * segment is never empty and never holds a `/`, so no value can reach another key space.
 */
export class KvRecord<T> {
	#prefix: string;
	#segments: number;
	#schema: v.GenericSchema<T>;

	constructor(prefix: string, segments: number, schema: v.GenericSchema<T>) {
		this.#prefix = prefix;
		this.#segments = segments;
		this.#schema = schema;
	}

	/** The full key. Throws `TypeError` for the wrong count of segments, or for a segment that is empty or holds a `/`. */
	key(segments: string[]): string {
		return `${this.#prefix}/${this.#join(segments, this.#segments)}`;
	}

	#join(segments: string[], count: number): string {
		if (segments.length !== count || segments.some((segment) => segment === "" || segment.includes("/"))) {
			throw new TypeError(`${this.#prefix} takes ${count} segments with no slash here, not ${JSON.stringify(segments)}`);
		}
		return segments.join("/");
	}

	/** Reads one value. A value that does not match the schema makes the call fail. */
	async get(storage: AuthDanceStorage, segments: string[]): Promise<T | undefined> {
		const value = await storage.getKv(this.key(segments));
		return value === undefined ? undefined : v.parse(this.#schema, JSON.parse(value));
	}

	/** Writes one value after a check against the schema. `ttl` is in seconds. Without it the value stays. */
	async set(storage: AuthDanceStorage, segments: string[], value: T, ttl?: number): Promise<void> {
		await storage.setKv(this.key(segments), JSON.stringify(v.parse(this.#schema, value)), ttl);
	}

	/** Deletes one value. A key that holds nothing is not a failure. */
	async unset(storage: AuthDanceStorage, segments: string[]): Promise<void> {
		await storage.unsetKv(this.key(segments));
	}

	/** Lists the last segment of each key under the leading segments, for example the session ids of one client. */
	async list(storage: AuthDanceStorage, leading: string[]): Promise<string[]> {
		const prefix = leading.length === 0 ? `${this.#prefix}/` : `${this.#prefix}/${this.#join(leading, this.#segments - 1)}/`;
		const keys = await storage.listKv(prefix);
		return keys.map((key) => key.slice(prefix.length));
	}
}

/** `oauth2/login/<challenge>`, for `durations.challenge`. */
export const loginRecords: KvRecord<LoginRecord> = new KvRecord("oauth2/login", 1, LoginRecordSchema);
/** `oauth2/consent/<challenge>`, for `durations.challenge`. */
export const consentRecords: KvRecord<ConsentRecord> = new KvRecord("oauth2/consent", 1, ConsentRecordSchema);
/** `oauth2/code/<sha256>`, for `durations.code`. */
export const codeRecords: KvRecord<CodeRecord> = new KvRecord("oauth2/code", 1, CodeRecordSchema);
/** `oauth2/device/<sha256>`, for twice `durations.device`. */
export const deviceRecords: KvRecord<DeviceRecord> = new KvRecord("oauth2/device", 1, DeviceRecordSchema);
/** `oauth2/user-code/<user code>`, for `durations.device`. */
export const userCodeRecords: KvRecord<UserCodeRecord> = new KvRecord("oauth2/user-code", 1, UserCodeRecordSchema);
/** `oauth2/device-challenge/<challenge>`, for `durations.challenge`. */
export const deviceChallengeRecords: KvRecord<DeviceChallengeRecord> = new KvRecord(
	"oauth2/device-challenge",
	1,
	DeviceChallengeRecordSchema,
);
/** `oauth2/client-sessions/<clientId>/<sessionId>`, for the time to live of the session. */
export const clientSessionRecords: KvRecord<ClientSessionRecord> = new KvRecord("oauth2/client-sessions", 2, ClientSessionRecordSchema);
/** `oauth2/consents/<identityId>/<clientId>`, with no time to live. */
export const rememberedConsentRecords: KvRecord<RememberedConsentRecord> = new KvRecord(
	"oauth2/consents",
	2,
	RememberedConsentRecordSchema,
);
