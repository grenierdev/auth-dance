import { ClaimsMapperError } from "./error.ts";
import type { AuthDanceIdentity } from "./identity.ts";

/** Any JSON value. A claim can hold an object or an array. */
export type AuthDanceClaimJson = string | number | boolean | null | AuthDanceClaimJson[] | { [key: string]: AuthDanceClaimJson };

/** The claims a token carries, by name. */
export type AuthDanceClaims = Record<string, AuthDanceClaimJson>;

/** One scope the server knows. */
export interface AuthDanceScope {
	/** The text of the consent page. Key it by BCP 47 language tag to give one text for each language. */
	description: string | Record<string, string>;
	/** The keys of the identity data bag that this scope discloses, when no `claims` mapper replaces the default. */
	claims?: string[];
}

/**
 * The scope that opens the management routes of the core: sign-out, the session and component lists, enroll, unenroll,
 * rotate, subscribe, unsubscribe and delete. A dance always grants it. A client of the oauth2 module gets it only when
 * it asks for it and the owner consents.
 */
export const ACCOUNT_SCOPE = "account";

/** The `account` scope the server knows when `tokens.scopes` does not declare it. */
export const AccountScope: AuthDanceScope = {
	description: "Manage your account: its sign-in methods, its channels, its sessions, and its deletion",
};

/**
 * How a token came to be: a dance, or a grant type of the oauth2 module. A refresh keeps the scopes and the session of
 * the token it replaces.
 */
export type AuthDanceGrantType =
	| "sign-in"
	| "sign-up"
	| "authorization_code"
	| "refresh_token"
	| "client_credentials"
	| "urn:ietf:params:oauth:grant-type:device_code";

/** What the `claims` mapper gets each time the library mints an access token. */
export interface AuthDanceClaimsContext {
	/** The client the token is for. A dance mints its tokens for the issuer. Use it to find the tenant to read from. */
	client_id: string;
	/** The identity behind the token. `undefined` for `client_credentials`, where `subject` is the client id. */
	identity: AuthDanceIdentity | undefined;
	/** The `sub` of the token. */
	subject: string;
	/** The scopes of this token: the granted scopes, or fewer when a refresh asks for fewer. */
	scopes: string[];
	/** The session the token belongs to, its `sid`. `undefined` for `client_credentials`. */
	session_id: string | undefined;
	/** How the token came to be. */
	grant_type: AuthDanceGrantType;
	/** Where the claims go. `access_token` is the only target. */
	target: "access_token";
	/** The claims of the default mapping, keyed by scope: for each scope, the keys of the identity data bag it names. */
	defaults: Record<string, Record<string, AuthDanceClaimJson>>;
}

/**
 * Maps the scopes of a token to its claims, from any source. It returns the claims of each scope, keyed by scope.
 *
 * The library keeps only the groups of the scopes in `context.scopes`, then merges them. Two scopes that give one claim
 * two values, a claim with a reserved name (`iss`, `sub`, `aud`, `exp` and the others the token sets), a value that is
 * not JSON, and a mapper that throws each make the mint fail with `ClaimsMapperError`. The library calls the mapper
 * each time it mints an access token, and keeps no copy of the result.
 */
export type AuthDanceClaimsMapper = (
	context: AuthDanceClaimsContext,
) => Record<string, Record<string, AuthDanceClaimJson>> | Promise<Record<string, Record<string, AuthDanceClaimJson>>>;

/** The claims the library sets on every access token. A mapper cannot give them. */
export const RESERVED_CLAIMS: ReadonlySet<string> = new Set([
	"iss",
	"sub",
	"aud",
	"exp",
	"nbf",
	"iat",
	"jti",
	"client_id",
	"scope",
	"auth_time",
	"sid",
	"typ",
]);

// RFC 6749 §3.3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E ).
const SCOPE_TOKEN = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

/** Whether a value is a scope token of RFC 6749 §3.3: printable ASCII with no space, no `"` and no `\`. */
export function isScopeToken(value: string): boolean {
	return SCOPE_TOKEN.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		return false;
	}
	const prototype = Object.getPrototypeOf(value);
	return prototype === Object.prototype || prototype === null;
}

// `undefined` in an object drops out, as `JSON.stringify` drops it. In an array it is not JSON.
function isJson(value: unknown): value is AuthDanceClaimJson {
	if (value === null || typeof value === "string" || typeof value === "boolean") {
		return true;
	}
	if (typeof value === "number") {
		return Number.isFinite(value);
	}
	if (Array.isArray(value)) {
		return value.every(isJson);
	}
	return isRecord(value) && Object.values(value).every((item) => item === undefined || isJson(item));
}

function sameJson(a: unknown, b: unknown): boolean {
	if (Array.isArray(a) && Array.isArray(b)) {
		return a.length === b.length && a.every((item, i) => sameJson(item, b[i]));
	}
	if (isRecord(a) && isRecord(b)) {
		const keys = (record: Record<string, unknown>) =>
			Object.keys(record)
				.filter((key) => record[key] !== undefined)
				.sort();
		const keysA = keys(a);
		const keysB = keys(b);
		return keysA.length === keysB.length && keysA.every((key, i) => key === keysB[i] && sameJson(a[key], b[key]));
	}
	return a === b;
}

/** The default mapping: for each scope, the keys of `identity.data` that the scope names in `claims`. */
export function defaultClaims(
	identity: AuthDanceIdentity | undefined,
	scopes: string[],
	known: Record<string, AuthDanceScope>,
): Record<string, Record<string, AuthDanceClaimJson>> {
	// `Object.fromEntries` defines own properties, so a name such as `__proto__` stays a plain key.
	return Object.fromEntries(
		scopes.map((scope) => {
			const keys = Object.hasOwn(known, scope) ? (known[scope].claims ?? []) : [];
			const group = keys.flatMap((key) => {
				const value = identity?.data?.[key];
				return value === undefined ? [] : [[key, value as AuthDanceClaimJson] as const];
			});
			return [scope, Object.fromEntries(group)];
		}),
	);
}

function refuse(reason: string): ClaimsMapperError {
	return new ClaimsMapperError(reason, { cause: new TypeError(reason) });
}

/**
 * Computes the claims of one access token. It runs the mapper, or the default mapping without one, keeps the groups
 * of `context.scopes`, and merges them.
 *
 * @throws ClaimsMapperError for a mapper that throws, with the failure in `cause`, and for a result that breaks a rule
 * of `AuthDanceClaimsMapper`.
 */
export async function resolveClaims(
	context: Omit<AuthDanceClaimsContext, "defaults">,
	known: Record<string, AuthDanceScope>,
	mapper?: AuthDanceClaimsMapper,
): Promise<AuthDanceClaims> {
	const defaults = defaultClaims(context.identity, context.scopes, known);
	let groups: unknown = defaults;
	if (mapper) {
		try {
			groups = await mapper({ ...context, defaults });
		} catch (cause) {
			throw new ClaimsMapperError("the claims mapper threw", { cause });
		}
	}
	if (!isRecord(groups)) {
		throw refuse("the claims mapper must return an object of claim groups keyed by scope");
	}
	const merged = new Map<string, AuthDanceClaimJson>();
	for (const scope of context.scopes) {
		if (!Object.hasOwn(groups, scope)) {
			continue;
		}
		const group = groups[scope];
		if (!isRecord(group)) {
			throw refuse(`the claims of scope ${scope} are not an object`);
		}
		for (const [name, value] of Object.entries(group)) {
			if (value === undefined) {
				continue;
			}
			if (RESERVED_CLAIMS.has(name)) {
				throw refuse(`scope ${scope} gives the reserved claim ${name}`);
			}
			if (!isJson(value)) {
				throw refuse(`scope ${scope} gives claim ${name} a value that is not JSON`);
			}
			if (merged.has(name) && !sameJson(merged.get(name), value)) {
				throw refuse(`two scopes give claim ${name} two values`);
			}
			merged.set(name, value);
		}
	}
	return Object.fromEntries(merged);
}
