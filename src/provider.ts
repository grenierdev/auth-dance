import type { Identity } from "./identity.ts";

export interface AuthDanceIdentityProvider {
	list: (offset?: number, limit?: number) => Promise<Identity[]>;
	get: (id: string) => Promise<Identity | undefined>;
	getByIdentification: (type: string, identification: string) => Promise<Identity | undefined>;
	set: (identity: Identity) => Promise<void>;
	delete: (id: string) => Promise<void>;
}

export interface AuthDanceKvProvider {
	get: (key: string) => Promise<string | undefined>;
	list: (prefix: string, limit?: number, offset?: number) => Promise<string[]>;
	set: (key: string, value: string, ttl?: number) => Promise<void>;
	unset: (key: string) => Promise<void>;
}

export interface AuthDanceRateLimiterResult {
	allowed: boolean;
	retryAfter: number | undefined;
}

export interface AuthDanceRateLimiterProvider {
	limit: (key: string, limit: number, window: number) => Promise<AuthDanceRateLimiterResult>;
}

export class KVKeyNotFoundError extends Error {}
