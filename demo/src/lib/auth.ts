import { AuthDanceClient, webStorageStore } from "auth-dance/client";

/**
 * The one client of the page. It keeps the tokens of the session in `localStorage`, so a reload stays signed in. The
 * shell of the SPA renders once at build time, where no storage exists.
 */
export const client = new AuthDanceClient({
	baseUrl: "/auth",
	store: typeof window === "undefined" ? undefined : webStorageStore("auth-dance-demo.tokens", window.localStorage),
});

/** The claims of a JWT, read without verifying it. The page only shows them. */
export function decodeJwt(token: string): Record<string, unknown> {
	const [, payload] = token.split(".");
	const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
	return JSON.parse(new TextDecoder().decode(Uint8Array.from(json, (c) => c.charCodeAt(0))));
}

/** An access token of the session that is still valid for a few seconds. The client refreshes it when it is not. */
export async function bearer(): Promise<string> {
	await client.restore();
	const token = client.tokens?.access_token;
	if (!token) {
		throw new Error("Sign in first");
	}
	const { exp } = decodeJwt(token) as { exp?: number };
	if (exp === undefined || exp - Date.now() / 1000 < 10) {
		return (await client.refreshTokens()).tokens.access_token;
	}
	return token;
}

/** The email address the session carries, from the `profile` claims of its access token. */
export function emailOf(access_token: string | undefined): string | undefined {
	if (!access_token) {
		return undefined;
	}
	const email = decodeJwt(access_token).email;
	return typeof email === "string" ? email : undefined;
}

/** The text of an error, for the owner. Library errors carry a code, OAuth 2.0 errors an `error`. */
export function describeError(error: unknown): string {
	const code = (error as { code?: unknown } | null)?.code;
	if (typeof code === "string") {
		return ERROR_TEXT[code] ?? code.toLowerCase().replaceAll("_", " ");
	}
	if (error instanceof Error) {
		return error.message;
	}
	return String(error);
}

const ERROR_TEXT: Record<string, string> = {
	INVALID_PROMPT_VALUE: "That value was not accepted. Check it and try again.",
	INVALID_VALIDATION_VALUE: "That code is not the one we sent. Check the inbox and try again.",
	FRESH_SIGN_IN_REQUIRED: "This action needs a recent sign-in. Sign in again to continue.",
	RATE_LIMITED: "Too many attempts. Wait a moment and try again.",
	IDENTIFICATION_TAKEN: "An account already uses that address or passkey.",
	COMPONENT_ALREADY_ENROLLED: "That sign-in method is already set up.",
	COMPONENT_NOT_ENROLLED: "That sign-in method is not set up on this account.",
	COMPONENT_NOT_RECOVERABLE: "That sign-in method cannot be recovered: no other way in is left to prove who you are.",
	WOULD_LOCK_OUT: "Removing it would leave no complete way to sign in.",
	CHANNEL_ALREADY_SUBSCRIBED: "That channel is already subscribed.",
	CHANNEL_NOT_SUBSCRIBED: "Nothing is subscribed to receive the code.",
	IDENTITY_NOT_RESOLVED: "We could not find that account.",
	INVALID_STATE: "This dance expired. Start again.",
	COMPONENT_ALREADY_COLLECTED: "That step is already answered. Start again to change it.",
};
