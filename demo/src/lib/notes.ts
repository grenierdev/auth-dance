// The storage of Dance Notes, the third-party web app of the demo. It shares the origin of the authorization server
// only because the demo runs on one port; it keeps its own keys, and never reads the tokens of the dance.

export interface NotesTokens {
	access_token: string;
	refresh_token?: string;
	expires_in: number;
	scope: string;
	token_type: string;
}

const TOKENS = "dance-notes.tokens";
const PENDING = "dance-notes.pending";

export const REDIRECT_URI = typeof window === "undefined" ? "" : `${window.location.origin}/playground/callback`;

function read<T>(key: string): T | undefined {
	try {
		const raw = sessionStorage.getItem(key);
		return raw ? (JSON.parse(raw) as T) : undefined;
	} catch {
		return undefined;
	}
}

export function readNotesTokens(): NotesTokens | undefined {
	return read<NotesTokens>(TOKENS);
}

export function writeNotesTokens(tokens: NotesTokens | undefined): void {
	if (tokens) {
		sessionStorage.setItem(TOKENS, JSON.stringify(tokens));
	} else {
		sessionStorage.removeItem(TOKENS);
	}
}

/** What the app keeps between the redirect to `/oauth2/authorize` and the callback. */
export interface PendingAuthorization {
	state: string;
	code_verifier: string;
}

export function takePendingAuthorization(): PendingAuthorization | undefined {
	const pending = read<PendingAuthorization>(PENDING);
	sessionStorage.removeItem(PENDING);
	return pending;
}

function base64url(bytes: Uint8Array): string {
	return btoa(String.fromCharCode(...bytes))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");
}

/** Builds the authorization request with PKCE S256, keeps the verifier, and sends the browser away. */
export async function startAuthorization(client_id: string, scope: string): Promise<void> {
	const code_verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
	const state = base64url(crypto.getRandomValues(new Uint8Array(16)));
	const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(code_verifier)));
	sessionStorage.setItem(PENDING, JSON.stringify({ state, code_verifier } satisfies PendingAuthorization));
	const url = new URL("/oauth2/authorize", window.location.origin);
	url.search = new URLSearchParams({
		response_type: "code",
		client_id,
		redirect_uri: REDIRECT_URI,
		scope,
		state,
		code_challenge: base64url(digest),
		code_challenge_method: "S256",
	}).toString();
	window.location.assign(url);
}
