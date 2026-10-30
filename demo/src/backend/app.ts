/**
 * The backend of the demo, built for the service worker of `sw.ts`. One Hono app serves:
 *
 * - `/auth/*`, the core dance of `createAuthDance`;
 * - `/oauth2/*` and `/.well-known/*`, the authorization server of `createAuthDanceOauth2`;
 * - `/api/*`, what the demo pages need on top: the inbox of the mail channel, the two demo clients, and the server
 *   side of the login, consent and device pages.
 *
 * Every record lives in IndexedDB, in this browser. The secrets, the signing key and the clients are drawn on the first
 * start, and kept for the next ones.
 */

import { AuthDanceStorage, choice, createAuthDance, generateSigningKey, sequence } from "auth-dance";
import { EmailAuthDanceComponent } from "auth-dance/components/email";
import { OtpAuthDanceComponent } from "auth-dance/components/otp";
import { PasswordAuthDanceComponent } from "auth-dance/components/password";
import { WebAuthnAuthDanceComponent } from "auth-dance/components/webauthn";
import { AuthDanceOauth2ClientStorage, AuthDanceOauth2Error, createAuthDanceOauth2 } from "auth-dance/oauth2";
import { MemoryRateLimiterProvider } from "auth-dance/providers/memory";
import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import { DemoMailbox } from "./mailbox.ts";
import { IndexedDbIdentityProvider, IndexedDbKvProvider, IndexedDbOauth2ClientProvider, openDemoDatabase, remember } from "./storage.ts";

/** The choreography, as the home page prints it. */
export const DEMO_CHOREOGRAPHY_SOURCE = `choice(sequence("email", "password", "otp"), "passkey")`;

/** 32 random bytes as base64url: the shape of the state secret and of the password pepper. */
function randomSecret(): string {
	const bytes = crypto.getRandomValues(new Uint8Array(32));
	return btoa(String.fromCharCode(...bytes))
		.replaceAll("+", "-")
		.replaceAll("/", "_")
		.replace(/=+$/, "");
}

const scopes = {
	profile: { description: "Read your email address" },
	account: { description: "Manage your account: sessions, sign-in methods and deletion" },
};

/** Builds the backend for the pages of `origin`, and answers its requests with `fetch`. */
export async function createDemoBackend(origin: string): Promise<{ fetch: (request: Request) => Promise<Response> }> {
	const db = await openDemoDatabase();
	const mailbox = new DemoMailbox(db);

	const auth = createAuthDance({
		api: {
			// Two ways in: the address, its password and a code sent to it; or a passkey on its own.
			choreography: choice(sequence("email", "password", "otp"), "passkey"),
			components: {
				email: new EmailAuthDanceComponent({ channel: "email", challenge: "otp" }),
				otp: new OtpAuthDanceComponent({ channel: "email" }),
				password: new PasswordAuthDanceComponent(await remember(db, "pepper", randomSecret)),
				passkey: new WebAuthnAuthDanceComponent({
					rp: { id: new URL(origin).hostname, name: "Auth Dance Demo" },
					origins: [origin],
					residentKey: "required",
				}),
			},
			channels: { email: mailbox },
			secret: await remember(db, "secret", randomSecret),
			keys: [await remember(db, "key", () => generateSigningKey())],
			durations: { elevated: 10 * 60 },
			// A sign-up mails two codes and answers four prompts, and a visitor tries every flow on one account in a few
			// minutes. The defaults suit production; the demo allows more.
			limits: {
				identity: {
					verify: { limit: 50, window: 300 },
					send: { limit: 30, window: 300 },
					recipient: { limit: 30, window: 300 },
				},
			},
			tokens: {
				issuer: origin,
				scopes,
				// The `profile` scope carries the address the identity signs in with.
				claims: ({ identity, defaults }) => {
					const email = identity?.components.find((c) => c.kind === "identification" && c.component === "email");
					return email?.kind === "identification" ? { ...defaults, profile: { email: email.identification } } : defaults;
				},
			},
			storage: new AuthDanceStorage({
				identity: new IndexedDbIdentityProvider(db),
				kv: new IndexedDbKvProvider(db),
				// The counters may restart with the worker: losing them only lets a visitor try again sooner.
				rate_limiter: new MemoryRateLimiterProvider(),
			}),
		},
		app: { basePath: "/auth" },
		info: { title: "Auth Dance Demo", version: "1.0.0" },
	});

	const idp = createAuthDanceOauth2({
		oauth2: {
			api: auth.api,
			clients: new AuthDanceOauth2ClientStorage({ clients: new IndexedDbOauth2ClientProvider(db) }),
			issuer: origin,
			ui: { login: `${origin}/idp/login`, consent: `${origin}/idp/consent`, device: `${origin}/idp/device` },
		},
		app: { basePath: "/oauth2" },
		info: { title: "Auth Dance Demo · OAuth 2.0", version: "1.0.0" },
	});

	// A web app that signs in with PKCE, and a TV that signs in with the device grant. Neither keeps a secret.
	const clients = await remember(db, "clients", async () => {
		const { client: notes } = await idp.oauth2.clients.createClient({
			client_name: "Dance Notes",
			client_uri: `${origin}/playground`,
			token_endpoint_auth_method: "none",
			grant_types: ["authorization_code", "refresh_token"],
			redirect_uris: [`${origin}/playground/callback`],
			scope: "profile account",
		});
		const { client: tv } = await idp.oauth2.clients.createClient({
			client_name: "Dance TV",
			token_endpoint_auth_method: "none",
			grant_types: ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
			scope: "profile",
		});
		return { notes: notes.client_id, tv: tv.client_id };
	});

	const app = new Hono();

	app.onError((error, c) => {
		if (error instanceof AuthDanceOauth2Error) {
			return c.json({ error: error.error, error_description: error.description }, error.status);
		}
		if (error instanceof HTTPException) {
			return c.json({ error: "access_denied", error_description: error.message }, error.status);
		}
		console.error(error);
		return c.json({ error: "server_error", error_description: String(error) }, 500);
	});

	app.all("/auth/*", (c) => auth.fetch(c.req.raw));
	app.all("/oauth2/*", (c) => idp.fetch(c.req.raw));
	app.all("/.well-known/*", (c) => idp.fetch(c.req.raw));

	app.get("/api/demo", (c) => c.json({ choreography: DEMO_CHOREOGRAPHY_SOURCE, clients, scopes }));

	app.get("/api/mailbox", async (c) => c.json({ messages: await mailbox.inbox() }));
	app.delete("/api/mailbox", async (c) => {
		await mailbox.empty();
		return c.json({ success: true });
	});

	// The server side of the login, consent and device pages. A real deployment keeps these behind its own session;
	// here the page hands over the access token of the dance, and the consent routes check it names the owner of the
	// request.
	async function owner(authorization: string | undefined): Promise<{ access_token: string; subject: string }> {
		const access_token = authorization?.replace(/^Bearer /i, "");
		if (!access_token) {
			throw new HTTPException(401, { message: "sign in first" });
		}
		const verified = await auth.api.verifyAccessToken(access_token, { session: true }).catch(() => {
			throw new HTTPException(401, { message: "the access token is not valid" });
		});
		return { access_token, subject: verified.subject };
	}

	async function body(c: { req: { json(): Promise<unknown> } }): Promise<Record<string, unknown>> {
		return ((await c.req.json().catch(() => ({}))) ?? {}) as Record<string, unknown>;
	}

	async function consentOf(challenge: string, subject: string) {
		const request = await idp.oauth2.getConsentRequest(challenge);
		if (request.subject !== subject) {
			throw new HTTPException(403, { message: "this consent belongs to someone else" });
		}
		return request;
	}

	app.get("/api/idp/login", async (c) => c.json(await idp.oauth2.getLoginRequest(c.req.query("challenge") ?? "")));
	app.post("/api/idp/login/accept", async (c) => {
		const { access_token } = await owner(c.req.header("authorization"));
		const { challenge } = await body(c);
		return c.json(await idp.oauth2.acceptLoginRequest(String(challenge), { access_token }));
	});
	app.post("/api/idp/login/reject", async (c) => {
		const { challenge } = await body(c);
		return c.json(await idp.oauth2.rejectLoginRequest(String(challenge), { error: "access_denied", error_description: "The owner left" }));
	});

	app.get("/api/idp/consent", async (c) => {
		const { subject } = await owner(c.req.header("authorization"));
		return c.json(await consentOf(c.req.query("challenge") ?? "", subject));
	});
	app.post("/api/idp/consent/accept", async (c) => {
		const { subject } = await owner(c.req.header("authorization"));
		const { challenge, grant_scope, remember } = await body(c);
		await consentOf(String(challenge), subject);
		return c.json(
			await idp.oauth2.acceptConsentRequest(String(challenge), {
				grant_scope: Array.isArray(grant_scope) ? grant_scope.map(String) : [],
				remember: remember === true,
			}),
		);
	});
	app.post("/api/idp/consent/reject", async (c) => {
		const { subject } = await owner(c.req.header("authorization"));
		const { challenge } = await body(c);
		await consentOf(String(challenge), subject);
		return c.json(
			await idp.oauth2.rejectConsentRequest(String(challenge), { error: "access_denied", error_description: "The owner refused" }),
		);
	});

	app.get("/api/idp/device", async (c) => c.json(await idp.oauth2.getDeviceRequest(c.req.query("challenge") ?? "")));
	app.post("/api/idp/device/accept", async (c) => {
		const { challenge, user_code } = await body(c);
		return c.json(await idp.oauth2.acceptDeviceRequest(String(challenge), { user_code: String(user_code) }));
	});

	return { fetch: async (request) => app.fetch(request) };
}
