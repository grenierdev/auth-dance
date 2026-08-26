/**
 * @module
 *
 * The instance the page dances with, and the client that calls it. Everything runs in the browser. The memory
 * providers keep identities, sessions, one-time codes and rate limit counters in a `Map` that a reload erases.
 * `buildDance` takes a sink, and the store hands it one that lands in state.
 *
 * The client of `auth-dance/client` is handed the `fetch` of the instance, so the whole exchange stays in this tab. It
 * is wrapped one time, so the wire panel reads every call the client makes, the exchanges it makes on its own included.
 */

import {
	type AuthDance,
	type AuthDanceChoreography,
	type AuthDanceComponent,
	type AuthDanceComponentContext,
	type AuthDanceIdentity,
	type AuthDanceMessage,
	AuthDanceStorage,
	createAuthDance,
} from "auth-dance";
import { AuthDanceClient } from "auth-dance/client";
import { MemoryAuthDanceChannel, MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "auth-dance/providers/memory";
import { EmailAuthDanceComponent } from "auth-dance/components/email";
import { OtpAuthDanceComponent } from "auth-dance/components/otp";
import { PasswordAuthDanceComponent, pbkdf2PasswordHasher } from "auth-dance/components/password";
import { TotpAuthDanceComponent } from "auth-dance/components/totp";
import { WebAuthnAuthDanceComponent } from "auth-dance/components/webauthn";
import type { Durations } from "./config.ts";

/** The key that signs the tokens and encrypts the state. It sits in the bundle. A real deployment must not do this. */
export const SECRET = "zdJXI1jwuXW8A19fns0E_B4HSYm7AUHLGlU9WLo8mxs";

/** The PBKDF2 rounds of the password component. The library default is 600 000. */
export const PASSWORD_ROUNDS = 60_000;

/** The digits of the authenticator codes. The `totp-key` field reads it back out of the prompt. */
export const TOTP_DIGITS = 6;

/** The length of one time step of the authenticator codes, in seconds. */
export const TOTP_PERIOD = 30;

/** What every route path of the client hangs off. Nothing resolves it: the wrapped `fetch` answers every call. */
export const BASE_URL = "http://demo";

/**
 * The relying party of the passkeys: the domain this page is served from. A credential answers to that domain and to
 * no other, so a reload on another host makes every passkey of the old one unusable. A server pass holds no
 * `location`, so the fallback names the development host.
 */
export function webAuthnRelyingParty(): { id: string; name: string } {
	return { id: typeof location === "undefined" ? "localhost" : location.hostname, name: "Auth Dance demo" };
}

/** The origins the passkey component accepts in the client data. The page serves itself, so it is the only one. */
export function webAuthnOrigins(): string[] {
	return typeof location === "undefined" ? ["http://localhost:5173"] : [location.origin];
}

/** The language the client asks every message in. A server pass holds no `navigator`. */
export function currentLocale(): string {
	return typeof navigator === "undefined" ? "en" : navigator.language || "en";
}

/** The user agent a session records. A server pass holds no `navigator`. */
export function currentUserAgent(): string {
	return typeof navigator === "undefined" ? "auth-dance demo" : navigator.userAgent;
}

/** What the seed puts in storage, and what the start card offers to type. */
export const SEEDED = {
	id: "id_0000000000000000000demo",
	email: "john.doe@example.com",
	password: "hunter2",
	/**
	 * The authenticator key of the seeded identity, in base32. A choreography that names `totp` needs the identity to
	 * carry a key, or a sign-in reaches that step and can never answer it. The start card publishes both this key and
	 * the code it derives, so the demo needs no phone.
	 */
	totp: "JBSWY3DPEHPK3PXP",
};

/** The hash the authenticator codes derive through. It is the default of the component. */
export const TOTP_ALGORITHM = "SHA-1" as const;

/** The address the demo claims to call from, so a session carries one. */
export const CALLER_ADDRESS = "203.0.113.7";

/** What a channel took, as the inbox needs it. The store adds an id and a moment on the way in. */
export interface DeliveredMessage {
	/** The channel that took the message, by the name `api.channels` maps it under. */
	channel: string;
	/** The recipient the channel record carried, or an em dash when it carried none. */
	recipient: string;
	/** The subject line the component wrote. */
	subject: string;
	/** The bare one-time code, under `text/x-code`. Absent on any other message. */
	code?: string;
}

/** What a hook reported. The library calls a hook after it saved a change, and never before. */
export interface ReportedHook {
	/** The name of the hook, `onSessionCreated` for example. */
	hook: string;
	/** The flow that caused the change. */
	flow: string;
	/** The one line the log shows beside the flow: an identity id, a session id, or an id and a component name. */
	summary: string;
}

/** One call the client made, as the wire panel needs it. */
export interface CalledRoute {
	/** The route, `/submit-prompt` for example. */
	path: string;
	/** The status the call answered with. */
	status: number;
	/** How long the call took, in milliseconds. */
	ms: number;
	/** The body the call sent, or nothing on a route that takes none. */
	request?: unknown;
	/** The body the call answered with. */
	response?: unknown;
}

/** Where a running instance reports what happened out of band. */
export interface DanceSink {
	/** Called by a channel for every message it took. */
	delivered(message: DeliveredMessage): void;
	/** Called by every hook the instance declares. */
	reported(event: ReportedHook): void;
	/** Called for every call the client made, once the answer is in. */
	called(call: CalledRoute): void;
}

/** One built instance, with the client that calls it and the seed that fills it. */
export interface Dance {
	/** The library itself. `auth.fetch` is the whole transport of this page. */
	auth: AuthDance;
	/** The client of `auth-dance/client`, wired to `auth.fetch`. Every flow of the page runs through it. */
	client: AuthDanceClient;
	/** The storage the instance writes through, which the seed uses directly. */
	storage: AuthDanceStorage;
	/** The component names a flow that takes a component may name. */
	componentNames: string[];
	/** The channel names a flow that takes a channel may name. */
	channelNames: string[];
	/** Writes the John Doe identity into storage, the way a sign-up would leave one. */
	seedIdentity(): Promise<AuthDanceIdentity>;
}

/**
 * A one-time code as a step of the choreography, and not as the proof another component asks for.
 * The base class throws from `verificationComponent`. This class drops it, so a sign-up takes the code as proof.
 */
export class CodeAuthDanceComponent extends OtpAuthDanceComponent {
	override verificationComponent = undefined;
}

/** A memory channel that also reports what it received, which is what the inbox reads. */
export class DemoChannel extends MemoryAuthDanceChannel {
	#name: string;
	#sink: DanceSink;

	/**
	 * @param name - The key `api.channels` maps this channel under, which the inbox shows.
	 * @param type - The prompt type the channel declares when a subscribe collects a recipient for it.
	 * @param sink - Where every taken message is reported.
	 */
	constructor(name: string, type: string, sink: DanceSink) {
		super(type);
		this.#name = name;
		this.#sink = sink;
	}

	/** Keeps the message the way the memory channel does, and reports it to the sink on the way out. */
	override async sendMessage(message: AuthDanceMessage): Promise<void> {
		await super.sendMessage(message);
		const content = message.content as Record<string, string>;
		// The memory channel files every recipient under the literal key `sms`, so read the one string in the bag.
		const recipient = Object.values(message.recipient.data ?? {}).find((value) => typeof value === "string");
		this.#sink.delivered({
			channel: this.#name,
			recipient: typeof recipient === "string" ? recipient : "—",
			subject: message.subject,
			code: content["text/x-code"],
		});
	}
}

/**
 * Builds one instance from a choreography, a set of durations and a sink. The choreography picks components by name.
 * `email` and `email2` are two addresses with a channel each. `password` is a challenge. `otp` is a code over `email`.
 * `totp` is the key of an authenticator app, which the browser generates and the library never delivers.
 * `webauthn` and `webauthn2` are passkeys, each an identification of its own: the credential id names the owner, so
 * one signature signs in without an address. One component name holds one credential, which is why there are two.
 */
export function buildDance(choreography: AuthDanceChoreography, durations: Durations, sink: DanceSink): Dance {
	const channels = {
		email: new DemoChannel("email", "email", sink),
		email2: new DemoChannel("email2", "email", sink),
		sms: new DemoChannel("sms", "phone", sink),
	};

	const email = new EmailAuthDanceComponent({ channel: "email", challenge: "otp" });
	const otp = new OtpAuthDanceComponent({ channel: "email" });
	const email2 = new EmailAuthDanceComponent({ channel: "email2", challenge: "otp2" });
	const otp2 = new OtpAuthDanceComponent({ channel: "email2" });
	const password = new PasswordAuthDanceComponent("demo-pepper", pbkdf2PasswordHasher(PASSWORD_ROUNDS));
	const totp = new TotpAuthDanceComponent({ digits: TOTP_DIGITS, period: TOTP_PERIOD });
	const passkey = () =>
		new WebAuthnAuthDanceComponent({
			rp: webAuthnRelyingParty(),
			origins: webAuthnOrigins(),
			// A sign-up builds its prompt before the library holds an identity, so name the account here.
			user: (context) => {
				const identification = context.identity?.components
					.find((c) => c.kind === "identification" && c.component !== context.name && c.confirmed);
				// A sign-up holds no identity yet, and every run of the demo makes one more passkey under the same
				// domain. The minute tells the entries of the passkey manager apart.
				const minted = `demo account · ${new Date().toISOString().slice(0, 16).replace("T", " ")}`;
				const name = identification && "identification" in identification ? identification.identification : minted;
				return { name, displayName: String(context.identity?.data?.name ?? name) };
			},
		});
	const webauthn = passkey();
	const webauthn2 = passkey();
	const components: Record<string, AuthDanceComponent> = { email, email2, password, otp, otp2, totp, webauthn, webauthn2 };

	const storage = new AuthDanceStorage({
		identity: new MemoryIdentityProvider(),
		kv: new MemoryKvProvider(),
		rate_limiter: new MemoryRateLimiterProvider(),
	});

	const auth = createAuthDance({
		api: {
			channels,
			choreography,
			components,
			secret: SECRET,
			storage,
			durations,
			limits: {
				identity: {
					verify: { limit: 200, window: 300 },
					send: { limit: 200, window: 300 },
					manage: { limit: 200, window: 300 },
					refresh: { limit: 200, window: 300 },
				},
			},
			// A hook that throws never fails the flow.
			hooks: {
				onIdentityCreated: (event) => sink.reported({ hook: "onIdentityCreated", flow: event.flow, summary: event.identity.id }),
				onIdentityUpdated: (event) =>
					sink.reported({ hook: "onIdentityUpdated", flow: event.flow, summary: `${event.identity.id} · ${event.name ?? "—"}` }),
				onIdentityDeleted: (event) => sink.reported({ hook: "onIdentityDeleted", flow: event.flow, summary: event.identity.id }),
				onSessionCreated: (event) => sink.reported({ hook: "onSessionCreated", flow: event.flow, summary: event.session.id }),
				onSessionRefreshed: (event) => sink.reported({ hook: "onSessionRefreshed", flow: event.flow, summary: event.session.id }),
				onSessionDeleted: (event) => sink.reported({ hook: "onSessionDeleted", flow: event.flow, summary: event.session.id }),
			},
			tokens: { issuer: "auth-dance-demo" },
		},
		info: { title: "Auth Dance demo", version: "0.1.0" },
	});

	/**
	 * Hands one request to the instance and reports the exchange. Both bodies are read off a clone, because the client
	 * reads the answer itself and a body is read one time.
	 */
	async function trace(request: Request): Promise<Response> {
		const sent: unknown = await request.clone().json().catch(() => undefined);
		const started = performance.now();
		const response = await auth.fetch(request);
		const received: unknown = await response.clone().json().catch(() => undefined);
		sink.called({
			path: new URL(request.url).pathname,
			status: response.status,
			ms: Math.round(performance.now() - started),
			request: sent,
			response: received,
		});
		return response;
	}

	// No token store and no dance store: this page keeps every identity in a `Map`, so tokens that outlived a reload
	// would name a session nothing backs. The client holds them in memory, and a reload starts over.
	const client = new AuthDanceClient({
		baseUrl: BASE_URL,
		fetch: trace,
		locale: currentLocale(),
		headers: { "cf-connecting-ip": CALLER_ADDRESS, "user-agent": currentUserAgent() },
	});

	/**
	 * Writes the John Doe identity into storage, the way a sign-up would leave one.
	 * The password record uses the identity id as salt, so the id must exist before the components are built.
	 */
	async function seedIdentity(): Promise<AuthDanceIdentity> {
		const identity: AuthDanceIdentity = { id: SEEDED.id, data: { name: "John Doe" }, components: [] };
		const seed = (name: string): AuthDanceComponentContext => ({ storage, stateId: "state_seed", name, flow: "sign-up", identity });
		// An identity may carry a component the running choreography never names, and the authenticator key is here for
		// exactly that reason: the presets that name `totp` are otherwise a dead end for this identity.
		identity.components = [
			...await email.getIdentityComponent("email", SEEDED.email, true),
			...await password.getIdentityComponent("password", SEEDED.password, true, seed("password")),
			...await totp.getIdentityComponent("totp", SEEDED.totp, true, seed("totp")),
		];
		await storage.setIdentity(identity);
		return identity;
	}

	return { auth, client, storage, componentNames: Object.keys(components), channelNames: Object.keys(channels), seedIdentity };
}

/** Plain sentences for the codes this demo runs into most. Everything else shows the code alone. */
export const ERROR_HINTS: Record<string, string> = {
	INVALID_PROMPT_VALUE:
		"The value did not verify. A wrong password, an unknown address and a passkey no identity claims all answer the same way, so nobody can probe for accounts.",
	INVALID_VALIDATION_VALUE: "The one-time code did not match. Send a fresh one and try again.",
	CONFIRMATION_REQUIRED: "This flow ends on a confirmation, and only the boolean true goes through.",
	WOULD_LOCK_OUT: "Dropping this component, and everything linked to it, would leave no complete path through the choreography.",
	COMPONENT_IN_USE: "Another component still links to this one, and the removal cannot take that link with it.",
	COMPONENT_ALREADY_ENROLLED: "The identity already holds this component. Rotate it instead.",
	CHANNEL_ALREADY_SUBSCRIBED: "The identity already holds this channel.",
	COMPONENT_NOT_RECOVERABLE:
		"This component is not part of the choreography, or nothing else in it can identify you and prove control on its own.",
	FRESH_SIGN_IN_REQUIRED: "The elevated window closed. Sign in again to run a sensitive flow.",
	INVALID_ACCESS_TOKEN: "This route needs a valid access token.",
	INVALID_STATE: "The state is gone or expired. Start the flow again.",
	INVALID_STATE_FOR_FLOW: "This flow has nothing to deliver over a channel at this point.",
	IDENTITY_NOT_RESOLVED: "No step of this dance has said who is dancing yet.",
	RATE_LIMITED: "The bucket for this address or identity is empty for now.",
};

/**
 * The one sentence a refusal earns.
 *
 * Every failure the library reports carries a `code`, and so does the one the client raises for an answer it cannot
 * map. Anything else shows the message it came with.
 *
 * @param cause - What an action threw.
 * @returns The code and the sentence for it, or the message of the failure.
 */
export function describeFailure(cause: unknown): string {
	const code = (cause as { code?: unknown } | null | undefined)?.code;
	if (typeof code !== "string") {
		return cause instanceof Error ? cause.message : String(cause);
	}
	const hint = ERROR_HINTS[code];
	const retryAfter = (cause as { retryAfter?: unknown }).retryAfter;
	const wait = typeof retryAfter === "number" ? ` Try again in ${retryAfter} s.` : "";
	return hint ? `${code} — ${hint}${wait}` : `${code}${wait}`;
}
