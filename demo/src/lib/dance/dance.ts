/**
 * @module
 *
 * The instance the page dances with, and the shapes its answers take.
 *
 * Everything runs in the browser. The memory providers keep identities, sessions, one-time codes and rate limit
 * counters in a `Map` that a reload erases, and a call goes straight into `auth.fetch()`, which is the same HTTP
 * surface a server would expose, minus the server.
 *
 * The reference demo wrote what the channel and the hooks reported into module globals. A React page cannot: a module
 * global is shared by every instance and invisible to the renderer. `buildDance` therefore takes a sink, and the
 * store hands it one that lands in state. Nothing in this module is mutable at module scope.
 */

import {
	type AuthDance,
	type AuthDanceChoreography,
	type AuthDanceComponent,
	type AuthDanceComponentContext,
	type AuthDanceIdentity,
	type AuthDanceIdentityComponentPublic,
	type AuthDanceMessage,
	type AuthDanceResponseComponents,
	type AuthDanceResponseResult,
	type AuthDanceResponseSessions,
	type AuthDanceResponseState,
	type AuthDanceResponseTokens,
	AuthDanceStorage,
	createAuthDance,
} from "auth-dance";
import { MemoryAuthDanceChannel, MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "auth-dance/providers/memory";
import { EmailAuthDanceComponent } from "auth-dance/components/email";
import { OtpAuthDanceComponent } from "auth-dance/components/otp";
import { PasswordAuthDanceComponent, pbkdf2PasswordHasher } from "auth-dance/components/password";
import type { Durations } from "./config.ts";

/**
 * The key that signs the tokens and encrypts the state.
 *
 * It sits in the bundle in plain sight, which a real deployment must never do. Here both ends of the dance are the
 * same page, so there is no second party to keep it from.
 */
export const SECRET = "zdJXI1jwuXW8A19fns0E_B4HSYm7AUHLGlU9WLo8mxs";

/**
 * The PBKDF2 rounds of the password component. The library defaults to 600 000, which is right for a server and about
 * a second of a phone browser per submitted password.
 */
export const PASSWORD_ROUNDS = 60_000;

/** What the seed puts in storage, and what the start card offers to type. */
export const SEEDED = {
	id: "id_0000000000000000000demo",
	email: "john.doe@example.com",
	password: "hunter2",
};

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
	/** The bare one-time code, which `OtpAuthDanceComponent` puts under `text/x-code`. Absent on any other message. */
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

/**
 * Where a running instance reports what happened out of band.
 *
 * A channel takes a message and a hook fires while a call is still awaited, so neither can return anything the caller
 * would read. They report here instead, and the store turns each report into state.
 */
export interface DanceSink {
	/** Called by a channel for every message it took. */
	delivered(message: DeliveredMessage): void;
	/** Called by every hook the instance declares. */
	reported(event: ReportedHook): void;
}

/** One built instance, with the names its pickers offer and the seed that fills it. */
export interface Dance {
	/** The library itself. `auth.fetch` is the whole transport of this page. */
	auth: AuthDance;
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
 * A one-time code as a step of the choreography, rather than as the proof another component asks for.
 *
 * `OtpAuthDanceComponent` declares no verification of its own, and its `verificationComponent` throws to say so. A
 * sign-up calls that method for any collected value that is not confirmed yet, so the base class can only ever be a
 * verification. Dropping the method says the same thing in the form the sign-up reads: a code the owner read at an
 * address the identity already holds is proof enough on its own.
 *
 * This is all a component of your own has to do. The library asks for a prompt, a check and a record, and the
 * choreography names it like any other step.
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
		// The memory channel files every recipient under the literal key `sms`, whatever the channel is called, so the
		// address is read as the one string in the bag rather than under a fixed key.
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
 * Builds one instance from a choreography, a set of durations and a sink.
 *
 * The four components are fixed and the choreography picks among them by name. `email` and `email2` are two addresses,
 * each with a channel of its own — `inbox` and `inbox2`. `password` is a challenge. `otp` is a code over the `inbox`
 * channel, which lets a choreography name it as a step of its own rather than as a verification.
 */
export function buildDance(choreography: AuthDanceChoreography, durations: Durations, sink: DanceSink): Dance {
	// A name names one record, so a channel never shares the name of a component. The constructor of the library
	// refuses a policy that gives both the same one, because a `linkedTo` entry names a record by its name alone.
	const channels = {
		inbox: new DemoChannel("inbox", "email", sink),
		inbox2: new DemoChannel("inbox2", "email", sink),
		sms: new DemoChannel("sms", "phone", sink),
	};

	const email = new EmailAuthDanceComponent({ channel: "inbox" });
	const email2 = new EmailAuthDanceComponent({ channel: "inbox2" });
	const password = new PasswordAuthDanceComponent("demo-pepper", pbkdf2PasswordHasher(PASSWORD_ROUNDS));
	const components: Record<string, AuthDanceComponent> = { email, email2, password, otp: new CodeAuthDanceComponent({ channel: "inbox" }) };

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
			// A demo gets poked at far harder than an account does. The defaults allow one identity 10 verifications
			// and 5 deliveries per five minutes, which a curious visitor empties in a minute of clicking. These are
			// the same buckets, opened wide.
			limits: {
				identity: {
					verify: { limit: 200, window: 300 },
					send: { limit: 200, window: 300 },
					manage: { limit: 200, window: 300 },
					refresh: { limit: 200, window: 300 },
				},
			},
			// The listeners the library calls after it saves a change. They report what happened; they never decide
			// anything, and one that throws never fails the flow.
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
	 * Seeds an identity the way a sign-up would leave one, without running the flow. The password record is salted
	 * with the id of the identity, so the id comes first and the components are built against it. Hence `setIdentity`
	 * rather than `createIdentity`, which would mint an id of its own after the fact.
	 *
	 * A rebuild throws the old instance away with everything in it, so this small warm 🥔 of state is written again
	 * every time.
	 */
	async function seedIdentity(): Promise<AuthDanceIdentity> {
		const identity: AuthDanceIdentity = { id: SEEDED.id, data: { name: "John Doe" }, components: [] };
		const seed = (name: string): AuthDanceComponentContext => ({ storage, stateId: "state_seed", name, flow: "sign-up", identity });
		identity.components = [
			...await email.getIdentityComponent("email", SEEDED.email, true),
			...await password.getIdentityComponent("password", SEEDED.password, true, seed("password")),
		];
		await storage.setIdentity(identity);
		return identity;
	}

	return { auth, storage, componentNames: Object.keys(components), channelNames: Object.keys(channels), seedIdentity };
}

/**
 * A state response as it arrives over the wire.
 *
 * `AuthDanceResponseState` carries `expireAt` as a `Date`, which is what `auth.api` returns in process. The HTTP layer
 * serializes it, and this page reads the HTTP layer, so here it is a string.
 */
export interface StateBody extends Omit<AuthDanceResponseState, "expireAt"> {
	/** The moment the flow expires, as an ISO 8601 string. An answer to a prompt never extends it. */
	expireAt: string;
}

/** A completed sign-in, a completed sign-up or a refresh. Nothing in this shape is a `Date`, so the wire copies it as it is. */
export type TokensBody = AuthDanceResponseTokens;

/** A call that succeeded and returns nothing else, which is how every flow but a sign-in and a sign-up ends. */
export type ResultBody = AuthDanceResponseResult;

/** The body of `/list-sessions`: every open session, and the id of the one that asked. */
export type SessionsBody = AuthDanceResponseSessions;

/** The body of `/list-components`: every enrolled component, with the private `data` of each one dropped. */
export type ComponentsBody = AuthDanceResponseComponents;

/** The body of every failure. The library answers a single code and nothing else. */
export interface ErrorBody {
	/** One of the codes of the `Errors` registry, or `BAD_REQUEST` when the body did not parse. */
	error: string;
}

/** The public component records `/list-components` answers with. Re-exported so a panel types its list without reaching for the library. */
export type EnrolledComponent = AuthDanceIdentityComponentPublic;

/**
 * A refusal from the library. The body of a failure is always a single `{ error: CODE }`.
 *
 * Do not branch on the status. Everything but a missing body and an empty rate limit bucket comes back as 500, so
 * `INVALID_PROMPT_VALUE` and `FRESH_SIGN_IN_REQUIRED` share a status with a genuine fault. The code is the answer.
 */
export class ApiError extends Error {
	/** The HTTP status the call answered with: 400 for a missing body, 429 for a rate limit, 500 for everything else. */
	readonly status: number;
	/** The code the body named, which is what a caller branches on. */
	readonly code: string;

	constructor(status: number, code: string) {
		super(`${code} · HTTP ${status}`);
		this.status = status;
		this.code = code;
	}
}

/** Plain sentences for the codes this demo runs into most. Everything else shows the code alone. */
export const ERROR_HINTS: Record<string, string> = {
	INVALID_PROMPT_VALUE:
		"The value did not verify. A wrong password and an unknown address answer the same way, so nobody can probe for accounts.",
	INVALID_VALIDATION_VALUE: "The one-time code did not match. Send a fresh one and try again.",
	CONFIRMATION_REQUIRED: "This flow ends on a confirmation, and only the boolean true goes through.",
	WOULD_LOCK_OUT: "Dropping this component would leave no complete path through the choreography.",
	COMPONENT_IN_USE: "A record this one names in its linkedTo is still enrolled, so it cannot leave on its own.",
	COMPONENT_ALREADY_ENROLLED: "The identity already holds this component. Rotate it instead.",
	CHANNEL_ALREADY_SUBSCRIBED: "The identity already holds this channel.",
	COMPONENT_NOT_RECOVERABLE:
		"This component is not part of the choreography, or nothing else in it can identify you and prove control on its own.",
	FRESH_SIGN_IN_REQUIRED: "The elevated window closed. Sign in again to run a sensitive flow.",
	INVALID_ACCESS_TOKEN: "This route needs a valid access token.",
	INVALID_STATE: "The state is gone or expired. Start the flow again.",
	INVALID_STATE_FOR_FLOW: "This flow has nothing of that kind to answer or to send at this point.",
	IDENTITY_NOT_RESOLVED: "No step of this dance has said who is dancing yet.",
	RATE_LIMITED: "The bucket for this address or identity is empty for now.",
};
