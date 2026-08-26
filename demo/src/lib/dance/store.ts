/**
 * @module
 *
 * Everything the page knows that the library does not: the instance it built, the config that instance came from, the
 * inbox and the wire log. Only {@link useDance} knows React exists.
 *
 * Nothing here drives a flow. The client of `auth-dance/client` keeps the tokens, and `useAuthDanceFlow` of
 * `auth-dance/react` drives the dance, so the store hands the client to the tree and stays out of the way.
 *
 * The module builds no instance until {@link useDance} runs its effect, so a server pass is safe.
 */

import { useEffect, useSyncExternalStore } from "react";
import type { AuthDanceClient, AuthDanceIdentityComponentPublic, AuthDanceResponseSessions } from "auth-dance/client";
import {
	buildDance,
	type CalledRoute,
	type Dance,
	type DanceSink,
	type DeliveredMessage,
	describeFailure,
	type ReportedHook,
} from "./dance.ts";
import { type Config, currentChoreography, defaultConfig, loadConfig, saveConfig } from "./config.ts";

/** One message a channel took, as the inbox lists it. */
export interface Message extends DeliveredMessage {
	/** A number that rises with every message and every log entry. A list keys on it. */
	id: number;
	/** When the channel took it. */
	at: Date;
}

/** One line of the wire log: a call into the library, or a hook report. */
export interface LogEntry {
	/** A number that rises with every message and every log entry. A list keys on it. */
	id: number;
	/** When the line was written. */
	at: Date;
	/** Whether the line is a call or a hook. A hook carries no status and no duration. */
	kind: "http" | "hook";
	/** `POST /sign-in` for a call, the hook name for a hook. */
	label: string;
	/** The status the call answered with. Absent on a hook. */
	status?: number;
	/** How long the call took, in milliseconds. Absent on a hook. */
	ms?: number;
	/** The body the call sent. Absent on a hook, and on a route that takes no body. */
	request?: unknown;
	/** The body the call answered with, or the flow and the summary a hook reported. */
	response?: unknown;
}

/** A one-time code the inbox handed to the form. The id rises, so the same code twice still moves the field. */
export interface HandedCode {
	/** The bare code. */
	value: string;
	/** A number that rises with every hand-over. */
	id: number;
}

/** The whole state of the page. Every field is replaced, never mutated. */
export interface DanceState {
	/** The config the running instance was built from. */
	config: Config;
	/** The client of the running instance, or nothing while one is being built. */
	client: AuthDanceClient | undefined;
	/** Whether the running instance holds the John Doe identity. It reports the seed that landed, not the one asked for. */
	seeded: boolean;
	/** The component names the running choreography can name, for the pickers of `enroll`, `unenroll`, `rotate` and `recover`. */
	componentNames: string[];
	/** The channel names of the running instance, for the pickers of `subscribe` and `unsubscribe`. */
	channelNames: string[];
	/** What `/list-sessions` last answered, until a rebuild or a sign-out drops it. */
	sessions: AuthDanceResponseSessions | undefined;
	/** What `/list-components` last answered, until a rebuild or a sign-out drops it. */
	enrolled: AuthDanceIdentityComponentPublic[] | undefined;
	/** Every message a channel took, newest first. */
	messages: Message[];
	/** Every call and every hook report, newest first. */
	log: LogEntry[];
	/** The code the inbox handed over, until a field takes it. */
	code: HandedCode | undefined;
	/** Whether an action of the store is running. A running flow reports through its own handle. */
	busy: boolean;
	/** What the last action of the store refused with: the code, and the sentence for it when there is one. */
	error: string | undefined;
	/** What the last action, or the last completed flow, reported. */
	notice: string | undefined;
}

/** Everything a control can do that the client does not do on its own. Every action is bound. */
export interface DanceActions {
	/** Runs one action, and turns whatever it throws into the alert. A second call while one is running does nothing. */
	act(action: () => void | Promise<void>): Promise<void>;
	/** Loads the stored config and builds the first instance. Idempotent, and called for you by {@link useDance}. */
	start(): Promise<void>;
	/** Rebuilds the instance from the current config. Every identity, session and message of the old one goes with it. */
	rebuild(): Promise<void>;
	/** Ends this session. */
	signOut(): Promise<void>;
	/** Ends every session of the identity, this one included. */
	signOutEverywhere(): Promise<void>;
	/** Exchanges the refresh token for a fresh set on the same session. */
	refreshTokens(): Promise<void>;
	/** Reads every session open on the identity into {@link DanceState.sessions}. */
	listSessions(): Promise<void>;
	/** Reads every enrolled component into {@link DanceState.enrolled}. */
	listComponents(): Promise<void>;
	/** Empties the wire log. */
	clearLog(): Promise<void>;
	/** Hands a one-time code out of the inbox to whichever field takes one. */
	fillCode(code: string): void;
	/** Drops the handed code, once a field took it. */
	clearCode(): void;
	/** Writes the affirmative line of the page. A completed flow reports through here. */
	notify(notice: string): void;
	/** Empties both alerts of the page. A flow that starts calls it, so no stale line sits behind the card. */
	clearAlerts(): void;
	/** Stores a config and rebuilds on it. It refuses a broken custom tree before it drops the running instance. */
	applyConfig(next: Config): Promise<void>;
	/** Goes back to the shipped config and rebuilds on it. */
	restoreDefaults(): Promise<void>;
}

/** The state before anything is built. A server pass reads it, so hydration starts from it. */
const INITIAL: DanceState = {
	config: defaultConfig(),
	client: undefined,
	seeded: false,
	componentNames: [],
	channelNames: [],
	sessions: undefined,
	enrolled: undefined,
	messages: [],
	log: [],
	code: undefined,
	busy: false,
	error: undefined,
	notice: undefined,
};

/** The page, as a store. Nothing constructs an instance of the library until {@link start} runs. */
export class DanceStore implements DanceActions {
	#state: DanceState = INITIAL;
	#listeners = new Set<() => void>();
	#dance: Dance | undefined;
	#counter = 0;
	#started = false;

	/** Where the channels, the hooks and the client of the running instance report. */
	#sink: DanceSink = {
		delivered: (message) => this.#deliver(message),
		reported: (event) => this.#report(event),
		called: (call) => this.#trace(call),
	};

	/** Registers a listener, and returns the call that drops it again. */
	readonly subscribe = (listener: () => void): () => void => {
		this.#listeners.add(listener);
		return () => {
			this.#listeners.delete(listener);
		};
	};

	/** The current state. The reference changes on every write. */
	readonly getSnapshot = (): DanceState => this.#state;

	/** The state a server pass reads. */
	readonly getServerSnapshot = (): DanceState => INITIAL;

	readonly act = async (action: () => void | Promise<void>): Promise<void> => {
		if (this.#state.busy) {
			return;
		}
		this.#patch({ busy: true, error: undefined, notice: undefined });
		try {
			await action();
		} catch (cause) {
			this.#patch({ error: describeFailure(cause) });
		}
		this.#patch({ busy: false });
	};

	readonly start = async (): Promise<void> => {
		if (this.#started) {
			return;
		}
		this.#started = true;
		this.#patch({ config: loadConfig() });
		await this.act(() => this.#rebuild());
	};

	readonly rebuild = (): Promise<void> => this.act(() => this.#rebuild());

	readonly signOut = (): Promise<void> =>
		this.act(async () => {
			await this.#client().signOut();
			this.#patch({
				sessions: undefined,
				enrolled: undefined,
				notice: "Signed out. The client dropped the tokens it held.",
			});
		});

	readonly signOutEverywhere = (): Promise<void> =>
		this.act(async () => {
			// `others` destroys every session of the identity, this one included, which is exactly what
			// `listSessions` enumerates. The client drops the tokens with them.
			await this.#client().signOut({ others: true });
			this.#patch({
				sessions: undefined,
				enrolled: undefined,
				notice: "Every session of this identity is gone, this one included.",
			});
		});

	readonly refreshTokens = (): Promise<void> =>
		this.act(async () => {
			await this.#client().refreshTokens();
			this.#patch({
				notice: "Fresh tokens on the same session. A refresh keeps aat, so it never reopens the elevated window.",
			});
		});

	readonly listSessions = (): Promise<void> =>
		this.act(async () => {
			this.#patch({ sessions: await this.#client().listSessions() });
		});

	readonly listComponents = (): Promise<void> =>
		this.act(async () => {
			this.#patch({ enrolled: await this.#client().listComponents() });
		});

	readonly clearLog = (): Promise<void> => this.act(() => this.#patch({ log: [] }));

	readonly fillCode = (code: string): void => {
		this.#patch({ code: { value: code, id: ++this.#counter } });
	};

	readonly clearCode = (): void => {
		if (this.#state.code) {
			this.#patch({ code: undefined });
		}
	};

	readonly notify = (notice: string): void => {
		this.#patch({ error: undefined, notice });
	};

	readonly clearAlerts = (): void => {
		if (this.#state.error !== undefined || this.#state.notice !== undefined) {
			this.#patch({ error: undefined, notice: undefined });
		}
	};

	readonly applyConfig = (next: Config): Promise<void> =>
		this.act(async () => {
			currentChoreography(next);
			saveConfig(next);
			this.#patch({ config: next });
			await this.#rebuild();
			this.#patch({ notice: "Rebuilt with the new options." });
		});

	readonly restoreDefaults = (): Promise<void> =>
		this.act(async () => {
			const next = defaultConfig();
			saveConfig(next);
			this.#patch({ config: next });
			await this.#rebuild();
			this.#patch({ notice: "Back to the defaults." });
		});

	#patch(partial: Partial<DanceState>): void {
		this.#state = { ...this.#state, ...partial };
		for (const listener of this.#listeners) {
			listener();
		}
	}

	#client(): AuthDanceClient {
		if (!this.#dance) {
			throw new Error("The library is not built yet.");
		}
		return this.#dance.client;
	}

	/** Builds the instance, seeds it, and empties everything the old one held. It runs outside {@link act}. */
	async #rebuild(): Promise<void> {
		const config = this.#state.config;
		const dance = buildDance(currentChoreography(config), config.durations, this.#sink);
		this.#dance = dance;
		// Nothing reads the instance until the seed is in storage. A card that offers John Doe before the record
		// exists earns INVALID_PROMPT_VALUE on the first prompt, and the owner has no way to tell why.
		this.#patch({
			client: undefined,
			seeded: false,
			sessions: undefined,
			enrolled: undefined,
			messages: [],
			log: [],
			code: undefined,
		});
		if (config.seed) {
			await dance.seedIdentity();
		}
		// The new client holds no tokens, so the tree under it renders as signed out on its own.
		this.#patch({
			client: dance.client,
			seeded: config.seed,
			componentNames: dance.componentNames,
			channelNames: dance.channelNames,
		});
	}

	#deliver(message: DeliveredMessage): void {
		this.#patch({ messages: [{ id: ++this.#counter, at: new Date(), ...message }, ...this.#state.messages] });
	}

	#report(event: ReportedHook): void {
		this.#write({
			id: ++this.#counter,
			at: new Date(),
			kind: "hook",
			label: event.hook,
			response: { flow: event.flow, summary: event.summary },
		});
	}

	#trace(call: CalledRoute): void {
		this.#write({
			id: ++this.#counter,
			at: new Date(),
			kind: "http",
			label: `POST ${call.path}`,
			status: call.status,
			ms: call.ms,
			request: call.request,
			response: call.response,
		});
	}

	#write(entry: LogEntry): void {
		this.#patch({ log: [entry, ...this.#state.log] });
	}
}

let store: DanceStore | undefined;

/** The one store of the page. Construction touches nothing, so a server pass can call it. */
export function getDanceStore(): DanceStore {
	store ??= new DanceStore();
	return store;
}

/** Reads the state of the page, and boots it on the first mount. */
export function useDance(): DanceState {
	const dance = getDanceStore();
	const state = useSyncExternalStore(dance.subscribe, dance.getSnapshot, dance.getServerSnapshot);
	useEffect(() => {
		void dance.start();
	}, [dance]);
	return state;
}

/** The actions of the page. The reference never changes. */
export function useDanceActions(): DanceActions {
	return getDanceStore();
}
