/**
 * @module
 *
 * Everything the page knows, in one observable record. Only {@link useDance} knows React exists.
 *
 * Every field of a prompt is controlled state, keyed by prompt name. A checkbox that nobody touched submits `false`.
 * The module builds no instance until {@link useDance} runs its effect, so a server pass is safe.
 */

import { useEffect, useSyncExternalStore } from "react";
import type { AuthDancePromptInput, AuthDanceSession } from "auth-dance";
import { generateKey } from "auth-dance";
import {
	ApiError,
	buildDance,
	CALLER_ADDRESS,
	type ComponentsBody,
	type Dance,
	type DanceSink,
	type DeliveredMessage,
	type EnrolledComponent,
	ERROR_HINTS,
	type ErrorBody,
	type ReportedHook,
	type ResultBody,
	type SessionsBody,
	type StateBody,
	type TokensBody,
} from "./dance.ts";
import { type Config, currentChoreography, defaultConfig, loadConfig, saveConfig } from "./config.ts";
import { activePrompt, type FlowName, FLOWS, promptInputs, type Step } from "./flows.ts";

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

/** The whole state of the page. Every field is replaced, never mutated. */
export interface DanceState {
	/** Whether the first instance has been built. Every panel shows a placeholder until it has. */
	ready: boolean;
	/** The config the running instance was built from. */
	config: Config;
	/** The component names the running choreography can name, for the pickers of `enroll`, `unenroll`, `rotate` and `recover`. */
	componentNames: string[];
	/** The channel names of the running instance, for the pickers of `subscribe` and `unsubscribe`. */
	channelNames: string[];
	/** The flow in progress, or nothing when the page is between flows. */
	step: Step | undefined;
	/** The value of every field of the current prompt, keyed by prompt name. Seeded on arrival, dropped on advance. */
	values: Record<string, unknown>;
	/** The branch of a choice prompt the owner picked, by name. The first branch is picked when the prompt arrives. */
	branch: string | undefined;
	/** The three tokens of the session, or nothing while signed out. */
	tokens: TokensBody["tokens"] | undefined;
	/** The whole answer of the sign-in, the sign-up or the last refresh. The session record sits at `session.session`. */
	session: TokensBody | undefined;
	/** What `/list-sessions` last answered, until a rebuild or a sign-out drops it. */
	sessions: AuthDanceSession[] | undefined;
	/** What `/list-components` last answered, until a rebuild or a sign-out drops it. */
	enrolled: EnrolledComponent[] | undefined;
	/** Every message a channel took, newest first. */
	messages: Message[];
	/** Every call and every hook report, newest first. */
	log: LogEntry[];
	/** Whether an action is running. */
	busy: boolean;
	/** What the last action refused with: the code, and the sentence for it when there is one. */
	error: string | undefined;
	/** What the last action reported on success. */
	notice: string | undefined;
}

/** Everything a control can do. Every action is bound. */
export interface DanceActions {
	/** Runs one action, and turns whatever it throws into the alert. A second call while one is running does nothing. */
	act(action: () => void | Promise<void>): Promise<void>;
	/** Loads the stored config and builds the first instance. Idempotent, and called for you by {@link useDance}. */
	start(): Promise<void>;
	/** Rebuilds the instance from the current config. Every identity, session and message of the old one goes with it. */
	rebuild(): Promise<void>;
	/** Starts a flow and keeps the first prompt. `argument` names a component or a channel for the flows that take one. */
	startFlow(flow: FlowName, argument?: string): Promise<void>;
	/**
	 * Answers the current prompt and takes whatever comes back: the next prompt, the tokens, or a plain success.
	 * @param prepare Builds the value instead of reading it out of the fields, for a type that nothing types into.
	 * It runs inside the same action as the call, so what it throws lands in the same alert.
	 */
	submitCurrent(prepare?: (prompt: AuthDancePromptInput) => Promise<unknown>): Promise<void>;
	/** Asks the library to deliver the current prompt over its channel. */
	sendCurrent(): Promise<void>;
	/** Drops the flow in progress. */
	cancel(): Promise<void>;
	/** Ends this session. */
	signOut(): Promise<void>;
	/** Ends every session but this one. */
	signOutOthers(): Promise<void>;
	/** Exchanges the refresh token for a fresh set on the same session. */
	refreshTokens(): Promise<void>;
	/** Reads every session open on the identity into {@link DanceState.sessions}. */
	listSessions(): Promise<void>;
	/** Reads every enrolled component into {@link DanceState.enrolled}. */
	listComponents(): Promise<void>;
	/** Empties the wire log. */
	clearLog(): Promise<void>;
	/**
	 * Fills the one-time code field of the current prompt with a code out of the inbox.
	 * @returns The prompt name it filled, or nothing when the step has no code field.
	 */
	useCode(code: string): string | undefined;
	/** Writes one field of the current prompt. */
	setPromptValue(name: string, value: unknown): void;
	/** Picks a branch of a choice prompt, by name. */
	setBranch(name: string): void;
	/** Stores a config and rebuilds on it. It refuses a broken custom tree before it drops the running instance. */
	applyConfig(next: Config): Promise<void>;
	/** Goes back to the shipped config and rebuilds on it. */
	restoreDefaults(): Promise<void>;
}

/** The state before anything is built. A server pass reads it, so hydration starts from it. */
const INITIAL: DanceState = {
	ready: false,
	config: defaultConfig(),
	componentNames: [],
	channelNames: [],
	step: undefined,
	values: {},
	branch: undefined,
	tokens: undefined,
	session: undefined,
	sessions: undefined,
	enrolled: undefined,
	messages: [],
	log: [],
	busy: false,
	error: undefined,
	notice: undefined,
};

/**
 * What one field holds before the owner touches it. A confirmation starts at `false`.
 *
 * A `totp-key` field starts on a key this browser draws. The library never generates one and never delivers one, so
 * every arrival of that prompt draws a new key, and the owner takes it off the screen.
 */
function initialValue(input: AuthDancePromptInput): unknown {
	if (input.type === "confirmation") {
		return false;
	}
	if (input.type === "totp-key") {
		return generateKey(16);
	}
	return "";
}

/** What every field of a prompt holds before the owner touches it. */
function emptyValues(step: Step): Record<string, unknown> {
	const values: Record<string, unknown> = {};
	for (const input of promptInputs(step.prompt)) {
		values[input.name] = initialValue(input);
	}
	return values;
}

function firstBranch(step: Step): string | undefined {
	return step.prompt.kind === "choice" ? promptInputs(step.prompt)[0]?.name : undefined;
}

function describe(cause: unknown): string {
	if (cause instanceof ApiError) {
		const hint = ERROR_HINTS[cause.code];
		return hint ? `${cause.code} — ${hint}` : cause.code;
	}
	return cause instanceof Error ? cause.message : String(cause);
}

/** The page, as a store. Nothing constructs an instance of the library until {@link start} runs. */
export class DanceStore implements DanceActions {
	#state: DanceState = INITIAL;
	#listeners = new Set<() => void>();
	#dance: Dance | undefined;
	#counter = 0;
	#started = false;

	/** Where the channels and the hooks of the running instance report. */
	#sink: DanceSink = {
		delivered: (message) => this.#deliver(message),
		reported: (event) => this.#report(event),
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
			this.#patch({ error: describe(cause) });
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

	readonly startFlow = (flow: FlowName, argument?: string): Promise<void> =>
		this.act(async () => {
			const definition = FLOWS[flow];
			const body = definition.argument === "none" ? undefined : { name: argument };
			const result = await this.#post<StateBody>(definition.path, body, definition.authenticated);
			this.#enter({
				flow,
				state: result.state,
				prompt: result.prompt,
				expireAt: result.expireAt,
				trail: [],
			});
		});

	readonly submitCurrent = (prepare?: (prompt: AuthDancePromptInput) => Promise<unknown>): Promise<void> =>
		this.act(async () => {
			const step = this.#state.step;
			if (!step) {
				return;
			}
			const target = activePrompt(step.prompt, this.#state.branch);
			if (!target) {
				throw new Error("Pick which component to answer.");
			}
			const value = prepare ? await prepare(target) : this.#state.values[target.name];
			const result = await this.#post<StateBody | TokensBody | ResultBody>("/submit-prompt", {
				name: target.name,
				value,
				state: step.state,
			});
			const trail = [...step.trail, target.name];
			if ("tokens" in result) {
				this.#leave({
					tokens: result.tokens,
					session: result,
					notice: `Signed in as ${result.identity.id}. The session panel holds the tokens.`,
				});
				return;
			}
			if ("success" in result) {
				this.#leave({ notice: `${FLOWS[step.flow].label} completed.` });
				return;
			}
			this.#enter({
				...step,
				state: result.state,
				prompt: result.prompt,
				expireAt: result.expireAt,
				trail,
			});
		});

	readonly sendCurrent = (): Promise<void> =>
		this.act(async () => {
			const step = this.#state.step;
			if (!step) {
				return;
			}
			const target = activePrompt(step.prompt, this.#state.branch);
			if (!target) {
				throw new Error("Pick which component to send.");
			}
			await this.#post<ResultBody>("/send-prompt", { name: target.name, locale: this.#locale(), state: step.state });
			this.#patch({ notice: "Sent. The inbox holds it." });
		});

	readonly cancel = (): Promise<void> => this.act(() => this.#leave({}));

	readonly signOut = (): Promise<void> =>
		this.act(async () => {
			await this.#post<ResultBody>("/sign-out", { others: false }, true);
			this.#patch({
				tokens: undefined,
				session: undefined,
				sessions: undefined,
				enrolled: undefined,
				notice: "Signed out. The session is gone from storage.",
			});
		});

	readonly signOutOthers = (): Promise<void> =>
		this.act(async () => {
			await this.#post<ResultBody>("/sign-out", { others: true }, true);
			this.#patch({ sessions: undefined, notice: "Every other session is gone." });
		});

	readonly refreshTokens = (): Promise<void> =>
		this.act(async () => {
			const tokens = this.#state.tokens;
			if (!tokens) {
				throw new Error("This route needs an access token. Sign in first.");
			}
			const result = await this.#post<TokensBody>("/refresh-token", { refresh_token: tokens.refresh_token });
			this.#patch({
				tokens: result.tokens,
				session: result,
				notice: "Fresh tokens on the same session. A refresh keeps aat, so it never reopens the elevated window.",
			});
		});

	readonly listSessions = (): Promise<void> =>
		this.act(async () => {
			const result = await this.#post<SessionsBody>("/list-sessions", undefined, true);
			this.#patch({ sessions: result.sessions });
		});

	readonly listComponents = (): Promise<void> =>
		this.act(async () => {
			const result = await this.#post<ComponentsBody>("/list-components", undefined, true);
			this.#patch({ enrolled: result.components });
		});

	readonly clearLog = (): Promise<void> => this.act(() => this.#patch({ log: [] }));

	readonly useCode = (code: string): string | undefined => {
		const step = this.#state.step;
		if (!step) {
			return undefined;
		}
		const field = promptInputs(step.prompt).find((input) => input.type === "otp");
		if (!field) {
			return undefined;
		}
		this.setPromptValue(field.name, code);
		return field.name;
	};

	readonly setPromptValue = (name: string, value: unknown): void => {
		this.#patch({ values: { ...this.#state.values, [name]: value } });
	};

	readonly setBranch = (name: string): void => {
		this.#patch({ branch: name });
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

	#enter(step: Step): void {
		this.#patch({ step, values: emptyValues(step), branch: firstBranch(step) });
	}

	#leave(partial: Partial<DanceState>): void {
		this.#patch({ step: undefined, values: {}, branch: undefined, ...partial });
	}

	#locale(): string {
		return navigator.language || "en";
	}

	#require(): Dance {
		if (!this.#dance) {
			throw new Error("The library is not built yet.");
		}
		return this.#dance;
	}

	/** Builds the instance and empties everything the old one held. It runs outside {@link act}. */
	async #rebuild(): Promise<void> {
		const config = this.#state.config;
		const dance = buildDance(currentChoreography(config), config.durations, this.#sink);
		this.#dance = dance;
		this.#patch({
			ready: true,
			componentNames: dance.componentNames,
			channelNames: dance.channelNames,
			step: undefined,
			values: {},
			branch: undefined,
			tokens: undefined,
			session: undefined,
			sessions: undefined,
			enrolled: undefined,
			messages: [],
			log: [],
		});
		if (config.seed) {
			await dance.seedIdentity();
		}
	}

	/**
	 * Sends one request into the library and records it.
	 * @throws {ApiError} For any status other than 200, carrying the code the body names.
	 */
	async #post<T>(path: string, body?: unknown, authenticated = false): Promise<T> {
		const dance = this.#require();
		const headers: Record<string, string> = {
			"content-type": "application/json",
			"accept-language": this.#locale(),
			"cf-connecting-ip": CALLER_ADDRESS,
			"user-agent": navigator.userAgent,
		};
		if (authenticated) {
			const tokens = this.#state.tokens;
			if (!tokens) {
				throw new Error("This route needs an access token. Sign in first.");
			}
			headers.authorization = `Bearer ${tokens.access_token}`;
		}
		const started = performance.now();
		const response = await dance.auth.fetch(
			new Request(`http://demo${path}`, { method: "POST", headers, body: body === undefined ? undefined : JSON.stringify(body) }),
		);
		const payload: unknown = await response.json();
		this.#write({
			id: ++this.#counter,
			at: new Date(),
			kind: "http",
			label: `POST ${path}`,
			status: response.status,
			ms: Math.round(performance.now() - started),
			request: body,
			response: payload,
		});
		if (response.status !== 200) {
			throw new ApiError(response.status, String((payload as Partial<ErrorBody> | null)?.error ?? "UNKNOWN"));
		}
		return payload as T;
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
