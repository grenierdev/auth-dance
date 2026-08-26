/**
 * @module
 *
 * React bindings for the dance. {@link AuthDanceProvider} shares one client with a tree, {@link useAuthDanceFlow}
 * starts one flow and drives it, and {@link AuthDancePromptSwitch} renders the prompt the owner answers next.
 *
 * This module keeps no state of its own. It reads the client and the dance of `auth-dance/client`, and it renders
 * again every time either one reports a change. Every action it exposes keeps the failure it caught under `error`,
 * so a page reads a refused answer off the same object it renders from.
 *
 * @example
 * ```tsx
 * <AuthDanceProvider client={client}>
 * 	<AuthDanceFlowProvider flow="sign-in">
 * 		<AuthDancePromptSwitch
 * 			prompts={{
 * 				email: (prompt, flow) => <input onChange={(e) => flow.submitPrompt(e.target.value)} />,
 * 				password: (prompt, flow) => <input type="password" onChange={(e) => flow.submitPrompt(e.target.value)} />,
 * 			}}
 * 		/>
 * 	</AuthDanceFlowProvider>
 * </AuthDanceProvider>
 * ```
 */

// @deno-types="npm:@types/react@^19.2.17"
import {
	type Context,
	createContext,
	createElement,
	type ReactNode,
	useCallback,
	useContext,
	useEffect,
	useMemo,
	useReducer,
	useRef,
	useState,
} from "react";
import {
	type AuthDanceClient,
	AuthDanceClientChoreography,
	type AuthDanceClientChoreographyStore,
	type AuthDanceFlow,
	type AuthDancePrompt,
	type AuthDancePromptInput,
	type AuthDanceResponse,
	type AuthDanceResponseTokens,
	type AuthDanceSession,
} from "./client.ts";

// What the surface below names. A page imports them from here, so the React half needs no second import path.
export type {
	AuthDanceClient,
	AuthDanceClientChoreography,
	AuthDanceClientChoreographySnapshot,
	AuthDanceClientChoreographyStep,
	AuthDanceClientChoreographyStore,
	AuthDanceFlow,
	AuthDancePrompt,
	AuthDancePromptChoice,
	AuthDancePromptInput,
	AuthDanceResponse,
	AuthDanceResponseTokens,
	AuthDanceSession,
} from "./client.ts";

const ClientContext: Context<AuthDanceClient | undefined> = createContext<AuthDanceClient | undefined>(undefined);
const FlowContext: Context<AuthDanceFlowHandle | undefined> = createContext<AuthDanceFlowHandle | undefined>(undefined);

/** What {@link AuthDanceProvider} takes. */
export interface AuthDanceProviderProps {
	/** The client every hook under this node reads, unless a call names another one. */
	client: AuthDanceClient;
	/** The tree that reads the client. */
	children?: ReactNode;
}

/**
 * Shares one client with everything under it.
 *
 * @param props The client, and the tree that reads it.
 * @returns The tree, under the client.
 */
export function AuthDanceProvider({ client, children }: AuthDanceProviderProps): ReactNode {
	return createElement(ClientContext.Provider, { value: client }, children);
}

/**
 * Reads the client of the tree.
 *
 * @param client A client to use over the one of the tree.
 * @returns The client this node reads.
 * @throws TypeError when no call names a client and no {@link AuthDanceProvider} stands above this node.
 */
export function useAuthDanceClient(client?: AuthDanceClient): AuthDanceClient {
	const context = useContext(ClientContext);
	const resolved = client ?? context;
	if (!resolved) {
		throw new TypeError("this hook needs a client, from a call or from an AuthDanceProvider above it");
	}
	return resolved;
}

/**
 * Reads the client of the tree, and answers with nothing when no {@link AuthDanceProvider} stands above this node. It
 * never throws, so a component that takes its own client calls it without a condition.
 *
 * @returns The client of the tree, or nothing.
 */
export function useOptionalAuthDanceClient(): AuthDanceClient | undefined {
	return useContext(ClientContext);
}

/**
 * Reads the tokens of the session the client holds, and renders again every time they change.
 *
 * The first render answers with what the client holds in memory. The client then reads its store, and this hook
 * renders again with whatever the store held.
 *
 * @param client A client to read over the one of the tree.
 * @returns The tokens, the session and the scoped identity data, or nothing while the owner is signed out.
 */
export function useAuthDanceTokens(client?: AuthDanceClient): AuthDanceResponseTokens | undefined {
	const resolved = useAuthDanceClient(client);
	const [tokens, setTokens] = useState<AuthDanceResponseTokens | undefined>(() => resolved.credentials);

	useEffect(() => {
		let mounted = true;
		setTokens(resolved.credentials);
		const listener = resolved.onTokensChange((next) => setTokens(next));
		// `restore` reads the store one time and reports nothing, so the answer comes back through here.
		resolved.restore().then(
			() => {
				if (mounted) {
					setTokens(resolved.credentials);
				}
			},
			() => {},
		);
		return () => {
			mounted = false;
			listener[Symbol.dispose]();
		};
	}, [resolved]);

	return tokens;
}

/**
 * Reads who the tokens belong to.
 *
 * @param client A client to read over the one of the tree.
 * @returns The identity id and the scoped identity data, or nothing while the owner is signed out.
 */
export function useAuthDanceIdentity(client?: AuthDanceClient): AuthDanceResponseTokens["identity"] | undefined {
	return useAuthDanceTokens(client)?.identity;
}

/**
 * Reads the session the tokens belong to.
 *
 * @param client A client to read over the one of the tree.
 * @returns The session record, or nothing while the owner is signed out.
 */
export function useAuthDanceSession(client?: AuthDanceClient): AuthDanceSession | undefined {
	return useAuthDanceTokens(client)?.session;
}

/** What {@link useAuthDanceFlow} needs before it starts a flow. */
export interface AuthDanceFlowOptions {
	/** The flow to start, under the name its route uses. A new flow here starts the new one and drops the old dance. */
	flow: AuthDanceFlow;
	/** The component or the channel the flow acts on. Seven of the nine flows name one. */
	name?: string;
	/** A client to use over the one of the tree. */
	client?: AuthDanceClient;
	/**
	 * Where the dance keeps its progress, so a page that reloads goes on from the same step. The hook reads it when the
	 * flow starts, and another store later never starts the flow again.
	 */
	store?: AuthDanceClientChoreographyStore;
	/**
	 * Whether the flow starts. Turn it off to hold a flow back until the page is ready for it.
	 * @defaultValue true
	 */
	enabled?: boolean;
	/** What to call once an answer ends the flow, with what that answer carried. */
	onDone?: (response: AuthDanceResponse, choreography: AuthDanceClientChoreography) => void;
	/** What to call every time an action is refused, with the failure the library raised. */
	onError?: (error: unknown) => void;
}

/**
 * One flow in progress, as a React component reads it.
 *
 * Every action answers rather than throws: a refused action keeps its failure under {@link AuthDanceFlowHandle.error}
 * and answers with nothing. Read `error` to render it, and {@link AuthDanceFlowHandle.clearError} to drop it.
 */
export interface AuthDanceFlowHandle {
	/** The dance itself, or nothing while the call that starts the flow is out, or once that call was refused. */
	choreography: AuthDanceClientChoreography | undefined;
	/** The flow that is running. */
	flow: AuthDanceFlow;
	/** The component or the channel the flow acts on. A flow that takes no argument carries none. */
	name: string | undefined;
	/** What the owner answers next: one input, or a choice between branches. It is `null` once the flow is over. */
	prompt: AuthDancePrompt | null;
	/** The one input the owner answers now. It is `null` while the step is a choice and no branch is picked. */
	current: AuthDancePromptInput | null;
	/** The branches of the current step, or an empty array when the step holds one input. */
	choices: AuthDancePromptInput[];
	/** The branch the owner picked, by name. */
	selected: string | undefined;
	/** The names answered so far in this flow, oldest first. */
	trail: string[];
	/** Whether {@link AuthDanceFlowHandle.sendPrompt} has something to deliver over a channel. */
	sendable: boolean;
	/** Whether the flow expired. Take it from the top with {@link AuthDanceFlowHandle.restart}. */
	expired: boolean;
	/** Whether the flow is over: an answer carried the tokens or a bare success. */
	done: boolean;
	/** Whether a call is out: the one that starts the flow, or the one an action made. */
	pending: boolean;
	/** The failure of the last refused action, or nothing. */
	error: unknown;
	/**
	 * Picks one branch of a choice, by name.
	 * @param name The name of the branch, as {@link AuthDanceFlowHandle.choices} carries it.
	 */
	choose(name: string): Promise<void>;
	/**
	 * Asks the library to deliver the current prompt over its channel, a one-time code for example.
	 * @param options `name` picks the branch to deliver. `locale` picks the language of the message.
	 */
	sendPrompt(options?: { name?: string; locale?: string }): Promise<void>;
	/**
	 * Answers the current prompt and moves the dance one step.
	 * @param value What the owner gave.
	 * @param options `name` picks the branch to answer.
	 * @returns The next prompt, the minted tokens, a bare success, or nothing when the answer was refused.
	 */
	submitPrompt(value: unknown, options?: { name?: string }): Promise<AuthDanceResponse | undefined>;
	/**
	 * Answers a confirmation prompt with the boolean `true`. An unenroll, an unsubscribe and a delete each end on one.
	 * @returns A bare success, or nothing when the answer was refused.
	 */
	confirm(): Promise<AuthDanceResponse | undefined>;
	/** Goes back one step. It does nothing on the first step. */
	prev(): Promise<void>;
	/** Takes the flow from the top. A flow whose start was refused starts over from here. */
	restart(): Promise<void>;
	/** Drops the flow. It calls no route: the library keeps nothing, so the state simply expires. */
	abandon(): Promise<void>;
	/** Drops the failure under {@link AuthDanceFlowHandle.error}. */
	clearError(): void;
}

/**
 * Starts one flow and drives it, and renders again every time the dance moves.
 *
 * The hook starts the flow when the node mounts, and again when the flow or the name changes. It disposes the dance
 * when the node unmounts, and it keeps the snapshot in the store, so the same node picks the flow back up on the step
 * it left.
 *
 * @param options The flow, what it acts on, where the progress goes, and what to call once it ends.
 * @returns The dance, everything a component renders from it, and the actions that move it.
 * @throws TypeError when no `client` is given and no {@link AuthDanceProvider} stands above this node.
 *
 * @example
 * ```tsx
 * const flow = useAuthDanceFlow({ flow: "rotate", name: "password" });
 * <input disabled={flow.pending} onChange={(e) => flow.submitPrompt(e.target.value)} />;
 * ```
 */
export function useAuthDanceFlow(options: AuthDanceFlowOptions): AuthDanceFlowHandle {
	const { flow, name, enabled = true } = options;
	const client = useAuthDanceClient(options.client);
	const [choreography, setChoreography] = useState<AuthDanceClientChoreography | undefined>(undefined);
	const [pending, setPending] = useState(true);
	const [error, setError] = useState<unknown>(undefined);
	const [attempt, retry] = useReducer((value: number) => value + 1, 0);
	// The dance changes in place, so a render needs a reason of its own. This counter is that reason.
	const [tick, bump] = useReducer((value: number) => value + 1, 0);
	// A store or a handler a page builds inline is a new object on every render. Reading them through a box keeps that
	// out of the reasons the flow starts again.
	const store = useRef(options.store);
	const onDone = useRef(options.onDone);
	const onError = useRef(options.onError);
	store.current = options.store;
	onDone.current = options.onDone;
	onError.current = options.onError;

	useEffect(() => {
		if (!enabled) {
			setPending(false);
			return;
		}
		let mounted = true;
		const controller = new AbortController();
		setPending(true);
		setError(undefined);
		AuthDanceClientChoreography.start(client, flow, { name, store: store.current, signal: controller.signal })
			.then(
				(started) => {
					if (!mounted) {
						started[Symbol.dispose]();
						return;
					}
					setChoreography(started);
				},
				(reason) => {
					if (mounted) {
						setChoreography(undefined);
						setError(reason);
						onError.current?.(reason);
					}
				},
			)
			.finally(() => {
				if (mounted) {
					setPending(false);
				}
			});
		return () => {
			mounted = false;
			controller.abort();
		};
	}, [client, flow, name, enabled, attempt]);

	useEffect(() => {
		if (!choreography) {
			return;
		}
		const listener = choreography.onChange(() => bump());
		return () => {
			listener[Symbol.dispose]();
			// The node is done with this dance. Disposing it disarms the timer of the expiry; the snapshot stays.
			choreography[Symbol.dispose]();
		};
	}, [choreography]);

	const run = useCallback(
		async <T>(action: (choreography: AuthDanceClientChoreography) => Promise<T>): Promise<T | undefined> => {
			if (!choreography) {
				return undefined;
			}
			setPending(true);
			setError(undefined);
			try {
				const answer = await action(choreography);
				bump();
				return answer;
			} catch (reason) {
				setError(reason);
				onError.current?.(reason);
				bump();
				return undefined;
			} finally {
				setPending(false);
			}
		},
		[choreography],
	);

	const choose = useCallback(async (branch: string): Promise<void> => {
		await run((dance) => dance.choose(branch));
	}, [run]);

	const sendPrompt = useCallback(async (sendOptions?: { name?: string; locale?: string }): Promise<void> => {
		await run((dance) => dance.sendPrompt(sendOptions));
	}, [run]);

	const submitPrompt = useCallback(
		async (value: unknown, submitOptions?: { name?: string }): Promise<AuthDanceResponse | undefined> => {
			const answer = await run((dance) => dance.submitPrompt(value, submitOptions));
			if (answer && choreography?.done) {
				onDone.current?.(answer, choreography);
			}
			return answer;
		},
		[run, choreography],
	);

	const confirm = useCallback((): Promise<AuthDanceResponse | undefined> => submitPrompt(true), [submitPrompt]);

	const prev = useCallback(async (): Promise<void> => {
		await run((dance) => dance.prev());
	}, [run]);

	const restart = useCallback(async (): Promise<void> => {
		// A start that was refused left no dance behind, so the only way back is the call that starts the flow.
		if (!choreography) {
			setError(undefined);
			retry();
			return;
		}
		await run((dance) => dance.restart());
	}, [run, choreography]);

	const abandon = useCallback(async (): Promise<void> => {
		await run((dance) => dance.abandon());
	}, [run]);

	const clearError = useCallback((): void => setError(undefined), []);

	return useMemo<AuthDanceFlowHandle>(() => ({
		choreography,
		flow,
		name,
		prompt: choreography?.prompt ?? null,
		current: choreography?.current ?? null,
		choices: choreography?.choices ?? [],
		selected: choreography?.selected,
		trail: choreography?.trail ?? [],
		sendable: choreography?.sendable ?? false,
		expired: choreography?.expired ?? false,
		done: choreography?.done ?? false,
		pending,
		error,
		choose,
		sendPrompt,
		submitPrompt,
		confirm,
		prev,
		restart,
		abandon,
		clearError,
		// `tick` reads as unused here, and it is the whole point: it is what a change of the dance moves.
	}), [choreography, tick, flow, name, pending, error, choose, sendPrompt, submitPrompt, confirm, prev, restart, abandon, clearError]);
}

/** What {@link AuthDanceFlowProvider} takes: everything {@link useAuthDanceFlow} needs, and what to render. */
export interface AuthDanceFlowProviderProps extends AuthDanceFlowOptions {
	/** The tree that reads the flow, or a function the provider calls with it. */
	children?: ReactNode | ((flow: AuthDanceFlowHandle) => ReactNode);
	/** What to render while the call that starts the flow is out. Without one, the children render at once. */
	fallback?: ReactNode;
}

/**
 * Starts one flow and shares it with everything under it.
 *
 * @param props The flow, what it acts on, where the progress goes, and what to render.
 * @returns The tree, under the flow.
 *
 * @example
 * ```tsx
 * <AuthDanceFlowProvider flow="sign-up" fallback={<p>one moment</p>}>
 * 	{(flow) => <AuthDancePromptSwitch prompts={prompts} />}
 * </AuthDanceFlowProvider>
 * ```
 */
export function AuthDanceFlowProvider({ children, fallback, ...options }: AuthDanceFlowProviderProps): ReactNode {
	const handle = useAuthDanceFlow(options);
	const node = typeof children === "function" ? children(handle) : children;
	const content = handle.choreography === undefined && fallback !== undefined ? fallback : node;
	return createElement(FlowContext.Provider, { value: handle }, content);
}

/**
 * Reads the flow of the tree.
 *
 * @param flow A flow to use over the one of the tree.
 * @returns The flow this node reads.
 * @throws TypeError when no call names a flow and no {@link AuthDanceFlowProvider} stands above this node.
 */
export function useAuthDanceFlowContext(flow?: AuthDanceFlowHandle): AuthDanceFlowHandle {
	const context = useContext(FlowContext);
	const resolved = flow ?? context;
	if (!resolved) {
		throw new TypeError("this hook needs a flow, from a call or from an AuthDanceFlowProvider above it");
	}
	return resolved;
}

/**
 * Reads the flow of the tree, and answers with nothing when no {@link AuthDanceFlowProvider} stands above this node.
 *
 * @returns The flow of the tree, or nothing.
 */
export function useOptionalAuthDanceFlowContext(): AuthDanceFlowHandle | undefined {
	return useContext(FlowContext);
}

/** What {@link AuthDancePromptSwitch} takes. */
export interface AuthDancePromptSwitchProps {
	/**
	 * What to render for one input, under the name of the component or the channel. A name this record does not hold
	 * falls back to the `type` of the input, so one entry under `otp` covers every one-time code.
	 */
	prompts: Record<string, (prompt: AuthDancePromptInput, flow: AuthDanceFlowHandle) => ReactNode>;
	/** What to render for a choice the owner has not picked a branch of yet. */
	choice?: (choices: AuthDancePromptInput[], flow: AuthDanceFlowHandle) => ReactNode;
	/** What to render when nothing above matches, the end of the flow included. The prompt is `null` from then on. */
	fallback?: (prompt: AuthDancePrompt | null, flow: AuthDanceFlowHandle) => ReactNode;
	/** A flow to render over the one of the tree. */
	flow?: AuthDanceFlowHandle;
}

/**
 * Renders the prompt the owner answers next.
 *
 * A step that holds one input goes to the entry of `prompts` under the name of that input, or under its type. A step
 * that holds a choice goes to `choice` until {@link AuthDanceFlowHandle.choose} picks a branch, and to the entry of
 * that branch from then on.
 *
 * @param props What to render for each prompt, for a choice, and for everything else.
 * @returns What the matching function returned, or what `fallback` returned, or nothing.
 * @throws TypeError when no `flow` is given and no {@link AuthDanceFlowProvider} stands above this node.
 *
 * @example
 * ```tsx
 * <AuthDancePromptSwitch
 * 	choice={(choices, flow) => choices.map((branch) => <button onClick={() => flow.choose(branch.name)}>{branch.name}</button>)}
 * 	prompts={{ email: (prompt, flow) => <input onChange={(e) => flow.submitPrompt(e.target.value)} /> }}
 * />
 * ```
 */
export function AuthDancePromptSwitch({ prompts, choice, fallback, flow }: AuthDancePromptSwitchProps): ReactNode {
	const handle = useAuthDanceFlowContext(flow);
	const current = handle.current;
	if (current) {
		const render = prompts[current.name] ?? prompts[current.type];
		return render ? render(current, handle) : fallback?.(handle.prompt, handle) ?? null;
	}
	const prompt = handle.prompt;
	if (prompt?.kind === "choice") {
		return choice ? choice(handle.choices, handle) : fallback?.(prompt, handle) ?? null;
	}
	return fallback?.(prompt, handle) ?? null;
}
