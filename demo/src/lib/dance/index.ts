/**
 * @module
 *
 * The whole non-visual half of the demo, in one import.
 *
 * A panel takes its state from {@link useDance}, its controls from {@link useDanceActions}, and everything it needs to
 * read a prompt from the pure helpers of `flows.ts`. Nothing under this folder renders anything.
 */

export {
	type Config,
	CONFIG_KEY,
	currentChoreography,
	DEFAULT_DURATIONS,
	defaultConfig,
	DURATION_FIELDS,
	type DurationField,
	type Durations,
	formatChoreography,
	loadConfig,
	parseChoreography,
	type Preset,
	PRESETS,
	saveConfig,
} from "./config.ts";

export {
	ApiError,
	buildDance,
	CALLER_ADDRESS,
	CodeAuthDanceComponent,
	type ComponentsBody,
	type Dance,
	type DanceSink,
	type DeliveredMessage,
	DemoChannel,
	type EnrolledComponent,
	ERROR_HINTS,
	type ErrorBody,
	PASSWORD_ROUNDS,
	type ReportedHook,
	type ResultBody,
	SECRET,
	SEEDED,
	type SessionsBody,
	type StateBody,
	type TokensBody,
} from "./dance.ts";

export {
	activePrompt,
	type Call,
	FLOW_NAMES,
	type FlowDefinition,
	type FlowName,
	FLOWS,
	initialCall,
	isSendable,
	nextCall,
	promptInputs,
	sendPath,
	type Step,
	submitPath,
} from "./flows.ts";

export {
	type DanceActions,
	type DanceState,
	DanceStore,
	getDanceStore,
	type LogEntry,
	type Message,
	useDance,
	useDanceActions,
} from "./store.ts";
