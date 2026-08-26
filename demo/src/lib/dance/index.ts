/**
 * @module
 *
 * The whole non-visual half of the demo, in one import. Nothing under this folder renders anything.
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
	BASE_URL,
	buildDance,
	type CalledRoute,
	CALLER_ADDRESS,
	CodeAuthDanceComponent,
	currentLocale,
	currentUserAgent,
	type Dance,
	type DanceSink,
	type DeliveredMessage,
	DemoChannel,
	describeFailure,
	ERROR_HINTS,
	PASSWORD_ROUNDS,
	type ReportedHook,
	SECRET,
	SEEDED,
	TOTP_ALGORITHM,
	TOTP_DIGITS,
	TOTP_PERIOD,
	webAuthnOrigins,
	webAuthnRelyingParty,
} from "./dance.ts";

export { FLOW_LABELS, FLOW_NAMES, isSendable } from "./flows.ts";

export {
	type DanceActions,
	type DanceState,
	DanceStore,
	getDanceStore,
	type HandedCode,
	type LogEntry,
	type Message,
	useDance,
	useDanceActions,
} from "./store.ts";
