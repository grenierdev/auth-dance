/**
 * @module
 *
 * The whole demo, in one file and with no render library.
 *
 * The page builds an Auth Dance over the memory providers, so identities, sessions, one-time codes and rate
 * limit counters all live in a `Map` that a reload erases. Nothing is fetched over the network: a call goes
 * straight into `auth.fetch()`, which is the same HTTP surface a server would expose, minus the server.
 *
 * A flow works the same way here as anywhere else. The client starts one, receives a prompt, submits a value,
 * receives the next prompt, and repeats until the answer carries tokens or a plain success. The state between
 * two calls is the opaque string the library hands back, so the page keeps nothing else.
 */

import {
	type AuthDance,
	type AuthDanceApiOptions,
	type AuthDanceChoreography,
	type AuthDanceComponent,
	type AuthDanceComponentContext,
	type AuthDanceIdentity,
	type AuthDanceMessage,
	type AuthDancePrompt,
	type AuthDancePromptInput,
	AuthDanceStorage,
	choice,
	createAuthDance,
	sequence,
} from "auth-dance";
import { MemoryAuthDanceChannel, MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "auth-dance/providers/memory";
import EmailAuthDanceComponent from "auth-dance/components/email";
import OtpAuthDanceComponent from "auth-dance/components/otp";
import PasswordAuthDanceComponent, { pbkdf2PasswordHasher } from "auth-dance/components/password";

// Every response of the library is JSON, failures included, so one loose type covers what a call yields.
// deno-lint-ignore no-explicit-any
type Json = any;

// ─────────────────────────────────────────────────────────────────────────────
// What the options slideout edits
// ─────────────────────────────────────────────────────────────────────────────

/** The durations of `api.durations`, with every key required so an input always has a number to show. */
type Durations = Required<NonNullable<AuthDanceApiOptions["durations"]>>;

/** The defaults of the library, spelled out. */
const DEFAULT_DURATIONS: Durations = {
	sign_in: 300,
	sign_up: 300,
	enroll: 300,
	unenroll: 300,
	rotate: 300,
	recover: 300,
	subscribe: 300,
	unsubscribe: 300,
	delete: 300,
	access: 300,
	refresh: 86400,
	elevated: 300,
};

/** The order and the wording of the duration inputs. */
const DURATION_FIELDS: ReadonlyArray<{ key: keyof Durations; hint: string }> = [
	{ key: "sign_in", hint: "A sign-in state" },
	{ key: "sign_up", hint: "A sign-up state" },
	{ key: "enroll", hint: "An enroll state" },
	{ key: "unenroll", hint: "An unenroll confirmation" },
	{ key: "rotate", hint: "Both rounds of a rotation" },
	{ key: "recover", hint: "The whole reset" },
	{ key: "subscribe", hint: "A subscribe state" },
	{ key: "unsubscribe", hint: "An unsubscribe confirmation" },
	{ key: "delete", hint: "A delete confirmation" },
	{ key: "access", hint: "An access token" },
	{ key: "refresh", hint: "A refresh token" },
	{ key: "elevated", hint: "The window a sensitive flow needs" },
];

/**
 * The choreographies the picker offers.
 *
 * Every name is a key of the components map below: `email`, `email2`, `password` and `otp`. The tree is inert
 * data, which is why one picker can swap the whole policy without touching a line of flow logic.
 */
const PRESETS: ReadonlyArray<{ id: string; label: string; hint: string; choreography?: AuthDanceChoreography }> = [
	{
		id: "email-password",
		label: "Email, then password",
		hint: 'sequence("email", "password")',
		choreography: sequence("email", "password"),
	},
	{
		id: "passwordless",
		label: "Passwordless: email, then a code",
		hint: 'sequence("email", "otp") — the code goes to the address the identity holds',
		choreography: sequence("email", "otp"),
	},
	{
		id: "two-factor",
		label: "Two factors: email, password, then a code",
		hint: 'sequence("email", "password", "otp")',
		choreography: sequence("email", "password", "otp"),
	},
	{
		id: "second-factor-choice",
		label: "Email, then a password or a code",
		hint: 'sequence("email", choice("password", "otp")) — the second step arrives as a choice prompt',
		choreography: sequence("email", choice("password", "otp")),
	},
	{
		id: "alternative-path",
		label: "Email and password, or the second address alone",
		hint: 'choice(sequence("email", "password"), "email2") — a second path makes the password droppable',
		choreography: choice(sequence("email", "password"), "email2"),
	},
	{
		id: "custom",
		label: "Custom tree",
		hint: "A tree of component, choice and sequence nodes, written as JSON",
	},
];

interface Config {
	preset: string;
	custom: string;
	durations: Durations;
	seed: boolean;
}

const CONFIG_KEY = "auth-dance-demo/config@1";

function defaultConfig(): Config {
	return {
		preset: PRESETS[0].id,
		custom: JSON.stringify(sequence("email", "password"), null, "\t"),
		durations: { ...DEFAULT_DURATIONS },
		seed: true,
	};
}

function loadConfig(): Config {
	const fallback = defaultConfig();
	try {
		const stored = localStorage.getItem(CONFIG_KEY);
		if (!stored) {
			return fallback;
		}
		const parsed = JSON.parse(stored) as Partial<Config>;
		return {
			preset: typeof parsed.preset === "string" ? parsed.preset : fallback.preset,
			custom: typeof parsed.custom === "string" ? parsed.custom : fallback.custom,
			durations: { ...fallback.durations, ...parsed.durations },
			seed: typeof parsed.seed === "boolean" ? parsed.seed : fallback.seed,
		};
	} catch {
		return fallback;
	}
}

function saveConfig(config: Config): void {
	try {
		localStorage.setItem(CONFIG_KEY, JSON.stringify(config));
	} catch {
		// A browser that refuses storage keeps the running config in memory only.
	}
}

/**
 * Reads a choreography out of parsed JSON. The library ships a schema for this, and the demo keeps the check
 * here so the whole page depends on nothing but the library itself.
 *
 * @throws {Error} When a node is not one of the three kinds. The message names the path of the bad node.
 */
function parseChoreography(node: unknown, path = "$"): AuthDanceChoreography {
	const record = node as Record<string, unknown>;
	if (record?.kind === "component" && typeof record.component === "string") {
		return { kind: "component", component: record.component };
	}
	if ((record?.kind === "choice" || record?.kind === "sequence") && Array.isArray(record.components)) {
		return {
			kind: record.kind,
			components: record.components.map((child, index) => parseChoreography(child, `${path}.components[${index}]`)),
		};
	}
	throw new Error(`${path} is not a component, a choice or a sequence node`);
}

/** The tree the current config resolves to. */
function currentChoreography(config: Config): AuthDanceChoreography {
	const preset = PRESETS.find((entry) => entry.id === config.preset);
	if (preset?.choreography) {
		return preset.choreography;
	}
	return parseChoreography(JSON.parse(config.custom));
}

/** Renders a tree as indented text, for the preview under the picker. */
function formatChoreography(choreography: AuthDanceChoreography, indent = ""): string {
	if (choreography.kind === "component") {
		return `${indent}${choreography.component}`;
	}
	const children = choreography.components.map((child) => formatChoreography(child, `${indent}  `));
	return [`${indent}${choreography.kind}`, ...children].join("\n");
}

// ─────────────────────────────────────────────────────────────────────────────
// The dance itself
// ─────────────────────────────────────────────────────────────────────────────

/**
 * The key that signs the tokens and encrypts the state.
 *
 * It sits in the bundle in plain sight, which a real deployment must never do. Here both ends of the dance are
 * the same page, so there is no second party to keep it from.
 */
const SECRET = "zdJXI1jwuXW8A19fns0E_B4HSYm7AUHLGlU9WLo8mxs";

/**
 * The PBKDF2 rounds of the password component. The library defaults to 600 000, which is right for a server and
 * about a second of a phone browser per submitted password.
 */
const PASSWORD_ROUNDS = 60_000;

/** What the seed puts in storage, and what the start card offers to type. */
const SEEDED = {
	id: "id_0000000000000000000demo",
	email: "john.doe@example.com",
	password: "hunter2",
};

/** The address the demo claims to call from, so a session carries one. */
const CALLER_ADDRESS = "203.0.113.7";

interface Dance {
	auth: AuthDance;
	storage: AuthDanceStorage;
	componentNames: string[];
	channelNames: string[];
	seedIdentity(): Promise<AuthDanceIdentity>;
}

/**
 * A one-time code as a step of the choreography, rather than as the proof another component asks for.
 *
 * `OtpAuthDanceComponent` declares no verification of its own, and its `verificationComponent` throws to say so.
 * A sign-up calls that method for any collected value that is not confirmed yet, so the base class can only ever
 * be a verification. Dropping the method says the same thing in the form the sign-up reads: a code the owner
 * read at an address the identity already holds is proof enough on its own.
 *
 * This is all a component of your own has to do. The library asks for a prompt, a check and a record, and the
 * choreography names it like any other step.
 */
class CodeAuthDanceComponent extends OtpAuthDanceComponent {
	override verificationComponent = undefined;
}

/** A memory channel that also reports what it received, which is what the inbox reads. */
class DemoChannel extends MemoryAuthDanceChannel {
	#name: string;

	constructor(name: string, type: string) {
		super(type);
		this.#name = name;
	}

	override async sendMessage(message: AuthDanceMessage): Promise<void> {
		await super.sendMessage(message);
		const content = message.content as Record<string, string>;
		const recipient = Object.values(message.recipient.data ?? {}).find((value) => typeof value === "string");
		messages.unshift({
			id: ++counter,
			at: new Date(),
			channel: this.#name,
			recipient: typeof recipient === "string" ? recipient : "—",
			subject: message.subject,
			code: content["text/x-code"],
		});
	}
}

/**
 * Builds one instance from a choreography and a set of durations.
 *
 * The four components are fixed and the choreography picks among them by name. `email` and `email2` are two
 * addresses, each with a channel of its own. `password` is a challenge. `otp` is a code over the `email`
 * channel, which lets a choreography name it as a step of its own rather than as a verification.
 */
function buildDance(choreography: AuthDanceChoreography, durations: Durations): Dance {
	const channels = {
		email: new DemoChannel("email", "email"),
		email2: new DemoChannel("email2", "email"),
		sms: new DemoChannel("sms", "phone"),
	};

	const email = new EmailAuthDanceComponent("email");
	const email2 = new EmailAuthDanceComponent("email2");
	const password = new PasswordAuthDanceComponent("demo-pepper", pbkdf2PasswordHasher(PASSWORD_ROUNDS));
	const components: Record<string, AuthDanceComponent> = { email, email2, password, otp: new CodeAuthDanceComponent("email") };

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
			// A demo gets poked at far harder than an account does. The defaults allow one identity 10
			// verifications and 5 deliveries per five minutes, which a curious visitor empties in a minute of
			// clicking. These are the same buckets, opened wide.
			limits: {
				identity: {
					verify: { limit: 200, window: 300 },
					send: { limit: 200, window: 300 },
					manage: { limit: 200, window: 300 },
					refresh: { limit: 200, window: 300 },
				},
			},
			// The listeners the library calls after it saves a change. They report what happened; they never
			// decide anything, and one that throws never fails the flow.
			hooks: {
				onIdentityCreated: (event) => note("onIdentityCreated", event.flow, event.identity.id),
				onIdentityUpdated: (event) => note("onIdentityUpdated", event.flow, `${event.identity.id} · ${event.name ?? "—"}`),
				onIdentityDeleted: (event) => note("onIdentityDeleted", event.flow, event.identity.id),
				onSessionCreated: (event) => note("onSessionCreated", event.flow, event.session.id),
				onSessionRefreshed: (event) => note("onSessionRefreshed", event.flow, event.session.id),
				onSessionDeleted: (event) => note("onSessionDeleted", event.flow, event.session.id),
			},
			tokens: { issuer: "auth-dance-demo" },
		},
		info: { title: "Auth Dance demo", version: "0.1.0" },
	});

	/**
	 * Seeds an identity the way a sign-up would leave one, without running the flow. The password record is
	 * salted with the id of the identity, so the id comes first and the components are built against it. Hence
	 * `setIdentity` rather than `createIdentity`, which would mint an id of its own after the fact.
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

// ─────────────────────────────────────────────────────────────────────────────
// Talking to it
// ─────────────────────────────────────────────────────────────────────────────

/** A refusal from the library. The body of a failure is always a single `{ error: CODE }`. */
class ApiError extends Error {
	readonly status: number;
	readonly code: string;

	constructor(status: number, code: string) {
		super(`${code} · HTTP ${status}`);
		this.status = status;
		this.code = code;
	}
}

/** Plain sentences for the codes this demo runs into most. Everything else shows the code alone. */
const ERROR_HINTS: Record<string, string> = {
	INVALID_PROMPT_VALUE:
		"The value did not verify. A wrong password and an unknown address answer the same way, so nobody can probe for accounts.",
	INVALID_VALIDATION_VALUE: "The one-time code did not match. Send a fresh one and try again.",
	CONFIRMATION_REQUIRED: "This flow ends on a confirmation, and only the boolean true goes through.",
	WOULD_LOCK_OUT: "Dropping this component would leave no complete path through the choreography.",
	CHANNEL_IN_USE: "A component still links to this channel, so it cannot be detached.",
	COMPONENT_ALREADY_ENROLLED: "The identity already holds this component. Rotate it instead.",
	CHANNEL_ALREADY_SUBSCRIBED: "The identity already holds this channel.",
	COMPONENT_NOT_RECOVERABLE: "A recovery starts from a component that both resolves an identity and proves control of it.",
	FRESH_SIGN_IN_REQUIRED: "The elevated window closed. Sign in again to run a sensitive flow.",
	INVALID_ACCESS_TOKEN: "This route needs a valid access token.",
	INVALID_STATE: "The state is gone or expired. Start the flow again.",
	INVALID_STATE_FOR_FLOW: "This flow has nothing of that kind to answer or to send at this point.",
	IDENTITY_NOT_RESOLVED: "No step of this dance has said who is dancing yet.",
	NO_VERIFICATION_CHANNEL: "Subscribing a channel is confirmed over a channel the identity already trusts.",
	RATE_LIMITED: "The bucket for this address or identity is empty for now.",
};

/**
 * Sends one request into the library and records it.
 *
 * @throws {ApiError} For any status other than 200, carrying the code the body names.
 */
async function post(path: string, body?: Json, authenticated = false): Promise<Json> {
	const headers: Record<string, string> = {
		"content-type": "application/json",
		"accept-language": navigator.language || "en",
		// The library reads the caller off the connection and never off the body, so these two are headers.
		"cf-connecting-ip": CALLER_ADDRESS,
		"user-agent": navigator.userAgent,
	};
	if (authenticated) {
		if (!tokens) {
			throw new Error("This route needs an access token. Sign in first.");
		}
		headers.authorization = `Bearer ${tokens.access_token}`;
	}
	const started = performance.now();
	const response = await dance.auth.fetch(
		new Request(`http://demo${path}`, { method: "POST", headers, body: body === undefined ? undefined : JSON.stringify(body) }),
	);
	const payload = await response.json();
	log.unshift({
		id: ++counter,
		at: new Date(),
		kind: "http",
		label: `POST ${path}`,
		status: response.status,
		ms: Math.round(performance.now() - started),
		request: body,
		response: payload,
	});
	if (response.status !== 200) {
		throw new ApiError(response.status, String(payload?.error ?? "UNKNOWN"));
	}
	return payload;
}

/** Records what a hook reported, beside the calls in the wire log. */
function note(hook: string, flow: string, summary: string): void {
	log.unshift({ id: ++counter, at: new Date(), kind: "hook", label: hook, status: undefined, response: { flow, summary } });
}

// ─────────────────────────────────────────────────────────────────────────────
// The flows
// ─────────────────────────────────────────────────────────────────────────────

/** Which endpoint answers the current prompt: the collecting one, or the one that proves control. */
type Call = "prompt" | "validation";

interface Step {
	flow: FlowName;
	/** The opaque state of the dance in progress, which every later call echoes back. */
	state: string;
	prompt: AuthDancePrompt;
	expireAt: string;
	call: Call;
	/** The names answered so far in this flow, for the progress trail. */
	trail: string[];
}

const FLOWS = {
	"sign-in": { label: "Sign in", path: "/sign-in", authenticated: false, argument: "none" },
	"sign-up": { label: "Sign up", path: "/sign-up", authenticated: false, argument: "none" },
	"recover": { label: "Recover", path: "/recover", authenticated: false, argument: "component" },
	"enroll": { label: "Enroll", path: "/enroll", authenticated: true, argument: "component" },
	"unenroll": { label: "Unenroll", path: "/unenroll", authenticated: true, argument: "component" },
	"rotate": { label: "Rotate", path: "/rotate", authenticated: true, argument: "component" },
	"subscribe": { label: "Subscribe", path: "/subscribe", authenticated: true, argument: "channel" },
	"unsubscribe": { label: "Unsubscribe", path: "/unsubscribe", authenticated: true, argument: "channel" },
	"delete": { label: "Delete identity", path: "/delete", authenticated: true, argument: "none" },
} as const;

type FlowName = keyof typeof FLOWS;

/**
 * Whether the first prompt of a flow already asks for proof.
 *
 * A rotation of a component that can verify itself opens by proving control of the current value, and that
 * prompt is a validation. Every other flow opens by collecting something.
 */
function initialCall(flow: FlowName, prompt: AuthDancePrompt): Call {
	return flow === "rotate" && prompt.kind === "input" && prompt.sendable ? "validation" : "prompt";
}

/**
 * Whether the prompt that came back is a validation of what was just submitted.
 *
 * When a collected value still needs proof of control, the library answers with a prompt under the same name
 * instead of advancing. Two steps of one choreography never share a name, so the repeated name is the tell.
 */
function nextCall(step: Step, submitted: string, prompt: AuthDancePrompt): Call {
	return step.call === "prompt" && prompt.kind === "input" && prompt.name === submitted ? "validation" : "prompt";
}

/** Starts a flow and keeps the first prompt. */
async function startFlow(flow: FlowName, argument?: string): Promise<void> {
	const definition = FLOWS[flow];
	const body = definition.argument === "none" ? undefined : { name: argument };
	const result = await post(definition.path, body, definition.authenticated);
	step = { flow, state: result.state, prompt: result.prompt, expireAt: result.expireAt, call: initialCall(flow, result.prompt), trail: [] };
}

/** Answers the current prompt and takes whatever comes back: the next prompt, the tokens, or a plain success. */
async function submitCurrent(): Promise<void> {
	if (!step) {
		return;
	}
	const target = activePrompt(step.prompt);
	if (!target) {
		throw new Error("Pick which component to answer.");
	}
	const path = step.call === "validation" ? "/submit-validation" : "/submit-prompt";
	const result = await post(path, { name: target.name, value: readField(target), state: step.state });
	const trail = [...step.trail, `${target.name}${step.call === "validation" ? " ✓" : ""}`];
	if (result.tokens) {
		tokens = result.tokens;
		session = result;
		step = undefined;
		notice = `Signed in as ${result.identity.id}. The identity tab holds the tokens.`;
		return;
	}
	if (result.success) {
		notice = `${FLOWS[step.flow].label} completed.`;
		step = undefined;
		return;
	}
	step = {
		...step,
		state: result.state,
		prompt: result.prompt,
		expireAt: result.expireAt,
		call: nextCall(step, target.name, result.prompt),
		trail,
	};
}

/** Asks the library to deliver the current prompt over its channel, which is how a one-time code arrives. */
async function sendCurrent(): Promise<void> {
	if (!step) {
		return;
	}
	const target = activePrompt(step.prompt);
	if (!target) {
		throw new Error("Pick which component to send.");
	}
	const path = step.call === "validation" ? "/send-validation" : "/send-prompt";
	await post(path, { name: target.name, locale: navigator.language || "en", state: step.state });
	notice = "Sent. The inbox holds it.";
}

/** The prompt the owner is answering: the input itself, or the branch picked in a choice. */
function activePrompt(prompt: AuthDancePrompt): AuthDancePromptInput | undefined {
	if (prompt.kind === "input") {
		return prompt;
	}
	const picked = document.querySelector<HTMLInputElement>('input[name="branch"]:checked')?.value;
	return prompt.components.find((branch): branch is AuthDancePromptInput => branch.kind === "input" && branch.name === picked);
}

// ─────────────────────────────────────────────────────────────────────────────
// Prompt fields, one entry per prompt type
// ─────────────────────────────────────────────────────────────────────────────

/**
 * How one type of prompt is collected.
 *
 * The library ships `email`, `password` and `otp`, and builds `confirmation` itself. A channel contributes
 * whatever type it declares, `phone` here. A component of your own can declare any other type: add an entry and
 * the flow driver needs no change, because it only ever asks this table to render and to read.
 */
interface PromptField {
	label: string;
	/** The control, named by `id` so the visible label can point at it. */
	control(prompt: AuthDancePromptInput, id: string): string;
	/** What `submit-prompt` sends as `value`. */
	read(element: HTMLElement): unknown;
}

const value = (element: HTMLElement): unknown => (element as HTMLInputElement).value;

const FIELDS: Record<string, PromptField> = {
	text: {
		label: "Value",
		control: (_prompt, id) => `<input id="${id}" type="text" class="input w-full" autocomplete="off" />`,
		read: value,
	},
	email: {
		label: "Email address",
		control: (_prompt, id) =>
			`<input id="${id}" type="email" class="input w-full" autocomplete="email" placeholder="john.doe@example.com" />`,
		read: value,
	},
	password: {
		label: "Password",
		control: (_prompt, id) => `<input id="${id}" type="password" class="input w-full" autocomplete="current-password" />`,
		read: value,
	},
	phone: {
		label: "Phone number",
		control: (_prompt, id) => `<input id="${id}" type="tel" class="input w-full" autocomplete="tel" placeholder="5551234567" />`,
		read: value,
	},
	otp: {
		label: "One-time code",
		control: (_prompt, id) =>
			`<label class="otp">
				<span></span><span></span><span></span><span></span><span></span><span></span>
				<input id="${id}" type="text" autocomplete="one-time-code" inputmode="numeric" maxlength="6" pattern="[0-9]{6}" data-otp />
			</label>`,
		read: value,
	},
	confirmation: {
		label: "Confirmation",
		// The library takes the boolean true and nothing else, so an unchecked box submits false on purpose:
		// the refusal it earns is part of what this demo shows.
		control: (_prompt, id) =>
			`<label class="label">
				<input id="${id}" type="checkbox" class="checkbox" />
				<span>Yes, go ahead</span>
			</label>`,
		read: (element) => (element as HTMLInputElement).checked,
	},
};

const fieldFor = (type: string): PromptField => FIELDS[type] ?? FIELDS.text;

function renderField(prompt: AuthDancePromptInput): string {
	const field = fieldFor(prompt.type);
	const id = `prompt-${prompt.name}`;
	return `
		<label class="label" for="${id}">${esc(field.label)}</label>
		${field.control(prompt, id)}
		<p class="label">
			name <code>${esc(prompt.name)}</code> · type <code>${esc(prompt.type)}</code>${prompt.sendable ? " · sendable" : ""}
		</p>`;
}

function readField(prompt: AuthDancePromptInput): unknown {
	const element = document.getElementById(`prompt-${prompt.name}`);
	return element ? fieldFor(prompt.type).read(element) : undefined;
}

// ─────────────────────────────────────────────────────────────────────────────
// State of the page
// ─────────────────────────────────────────────────────────────────────────────

interface Message {
	id: number;
	at: Date;
	channel: string;
	recipient: string;
	subject: string;
	code?: string;
}

interface LogEntry {
	id: number;
	at: Date;
	kind: "http" | "hook";
	label: string;
	status?: number;
	ms?: number;
	request?: Json;
	response?: Json;
}

let counter = 0;
let config = loadConfig();
let dance: Dance;
let step: Step | undefined;
let tokens: Json | undefined;
let session: Json | undefined;
let sessions: Json[] | undefined;
let enrolled: Json[] | undefined;
let messages: Message[] = [];
let log: LogEntry[] = [];
let busy = false;
let error: string | undefined;
let notice: string | undefined;

/** Rebuilds the instance from the config. Every identity, session and message of the old one goes with it. */
async function rebuild(): Promise<void> {
	dance = buildDance(currentChoreography(config), config.durations);
	step = undefined;
	tokens = undefined;
	session = undefined;
	sessions = undefined;
	enrolled = undefined;
	messages = [];
	log = [];
	if (config.seed) {
		await dance.seedIdentity();
	}
}

/**
 * Runs one action, and turns whatever it throws into the alert at the top of the stage.
 *
 * The only thing that moves while the action runs is the progress bar. Nothing else is rendered until it ends,
 * because an action reads the form it was fired from: rebuilding the stage first would hand it an empty one.
 */
async function act(action: () => void | Promise<void>): Promise<void> {
	if (busy) {
		return;
	}
	busy = true;
	error = undefined;
	notice = undefined;
	byId("busy").classList.remove("invisible");
	try {
		await action();
	} catch (cause) {
		error = cause instanceof ApiError
			? `${cause.code}${ERROR_HINTS[cause.code] ? ` — ${ERROR_HINTS[cause.code]}` : ""}`
			: (cause as Error).message;
	}
	busy = false;
	byId("busy").classList.add("invisible");
	render();
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendering
// ─────────────────────────────────────────────────────────────────────────────

function byId<T extends HTMLElement = HTMLElement>(id: string): T {
	const element = document.getElementById(id);
	if (!element) {
		throw new Error(`#${id} is missing from index.html`);
	}
	return element as T;
}

const ESCAPED: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const esc = (input: unknown): string => String(input).replace(/[&<>"']/g, (character) => ESCAPED[character]);
const clock = (at: Date): string => at.toLocaleTimeString(undefined, { hour12: false });
const short = (
	input: string,
	keep = 12,
): string => (input.length <= keep * 2 + 1 ? input : `${input.slice(0, keep)}…${input.slice(-keep)}`);

function render(): void {
	byId("status").outerHTML = renderStatus();
	byId("stage").innerHTML = renderStage();
	byId("inbox").innerHTML = renderInbox();
	byId("wire").innerHTML = renderWire();
	byId("session").innerHTML = renderSession();
}

function renderStatus(): string {
	const label = tokens ? `Signed in · ${session?.identity?.id ?? ""}` : "Signed out";
	return `<span id="status" class="badge ${tokens ? "badge-success" : "badge-ghost"}">${esc(label)}</span>`;
}

function renderStage(): string {
	return [
		error ? `<div role="alert" class="alert alert-error"><span>${esc(error)}</span></div>` : "",
		notice ? `<div role="alert" class="alert alert-success"><span>${esc(notice)}</span></div>` : "",
		step ? renderPromptCard(step) : renderStartCard(),
		renderChoreographyCard(),
	].join("");
}

function renderStartCard(): string {
	const signedIn = tokens !== undefined;
	const rows = (Object.keys(FLOWS) as FlowName[])
		.filter((flow) => FLOWS[flow].authenticated === signedIn)
		.map(renderFlowRow)
		.join("");
	return `
	<div class="card bg-base-100 shadow-sm">
		<div class="card-body gap-4">
			<h2 class="card-title">${signedIn ? "Manage this identity" : "Start a flow"}</h2>
			${
		signedIn
			? `<p class="text-sm opacity-70">
					Every one of these needs a recent sign-in: past the <code>elevated</code> window the library answers
					FRESH_SIGN_IN_REQUIRED.
				</p>`
			: `<p class="text-sm opacity-70">
					${
				config.seed
					? `An identity is already seeded: <code>${esc(SEEDED.email)}</code> with the password
						<code>${esc(SEEDED.password)}</code>. Sign up to make another one.`
					: "No identity is seeded. Sign up to make one."
			}
				</p>`
	}
			<div class="flex flex-col gap-2">${rows}</div>
			${
		signedIn
			? `<div class="card-actions justify-end">
					<button class="btn btn-sm" data-action="refresh-token">Refresh tokens</button>
					<button class="btn btn-sm" data-action="sign-out-others">Sign out others</button>
					<button class="btn btn-sm btn-outline" data-action="sign-out">Sign out</button>
				</div>`
			: ""
	}
		</div>
	</div>`;
}

function renderFlowRow(flow: FlowName): string {
	const definition = FLOWS[flow];
	const names = definition.argument === "channel" ? dance.channelNames : dance.componentNames;
	const select = definition.argument === "none" ? "" : `
		<select id="argument-${flow}" class="select select-sm w-full sm:w-48" aria-label="Which ${definition.argument} for ${definition.label}">
			${names.map((name) => `<option value="${esc(name)}">${esc(name)}</option>`).join("")}
		</select>`;
	return `
	<div class="flex flex-wrap items-center gap-2">
		<button class="btn btn-sm ${
		flow === "sign-in" || flow === "sign-up" ? "btn-primary" : ""
	} w-full sm:w-40" data-action="start" data-flow="${flow}">
			${esc(definition.label)}
		</button>
		${select}
	</div>`;
}

function renderPromptCard(current: Step): string {
	const endpoint = current.call === "validation" ? "/submit-validation" : "/submit-prompt";
	// A prompt the library can deliver is one it already knows the recipient of: a code it is about to mail. The
	// recipient a subscribe collects is sendable too, in the sense that the channel offers to send there one day,
	// but there is nothing to deliver until the owner has given it.
	const inputs = current.prompt.kind === "input"
		? [current.prompt]
		: current.prompt.components.filter((branch): branch is AuthDancePromptInput => branch.kind === "input");
	const sendable = inputs.some((input) => input.sendable && (current.call === "validation" || input.type === "otp"));
	return `
	<div class="card bg-base-100 shadow-sm">
		<div class="card-body gap-4">
			<div class="flex flex-wrap items-center justify-between gap-2">
				<h2 class="card-title">${esc(FLOWS[current.flow].label)}</h2>
				<span class="badge badge-outline font-mono text-xs">POST ${endpoint}</span>
			</div>

			${renderTrail(current)}

			<form id="prompt-form" class="flex flex-col gap-3">
				<fieldset class="fieldset">
					<legend class="fieldset-legend">${current.call === "validation" ? "Prove control of the value" : "Answer the prompt"}</legend>
					${renderPrompt(current.prompt)}
				</fieldset>
				<div class="flex flex-wrap items-center justify-between gap-2">
					<span class="text-xs opacity-70">Expires ${
		esc(new Date(current.expireAt).toLocaleTimeString(undefined, { hour12: false }))
	}</span>
					<div class="flex gap-2">
						<button type="button" class="btn btn-sm btn-ghost" data-action="cancel">Abandon</button>
						${
		sendable
			? `<button type="button" class="btn btn-sm" data-action="send">
							Send it to me
						</button>`
			: ""
	}
						<button type="submit" class="btn btn-sm btn-primary">Submit</button>
					</div>
				</div>
			</form>
		</div>
	</div>`;
}

/** The names answered so far, plus the one on screen. */
function renderTrail(current: Step): string {
	const pending = current.prompt.kind === "input" ? current.prompt.name : "choice";
	const steps = [
		...current.trail.map((name) => `<li class="step step-primary">${esc(name)}</li>`),
		`<li class="step">${esc(pending)}</li>`,
	];
	return `<ul class="steps w-full overflow-x-auto text-xs">${steps.join("")}</ul>`;
}

function renderPrompt(prompt: AuthDancePrompt): string {
	if (prompt.kind === "input") {
		return renderField(prompt);
	}
	// A choice is a fork of the choreography: every branch is a whole path, and answering one takes it.
	const branches = prompt.components.filter((branch): branch is AuthDancePromptInput => branch.kind === "input");
	return `
	<p class="label">The dance forks here. Pick a branch and answer it.</p>
	<div class="tabs tabs-box">
		${
		branches.map((branch, index) => `
			<label class="tab">
				<input type="radio" name="branch" value="${esc(branch.name)}" ${index === 0 ? "checked" : ""} />
				${esc(branch.name)}
			</label>
			<div class="tab-content border-base-300 bg-base-100 p-4">${renderField(branch)}</div>`).join("")
	}
	</div>`;
}

function renderChoreographyCard(): string {
	const preset = PRESETS.find((entry) => entry.id === config.preset);
	let tree: string;
	try {
		tree = formatChoreography(currentChoreography(config));
	} catch (cause) {
		tree = (cause as Error).message;
	}
	return `
	<div class="card bg-base-100 shadow-sm">
		<div class="card-body gap-2">
			<div class="flex flex-wrap items-center justify-between gap-2">
				<h2 class="card-title text-base">Choreography</h2>
				<label for="options-drawer" class="btn btn-xs">Change</label>
			</div>
			<p class="text-sm opacity-70">${esc(preset?.hint ?? "")}</p>
			<pre class="overflow-x-auto rounded-box bg-base-200 p-3 text-xs">${esc(tree)}</pre>
		</div>
	</div>`;
}

function renderInbox(): string {
	if (messages.length === 0) {
		return `
		<h2 class="mb-2 font-semibold">Inbox</h2>
		<p class="text-sm opacity-70">
			Nothing yet. A channel here keeps its messages instead of delivering them, so a one-time code the library
			sends lands in this list.
		</p>`;
	}
	return `
	<h2 class="mb-2 font-semibold">Inbox</h2>
	<ul class="flex flex-col gap-2">
		${
		messages.map((message) => `
		<li class="rounded-box bg-base-200 p-3">
			<div class="flex flex-wrap items-center gap-2 text-xs opacity-70">
				<span class="badge badge-sm badge-outline">${esc(message.channel)}</span>
				<span>${esc(message.recipient)}</span>
				<span class="ml-auto">${esc(clock(message.at))}</span>
			</div>
			${
			message.code
				? `<div class="mt-2 flex items-center gap-2">
					<code class="text-lg tracking-widest">${esc(message.code)}</code>
					<button class="btn btn-xs" data-action="use-code" data-code="${esc(message.code)}">Use this code</button>
				</div>`
				: `<p class="mt-2 text-sm">${esc(message.subject)}</p>`
		}
		</li>`).join("")
	}
	</ul>`;
}

function renderWire(): string {
	return `
	<div class="mb-2 flex items-center justify-between gap-2">
		<h2 class="font-semibold">Wire</h2>
		<button class="btn btn-xs" data-action="clear-log" ${log.length === 0 ? "disabled" : ""}>Clear</button>
	</div>
	${
		log.length === 0
			? '<p class="text-sm opacity-70">Every call into the library, and everything its hooks report, shows up here.</p>'
			: `<ul class="flex flex-col gap-2">${log.slice(0, 40).map(renderLogEntry).join("")}</ul>`
	}`;
}

function renderLogEntry(entry: LogEntry): string {
	const badge = entry.kind === "hook" ? "badge-info" : entry.status === 200 ? "badge-success" : "badge-error";
	const status = entry.kind === "hook" ? "hook" : `${entry.status} · ${entry.ms} ms`;
	return `
	<li>
		<details class="collapse-arrow collapse rounded-box bg-base-200">
			<summary class="collapse-title flex flex-wrap items-center gap-2 py-2 text-sm font-mono">
				<span class="badge badge-sm ${badge}">${esc(status)}</span>
				<span>${esc(entry.label)}</span>
				<span class="ml-auto text-xs opacity-70">${esc(clock(entry.at))}</span>
			</summary>
			<div class="collapse-content">
				${entry.request === undefined ? "" : `<pre class="overflow-x-auto text-xs">${esc(JSON.stringify(entry.request, null, 2))}</pre>`}
				<pre class="overflow-x-auto text-xs opacity-80">${esc(JSON.stringify(entry.response, null, 2))}</pre>
			</div>
		</details>
	</li>`;
}

function renderSession(): string {
	if (!tokens) {
		return `
		<h2 class="mb-2 font-semibold">Session</h2>
		<p class="text-sm opacity-70">Sign in or sign up, and the tokens the library mints show up here.</p>`;
	}
	return `
	<h2 class="mb-2 font-semibold">Session</h2>
	<dl class="mb-3 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-sm">
		<dt class="opacity-70">identity</dt><dd class="font-mono break-all">${esc(session?.identity?.id ?? "—")}</dd>
		<dt class="opacity-70">session</dt><dd class="font-mono break-all">${esc(session?.session?.id ?? "—")}</dd>
		<dt class="opacity-70">address</dt><dd class="font-mono break-all">${esc(session?.session?.address ?? "—")}</dd>
	</dl>
	<div class="mb-3 flex flex-col gap-1 text-xs">
		${
		(["access_token", "id_token", "refresh_token"] as const).map((name) => `
		<div class="flex items-center gap-2">
			<span class="badge badge-sm badge-outline">${esc(name)}</span>
			<code class="truncate">${esc(short(String(tokens[name])))}</code>
		</div>`).join("")
	}
	</div>
	<div class="mb-3 flex flex-wrap gap-2">
		<button class="btn btn-xs" data-action="list-sessions">List sessions</button>
		<button class="btn btn-xs" data-action="list-components">List components</button>
	</div>
	${
		sessions
			? `<h3 class="mb-1 text-sm font-semibold">Sessions</h3>
			<ul class="mb-3 flex flex-col gap-1 text-xs">
				${
				sessions.map((entry) => `
				<li class="rounded-box bg-base-200 p-2 font-mono break-all">
					${esc(entry.id)}${entry.id === session?.session?.id ? ' <span class="badge badge-xs">this one</span>' : ""}
				</li>`).join("")
			}
			</ul>`
			: ""
	}
	${
		enrolled
			? `<h3 class="mb-1 text-sm font-semibold">Components</h3>
			<ul class="flex flex-col gap-1 text-xs">
				${
				enrolled.map((entry) => `
				<li class="flex flex-wrap items-center gap-2 rounded-box bg-base-200 p-2">
					<span class="badge badge-xs badge-outline">${esc(entry.kind)}</span>
					<span class="font-mono">${esc(entry.component ?? entry.channel)}</span>
					${entry.identification ? `<span class="opacity-70">${esc(entry.identification)}</span>` : ""}
					<span class="ml-auto opacity-70">${entry.confirmed ? "confirmed" : "unconfirmed"}</span>
				</li>`).join("")
			}
			</ul>`
			: ""
	}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// The options slideout
// ─────────────────────────────────────────────────────────────────────────────

function renderOptions(): void {
	byId("options").innerHTML = `
	<div class="mb-4 flex items-center justify-between gap-2">
		<h2 class="text-lg font-semibold">Options</h2>
		<label for="options-drawer" class="btn btn-sm btn-ghost">Close</label>
	</div>
	<div role="alert" class="alert alert-warning mb-4 text-sm">
		<span>Applying rebuilds the library. Every identity, session and message of the running one is lost.</span>
	</div>

	<fieldset class="fieldset">
		<legend class="fieldset-legend">Choreography</legend>
		<label class="label" for="preset">Preset</label>
		<select id="preset" class="select w-full">
			${
		PRESETS.map((preset) =>
			`<option value="${esc(preset.id)}" ${preset.id === config.preset ? "selected" : ""}>${esc(preset.label)}</option>`
		)
			.join("")
	}
		</select>
		<p class="label" id="preset-hint">${esc(PRESETS.find((preset) => preset.id === config.preset)?.hint ?? "")}</p>

		<div id="custom-block" class="${config.preset === "custom" ? "" : "hidden"}">
			<label class="label" for="custom">Custom tree</label>
			<textarea id="custom" class="textarea w-full font-mono text-xs" rows="10">${esc(config.custom)}</textarea>
		</div>

		<p class="label">Resolves to</p>
		<pre id="preview" class="overflow-x-auto rounded-box bg-base-200 p-3 text-xs"></pre>
	</fieldset>

	<fieldset class="fieldset">
		<legend class="fieldset-legend">Durations, in seconds</legend>
		<div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
			${
		DURATION_FIELDS.map((field) => `
			<div>
				<label class="label" for="duration-${field.key}">${esc(field.key)}</label>
				<input id="duration-${field.key}" type="number" min="1" step="1" class="input input-sm w-full" value="${
			config.durations[field.key]
		}" />
				<p class="label text-xs">${esc(field.hint)}</p>
			</div>`).join("")
	}
		</div>
	</fieldset>

	<fieldset class="fieldset">
		<legend class="fieldset-legend">Demo data</legend>
		<label class="label">
			<input id="seed" type="checkbox" class="toggle" ${config.seed ? "checked" : ""} />
			<span>Seed the John Doe identity on every rebuild</span>
		</label>
	</fieldset>

	<div class="mt-4 flex flex-wrap gap-2">
		<button class="btn btn-primary" data-action="apply-options">Apply and restart</button>
		<button class="btn btn-ghost" data-action="default-options">Restore defaults</button>
	</div>`;

	const preset = byId<HTMLSelectElement>("preset");
	const custom = byId<HTMLTextAreaElement>("custom");
	const updatePreview = (): void => {
		byId("custom-block").classList.toggle("hidden", preset.value !== "custom");
		byId("preset-hint").textContent = PRESETS.find((entry) => entry.id === preset.value)?.hint ?? "";
		try {
			byId("preview").textContent = formatChoreography(currentChoreography({ ...config, preset: preset.value, custom: custom.value }));
		} catch (cause) {
			byId("preview").textContent = (cause as Error).message;
		}
	};
	preset.addEventListener("change", updatePreview);
	custom.addEventListener("input", updatePreview);
	updatePreview();
}

/** Reads the slideout back into a config. */
function readOptions(): Config {
	const durations = { ...config.durations };
	for (const field of DURATION_FIELDS) {
		const read = Number(byId<HTMLInputElement>(`duration-${field.key}`).value);
		durations[field.key] = Number.isFinite(read) && read > 0 ? Math.floor(read) : DEFAULT_DURATIONS[field.key];
	}
	return {
		preset: byId<HTMLSelectElement>("preset").value,
		custom: byId<HTMLTextAreaElement>("custom").value,
		durations,
		seed: byId<HTMLInputElement>("seed").checked,
	};
}

// ─────────────────────────────────────────────────────────────────────────────
// Wiring
// ─────────────────────────────────────────────────────────────────────────────

const ACTIONS: Record<string, (target: HTMLElement) => void | Promise<void>> = {
	start: (target) => {
		const flow = target.dataset.flow as FlowName;
		const argument = FLOWS[flow].argument === "none" ? undefined : byId<HTMLSelectElement>(`argument-${flow}`).value;
		return startFlow(flow, argument);
	},
	cancel: () => {
		step = undefined;
	},
	send: () => sendCurrent(),
	"sign-out": async () => {
		await post("/sign-out", { others: false }, true);
		tokens = undefined;
		session = undefined;
		sessions = undefined;
		enrolled = undefined;
		notice = "Signed out. The session is gone from storage.";
	},
	"sign-out-others": async () => {
		await post("/sign-out", { others: true }, true);
		sessions = undefined;
		notice = "Every other session is gone.";
	},
	"refresh-token": async () => {
		const result = await post("/refresh-token", { refresh_token: tokens.refresh_token });
		tokens = result.tokens;
		session = result;
		notice = "Fresh tokens on the same session. A refresh keeps auth_time, so it never reopens the elevated window.";
	},
	"list-sessions": async () => {
		sessions = (await post("/list-sessions", undefined, true)).sessions;
	},
	"list-components": async () => {
		enrolled = (await post("/list-components", undefined, true)).components;
	},
	"clear-log": () => {
		log = [];
	},
	"apply-options": async () => {
		const next = readOptions();
		currentChoreography(next); // Refuses a broken custom tree before the running instance is thrown away.
		config = next;
		saveConfig(config);
		await rebuild();
		renderOptions();
		byId<HTMLInputElement>("options-drawer").checked = false;
		notice = "Rebuilt with the new options.";
	},
	"default-options": async () => {
		config = defaultConfig();
		saveConfig(config);
		await rebuild();
		renderOptions();
		notice = "Back to the defaults.";
	},
};

document.addEventListener("click", (event) => {
	const target = (event.target as HTMLElement).closest<HTMLElement>("[data-action]");
	if (!target) {
		return;
	}
	const name = target.dataset.action ?? "";
	// Taking a code out of the inbox fills the form and changes nothing else. It stays out of `act`, which ends
	// on a render that would throw the value straight back away.
	if (name === "use-code") {
		event.preventDefault();
		const field = document.querySelector<HTMLInputElement>("[data-otp]");
		if (field) {
			field.value = target.dataset.code ?? "";
			field.focus();
		}
		return;
	}
	const action = ACTIONS[name];
	if (action) {
		event.preventDefault();
		void act(() => action(target));
	}
});

document.addEventListener("submit", (event) => {
	if ((event.target as HTMLElement).id === "prompt-form") {
		event.preventDefault();
		void act(submitCurrent);
	}
});

await rebuild();
renderOptions();
render();
