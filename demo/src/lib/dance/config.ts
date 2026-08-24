/**
 * @module
 *
 * What the options panel edits, and what a reload remembers.
 */

import { type AuthDanceApiOptions, type AuthDanceChoreography, choice, sequence } from "auth-dance";

/** The durations of `api.durations`, with every key required. */
export type Durations = Required<NonNullable<AuthDanceApiOptions["durations"]>>;

/** The default durations, in seconds. */
export const DEFAULT_DURATIONS: Durations = {
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

/** One row of the durations grid. */
export interface DurationField {
	/** The key of {@link Durations} this row writes. It is also the label. */
	key: keyof Durations;
	/** What the duration governs. */
	hint: string;
}

/** The order of the duration inputs. */
export const DURATION_FIELDS: ReadonlyArray<DurationField> = [
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

/** One entry of the choreography picker. The entry without a tree is the custom one. */
export interface Preset {
	/** The value the picker stores in `Config.preset`. */
	id: string;
	/** What the picker shows. */
	label: string;
	/** The policy written as the call that builds it. */
	hint: string;
	/** The tree the preset resolves to. Absent on the custom entry. */
	choreography?: AuthDanceChoreography;
}

/** The choreographies the picker offers. Every name is a key of the components map. */
export const PRESETS: ReadonlyArray<Preset> = [
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
		id: "authenticator",
		label: "Two factors: email, password, then an authenticator code",
		hint: 'sequence("email", "password", "totp") — the sign-up collects the key, the sign-in takes the code',
		choreography: sequence("email", "password", "totp"),
	},
	{
		id: "passkey",
		label: "Passkey only: one signature",
		hint: 'sequence("webauthn") — the credential id names the owner, so no address and no password are asked for',
		choreography: sequence("webauthn"),
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

/** Everything the options panel edits. */
export interface Config {
	/** The id of the picked {@link Preset}. The custom entry sends the reader to `custom`. */
	preset: string;
	/** The custom tree, as JSON. */
	custom: string;
	/** Every duration of `api.durations`, in seconds. */
	durations: Durations;
	/** Whether a rebuild seeds the John Doe identity again. */
	seed: boolean;
}

/** Where a reload finds the config again. */
export const CONFIG_KEY = "auth-dance-demo/config@1";

/** The config a first visit gets. */
export function defaultConfig(): Config {
	return {
		preset: PRESETS[0].id,
		custom: JSON.stringify(sequence("email", "password"), null, "\t"),
		durations: { ...DEFAULT_DURATIONS },
		seed: true,
	};
}

/**
 * Reads the stored config, and falls back to the defaults for anything missing or broken.
 *
 * Deno has a `localStorage` shared by every request, so this checks for a document instead.
 */
export function loadConfig(): Config {
	const fallback = defaultConfig();
	if (typeof document === "undefined") {
		return fallback;
	}
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

/** Stores the config for the next reload. */
export function saveConfig(config: Config): void {
	if (typeof document === "undefined") {
		return;
	}
	try {
		localStorage.setItem(CONFIG_KEY, JSON.stringify(config));
	} catch {
		// The browser refuses storage.
	}
}

/**
 * Reads a choreography out of parsed JSON.
 *
 * @param node - The parsed JSON to read.
 * @param path - The position of `node` in the tree.
 * @returns The tree the JSON describes.
 * @throws {Error} When a node is not one of the three kinds. The message names its path.
 */
export function parseChoreography(node: unknown, path = "$"): AuthDanceChoreography {
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

/**
 * The tree the current config resolves to.
 *
 * @throws {Error} When the config picks the custom entry and its JSON is not a tree.
 */
export function currentChoreography(config: Config): AuthDanceChoreography {
	const preset = PRESETS.find((entry) => entry.id === config.preset);
	if (preset?.choreography) {
		return preset.choreography;
	}
	return parseChoreography(JSON.parse(config.custom));
}

/** Renders a tree as indented text. */
export function formatChoreography(choreography: AuthDanceChoreography, indent = ""): string {
	if (choreography.kind === "component") {
		return `${indent}${choreography.component}`;
	}
	const children = choreography.components.map((child) => formatChoreography(child, `${indent}  `));
	return [`${indent}${choreography.kind}`, ...children].join("\n");
}
