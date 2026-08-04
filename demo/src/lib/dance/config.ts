/**
 * @module
 *
 * What the options panel edits, and what a reload remembers.
 *
 * A choreography is inert data: a tree of component, choice and sequence nodes. Swapping that tree swaps the whole
 * authentication policy, and no line of flow logic changes with it. The presets below are the ready-made trees the
 * picker offers, and the custom entry lets the same picker take one written by hand as JSON.
 *
 * Nothing here builds an instance. This module reads and writes a plain config record, and it answers what tree that
 * record resolves to. The store rebuilds the library when the record changes.
 */

import { type AuthDanceApiOptions, type AuthDanceChoreography, choice, sequence } from "auth-dance";

/** The durations of `api.durations`, with every key required so an input always has a number to show. */
export type Durations = Required<NonNullable<AuthDanceApiOptions["durations"]>>;

/** The defaults of the library, spelled out. */
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

/** One row of the durations grid: the key it edits, and the sentence under the input. */
export interface DurationField {
	/** The key of {@link Durations} this row writes. It is also the label, since the library name is the clearest one. */
	key: keyof Durations;
	/** What the duration governs, in one clause. */
	hint: string;
}

/** The order and the wording of the duration inputs. */
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

/** One entry of the choreography picker. The entry without a tree is the custom one, which reads its tree from the config. */
export interface Preset {
	/** The value the picker stores in `Config.preset`. */
	id: string;
	/** What the picker shows. */
	label: string;
	/** The same policy written as the call that builds it, so the label and the code stay tied together. */
	hint: string;
	/** The tree the preset resolves to. Absent on the custom entry, which parses `Config.custom` instead. */
	choreography?: AuthDanceChoreography;
}

/**
 * The choreographies the picker offers.
 *
 * Every name is a key of the components map of the running instance: `email`, `email2`, `password` and `otp`. The tree
 * is inert data, which is why one picker can swap the whole policy without touching a line of flow logic.
 */
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

/** Everything the options panel edits. One record rebuilds the whole instance. */
export interface Config {
	/** The id of the picked {@link Preset}. The custom entry sends the reader to `custom`. */
	preset: string;
	/** The custom tree, as the JSON the textarea holds. It stays in the config even while a preset is picked. */
	custom: string;
	/** Every duration of `api.durations`, in seconds. */
	durations: Durations;
	/** Whether a rebuild seeds the John Doe identity again. */
	seed: boolean;
}

/** Where a reload finds the config again. */
export const CONFIG_KEY = "auth-dance-demo/config@1";

/** The config a first visit gets: the first preset, the default durations, and the seeded identity. */
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
 * The check for a document is the only reliable way to tell a browser from the server pass. Deno carries a
 * disk-backed `localStorage` of its own, so the usual `typeof localStorage !== "undefined"` guard passes there and
 * quietly reads a store shared by every request.
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

/** Stores the config for the next reload. A browser that refuses storage keeps the running config in memory only. */
export function saveConfig(config: Config): void {
	if (typeof document === "undefined") {
		return;
	}
	try {
		localStorage.setItem(CONFIG_KEY, JSON.stringify(config));
	} catch {
		// A browser that refuses storage keeps the running config in memory only.
	}
}

/**
 * Reads a choreography out of parsed JSON. The library ships a schema for this, and the demo keeps the check here so
 * the whole page depends on nothing but the library itself.
 *
 * @param node - The parsed JSON to read.
 * @param path - The position of `node` in the tree, which the message of a failure names.
 * @returns The tree the JSON describes.
 * @throws {Error} When a node is not one of the three kinds. The message names the path of the bad node.
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
 * @throws {Error} When the config picks the custom entry and its JSON is not a tree. Call this before a rebuild to
 * refuse a broken tree while the running instance is still worth keeping.
 */
export function currentChoreography(config: Config): AuthDanceChoreography {
	const preset = PRESETS.find((entry) => entry.id === config.preset);
	if (preset?.choreography) {
		return preset.choreography;
	}
	return parseChoreography(JSON.parse(config.custom));
}

/** Renders a tree as indented text, for the preview under the picker. */
export function formatChoreography(choreography: AuthDanceChoreography, indent = ""): string {
	if (choreography.kind === "component") {
		return `${indent}${choreography.component}`;
	}
	const children = choreography.components.map((child) => formatChoreography(child, `${indent}  `));
	return [`${indent}${choreography.kind}`, ...children].join("\n");
}
