import { type AuthDanceChoreography, choice, sequence, walk } from "@lib/choreography.ts";

/**
 * What the landing page needs to know about a component to derive a recovery. It mirrors the kinds of the
 * components that ship with the library: an identification resolves the identity, a challenge proves control.
 */
export interface StepKind {
	identification: boolean;
	/** The step proves control on its own (a passkey, a password, a TOTP or a one-time code). */
	proves: boolean;
	/** An identification that can prove control through its own verification, as an address does with a code. */
	verifiable?: boolean;
	/** The step holds a credential the owner can lose, so a recovery row is worth showing. */
	credential?: boolean;
}

export interface Preset {
	id: string;
	label: string;
	code: string;
	choreography: AuthDanceChoreography;
	kinds: Record<string, StepKind>;
}

const email: StepKind = { identification: true, proves: false, verifiable: true };
const password: StepKind = { identification: false, proves: true, credential: true };
const passkey: StepKind = { identification: true, proves: true, credential: true };
const totp: StepKind = { identification: false, proves: true, credential: true };
const otp: StepKind = { identification: false, proves: true };

export const PRESETS: Preset[] = [
	{
		id: "password-or-passkey",
		label: "Passkey option",
		code: `choice(sequence("email", "password"), "passkey")`,
		choreography: choice(sequence("email", "password"), "passkey"),
		kinds: { email, password, passkey },
	},
	{
		id: "second-factor",
		label: "Second factor",
		code: `sequence("email", "password", "totp")`,
		choreography: sequence("email", "password", "totp"),
		kinds: { email, password, totp },
	},
	{
		id: "passwordless",
		label: "Passwordless",
		code: `choice(sequence("email", "otp"), "passkey")`,
		choreography: choice(sequence("email", "otp"), "passkey"),
		kinds: { email, otp, passkey },
	},
];

export interface Flow {
	id: string;
	label: string;
	note: string;
	/** Each complete path of the flow. An empty list means the flow does not exist for this choreography. */
	paths: string[][];
	/** Display names for steps that act differently in this flow. */
	labels?: Record<string, string>;
	/** What a completed path ends on. */
	outcome: string;
}

/** Every complete path of the choreography, from the library's own `walk`. */
export function paths(choreography: AuthDanceChoreography): string[][] {
	const out: string[][] = [];
	for (const { component, path } of walk(choreography)) {
		if (component === null) out.push(path.map((c) => c.component));
	}
	return out;
}

/** The rule of `AuthDanceApi`: a sign-in without the component, on a path that starts with an identification and proves control. */
function recovery(all: string[][], name: string, kinds: Record<string, StepKind>): string[][] {
	const out: string[][] = [];
	for (const p of all) {
		if (!p.includes(name)) continue;
		const rest = p.filter((s) => s !== name);
		const ok = rest.length > 0 && kinds[rest[0]]?.identification && rest.some((s) => kinds[s]?.proves || (kinds[s]?.identification && kinds[s]?.verifiable));
		if (ok && !out.some((o) => o.join() === rest.join())) out.push(rest);
	}
	return out;
}

export function deriveFlows(preset: Preset): Flow[] {
	const all = paths(preset.choreography);
	const flows: Flow[] = [
		{ id: "sign-in", label: "Sign-in", note: "one complete path", paths: all, outcome: "tokens" },
		{ id: "sign-up", label: "Sign-up", note: "each step registers", paths: all, outcome: "tokens" },
	];
	for (const [name, kind] of Object.entries(preset.kinds)) {
		if (!kind.credential) continue;
		const paths = recovery(all, name, preset.kinds);
		// An address proves nothing on a sign-in, but inside a recovery it proves control with its own one-time code.
		const labels: Record<string, string> = {};
		for (const [step, k] of Object.entries(preset.kinds)) if (k.identification && !k.proves && k.verifiable) labels[step] = `${step} + code`;
		flows.push({ id: `recover-${name}`, label: `Recover ${name}`, note: "a sign-in without it", paths, labels, outcome: `new ${name}` });
	}
	return flows;
}

/** The steps the landing composer can toggle, in the order a path performs them. */
export const COMPOSABLE = ["password", "otp", "totp"] as const;
export type Composable = (typeof COMPOSABLE)[number];

const KINDS: Record<string, StepKind> = { email, password, passkey, totp, otp };

export interface Composition {
	steps: Composable[];
	passkey: boolean;
}

/** A preset built from the composer's toggles: `email`, then the chosen steps, and optionally `"passkey"` as the other branch. */
export function compose({ steps, passkey: withPasskey }: Composition): Preset & { invalid?: string[] } {
	const ordered = COMPOSABLE.filter((s) => steps.includes(s));
	const first = ordered.length ? `sequence(${["email", ...ordered].map((s) => `"${s}"`).join(", ")})` : `"email"`;
	const code = withPasskey ? `choice(${first}, "passkey")` : first;
	const main = sequence("email", ...ordered);
	const choreography = withPasskey ? choice(main, "passkey") : main;
	const kinds: Record<string, StepKind> = { email: KINDS.email };
	for (const s of ordered) kinds[s] = KINDS[s];
	if (withPasskey) kinds.passkey = KINDS.passkey;
	// The startup rule of `AuthDanceApi`: every complete path holds a step that proves control.
	const bad = paths(choreography).find((p) => !p.some((s) => kinds[s]?.proves));
	return { id: "composed", label: "Composed", code, choreography, kinds, invalid: bad };
}
