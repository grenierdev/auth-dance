import * as v from "valibot";
import { ComponentNotInChoreographyError } from "./error.ts";

export interface AuthDanceChoreographyComponent {
	kind: "component";
	component: string;
}

export const AuthDanceChoreographyComponent: v.GenericSchema<AuthDanceChoreographyComponent> = v.pipe(
	v.object({
		kind: v.literal("component"),
		component: v.string(),
	}),
	v.title("ChoreographyComponent"),
	v.description("A single choreography component"),
);

export interface AuthDanceChoreographyChoice<T extends AuthDanceChoreography = AuthDanceChoreography> {
	kind: "choice";
	components: T[];
}

export const AuthDanceChoreographyChoice: v.GenericSchema<AuthDanceChoreographyChoice> = v.lazy(() =>
	v.pipe(
		v.object({
			kind: v.literal("choice"),
			components: v.array(AuthDanceChoreography),
		}),
		v.title("ChoreographyChoice"),
		v.description("A choice of choreography components"),
	)
);

export interface AuthDanceChoreographySequence<T extends AuthDanceChoreography = AuthDanceChoreography> {
	kind: "sequence";
	components: T[];
}

export const AuthDanceChoreographySequence: v.GenericSchema<AuthDanceChoreographySequence> = v.lazy(() =>
	v.pipe(
		v.object({
			kind: v.literal("sequence"),
			components: v.array(AuthDanceChoreography),
		}),
		v.title("ChoreographySequence"),
		v.description("A sequence of choreography components"),
	)
);

export type AuthDanceChoreography = AuthDanceChoreographyComponent | AuthDanceChoreographyChoice | AuthDanceChoreographySequence;

export const AuthDanceChoreography: v.GenericSchema<AuthDanceChoreography> = v.pipe(
	v.union([AuthDanceChoreographyComponent, AuthDanceChoreographyChoice, AuthDanceChoreographySequence]),
	v.title("Choreography"),
	v.description("A choreography, which can be a component, a choice, or a sequence"),
);

export function sequence<const T extends AuthDanceChoreography[]>(...components: T): AuthDanceChoreographySequence<T[number]>;
export function sequence(...components: Array<AuthDanceChoreography | string>): AuthDanceChoreographySequence;
export function sequence(...components: Array<AuthDanceChoreography | string>): AuthDanceChoreographySequence {
	return {
		kind: "sequence",
		components: components.map((c) => (typeof c === "string" ? component(c) : c)),
	};
}

export function choice<const T extends AuthDanceChoreography[]>(...components: T): AuthDanceChoreographyChoice<T[number]>;
export function choice(...components: Array<AuthDanceChoreography | string>): AuthDanceChoreographyChoice;
export function choice(...components: Array<AuthDanceChoreography | string>): AuthDanceChoreographyChoice {
	return {
		kind: "choice",
		components: components.map((c) => (typeof c === "string" ? component(c) : c)),
	};
}

export function component(component: string): AuthDanceChoreographyComponent {
	return {
		kind: "component",
		component,
	};
}

export function pick<const T extends AuthDanceChoreography[]>(count: number, ...components: T): AuthDanceChoreographyChoice<T[number]>;
export function pick(count: number, ...components: Array<AuthDanceChoreography | string>): AuthDanceChoreographyChoice;
export function pick(count: number, ...components: Array<AuthDanceChoreography | string>): AuthDanceChoreographyChoice {
	const permutations: AuthDanceChoreographySequence[] = [];
	function permute(chosen: AuthDanceChoreography[], remaining: AuthDanceChoreography[]): void {
		if (chosen.length === count) {
			permutations.push(sequence(...chosen));
			return;
		}
		for (let i = 0; i < remaining.length; i++) {
			permute([...chosen, remaining[i]], [...remaining.slice(0, i), ...remaining.slice(i + 1)]);
		}
	}
	permute([], components.map((c) => (typeof c === "string" ? component(c) : c)));
	return choice(...permutations);
}

export function isEquals(a: AuthDanceChoreography | null, b: AuthDanceChoreography | null): boolean {
	if (a === null || b === null) {
		return a === b;
	}
	if (a.kind !== b.kind) {
		return false;
	}
	if (a.kind === "component" && b.kind === "component") {
		return a.component === b.component;
	}
	if ((a.kind === "choice" && b.kind === "choice") || (a.kind === "sequence" && b.kind === "sequence")) {
		if (a.components.length !== b.components.length) {
			return false;
		}
		for (let i = 0; i < a.components.length; i++) {
			if (!isEquals(a.components[i], b.components[i])) {
				return false;
			}
		}
		return true;
	}
	return false;
}

export function simplify(choreography: AuthDanceChoreography): AuthDanceChoreography {
	if (choreography.kind === "sequence" || choreography.kind === "choice") {
		const simplified = choreography.components.flatMap((c) => {
			c = simplify(c);
			if (c.kind === choreography.kind) {
				return c.components;
			} else {
				return [c];
			}
		});
		const components = simplified.filter((c, i) => simplified.findIndex((x) => isEquals(x, c)) === i);
		if (components.length === 1) {
			return components[0];
		}
		return {
			kind: choreography.kind,
			components,
		};
	} else {
		return choreography;
	}
}

export function* walk(
	choreography: AuthDanceChoreography,
): Generator<{ component: AuthDanceChoreographyComponent | null; path: AuthDanceChoreographyComponent[] }> {
	function* innerWalk(
		choreography: AuthDanceChoreography,
		path: AuthDanceChoreographyComponent[],
	): Generator<{ component: AuthDanceChoreographyComponent; path: AuthDanceChoreographyComponent[] }> {
		if (choreography.kind === "component") {
			yield { component: choreography, path };
		} else if (choreography.kind === "choice") {
			for (const c of choreography.components) {
				yield* innerWalk(c, path);
			}
		} else if (choreography.components.length > 0) {
			const first = choreography.components[0];
			const rest = choreography.components.slice(1);
			if (first.kind === "choice") {
				for (const c of first.components) {
					yield* innerWalk(simplify(sequence(c, ...rest)), path);
				}
			} else if (first.kind === "component") {
				yield* innerWalk(first, path);
				yield* innerWalk(simplify(sequence(...rest)), [...path, first]);
			}
		}
	}

	const end = Symbol("end");
	const choreographyWithEnd = simplify(sequence(choreography, component(end as unknown as string)));
	for (const { component, path } of innerWalk(choreographyWithEnd, [])) {
		yield { component: component?.component as unknown === end ? null : component, path };
	}
}

export function peek(
	choreography: AuthDanceChoreography,
	path: string[] = [],
): AuthDanceChoreographyComponent | AuthDanceChoreographyChoice<AuthDanceChoreographyComponent> | null {
	const components: AuthDanceChoreographyComponent[] = [];
	for (const { component, path: p } of walk(choreography)) {
		if (component && p.length === path.length && p.every((pp, i) => pp.component === path[i])) {
			components.push(component);
		} else if (component === null && p.every((pp, i) => pp.component === path[i])) {
			return null;
		}
	}
	if (components.length === 0) {
		throw new ComponentNotInChoreographyError(`No components found at path ${path.join(" -> ")}`);
	}
	return simplify(choice(...components)) as AuthDanceChoreographyComponent | AuthDanceChoreographyChoice<AuthDanceChoreographyComponent>;
}
