import * as v from "valibot";
import { ComponentNotInChoreographyError } from "./error.ts";

/** One step of the dance. `AuthDanceApi` finds the component of this name in its `components` map. */
export interface AuthDanceChoreographyComponent {
	/** Marks this node as one step. */
	kind: "component";
	/** Name of the component to perform. It is a key of the `components` map. */
	component: string;
}

/** Parses one component node at runtime. */
export const AuthDanceChoreographyComponent: v.GenericSchema<AuthDanceChoreographyComponent> = v.pipe(
	v.object({
		kind: v.literal("component"),
		component: v.string(),
	}),
	v.title("ChoreographyComponent"),
	v.description("A single choreography component"),
);

/** A fork in the dance. The owner performs one branch, and each branch is a whole path on its own. */
export interface AuthDanceChoreographyChoice<T extends AuthDanceChoreography = AuthDanceChoreography> {
	/** Marks this node as a fork between the branches in `components`. */
	kind: "choice";
	/** The branches of the fork. The owner performs exactly one of them. */
	components: T[];
}

/** Parses a choice node at runtime. */
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

/** An ordered run of the dance. The owner performs every child, from the first one to the last one. */
export interface AuthDanceChoreographySequence<T extends AuthDanceChoreography = AuthDanceChoreography> {
	/** Marks this node as an ordered run of the children in `components`. */
	kind: "sequence";
	/** The children to perform, in this order. */
	components: T[];
}

/** Parses a sequence node at runtime. */
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

/** The authentication policy as data. Build the tree with the `component`, `sequence`, `choice` and `pick` combinators. */
export type AuthDanceChoreography = AuthDanceChoreographyComponent | AuthDanceChoreographyChoice | AuthDanceChoreographySequence;

/** Parses a whole choreography tree at runtime. */
export const AuthDanceChoreography: v.GenericSchema<AuthDanceChoreography> = v.pipe(
	v.union([AuthDanceChoreographyComponent, AuthDanceChoreographyChoice, AuthDanceChoreographySequence]),
	v.title("Choreography"),
	v.description("A choreography, which can be a component, a choice, or a sequence"),
);

/** Builds a `sequence` node from choreography nodes, and keeps the type of each node in the result. */
export function sequence<const T extends AuthDanceChoreography[]>(...components: T): AuthDanceChoreographySequence<T[number]>;
/**
 * Builds a `sequence` node. A plain string is sugar for `component(name)`.
 *
 * @example
 * sequence("email", "password");
 */
export function sequence(...components: Array<AuthDanceChoreography | string>): AuthDanceChoreographySequence;
export function sequence(...components: Array<AuthDanceChoreography | string>): AuthDanceChoreographySequence {
	return {
		kind: "sequence",
		components: components.map((c) => (typeof c === "string" ? component(c) : c)),
	};
}

/** Builds a `choice` node from choreography nodes, and keeps the type of each node in the result. */
export function choice<const T extends AuthDanceChoreography[]>(...components: T): AuthDanceChoreographyChoice<T[number]>;
/**
 * Builds a `choice` node. A plain string is sugar for `component(name)`.
 *
 * @example
 * choice("password", "passkey");
 */
export function choice(...components: Array<AuthDanceChoreography | string>): AuthDanceChoreographyChoice;
export function choice(...components: Array<AuthDanceChoreography | string>): AuthDanceChoreographyChoice {
	return {
		kind: "choice",
		components: components.map((c) => (typeof c === "string" ? component(c) : c)),
	};
}

/**
 * Wraps a component name in a `component` node.
 *
 * @param component - Name of the component. `AuthDanceApi` throws `UnknownComponentError` for an unknown name.
 */
export function component(component: string): AuthDanceChoreographyComponent {
	return {
		kind: "component",
		component,
	};
}

/** Builds a `choice` of every ordered permutation of `count` nodes, one `sequence` per permutation. */
export function pick<const T extends AuthDanceChoreography[]>(count: number, ...components: T): AuthDanceChoreographyChoice<T[number]>;
/**
 * Builds a `choice` of every ordered permutation of `count` components, one `sequence` per permutation. Order
 * matters, so a pair produces one branch per order. A plain string is sugar for `component(name)`.
 *
 * @param count - How many components the owner performs on one branch. A count above the number of components
 * gives a `choice` with no branch.
 * @example
 * pick(2, "totp", "sms", "backup-code"); // any 2 of 3, in any order
 */
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

/**
 * Compares two choreography nodes by structure. Two `null` values are equal, and a `null` never equals a node.
 * The comparison respects order, so `choice(a, b)` and `choice(b, a)` are two different policies.
 */
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

/**
 * Rewrites a choreography into a smaller tree that states the same policy. It lifts a child of the same kind
 * into its parent, drops an equal duplicate child, and replaces a node of one child with that child.
 */
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

/**
 * Walks every path through the choreography. Each yield holds one step and the ordered steps before it. A step
 * appears one time per path that leads to it. An entry with a `component` of `null` ends a complete path.
 */
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

/**
 * Reports what the dance asks for after the given path.
 *
 * @param path - Names of the components already performed, in order. An empty path asks for the first step.
 * @returns The next step, a `choice` of the alternatives, or `null` when the path completes the dance.
 * @throws {ComponentNotInChoreographyError} When no step sits at `path`, and no complete path matches `path`.
 * @example
 * peek(sequence("email", "password"), ["email"]); // component("password")
 */
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
