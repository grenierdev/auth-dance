import * as v from "valibot";
import { ComponentNotInChoreographyError } from "./error.ts";

/**
 * One step of the dance, the leaf of a choreography tree.
 *
 * The node carries a name, never behavior. `AuthDanceApi` finds the matching component in its `components` map
 * when the step arrives, so one declaration serves every flow.
 */
export interface AuthDanceChoreographyComponent {
	/** Marks this node as one step. Every traversal helper reads `kind` to know which node it has. */
	kind: "component";
	/** Name of the component to perform. It is a key of the `components` map, which a caller passes as `api.components`. */
	component: string;
}

/**
 * Parses one component node at runtime. The `AuthDanceChoreography` union includes it, so a caller can parse a
 * choreography that arrives as plain data.
 */
export const AuthDanceChoreographyComponent: v.GenericSchema<AuthDanceChoreographyComponent> = v.pipe(
	v.object({
		kind: v.literal("component"),
		component: v.string(),
	}),
	v.title("ChoreographyComponent"),
	v.description("A single choreography component"),
);

/**
 * A fork in the dance. The owner performs one branch, and each branch is a whole path on its own.
 *
 * `peek` gathers the first step of each open branch into one node of this kind. `AuthDanceApi` turns that node
 * into a prompt of kind `choice`, and the client renders the fork.
 *
 * @typeParam T - Node type of the branches. The `choice` combinator keeps it, so a caller sees the exact branches.
 */
export interface AuthDanceChoreographyChoice<T extends AuthDanceChoreography = AuthDanceChoreography> {
	/** Marks this node as a fork between the branches in `components`. */
	kind: "choice";
	/** The branches of the fork. The user performs exactly one of them. */
	components: T[];
}

/**
 * Parses a choice node at runtime. The schema is lazy because a branch holds another choreography, which makes
 * the definition recursive.
 */
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

/**
 * An ordered run of the dance. The owner performs every child, from the first one to the last one.
 *
 * A child is a whole choreography, so a sequence and a choice nest in each other. An example is
 * `sequence(choice("email", "passkey"), "totp")`.
 *
 * @typeParam T - Node type of the children. The `sequence` combinator keeps it, so a caller sees the exact steps.
 */
export interface AuthDanceChoreographySequence<T extends AuthDanceChoreography = AuthDanceChoreography> {
	/** Marks this node as an ordered run of the children in `components`. */
	kind: "sequence";
	/** The children to perform, in this order. */
	components: T[];
}

/**
 * Parses a sequence node at runtime. The schema is lazy because a child holds another choreography, which makes
 * the definition recursive.
 */
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

/**
 * The authentication policy as inert data: a tree of `component`, `choice` and `sequence` nodes.
 *
 * The library reads this tree to derive every flow, from sign-in to recovery. To add a factor, a caller edits
 * the declaration instead of the control flow. Build the tree with the `component`, `sequence`, `choice` and
 * `pick` combinators. Pass the result as `api.choreography`.
 */
export type AuthDanceChoreography = AuthDanceChoreographyComponent | AuthDanceChoreographyChoice | AuthDanceChoreographySequence;

/**
 * Parses a whole choreography tree at runtime. It accepts the three node kinds. It validates each child of a
 * `choice` and of a `sequence` with itself.
 */
export const AuthDanceChoreography: v.GenericSchema<AuthDanceChoreography> = v.pipe(
	v.union([AuthDanceChoreographyComponent, AuthDanceChoreographyChoice, AuthDanceChoreographySequence]),
	v.title("Choreography"),
	v.description("A choreography, which can be a component, a choice, or a sequence"),
);

/**
 * Builds a `sequence` node from choreography nodes, and keeps the type of each node in the result.
 *
 * @example
 * sequence(component("email"), component("password"));
 */
export function sequence<const T extends AuthDanceChoreography[]>(...components: T): AuthDanceChoreographySequence<T[number]>;
/**
 * Builds a `sequence` node. A plain string is sugar for `component(name)`, and the result type stays wide.
 *
 * @example
 * sequence("email", "password"); // email, then password
 */
export function sequence(...components: Array<AuthDanceChoreography | string>): AuthDanceChoreographySequence;
export function sequence(...components: Array<AuthDanceChoreography | string>): AuthDanceChoreographySequence {
	return {
		kind: "sequence",
		components: components.map((c) => (typeof c === "string" ? component(c) : c)),
	};
}

/**
 * Builds a `choice` node from choreography nodes, and keeps the type of each node in the result.
 *
 * @example
 * choice(sequence("email", "password"), component("passkey"));
 */
export function choice<const T extends AuthDanceChoreography[]>(...components: T): AuthDanceChoreographyChoice<T[number]>;
/**
 * Builds a `choice` node. A plain string is sugar for `component(name)`, and the result type stays wide.
 *
 * @example
 * choice("password", "passkey"); // either one
 */
export function choice(...components: Array<AuthDanceChoreography | string>): AuthDanceChoreographyChoice;
export function choice(...components: Array<AuthDanceChoreography | string>): AuthDanceChoreographyChoice {
	return {
		kind: "choice",
		components: components.map((c) => (typeof c === "string" ? component(c) : c)),
	};
}

/**
 * Wraps a component name in a `component` node. Every other combinator calls it for a plain string argument.
 *
 * @param component - Name of the component to perform. `AuthDanceApi` throws `UnknownComponentError` for a name
 * that is not a key of its `components` map.
 */
export function component(component: string): AuthDanceChoreographyComponent {
	return {
		kind: "component",
		component,
	};
}

/**
 * Builds a `choice` of every ordered permutation of `count` nodes, one `sequence` per permutation. This overload
 * takes nodes only, and the result type names their node types.
 *
 * @param count - How many nodes the owner performs on one branch. A count above the number of nodes gives a
 * `choice` with no branch.
 */
export function pick<const T extends AuthDanceChoreography[]>(count: number, ...components: T): AuthDanceChoreographyChoice<T[number]>;
/**
 * Builds a `choice` of every ordered permutation of `count` components, one `sequence` per permutation. This
 * states a policy such as "any two of these three". Order matters, so a pair produces one branch per order.
 *
 * A plain string is sugar for `component(name)`.
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
 * Compares two choreography nodes by structure, not by reference. Two `null` values are equal, and a `null`
 * never equals a node.
 *
 * The comparison respects order, so `choice(a, b)` and `choice(b, a)` are two different policies. `simplify`
 * uses this function to drop a duplicate child.
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
 * Rewrites a choreography into a smaller tree that states the same policy.
 *
 * The function starts at the leaves and moves toward the root. It lifts a child of the same kind into its
 * parent. Of two children that `isEquals` reports as equal, it keeps the first one. When one child remains,
 * that child replaces the node, so a `sequence` of one step is that step. `walk` and `peek` both call this
 * function, so they read one shape for one policy.
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
 * Walks every path through the choreography. Each yield holds one step and the ordered steps before it.
 *
 * `walk` yields one entry per branch of a `choice`, so a step appears one time per path that leads to it. It
 * flattens a nested node, so `path` holds single steps only.
 *
 * An entry with a `component` of `null` marks the end of a complete path. To find those ends, `walk` appends a
 * marker step that carries a `Symbol`, and no component name can match that marker. `AuthDanceApi` reads such
 * an entry as a finished dance. When the surviving components cover no complete path, `AuthDanceApi` refuses
 * the unenroll with `WouldLockOutError`.
 *
 * @yields The step to perform, and the ordered path of steps that leads to it.
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
 * Reports what the dance asks for after the given path. `AuthDanceApi` calls this function, so it does not hold
 * the order of the steps in its own logic.
 *
 * `peek` collects every step that `walk` reports at exactly `path`. It then simplifies the collected steps. One
 * step returns as a `component` node. Two or more return as a `choice` of those steps.
 *
 * @param path - Names of the components already performed, in order. The default is an empty path, which asks
 * for the first step of the dance.
 * @returns The next step, a `choice` of the alternatives, or `null` when the path completes the dance.
 * @throws {ComponentNotInChoreographyError} When no step of this choreography sits at `path`, and no complete
 * path matches `path`.
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
