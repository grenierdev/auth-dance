import { strictEqual as assertStrictEquals, throws as assertThrows, deepEqual, ok } from "node:assert";
import { describe, it } from "vitest";
import { choice, component, isEquals, peek, pick, sequence, simplify, walk } from "./choreography.ts";

describe("Choreography", () => {
	it("should create a component", () => {
		const c = component("test");
		deepEqual(c.kind, "component");
		deepEqual(c.component, "test");
	});
	it("should create a sequence", () => {
		const c = component("test");
		const s = { kind: "sequence", components: [c] };
		deepEqual(s.kind, "sequence");
		deepEqual(s.components.length, 1);
		assertStrictEquals(s.components[0], c);
	});
	it("should create a choice", () => {
		const c = component("test");
		const ch = { kind: "choice", components: [c] };
		deepEqual(ch.kind, "choice");
		deepEqual(ch.components.length, 1);
		assertStrictEquals(ch.components[0], c);
	});
	it("should compare components", () => {
		const c1 = component("test");
		const c2 = component("test");
		const c3 = component("test2");
		ok(isEquals(c1, c1));
		ok(isEquals(c2, c2));
		ok(isEquals(c3, c3));
		ok(isEquals(c1, c2));
		ok(isEquals(c2, c1));
		ok(!isEquals(c1, c3));
	});
	it("should compare sequences", () => {
		const c1 = component("test");
		const c2 = component("test");
		const s1 = sequence(c1);
		const s2 = sequence(c2);
		ok(isEquals(s1, s1));
		ok(isEquals(s2, s2));
		ok(isEquals(s1, s2));
		ok(isEquals(s2, s1));
	});
	it("should compare choices", () => {
		const c1 = component("test");
		const c2 = component("test");
		const ch1 = choice(c1);
		const ch2 = choice(c2);
		ok(isEquals(ch1, ch1));
		ok(isEquals(ch2, ch2));
		ok(isEquals(ch1, ch2));
		ok(isEquals(ch2, ch1));
	});
	it("should simplify sequences", () => {
		const c1 = component("test");
		const c2 = component("test");
		const s1 = sequence(c1, c2);
		ok(isEquals(simplify(s1), c1));
	});
	it("should simplify choices", () => {
		const c1 = component("test");
		const c2 = component("test");
		const ch1 = choice(c1, c2);
		ok(isEquals(simplify(ch1), c1));
	});
	it("should not simplify sequences with different components", () => {
		const c1 = component("test");
		const c2 = component("test2");
		const s1 = sequence(c1, c2);
		ok(isEquals(simplify(s1), s1));
	});
	it("should not simplify choices with different components", () => {
		const c1 = component("test");
		const c2 = component("test2");
		const ch1 = choice(c1, c2);
		ok(isEquals(simplify(ch1), ch1));
	});
	it("should simplify nested sequences", () => {
		const c1 = component("test");
		const c2 = component("test");
		const s1 = sequence(c1, c2);
		const s2 = sequence(s1);
		ok(isEquals(simplify(s2), c1));
	});
	it("should simplify nested choices", () => {
		const c1 = component("test");
		const c2 = component("test");
		const ch1 = choice(c1, c2);
		const ch2 = choice(ch1);
		ok(isEquals(simplify(ch2), c1));
	});
	it("should not simplify nested sequences with different components", () => {
		const c1 = component("test");
		const c2 = component("test2");
		const s1 = sequence(c1, c2);
		const s2 = sequence(c1, c2);
		ok(isEquals(simplify(s2), s1));
	});
	it("should not simplify nested choices with different components", () => {
		const c1 = component("test");
		const c2 = component("test2");
		const ch1 = choice(c1, c2);
		const ch2 = choice(c1, c2);
		ok(isEquals(simplify(ch2), ch1));
	});
	it("should simplify complex nested structures", () => {
		const c1 = component("test");
		const c2 = component("test");
		const c3 = component("test2");
		const s1 = sequence(c1, c2);
		const ch1 = choice(s1, c3);
		const s2 = sequence(ch1, c1);
		ok(isEquals(simplify(s2), sequence(choice(c1, c3), c1)));
	});
	it("should not simplify complex nested structures with different components", () => {
		const c1 = component("test");
		const c2 = component("test2");
		const c3 = component("test3");
		const s1 = sequence(c1, c2);
		const ch1 = choice(s1, c3);
		const s2 = sequence(ch1, c1);
		ok(isEquals(simplify(s2), s2));
	});
	it("should simplify complex nested structures with multiple levels", () => {
		const c1 = component("test");
		const c2 = component("test");
		const c3 = component("test2");
		const s1 = sequence(c1, c2);
		const ch1 = choice(s1, c3);
		const s2 = sequence(ch1, c1);
		const ch2 = choice(s2, c3);
		ok(isEquals(simplify(ch2), choice(sequence(choice(c1, c3), c1), c3)));
	});
	it("should not simplify complex nested structures with multiple levels and different components", () => {
		const c1 = component("test");
		const c2 = component("test2");
		const c3 = component("test3");
		const s1 = sequence(c1, c2);
		const ch1 = choice(s1, c3);
		const s2 = sequence(ch1, c1);
		const ch2 = choice(s2, c3);
		ok(isEquals(simplify(ch2), ch2));
	});
	it("should walk a component", () => {
		const c1 = component("test");
		const result = Array.from(walk(c1));
		deepEqual(result, [
			{ component: c1, path: [] },
			{ component: null, path: [c1] },
		]);
	});
	it("should walk a sequence", () => {
		const c1 = component("test");
		const c2 = component("test2");
		const s1 = sequence(c1, c2);
		const result = Array.from(walk(s1));
		deepEqual(result, [
			{ component: c1, path: [] },
			{ component: c2, path: [c1] },
			{ component: null, path: [c1, c2] },
		]);
	});
	it("should walk a choice", () => {
		const c1 = component("test");
		const c2 = component("test2");
		const ch1 = choice(c1, c2);
		const result = Array.from(walk(ch1));
		deepEqual(result, [
			{ component: c1, path: [] },
			{ component: null, path: [c1] },
			{ component: c2, path: [] },
			{ component: null, path: [c2] },
		]);
	});
	it("should peek choreography at path in sequence", () => {
		const c1 = component("test");
		const c2 = component("test2");
		const s1 = sequence(c1, c2);
		deepEqual(peek(s1, []), c1);
		deepEqual(peek(s1, ["test"]), c2);
		deepEqual(peek(s1, ["test", "test2"]), null);
		assertThrows(() => peek(s1, ["foo"]));
	});
	it("should peek choreography at path in choice", () => {
		const c1 = component("test");
		const c2 = component("test2");
		const ch1 = choice(c1, c2);
		deepEqual(peek(ch1, []), ch1);
		deepEqual(peek(ch1, ["test"]), null);
		deepEqual(peek(ch1, ["test2"]), null);
		assertThrows(() => peek(ch1, ["foo"]));
	});
	it("should peek choreography at path in nested structures", () => {
		const c1 = component("test");
		const c2 = component("test2");
		const c3 = component("test3");
		const s1 = sequence(c1, c2);
		const ch1 = choice(s1, c3);
		deepEqual(peek(ch1, []), choice(c1, c3));
		deepEqual(peek(ch1, ["test"]), c2);
		deepEqual(peek(ch1, ["test", "test2"]), null);
		deepEqual(peek(ch1, ["test3"]), null);
		assertThrows(() => peek(ch1, ["foo"]));
	});
	it("should pick ordered permutations of the given length", () => {
		const a = component("a");
		const b = component("b");
		const c = component("c");
		const result = pick(2, a, b, c);
		const expected = choice(sequence(a, b), sequence(a, c), sequence(b, a), sequence(b, c), sequence(c, a), sequence(c, b));
		ok(isEquals(result, expected));
	});
	it("should build full permutations when count deepEquals the number of components", () => {
		const a = component("a");
		const b = component("b");
		const result = pick(2, a, b);
		ok(isEquals(result, choice(sequence(a, b), sequence(b, a))));
	});
	it("should produce an empty choice when count exceeds the number of components", () => {
		const a = component("a");
		const result = pick(2, a);
		deepEqual(result.kind, "choice");
		deepEqual(result.components.length, 0);
	});
});
