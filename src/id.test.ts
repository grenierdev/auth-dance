import { notDeepStrictEqual as assertNotEquals, throws as assertThrows, deepEqual, ok } from "node:assert";
import { describe, it } from "vitest";
import { assertID, id, isID, ksuid, rksuid } from "./id.ts";

describe("ID", () => {
	it("id", () => {
		deepEqual(id().length, 26);
		deepEqual(id("test_").length, 31);
		assertNotEquals(id(), id());
	});
	it("isID", () => {
		deepEqual(isID(id()), true);
		deepEqual(isID("test_", id("test_")), true);
		deepEqual(isID("test_", id()), false);
		deepEqual(isID("..."), false);
		deepEqual(isID("test_", ""), false);
	});
	it("assertID", () => {
		assertID(id());
		assertID("test_", id("test_"));
		assertThrows(() => assertID("..."));
		assertThrows(() => assertID("test_", id()));
		assertThrows(() => assertID("test_", ""));
	});
	it("ksuid", () => {
		deepEqual(ksuid(0).length, 26);
		deepEqual(ksuid("test_", 0).length, 31);
		assertNotEquals(ksuid(0), ksuid(0));
		assertID(ksuid(0));
		ok(ksuid(0) < ksuid(1));
	});
	it("rksuid", () => {
		deepEqual(rksuid(0).length, 26);
		deepEqual(rksuid("test_", 0).length, 31);
		assertNotEquals(rksuid(0), rksuid(0));
		assertID(rksuid(0));
		ok(rksuid(0) > rksuid(1));
	});
});
