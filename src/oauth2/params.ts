// RFC 6749 §3.1 and §3.2: a parameter with an empty value counts as omitted, and no parameter may appear twice.
export function readParams(entries: Iterable<[string, string]>): { params: Map<string, string>; repeated: string[] } {
	const params = new Map<string, string>();
	const seen = new Set<string>();
	const repeated: string[] = [];
	for (const [name, value] of entries) {
		if (seen.has(name) && !repeated.includes(name)) {
			repeated.push(name);
		}
		seen.add(name);
		if (value !== "") {
			params.set(name, value);
		}
	}
	return { params, repeated };
}
