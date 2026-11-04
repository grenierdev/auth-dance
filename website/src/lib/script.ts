import type { Flow } from "./derive";

/**
 * One beat of the console: what the client sees and sends while it runs a flow. The routes, the prompt shape and the
 * response fields are the library's own; the values are made up for the page.
 */
export type ConsoleEvent =
	| { kind: "request"; route: string; body: string; response: string; ms: number }
	| { kind: "prompt"; step: string; type: string; sendable: boolean; choice?: string[] }
	| { kind: "answer"; step: string; value: string; secret?: boolean }
	| { kind: "done"; outcome: string; tokens: boolean };

const TYPE: Record<string, string> = { email: "email", password: "password", otp: "otp", totp: "otp", passkey: "webauthn" };
const VALUE: Record<string, { value: string; secret?: boolean }> = {
	email: { value: "ada@example.com" },
	password: { value: "correct-horse", secret: true },
	otp: { value: "482913" },
	totp: { value: "190245" },
	passkey: { value: "assertion from the platform authenticator" },
};
const STATE = '"eyJlbmMiOiJBMjU2R0NNIn0…"';
const MS = [14, 9, 11, 22, 8, 12, 17, 10];

function promptJson(name: string, type: string, sendable: boolean) {
	return `{ "kind": "input", "name": "${name}", "type": "${type}", "sendable": ${sendable} }`;
}

/** The beats of one complete path of a flow, from the first request to the result. */
export function script(flow: Flow, pathIndex: number): ConsoleEvent[] {
	const path = flow.paths[pathIndex];
	if (!path) return [];
	const recover = flow.id.startsWith("recover-");
	const lost = recover ? flow.id.slice("recover-".length) : undefined;
	const firsts = [...new Set(flow.paths.map((p) => p[0]))];
	const out: ConsoleEvent[] = [];
	let n = 0;
	const ms = () => MS[n++ % MS.length];

	const prompts: { step: string; name: string; type: string; sendable: boolean }[] = [];
	for (const step of path) {
		prompts.push({ step, name: step, type: TYPE[step] ?? step, sendable: step === "otp" });
		// Inside a recovery an address proves control only through its own one-time code.
		if (recover && flow.labels?.[step]) prompts.push({ step: `${step} code`, name: step, type: "otp", sendable: true });
	}
	if (lost) prompts.push({ step: `new ${lost}`, name: lost, type: TYPE[lost] ?? lost, sendable: false });

	const first = prompts[0];
	const startRoute = recover ? "/recover" : flow.id === "sign-up" ? "/sign-up" : "/sign-in";
	const choice = !recover && firsts.length > 1 ? firsts : undefined;
	out.push({
		kind: "request",
		route: startRoute,
		body: recover ? `{ "name": "${lost}" }` : "{}",
		response: choice
			? `{ "state": ${STATE}, "prompt": { "kind": "choice", "components": [${choice.map((c) => `{ "name": "${c}", … }`).join(", ")}] } }`
			: `{ "state": ${STATE}, "prompt": ${promptJson(first.name, first.type, first.sendable)} }`,
		ms: ms(),
	});

	prompts.forEach((p, i) => {
		out.push({ kind: "prompt", step: p.step, type: p.type, sendable: p.sendable, choice: i === 0 ? choice : undefined });
		if (p.sendable) out.push({ kind: "request", route: "/send-prompt", body: `{ "name": "${p.name}", "state": ${STATE} }`, response: '{ "success": true }', ms: ms() });
		const v = p.type === "otp" && p.step.endsWith("code") ? { value: "735102" } : p.step.startsWith("new ") ? { value: "a-new-secret", secret: true } : VALUE[p.name] ?? { value: "…" };
		out.push({ kind: "answer", step: p.step, ...v });
		const next = prompts[i + 1];
		const last = !next;
		out.push({
			kind: "request",
			route: "/submit-prompt",
			body: `{ "name": "${p.name}", "value": ${v.secret ? '"••••••"' : `"${v.value}"`}, "state": ${STATE} }`,
			response: !last
				? `{ "state": ${STATE}, "prompt": ${promptJson(next.name, next.type, next.sendable)} }`
				: recover
					? '{ "success": true }'
					: '{ "tokens": { "access_token": "eyJ0eXAiOiJhdCtqd3Qi…", "token_type": "Bearer", "expires_in": 900, "refresh_token": "eyJ0eXAiOiJydCtqd3Qi…", "scope": "…" }, "session": { … }, "identity": { "id": "id_01J…" } }',
			ms: ms(),
		});
	});
	out.push({ kind: "done", outcome: flow.outcome, tokens: !recover });
	return out;
}
