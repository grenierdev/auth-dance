import { useEffect, useState } from "react";

/** What `/api/demo` tells the pages: the choreography, the ids of the demo clients and the scopes. */
export interface DemoInfo {
	choreography: string;
	clients: { notes: string; tv: string };
	scopes: Record<string, { description: string }>;
}

let info: Promise<DemoInfo> | undefined;

/** Reads `/api/demo` once per page load. The ids of the clients change on every restart of the server. */
export function loadDemoInfo(): Promise<DemoInfo> {
	info ??= fetch("/api/demo").then((response) => response.json());
	return info;
}

export function useDemoInfo(): DemoInfo | undefined {
	const [value, setValue] = useState<DemoInfo>();
	useEffect(() => {
		loadDemoInfo().then(setValue, () => {});
	}, []);
	return value;
}

/** Calls a JSON route of the demo server. A status other than 2xx raises the `error_description` it answered with. */
export async function api<T>(path: string, init?: RequestInit & { token?: string; json?: unknown }): Promise<T> {
	const headers = new Headers(init?.headers);
	if (init?.token) {
		headers.set("authorization", `Bearer ${init.token}`);
	}
	if (init?.json !== undefined) {
		headers.set("content-type", "application/json");
	}
	const response = await fetch(path, {
		...init,
		headers,
		body: init?.json !== undefined ? JSON.stringify(init.json) : init?.body,
	});
	const body = await response.json().catch(() => ({}));
	if (!response.ok) {
		throw new Error(body.error_description ?? body.error ?? `HTTP ${response.status}`);
	}
	return body as T;
}

/** Posts a form to an OAuth 2.0 endpoint, the way a client of the authorization server does. */
export async function oauth2Form(path: string, params: Record<string, string>): Promise<{ status: number; body: any }> {
	const response = await fetch(path, {
		method: "POST",
		headers: { "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams(params),
	});
	return { status: response.status, body: await response.json().catch(() => ({})) };
}
