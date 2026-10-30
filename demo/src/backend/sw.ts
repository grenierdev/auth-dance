/**
 * The service worker that stands in for a server. It answers every request under `/auth`, `/oauth2`, `/.well-known`
 * and `/api`, navigations included, so the OAuth 2.0 redirects run as they would against a real host. Every other
 * request goes to the network.
 *
 * Vite bundles this file on its own into `public/sw.js`; see `vite.sw.config.ts`.
 */

import { createDemoBackend } from "./app.ts";

// The DOM library of the project types the window, not a worker. These are the few worker types this file needs.
interface ExtendableEvent extends Event {
	waitUntil(promise: Promise<unknown>): void;
}
interface FetchEvent extends ExtendableEvent {
	request: Request;
	respondWith(response: Promise<Response>): void;
}
interface ServiceWorkerScope {
	location: Location;
	skipWaiting(): Promise<void>;
	clients: { claim(): Promise<void> };
	addEventListener(type: "install" | "activate", listener: (event: ExtendableEvent) => void): void;
	addEventListener(type: "fetch", listener: (event: FetchEvent) => void): void;
}

const worker = self as unknown as ServiceWorkerScope;
const ROUTES = ["/auth/", "/oauth2/", "/.well-known/", "/api/"];

// The browser stops an idle worker and starts it again on the next request: the backend comes back from IndexedDB.
let backend: ReturnType<typeof createDemoBackend> | undefined;
function getBackend(): ReturnType<typeof createDemoBackend> {
	backend ??= createDemoBackend(worker.location.origin).catch((error) => {
		backend = undefined;
		throw error;
	});
	return backend;
}

// A new version takes over at once, and the pages already open move to it without a reload.
worker.addEventListener("install", (event) => event.waitUntil(worker.skipWaiting()));
worker.addEventListener("activate", (event) => event.waitUntil(worker.clients.claim()));

worker.addEventListener("fetch", (event) => {
	const url = new URL(event.request.url);
	if (url.origin !== worker.location.origin || !ROUTES.some((route) => url.pathname.startsWith(route))) {
		return;
	}
	event.respondWith(
		getBackend()
			.then((app) => app.fetch(event.request))
			.catch((error) => Response.json({ error: "server_error", error_description: String(error) }, { status: 500 })),
	);
});
