import { useEffect, useState } from "react";

const RELOADED = "auth-dance-demo.reloaded";

/**
 * Installs the service worker of `src/backend/sw.ts`, and resolves once it controls this page: before that, a call to
 * `/auth` reaches the static host, not the backend.
 */
async function connect(): Promise<void> {
	if (!("serviceWorker" in navigator)) {
		throw new Error("This browser has no service workers, and the demo runs its backend in one.");
	}
	const registration = await navigator.serviceWorker.register("/sw.js", { scope: "/" });
	await navigator.serviceWorker.ready;
	if (navigator.serviceWorker.controller) {
		sessionStorage.removeItem(RELOADED);
		return;
	}
	// A hard reload loads the page without the worker, and the worker does not claim a page it already activated for.
	// A plain reload hands the page back to it. Try that once.
	if (registration.active && !sessionStorage.getItem(RELOADED)) {
		sessionStorage.setItem(RELOADED, "1");
		window.location.reload();
		return new Promise(() => {});
	}
	// On the first visit the worker claims the page as it activates.
	await new Promise<void>((resolve) => navigator.serviceWorker.addEventListener("controllerchange", () => resolve(), { once: true }));
}

let connecting: Promise<void> | undefined;

/** `ready` once the backend answers this page, or the error that keeps it from running. */
export function useBackend(): { ready: boolean; error?: string } {
	const [state, setState] = useState<{ ready: boolean; error?: string }>({ ready: false });
	useEffect(() => {
		connecting ??= connect();
		connecting.then(
			() => setState({ ready: true }),
			(error) => setState({ ready: false, error: String(error?.message ?? error) }),
		);
	}, []);
	return state;
}
