/**
 * @module
 *
 * The document the demo lives in.
 *
 * Two components hang off this route and they run in different places. `shellComponent` writes the `<html>` the
 * client hydrates and always renders on the server, so it stays as plain as it can be. `component` is the ordinary
 * React tree, which is where the tooltip provider belongs: it is context and nothing else, but a page whose route
 * has opted out of server rendering should keep its providers on the same side of the fence as the things that use
 * them.
 */

import type { ReactNode } from "react";
import { createRootRoute, HeadContent, Outlet, Scripts } from "@tanstack/react-router";
import { TanStackRouterDevtoolsPanel } from "@tanstack/react-router-devtools";
import { TanStackDevtools } from "@tanstack/react-devtools";

import { TooltipProvider } from "@/components/ui/tooltip.tsx";

// @ts-types="../../types/css-url.d.ts"
import appCss from "../styles.css?url";

// The favicon the reference page carried, percent-encoded so it survives any transport that would rather not carry
// four raw bytes of UTF-8. There is no reason to be more serious about a favicon than the reference was.
const FAVICON =
	"data:image/svg+xml,%3Csvg%20xmlns='http://www%2Ew3%2Eorg/2000/svg'%20viewBox='0%200%2022%2016'%3E%3Ctext%20y='14'%3E%F0%9F%9A%80%3C/text%3E%3C/svg%3E";

/** The root of the tree: the document, the head, and the providers every panel below leans on. */
export const Route = createRootRoute({
	head: () => ({
		meta: [
			{
				charSet: "utf-8",
			},
			{
				name: "viewport",
				content: "width=device-width, initial-scale=1",
			},
			{
				title: "auth-dance — in-browser demo",
			},
		],
		links: [
			{
				rel: "stylesheet",
				href: appCss,
			},
			{
				rel: "icon",
				href: FAVICON,
			},
		],
	}),
	notFoundComponent: () => (
		<main className="container mx-auto p-4 pt-16">
			<h1>404</h1>
			<p>The requested page could not be found.</p>
		</main>
	),
	component: RootComponent,
	shellComponent: RootDocument,
});

function RootComponent() {
	return (
		<TooltipProvider>
			<div className="flex min-h-svh flex-col bg-sidebar">
				<Outlet />
				<footer className="shrink-0 px-4 py-3 text-center text-xs text-muted-foreground">
					No server, no network: the page builds an Auth Dance with the memory providers and calls{" "}
					<code className="font-mono">auth.fetch()</code> directly.
				</footer>
			</div>
		</TooltipProvider>
	);
}

function RootDocument({ children }: { children: ReactNode }) {
	return (
		<html lang="en">
			<head>
				<HeadContent />
			</head>
			<body>
				{children}
				<TanStackDevtools
					config={{
						position: "bottom-right",
					}}
					plugins={[
						{
							name: "Tanstack Router",
							render: <TanStackRouterDevtoolsPanel />,
						},
					]}
				/>
				<Scripts />
			</body>
		</html>
	);
}
