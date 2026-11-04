/// <reference types="vite/client" />
import { createRootRoute, HeadContent, Link, Outlet, Scripts } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { SiteFooter } from "@/components/site-footer";
import { SiteHeader } from "@/components/site-header";
import { themeScript } from "@/components/theme-toggle";
import appCss from "@/styles/app.css?url";

export const Route = createRootRoute({
	head: () => ({
		meta: [
			{ charSet: "utf-8" },
			{ name: "viewport", content: "width=device-width, initial-scale=1" },
			{ title: "Auth Dance — one choreography, every authentication flow" },
			{
				name: "description",
				content: "Auth Dance is an authentication library for TypeScript. Declare the steps once; sign-in, sign-up, enrollment and recovery follow.",
			},
		],
		links: [
			{ rel: "stylesheet", href: appCss },
			{ rel: "icon", href: "/favicon.svg", type: "image/svg+xml" },
		],
	}),
	shellComponent: RootDocument,
	component: () => (
		<>
			<SiteHeader />
			<Outlet />
			<SiteFooter />
		</>
	),
	notFoundComponent: NotFound,
});

function RootDocument({ children }: { children: ReactNode }) {
	return (
		<html lang="en" className="dark" suppressHydrationWarning>
			<head>
				{/* biome-ignore lint/security/noDangerouslySetInnerHtml: a static theme script, before paint */}
				<script dangerouslySetInnerHTML={{ __html: themeScript }} />
				<HeadContent />
			</head>
			<body className="min-h-svh">
				{children}
				<Scripts />
			</body>
		</html>
	);
}

function NotFound() {
	return (
		<main className="frame grid min-h-[60svh] place-content-center gap-4 px-6 py-24 text-center">
			<p className="font-mono text-sm text-muted">404</p>
			<h1 className="display text-4xl">No step at this path.</h1>
			<p className="text-muted">The page moved or never existed.</p>
			<Link to="/docs" className="mx-auto mt-2 text-sm underline underline-offset-4">
				Go to the documentation
			</Link>
		</main>
	);
}
