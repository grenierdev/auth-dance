/// <reference types="vite/client" />
import { createRootRoute, HeadContent, Link, Outlet, Scripts } from "@tanstack/react-router";
import { AuthDanceProvider, useAuthDanceTokens } from "auth-dance/react";
import { ArrowUpRightIcon, Loader2Icon } from "lucide-react";
import type { ReactNode } from "react";
import { Wordmark } from "@/components/logo";
import { Mailbox } from "@/components/mailbox";
import { ThemeToggle, themeScript } from "@/components/theme-toggle";
import { Toaster } from "@/components/ui/sonner";
import { client, emailOf } from "@/lib/auth";
import { useBackend } from "@/lib/backend";
import appCss from "@/styles/app.css?url";

export const Route = createRootRoute({
	head: () => ({
		meta: [{ charSet: "utf-8" }, { name: "viewport", content: "width=device-width, initial-scale=1" }, { title: "Auth Dance Demo" }],
		links: [
			{ rel: "stylesheet", href: appCss },
			{ rel: "icon", href: "/favicon.svg", type: "image/svg+xml" },
		],
	}),
	shellComponent: RootDocument,
	component: RootComponent,
});

function RootDocument({ children }: { children: ReactNode }) {
	return (
		<html lang="en" className="dark" suppressHydrationWarning>
			<head>
				{/* biome-ignore lint/security/noDangerouslySetInnerHtml: a static theme script, before paint */}
				<script dangerouslySetInnerHTML={{ __html: themeScript }} />
				<HeadContent />
			</head>
			<body className="min-h-svh bg-background antialiased">
				{children}
				<Scripts />
			</body>
		</html>
	);
}

function RootComponent() {
	const backend = useBackend();
	if (!backend.ready) {
		return (
			<div className="flex min-h-svh flex-col items-center justify-center gap-3 p-4 text-center text-sm text-muted-foreground">
				{backend.error ? (
					<p className="max-w-sm text-destructive">{backend.error}</p>
				) : (
					<>
						<Loader2Icon className="size-5 animate-spin" />
						Starting the backend in a service worker…
					</>
				)}
			</div>
		);
	}
	return (
		<AuthDanceProvider client={client}>
			<Header />
			<Outlet />
			<Mailbox />
			<Toaster richColors position="top-center" />
		</AuthDanceProvider>
	);
}

const NAV = [
	{ to: "/", label: "Home" },
	{ to: "/account", label: "Account" },
	{ to: "/playground", label: "Dance Notes" },
	{ to: "/tv", label: "Dance TV" },
] as const;

function Header() {
	const tokens = useAuthDanceTokens();
	return (
		<header className="sticky top-0 z-30 border-b bg-background/80 backdrop-blur-xl backdrop-saturate-150">
			<div className="mx-auto flex min-h-16 max-w-6xl flex-wrap items-center gap-x-4 px-4 sm:px-6 md:flex-nowrap">
				<Link to="/" className="flex h-16 shrink-0 items-center gap-2" aria-label="Auth Dance demo home">
					<Wordmark />
					<span className="rounded-md border px-1.5 py-0.5 text-[11px] font-medium text-muted-foreground">Demo</span>
				</Link>
				<nav className="order-last -mx-1 flex w-full items-center gap-1 overflow-x-auto pb-2 text-[13.5px] md:order-none md:mx-0 md:w-auto md:flex-1 md:pb-0">
					{NAV.map((item) => (
						<Link
							key={item.to}
							to={item.to}
							className="shrink-0 rounded-md px-3 py-1.5 text-muted-foreground transition-colors hover:text-foreground"
							activeProps={{ className: "bg-muted text-foreground" }}
							activeOptions={{ exact: item.to === "/" }}
						>
							{item.label}
						</Link>
					))}
				</nav>
				<a
					href="https://auth.dance"
					className="ml-auto hidden shrink-0 items-center gap-1 rounded-md px-2 text-[13.5px] text-muted-foreground transition-colors hover:text-foreground md:inline-flex"
				>
					Docs <ArrowUpRightIcon className="size-3.5" strokeWidth={1.5} />
				</a>
				<span className="ml-auto md:hidden" />
				<ThemeToggle />
				{tokens ? (
					<Link to="/account" className="max-w-[14rem] truncate text-[13px] text-muted-foreground transition-colors hover:text-foreground">
						{emailOf(tokens.tokens.access_token) ?? "Signed in with a passkey"}
					</Link>
				) : (
					<Link
						to="/login"
						className="inline-flex h-8 shrink-0 items-center rounded-full bg-primary px-3.5 text-[13px] font-medium text-primary-foreground transition-opacity hover:opacity-85"
					>
						Sign in
					</Link>
				)}
			</div>
		</header>
	);
}
