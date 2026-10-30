/// <reference types="vite/client" />
import { createRootRoute, HeadContent, Link, Outlet, Scripts } from "@tanstack/react-router";
import { AuthDanceProvider, useAuthDanceTokens } from "auth-dance/react";
import { FingerprintIcon, Loader2Icon } from "lucide-react";
import type { ReactNode } from "react";
import { Mailbox } from "@/components/mailbox";
import { Toaster } from "@/components/ui/sonner";
import { client, emailOf } from "@/lib/auth";
import { useBackend } from "@/lib/backend";
import appCss from "@/styles/app.css?url";

export const Route = createRootRoute({
	head: () => ({
		meta: [{ charSet: "utf-8" }, { name: "viewport", content: "width=device-width, initial-scale=1" }, { title: "Auth Dance Demo" }],
		links: [{ rel: "stylesheet", href: appCss }],
	}),
	shellComponent: RootDocument,
	component: RootComponent,
});

function RootDocument({ children }: { children: ReactNode }) {
	return (
		<html lang="en">
			<head>
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
		<header className="border-b">
			<div className="mx-auto flex h-14 max-w-5xl items-center gap-4 px-4">
				<Link to="/" className="flex items-center gap-2 font-semibold">
					<FingerprintIcon className="size-5" /> Auth Dance
				</Link>
				<nav className="flex flex-1 items-center gap-1 overflow-x-auto text-sm">
					{NAV.map((item) => (
						<Link
							key={item.to}
							to={item.to}
							className="rounded-md px-2.5 py-1.5 text-muted-foreground hover:text-foreground"
							activeProps={{ className: "bg-muted text-foreground" }}
							activeOptions={{ exact: item.to === "/" }}
						>
							{item.label}
						</Link>
					))}
				</nav>
				{tokens ? (
					<Link to="/account" className="truncate text-sm text-muted-foreground">
						{emailOf(tokens.tokens.access_token) ?? "Signed in with a passkey"}
					</Link>
				) : (
					<Link to="/login" className="text-sm font-medium">
						Sign in
					</Link>
				)}
			</div>
		</header>
	);
}
