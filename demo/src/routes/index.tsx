import { createFileRoute, Link } from "@tanstack/react-router";
import { KeyRoundIcon, MonitorIcon, NotebookPenIcon, UserCogIcon } from "lucide-react";
import type { ReactNode } from "react";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useDemoInfo } from "@/lib/demo";

export const Route = createFileRoute("/")({ component: Home });

function Home() {
	const info = useDemoInfo();
	return (
		<main className="mx-auto flex max-w-5xl flex-col gap-8 px-4 py-10">
			<section className="flex flex-col gap-3">
				<h1 className="text-3xl font-bold tracking-tight">Everybody already does the dance.</h1>
				<p className="max-w-2xl text-muted-foreground">
					This demo runs one choreography. Auth Dance derives every flow from it: sign-in, sign-up, enrollment, rotation, recovery, channel
					subscriptions and deletion. The same server is an OAuth 2.0 authorization server for a web app and for a TV.
				</p>
				<pre className="w-fit max-w-full overflow-x-auto rounded-lg bg-muted px-4 py-3 font-mono text-sm">
					choreography: {info?.choreography ?? "…"}
				</pre>
				<p className="max-w-2xl text-sm text-muted-foreground">
					Two ways in: an address, its password and a code mailed to it; or a passkey on its own. Mail goes nowhere: open the demo inbox at
					the bottom right to read the codes. Everything lives in memory, so a restart of the server forgets every account.
				</p>
			</section>
			<section className="grid gap-4 sm:grid-cols-2">
				<Tile to="/login" icon={<KeyRoundIcon />} title="Sign in or sign up">
					Pick a branch of the choreography: email, password and code, or a passkey. Recover a lost password or passkey.
				</Tile>
				<Tile to="/account" icon={<UserCogIcon />} title="Account settings">
					List the sessions, enroll, rotate and remove sign-in methods, subscribe channels, revoke connected apps, delete the account.
				</Tile>
				<Tile to="/playground" icon={<NotebookPenIcon />} title="Dance Notes, an OAuth 2.0 client">
					A third-party web app signs in through the authorization code grant with PKCE, a login page and a consent screen.
				</Tile>
				<Tile to="/tv" icon={<MonitorIcon />} title="Dance TV, the device grant">
					A device with no keyboard shows a user code. Type it on this page, sign in, approve, and the TV polls its tokens.
				</Tile>
			</section>
		</main>
	);
}

function Tile({ to, icon, title, children }: { to: string; icon: ReactNode; title: string; children: ReactNode }) {
	return (
		<Link to={to} className="group">
			<Card className="h-full transition-colors group-hover:bg-muted/50">
				<CardHeader>
					<CardTitle className="flex items-center gap-2 [&_svg]:size-4">
						{icon} {title}
					</CardTitle>
					<CardDescription>{children}</CardDescription>
				</CardHeader>
			</Card>
		</Link>
	);
}
