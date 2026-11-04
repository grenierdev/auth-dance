import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowRightIcon, KeyRoundIcon, MonitorIcon, NotebookPenIcon, UserCogIcon } from "lucide-react";
import type { ReactNode } from "react";
import { useDemoInfo } from "@/lib/demo";

export const Route = createFileRoute("/")({ component: Home });

function Home() {
	const info = useDemoInfo();
	return (
		<main className="mx-auto flex max-w-6xl flex-col px-4 pt-16 pb-24 sm:px-6 lg:pt-24">
			<section>
				<h1 className="display max-w-[18ch] text-[2.5rem] sm:text-6xl">
					Everybody already does the dance. <span className="text-muted-foreground">Try it here.</span>
				</h1>
				<p className="mt-6 max-w-2xl text-[17px] leading-relaxed text-muted-foreground">
					This demo runs one choreography. Auth Dance derives every flow from it: sign-in, sign-up, enrollment, rotation, recovery, channel
					subscriptions and deletion. The same server is an OAuth 2.0 authorization server for a web app and for a TV.
				</p>
			</section>

			<section className="window mt-12 overflow-hidden">
				<div className="flex h-11 items-center gap-3 border-b px-4 text-[13px] text-muted-foreground">
					<span className="text-foreground">server.ts</span>
					<span className="ml-auto flex items-center gap-1.5 text-xs">
						<span aria-hidden="true" className="size-1.5 rounded-full bg-brand" />
						running in a service worker
					</span>
				</div>
				<pre className="overflow-x-auto px-5 py-4 font-mono text-[13px] leading-relaxed">
					<span className="text-muted-foreground">choreography: </span>
					{info?.choreography ?? "…"}
				</pre>
				<p className="border-t px-5 py-4 text-[13.5px] leading-relaxed text-muted-foreground">
					Two ways in: an address, its password and a code mailed to it; or a passkey on its own. Mail goes nowhere: open the demo inbox at
					the bottom right to read the codes. Everything lives in memory, so a restart of the server forgets every account.
				</p>
			</section>

			<section className="mt-6 grid gap-px overflow-hidden rounded-xl border bg-border sm:grid-cols-2">
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
		<Link to={to} className="group flex flex-col gap-3 bg-card p-6 transition-colors duration-300 hover:bg-raised">
			<span className="grid size-8 place-items-center rounded-lg border bg-raised text-muted-foreground transition-colors group-hover:text-foreground [&_svg]:size-4">
				{icon}
			</span>
			<p className="flex items-center gap-1.5 text-[15px] font-medium">
				{title}
				<ArrowRightIcon className="size-3.5 text-muted-foreground opacity-0 transition-[opacity,transform] duration-300 ease-(--ease-out-expo) group-hover:translate-x-0.5 group-hover:opacity-100" strokeWidth={1.75} />
			</p>
			<p className="text-[13.5px] leading-relaxed text-muted-foreground">{children}</p>
		</Link>
	);
}
