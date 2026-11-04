import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowRightIcon, ArrowUpRightIcon, PlusIcon } from "lucide-react";
import type { ReactNode } from "react";
import { allSnippets } from "content-collections";
import { Composer } from "@/components/composer";
import { DanceConsole } from "@/components/console";
import { CopyButton, InstallCommand } from "@/components/copy-button";
import { FigureDeclare, FigureDerive, FigureRecover } from "@/components/figures";
import { Window, WindowBar } from "@/components/window";

export const Route = createFileRoute("/")({ component: Home });

const snippet = (name: string) => {
	const s = allSnippets.find((x) => x.name === name);
	if (!s) throw new Error(`missing snippet ${name}`);
	return s;
};

/** Each flow is one call on the client; the server reads the same choreography for all of them. */
const FLOWS = [
	{ call: "signIn()", text: "The owner performs one complete path." },
	{ call: "signUp()", text: "The owner performs a path, and each step registers." },
	{ call: 'recover("password")', text: "A sign-in by a path without the lost component." },
	{ call: 'enroll("passkey")', text: "A signed-in owner adds a component." },
	{ call: 'rotate("password")', text: "A signed-in owner replaces a credential." },
	{ call: 'unenroll("passkey")', text: "Refused when no complete path stays without it." },
	{ call: 'subscribe("sms")', text: "The owner adds a channel for one-time codes." },
	{ call: "delete()", text: "The owner removes the identity, and confirms it." },
];

const RFCS = [
	["Authorization code with PKCE", "RFC 6749, RFC 7636"],
	["Device authorization grant", "RFC 8628"],
	["Access tokens as JWT", "RFC 9068"],
	["Introspection and revocation", "RFC 7662, RFC 7009"],
	["Dynamic client registration", "RFC 7591"],
	["Server metadata", "RFC 8414"],
] as const;

/** What ships, grouped the way an integrator picks it. */
const SHIPS = [
	{ title: "Steps", from: "auth-dance/components/*", items: ["email", "password", "passkey", "otp", "totp", "oidc", "oauth2", "policy"], own: true },
	{ title: "Social sign-in", from: "auth-dance/components/oauth2/*", items: ["apple", "facebook", "github", "gitlab", "google", "microsoft", "x"] },
	{ title: "Storage", from: "auth-dance/providers/*", items: ["memory", "cloudflare"] },
	{ title: "Packages", from: "auth-dance/*", items: ["client", "react", "oauth2"] },
];

const TUTORIAL = [
	["install", "Install and make the secrets", "Create a project, install Auth Dance, and generate the three secrets the server needs."],
	["the-server", "The server", "Declare the choreography, say what each step does, and serve the routes on Node.js."],
	["the-first-dance", "The first dance", "A command-line client that signs up and signs in, one prompt at a time."],
	["react", "A React page", "A React page that signs up, signs in and signs out against the tutorial server."],
] as const;

function Home() {
	return (
		<main className="overflow-x-clip">
			{/* First viewport: the claim, the action, and the product already working below it. */}
			<section className="frame px-4 pt-20 sm:px-6 lg:pt-28">
				<h1 className="display max-w-[16ch] text-[2.75rem] sm:text-6xl lg:text-[4.5rem]">
					Declare the dance once. <span className="text-muted">Every flow follows.</span>
				</h1>
				<div className="mt-8 flex flex-col gap-8 lg:flex-row lg:items-end lg:justify-between">
					<p className="max-w-[34rem] text-[17px] leading-relaxed text-muted lg:max-w-none">A TypeScript authentication library. Every flow comes from one choreography.</p>
					<div className="flex w-full max-w-[30rem] flex-col gap-2.5 sm:flex-row lg:w-[30rem] lg:shrink-0">
						<InstallCommand />
						<Link
							to="/docs/$"
							params={{ _splat: "tutorial" }}
							className="group inline-flex h-11 shrink-0 items-center justify-center gap-2 rounded-lg bg-fg px-4 text-sm font-medium text-invert transition-opacity hover:opacity-90"
						>
							Start the tutorial <ArrowRightIcon className="size-4 transition-transform duration-300 ease-(--ease-out-expo) group-hover:translate-x-0.5" strokeWidth={1.75} />
						</Link>
					</div>
				</div>
			</section>

			<section className="frame mt-14 px-4 sm:px-6 lg:mt-20">
				<DanceConsole />
				<p className="mt-3 text-xs text-faint">
					Simulated in your browser from the library's own <code className="font-mono">walk()</code>. Values are examples.
				</p>
			</section>

			{/* The statement, then the idea in three drawings. */}
			<section className="frame px-4 pt-32 pb-8 sm:px-6 lg:pt-44">
				<p className="display max-w-[30ch] text-[1.75rem] leading-[1.2] tracking-[-0.025em] sm:text-[2.4rem]">
					One declaration, every flow.{" "}
					<span className="text-muted">
						Auth Dance derives each flow from one tree of steps, recovery included.
					</span>
				</p>
				<div className="mt-20 grid gap-12 md:grid-cols-3 md:gap-8">
					<Figure title="Declare" text="One tree of steps: a sequence, a choice, the components each step names.">
						<FigureDeclare />
					</Figure>
					<Figure title="Derive" text="Sign-in, sign-up, enroll, rotate, recover and delete all read the same tree.">
						<FigureDerive />
					</Figure>
					<Figure title="Recover" text="To recover a step, the owner signs in by a path without it.">
						<FigureRecover />
					</Figure>
				</div>
			</section>

			<Feature
				id="compose"
				title={["Compose", "the choreography"]}
				text="Add a step, and every flow includes it, the flows you did not consider yet too. One rule holds at startup: every complete path needs a step that proves control."
				link={{ label: "The choreography", splat: "concepts/choreography" }}
				subs={[
					{ title: "Proof of control", text: "A path with only an address is refused before the server starts.", splat: "concepts/choreography" },
					{ title: "Derived recovery", text: "Each credential recovers through a sign-in without it.", splat: "concepts/recovery" },
					{ title: "Your own steps", text: "Implement AuthDanceComponent, and your factor works in every flow.", splat: "guides/custom-component" },
				]}
			>
				<div className="mx-auto max-w-3xl">
					<Composer />
				</div>
			</Feature>

			<Feature
				id="loop"
				title={["One loop", "on every client"]}
				text="The server is a state machine behind one fetch handler. The client reads a prompt, answers it, and repeats until the tokens come back. Nothing binds it to a browser."
				link={{ label: "The prompt loop", splat: "concepts/prompt-loop" }}
				subs={[
					{ title: "Browser and CLI", text: "auth-dance/client runs the same loop anywhere fetch runs.", splat: "reference/client" },
					{ title: "React", text: "A provider, flow hooks and a prompt switch.", splat: "guides/react" },
					{ title: "Workers", text: "Web APIs only; D1 and KV storage ship with it.", splat: "guides/cloudflare" },
				]}
			>
				<Window className="overflow-hidden">
					<div className="grid lg:grid-cols-2">
						<Code name="server" />
						<Code name="client" className="border-t border-line lg:border-t-0 lg:border-l" />
					</div>
					<ul className="grid grid-cols-1 gap-px border-t border-line bg-line sm:grid-cols-2 lg:grid-cols-4">
						{FLOWS.map((f) => (
							<li key={f.call} className="group bg-surface p-4 transition-colors duration-300 hover:bg-surface-2">
								<code className="font-mono text-[12.5px]">
									<span className="text-faint">client.</span>
									<span className="text-fg transition-colors duration-300 group-hover:text-accent-text">{f.call}</span>
								</code>
								<p className="mt-2 text-[13px] leading-relaxed text-muted">{f.text}</p>
							</li>
						))}
					</ul>
				</Window>
			</Feature>

			<Feature
				id="idp"
				title={["Also an", "identity provider"]}
				text="auth-dance/oauth2 makes the same server an OAuth 2.0 authorization server for third-party apps. The owner signs in with the same dance, on login and consent pages you host."
				link={{ label: "The OAuth 2.0 guide", splat: "guides/oauth2-server" }}
				subs={[
					{ title: "Device grant", text: "Sign in a TV or a CLI with a user code.", splat: "guides/device-grant" },
					{ title: "Key rotation", text: "Asymmetric signing keys, served at the JWKS route.", splat: "guides/key-rotation" },
					{ title: "Rate limits", text: "Limits per address, behind proxies too.", splat: "guides/rate-limits" },
				]}
			>
				<Window className="grid overflow-hidden lg:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
					<Code name="oauth2" />
					<div className="border-t border-line lg:border-t-0 lg:border-l">
						<WindowBar>
							<span className="text-fg">Grants and endpoints</span>
						</WindowBar>
						<ul className="text-[13px]">
							{RFCS.map(([what, rfc]) => (
								<li key={what} className="flex items-center justify-between gap-4 border-b border-line px-4 py-3 last:border-b-0">
									<span className="flex items-center gap-2.5">
										<span aria-hidden="true" className="size-1.5 rounded-full bg-line-strong" />
										{what}
									</span>
									<span className="font-mono text-[11.5px] whitespace-nowrap text-faint">{rfc}</span>
								</li>
							))}
						</ul>
					</div>
				</Window>
			</Feature>

			<Feature
				id="ships"
				title={["The steps ship.", "Yours fit in."]}
				text="Components for the common factors, social providers over OAuth 2.0 and OpenID Connect, and storage for tests and for Workers."
				link={{ label: "Components reference", splat: "reference/components" }}
			>
				<Window className="overflow-hidden">
					{SHIPS.map((g) => (
						<div key={g.title} className="grid gap-x-8 gap-y-3 border-b border-line px-5 py-5 last:border-b-0 md:grid-cols-[15rem_minmax(0,1fr)]">
							<div>
								<p className="text-[13px] font-medium">{g.title}</p>
								<p className="mt-1 font-mono text-[11.5px] whitespace-nowrap text-faint">{g.from}</p>
							</div>
							<div className="flex flex-wrap gap-1.5">
								{g.items.map((it) => (
									<span key={it} className="rounded-md border border-line bg-surface-2/60 px-2.5 py-1 font-mono text-[12.5px] text-fg">
										{it}
									</span>
								))}
								{g.own && (
									<Link
										to="/docs/$"
										params={{ _splat: "guides/custom-component" }}
										className="inline-flex items-center gap-1 rounded-md border border-dashed border-accent px-2.5 py-1 font-mono text-[12.5px] text-accent-text transition-colors hover:bg-accent hover:text-accent-fg"
									>
										<PlusIcon aria-hidden="true" className="size-3.5" strokeWidth={1.75} />
										yours
									</Link>
								)}
							</div>
						</div>
					))}
				</Window>
			</Feature>

			{/* The tutorial as a timeline, the way a changelog runs. */}
			<section className="frame px-4 pt-32 sm:px-6 lg:pt-40">
				<div className="flex items-end justify-between gap-6">
					<h2 className="display text-[2rem] sm:text-[2.6rem]">The tutorial</h2>
					<Link to="/docs/$" params={{ _splat: "tutorial" }} className="group hidden items-center gap-1.5 text-sm text-muted transition-colors hover:text-fg sm:inline-flex">
						Four pages <ArrowRightIcon className="size-3.5 transition-transform duration-300 ease-(--ease-out-expo) group-hover:translate-x-0.5" strokeWidth={1.75} />
					</Link>
				</div>
				<ol className="relative mt-12 grid gap-10 sm:grid-cols-2 lg:grid-cols-4 lg:gap-8">
					<span aria-hidden="true" className="absolute top-[5px] right-0 left-0 hidden h-px bg-line-strong lg:block" />
					{TUTORIAL.map(([slug, title, text], i) => (
						<li key={slug} className="relative">
							<span aria-hidden="true" className={`relative block size-[11px] rounded-full border-2 border-bg ${i === 0 ? "bg-accent" : "bg-line-strong"}`} />
							<Link to="/docs/$" params={{ _splat: `tutorial/${slug}` }} className="mt-5 block text-[15px] font-medium transition-colors hover:text-accent-text">
								{title}
							</Link>
							<p className="mt-2 text-[13.5px] leading-relaxed text-muted">{text}</p>
						</li>
					))}
				</ol>
			</section>

			{/* The close. */}
			<section className="frame px-4 pt-40 pb-36 text-center sm:px-6 lg:pt-52 lg:pb-44">
				<h2 className="display mx-auto text-[2.5rem] sm:text-6xl">
					Declare it once.
					<span className="block text-muted">Run every flow.</span>
				</h2>
				<div className="mt-10 flex flex-wrap justify-center gap-3">
					<Link
						to="/docs/$"
						params={{ _splat: "tutorial" }}
						className="inline-flex h-11 items-center gap-2 rounded-lg bg-fg px-5 text-sm font-medium text-invert transition-opacity hover:opacity-90"
					>
						Start the tutorial
					</Link>
					<a
						href="https://demo.auth.dance"
						className="inline-flex h-11 items-center gap-1.5 rounded-lg border border-line-strong bg-surface px-5 text-sm font-medium transition-colors hover:bg-surface-2"
					>
						Live demo <ArrowUpRightIcon className="size-4 text-muted" strokeWidth={1.5} />
					</a>
				</div>
			</section>
		</main>
	);
}

function Figure({ title, text, children }: { title: string; text: string; children: ReactNode }) {
	return (
		<figure>
			<div className="flex aspect-[14/9] items-center justify-center px-2">{children}</div>
			<figcaption className="mt-6">
				<p className="text-[15px] font-medium">{title}</p>
				<p className="mt-1.5 text-[14px] leading-relaxed text-muted">{text}</p>
			</figcaption>
		</figure>
	);
}

/** A Linear feature block: a two-line title on the left, its case on the right, the product view, then its parts. */
function Feature({
	id,
	title,
	text,
	link,
	subs,
	children,
}: {
	id: string;
	title: [string, string];
	text: string;
	link: { label: string; splat: string };
	subs?: { title: string; text: string; splat: string }[];
	children: ReactNode;
}) {
	return (
		<section id={id} className="frame px-4 pt-32 sm:px-6 lg:pt-44">
			<div className="grid gap-6 md:grid-cols-2 md:items-end md:gap-12">
				<h2 className="display text-[2.25rem] sm:text-[3.25rem]">
					{title[0]}
					<span className="block">{title[1]}</span>
				</h2>
				<div className="max-w-md md:pb-1.5">
					<p className="text-[15px] leading-relaxed text-muted">{text}</p>
					<Link
						to="/docs/$"
						params={{ _splat: link.splat }}
						className="group mt-4 inline-flex items-center gap-1.5 text-sm font-medium transition-colors hover:text-accent-text"
					>
						{link.label} <ArrowRightIcon className="size-3.5 transition-transform duration-300 ease-(--ease-out-expo) group-hover:translate-x-0.5" strokeWidth={1.75} />
					</Link>
				</div>
			</div>
			<div className="mt-14 lg:mt-16">{children}</div>
			{subs && (
				<ul className="mt-12 grid gap-8 border-t border-line pt-8 sm:grid-cols-3">
					{subs.map((s) => (
						<li key={s.title}>
							<Link to="/docs/$" params={{ _splat: s.splat }} className="group block">
								<p className="flex items-center gap-1.5 text-[14px] font-medium">
									{s.title}
									<ArrowRightIcon className="size-3.5 text-faint opacity-0 transition-[opacity,transform] duration-300 ease-(--ease-out-expo) group-hover:translate-x-0.5 group-hover:opacity-100" strokeWidth={1.75} />
								</p>
								<p className="mt-1.5 text-[13.5px] leading-relaxed text-muted">{s.text}</p>
							</Link>
						</li>
					))}
				</ul>
			)}
		</section>
	);
}

function Code({ name, className = "" }: { name: string; className?: string }) {
	const s = snippet(name);
	return (
		<figure className={`flex min-w-0 flex-col ${className}`}>
			<figcaption className="flex h-11 items-center justify-between border-b border-line pr-2 pl-4 font-mono text-xs text-muted">
				{s.title}
				<CopyButton text={s.code} label={`Copy ${s.title}`} />
			</figcaption>
			<div
				className="overflow-x-auto p-4 font-mono text-[12.5px] leading-[1.7] [&_pre]:bg-transparent! [tab-size:2]"
				// biome-ignore lint/security/noDangerouslySetInnerHtml: highlighted at build time from our own snippet files
				dangerouslySetInnerHTML={{ __html: s.html }}
			/>
		</figure>
	);
}
