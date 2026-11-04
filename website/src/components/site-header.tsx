import { Link } from "@tanstack/react-router";
import { Wordmark } from "./logo";
import { ThemeToggle } from "./theme-toggle";

const nav = [
	{ splat: undefined, label: "Docs" },
	{ splat: "tutorial", label: "Tutorial" },
	{ splat: "concepts", label: "Concepts" },
	{ splat: "reference", label: "Reference" },
] as const;

export function SiteHeader() {
	return (
		<header className="sticky top-0 z-30 border-b border-line bg-bg/80 backdrop-blur-xl backdrop-saturate-150">
			<div className="frame flex h-16 items-center gap-6 px-4 sm:px-6">
				<Link to="/" className="shrink-0" aria-label="Auth Dance home">
					<Wordmark />
				</Link>
				<nav aria-label="Main" className="ml-auto hidden items-center gap-1 text-[13.5px] text-muted md:flex">
					{nav.map((n) => (
						<Link
							key={n.label}
							{...(n.splat ? { to: "/docs/$", params: { _splat: n.splat } } : { to: "/docs" })}
							activeOptions={{ exact: !n.splat }}
							className="rounded-md px-3 py-1.5 transition-colors hover:text-fg data-[status=active]:text-fg"
						>
							{n.label}
						</Link>
					))}
					<a href="https://demo.auth.dance" className="rounded-md px-3 py-1.5 transition-colors hover:text-fg">
						Demo
					</a>
				</nav>
				<div className="ml-auto flex items-center gap-1 md:ml-0">
					<span aria-hidden="true" className="mx-2 hidden h-4 w-px bg-line-strong md:block" />
					<a
						href="https://github.com/grenierdev/auth-dance"
						className="grid size-8 place-items-center rounded-md text-muted transition-colors hover:bg-surface-2 hover:text-fg"
						aria-label="Auth Dance on GitHub"
					>
						<GithubIcon />
					</a>
					<ThemeToggle />
					<Link
						to="/docs/$"
						params={{ _splat: "tutorial" }}
						className="ml-2 inline-flex h-8 items-center rounded-full bg-fg px-3.5 text-[13px] font-medium text-invert transition-opacity hover:opacity-85"
					>
						Get started
					</Link>
				</div>
			</div>
		</header>
	);
}

function GithubIcon() {
	return (
		<svg viewBox="0 0 16 16" className="size-4" fill="currentColor" aria-hidden="true">
			<path d="M8 0C3.58 0 0 3.58 0 8a8 8 0 0 0 5.47 7.59c.4.07.55-.17.55-.38v-1.33c-2.23.48-2.7-1.07-2.7-1.07-.36-.92-.89-1.17-.89-1.17-.73-.5.05-.49.05-.49.8.06 1.23.83 1.23.83.72 1.22 1.88.87 2.33.66.07-.52.28-.87.5-1.07-1.78-.2-3.65-.89-3.65-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.6 7.6 0 0 1 4 0c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48v2.2c0 .21.15.46.55.38A8 8 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
		</svg>
	);
}
