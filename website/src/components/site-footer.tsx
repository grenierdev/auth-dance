import { Link } from "@tanstack/react-router";
import { Mark } from "./logo";

const COLUMNS = [
	{
		title: "Learn",
		links: [
			{ label: "Tutorial", splat: "tutorial" },
			{ label: "Concepts", splat: "concepts" },
			{ label: "Guides", splat: "guides" },
			{ label: "Reference", splat: "reference" },
		],
	},
	{
		title: "Guides",
		links: [
			{ label: "OAuth 2.0 server", splat: "guides/oauth2-server" },
			{ label: "Device grant", splat: "guides/device-grant" },
			{ label: "Custom component", splat: "guides/custom-component" },
			{ label: "Cloudflare Workers", splat: "guides/cloudflare" },
		],
	},
	{
		title: "Project",
		links: [
			{ label: "GitHub", href: "https://github.com/grenierdev/auth-dance" },
			{ label: "npm", href: "https://www.npmjs.com/package/auth-dance" },
			{ label: "Live demo", href: "https://demo.auth.dance" },
			{ label: "llms.txt", href: "/llms.txt" },
		],
	},
] as const;

export function SiteFooter() {
	return (
		<footer className="border-t border-line">
			<div className="frame grid gap-12 px-4 pt-14 pb-10 sm:px-6 md:grid-cols-[minmax(0,1.4fr)_repeat(3,minmax(0,1fr))]">
				<div className="flex flex-col gap-4">
					<Mark className="size-5" />
					<p className="max-w-[16rem] text-[13px] leading-relaxed text-muted">Declare the dance once. Every flow follows.</p>
				</div>
				{COLUMNS.map((c) => (
					<div key={c.title}>
						<p className="mb-4 text-[13px] font-medium">{c.title}</p>
						<ul className="flex flex-col gap-2.5 text-[13px] text-muted">
							{c.links.map((l) => (
								<li key={l.label}>
									{"splat" in l ? (
										<Link to="/docs/$" params={{ _splat: l.splat }} className="transition-colors hover:text-fg">
											{l.label}
										</Link>
									) : (
										<a href={l.href} className="transition-colors hover:text-fg">
											{l.label}
										</a>
									)}
								</li>
							))}
						</ul>
					</div>
				))}
				<p className="text-xs text-faint md:col-span-4">MIT License</p>
			</div>
		</footer>
	);
}
