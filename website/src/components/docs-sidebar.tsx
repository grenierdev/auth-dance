import { Link } from "@tanstack/react-router";
import { overview, pagesOf, SECTIONS } from "@/lib/docs";

export function DocsNav({ onNavigate }: { onNavigate?: () => void }) {
	const link =
		"block rounded-md px-2.5 py-1.5 text-[13.5px] text-muted transition-colors hover:bg-surface-2/60 hover:text-fg data-[status=active]:bg-surface-2 data-[status=active]:text-fg";
	return (
		<nav aria-label="Documentation" className="text-sm">
			{overview && (
				<Link to="/docs" activeOptions={{ exact: true }} onClick={onNavigate} className="mb-6 block rounded-md px-2.5 py-1.5 text-[13.5px] font-medium text-muted transition-colors hover:text-fg data-[status=active]:bg-surface-2 data-[status=active]:text-fg">
					Introduction
				</Link>
			)}
			{SECTIONS.map((s) => {
				const pages = pagesOf(s.id);
				if (pages.length === 0) return null;
				return (
					<div key={s.id} className="mb-7">
						<Link
							to="/docs/$"
							params={{ _splat: s.id }}
							activeOptions={{ exact: true }}
							onClick={onNavigate}
							className="mb-1 block px-2.5 text-[12px] font-medium text-faint transition-colors hover:text-fg"
						>
							{s.title}
						</Link>
						<ul className="flex flex-col gap-px">
							{pages.map((p) => (
								<li key={p.url}>
									<Link to="/docs/$" params={{ _splat: p.slug }} activeOptions={{ exact: true }} onClick={onNavigate} className={link}>
										{p.title}
									</Link>
								</li>
							))}
						</ul>
					</div>
				);
			})}
		</nav>
	);
}
