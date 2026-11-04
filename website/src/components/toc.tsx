import { useEffect, useState } from "react";

type Heading = { depth: 2 | 3; text: string; id: string };

export function Toc({ headings }: { headings: Heading[] }) {
	const [active, setActive] = useState<string | undefined>(headings[0]?.id);
	useEffect(() => {
		const els = headings.map((h) => document.getElementById(h.id)).filter((e): e is HTMLElement => !!e);
		const io = new IntersectionObserver(
			(entries) => {
				const top = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
				if (top) setActive(top.target.id);
			},
			{ rootMargin: "-72px 0px -70% 0px" },
		);
		for (const el of els) io.observe(el);
		return () => io.disconnect();
	}, [headings]);

	if (headings.length < 2) return null;
	return (
		<nav aria-label="On this page" className="text-[13px]">
			<p className="mb-3 text-[12px] font-medium text-faint">On this page</p>
			<ul className="space-y-0.5">
				{headings.map((h) => (
					<li key={h.id}>
						<a
							href={`#${h.id}`}
							aria-current={active === h.id ? "location" : undefined}
							className={`block py-1 leading-snug text-muted transition-colors hover:text-fg aria-[current]:text-fg ${h.depth === 3 ? "pl-3" : ""}`}
						>
							{h.text}
						</a>
					</li>
				))}
			</ul>
		</nav>
	);
}
