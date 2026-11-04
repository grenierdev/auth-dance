import { createFileRoute, Link } from "@tanstack/react-router";
import { DocPage } from "@/components/doc-page";
import { overview, pagesOf, SECTIONS } from "@/lib/docs";

export const Route = createFileRoute("/docs/")({
	head: () => ({ meta: [{ title: "Documentation — Auth Dance" }, { name: "description", content: overview?.description ?? "" }] }),
	component: DocsIndex,
});

function DocsIndex() {
	if (overview) return <DocPage doc={overview} />;
	return <SectionGrid />;
}

export function SectionGrid() {
	return (
		<div className="grid gap-3 sm:grid-cols-2">
			{SECTIONS.map((s) => (
				<Link key={s.id} to="/docs/$" params={{ _splat: s.id }} className="rounded-xl border border-line bg-surface p-6 transition-colors hover:border-line-strong hover:bg-surface-2/60">
					<p className="font-medium">{s.title}</p>
					<p className="mt-1.5 text-sm leading-relaxed text-muted">{s.blurb}</p>
					<p className="mt-4 font-mono text-xs text-faint">{pagesOf(s.id).length} pages</p>
				</Link>
			))}
		</div>
	);
}
