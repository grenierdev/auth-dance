import { createFileRoute, Link, notFound } from "@tanstack/react-router";
import { ArrowRightIcon } from "lucide-react";
import { DocPage } from "@/components/doc-page";
import { findDoc, pagesOf, sectionOf } from "@/lib/docs";

export const Route = createFileRoute("/docs/$")({
	loader: ({ params }) => {
		const slug = (params._splat ?? "").replace(/\/$/, "");
		const doc = findDoc(slug);
		if (doc) return { kind: "doc" as const, slug };
		if (sectionOf(slug)) return { kind: "section" as const, slug };
		throw notFound();
	},
	head: ({ loaderData }) => {
		if (!loaderData) return {};
		const doc = loaderData.kind === "doc" ? findDoc(loaderData.slug) : undefined;
		const section = sectionOf(loaderData.slug);
		const title = doc?.title ?? section?.title ?? "Docs";
		return {
			meta: [{ title: `${title} — Auth Dance` }, { name: "description", content: doc?.description ?? section?.blurb ?? "" }],
		};
	},
	component: DocRoute,
});

function DocRoute() {
	const data = Route.useLoaderData();
	if (data.kind === "doc") {
		const doc = findDoc(data.slug);
		return doc ? <DocPage doc={doc} /> : null;
	}
	const section = sectionOf(data.slug);
	if (!section) return null;
	const pages = pagesOf(section.id);
	return (
		<article className="min-w-0 px-4 pt-10 pb-20 sm:px-10 lg:px-14 lg:pt-14">
			<header className="mb-10 max-w-[72ch] border-b border-line pb-8">
				<h1 className="text-[2.1rem] leading-[1.1] font-semibold tracking-[-0.035em] sm:text-[2.5rem]">{section.title}</h1>
				<p className="mt-3 text-lg leading-relaxed text-muted">{section.blurb}</p>
			</header>
			<ol className="max-w-[72ch] border-t border-line">
				{pages.map((p, i) => (
					<li key={p.url}>
						<Link to={p.url} className="group grid grid-cols-[2rem_1fr_auto] items-baseline gap-x-4 border-b border-line py-5 transition-colors hover:bg-surface sm:px-3">
							<span className="font-mono text-xs text-faint">{section.id === "tutorial" ? i + 1 : ""}</span>
							<span>
								<span className="block font-medium">{p.title}</span>
								<span className="mt-1 block text-sm leading-relaxed text-muted">{p.description}</span>
							</span>
							<ArrowRightIcon className="size-4 text-faint transition-transform group-hover:translate-x-0.5 group-hover:text-fg" strokeWidth={1.5} />
						</Link>
					</li>
				))}
			</ol>
		</article>
	);
}
