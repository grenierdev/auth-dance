import { Link } from "@tanstack/react-router";
import { ArrowLeftIcon, ArrowRightIcon } from "lucide-react";
import { type Doc, neighbours } from "@/lib/docs";
import { Mdx } from "./mdx";
import { Toc } from "./toc";

const REPO = "https://github.com/grenierdev/auth-dance/blob/main/docs/";

export function DocPage({ doc }: { doc: Doc }) {
	const { prev, next } = neighbours(doc);
	return (
		<div className="grid min-w-0 xl:grid-cols-[minmax(0,1fr)_13rem]">
			<article className="min-w-0 px-4 pt-10 pb-20 sm:px-10 lg:px-14 lg:pt-14">
				<header className="mb-10 max-w-[72ch] border-b border-line pb-8">
					<h1 className="display text-[2.1rem] leading-[1.1] sm:text-[2.6rem]">{doc.title}</h1>
					<p className="mt-3 text-lg leading-relaxed text-muted">{doc.description}</p>
				</header>
				<div className="prose">
					<Mdx code={doc.mdx} />
				</div>
				<footer className="mt-16 max-w-[72ch]">
					<a href={`${REPO}${doc.slug || "index"}.mdx`} className="text-xs text-faint underline-offset-4 hover:text-fg hover:underline">
						Edit this page on GitHub
					</a>
					<div className="mt-6 grid gap-3 sm:grid-cols-2">
						{prev ? <Neighbour doc={prev} dir="prev" /> : <span />}
						{next && <Neighbour doc={next} dir="next" />}
					</div>
				</footer>
			</article>
			<aside className="hidden border-l border-line xl:block">
				<div className="sticky top-16 px-6 py-14">
					<Toc headings={doc.headings} />
				</div>
			</aside>
		</div>
	);
}

function Neighbour({ doc, dir }: { doc: Doc; dir: "prev" | "next" }) {
	return (
		<Link
			to={doc.url}
			className={`group flex flex-col gap-1 rounded-xl border border-line bg-surface p-4 transition-colors hover:border-line-strong hover:bg-surface-2/60 ${dir === "next" ? "text-right sm:col-start-2" : ""}`}
		>
			<span className={`flex items-center gap-1.5 text-xs text-faint ${dir === "next" ? "justify-end" : ""}`}>
				{dir === "prev" && <ArrowLeftIcon className="size-3.5" strokeWidth={1.5} />}
				{dir === "prev" ? "Previous" : "Next"}
				{dir === "next" && <ArrowRightIcon className="size-3.5" strokeWidth={1.5} />}
			</span>
			<span className="text-sm font-medium">{doc.title}</span>
		</Link>
	);
}
