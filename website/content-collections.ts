import { defineCollection, defineConfig } from "@content-collections/core";
import { compileMDX } from "@content-collections/mdx";
import rehypeShiki from "@shikijs/rehype";
import { codeToHtml } from "shiki";
import GithubSlugger from "github-slugger";
import rehypeAutolinkHeadings from "rehype-autolink-headings";
import rehypeSlug from "rehype-slug";
import remarkGfm from "remark-gfm";
import { z } from "zod";


/** Monochrome syntax themes from the site tokens: no accent hue, emphasis by contrast only. */
function monoTheme(type: "light" | "dark") {
	const [fg, muted, faint, str] = type === "light" ? ["#0a0a0a", "#5c5c63", "#6b6b73", "#3f3f46"] : ["#f4f4f5", "#a1a1aa", "#8a8a93", "#d4d4d8"];
	return {
		name: `auth-dance-${type}`,
		type,
		colors: { "editor.foreground": fg, "editor.background": "#00000000" },
		settings: [
			{ settings: { foreground: fg } },
			{ scope: ["comment", "punctuation.definition.comment"], settings: { foreground: faint, fontStyle: "italic" } },
			{ scope: ["string", "string.template", "constant.other.symbol"], settings: { foreground: str } },
			{ scope: ["keyword", "storage", "storage.type", "storage.modifier"], settings: { foreground: muted } },
			{ scope: ["punctuation", "meta.brace", "keyword.operator"], settings: { foreground: muted } },
			{ scope: ["entity.name.function", "support.function", "meta.function-call"], settings: { foreground: fg, fontStyle: "bold" } },
			{ scope: ["constant.numeric", "constant.language"], settings: { foreground: fg } },
		],
	};
}
const THEMES = { light: monoTheme("light"), dark: monoTheme("dark") };

/** The four Diátaxis sections, in sidebar order. The folder of a page under `docs/` names its section. */
export const SECTIONS = ["tutorial", "concepts", "guides", "reference"] as const;

/** Reads the `##` and `###` headings of a page, outside code fences, with the ids that rehype-slug gives them. */
function headings(markdown: string) {
	const slugger = new GithubSlugger();
	const out: { depth: 2 | 3; text: string; id: string }[] = [];
	let fence = false;
	for (const line of markdown.split("\n")) {
		if (/^\s*(```|~~~)/.test(line)) fence = !fence;
		if (fence) continue;
		const m = /^(#{2,3})\s+(.+?)\s*#*\s*$/.exec(line);
		if (!m) continue;
		const text = m[2].replace(/`([^`]+)`/g, "$1").replace(/\[([^\]]+)\]\([^)]*\)/g, "$1").replace(/[*_]/g, "");
		out.push({ depth: m[1].length as 2 | 3, text, id: slugger.slug(text) });
	}
	return out;
}

const docs = defineCollection({
	name: "docs",
	directory: "../docs",
	include: "**/*.mdx",
	schema: z.object({
		title: z.string(),
		description: z.string(),
		order: z.number().default(100),
		content: z.string(),
	}),
	transform: async (document, context) => {
		const mdx = await compileMDX(context, document, {
			remarkPlugins: [remarkGfm],
			rehypePlugins: [
				rehypeSlug,
				[rehypeAutolinkHeadings, { behavior: "wrap" }],
				[
					rehypeShiki,
					{
						themes: THEMES,
						defaultColor: false,
						addLanguageClass: true,
						transformers: [
							{
								// Carries `title="…"` from the fence meta to the `pre`, for the code frame header.
								pre(node: { properties: Record<string, unknown> }) {
									const raw = (this as unknown as { options: { meta?: { __raw?: string }; lang: string } }).options;
									const title = /title="([^"]+)"/.exec(raw.meta?.__raw ?? "")?.[1];
									if (title) node.properties["data-title"] = title;
									node.properties["data-lang"] = raw.lang;
								},
							},
						],
					},
				],
			],
		});
		const dir = document._meta.directory;
		const section = dir === "." || dir === "" ? "overview" : dir.split("/")[0];
		const slug = document._meta.path === "index" ? "" : document._meta.path;
		return {
			title: document.title,
			description: document.description,
			order: document.order,
			section,
			slug,
			url: slug ? `/docs/${slug}` : "/docs",
			headings: headings(document.content),
			mdx,
		};
	},
});

/** Code shown on the landing page, highlighted at build time so no highlighter ships to the browser. */
const snippets = defineCollection({
	name: "snippets",
	directory: "src/snippets",
	include: "*.md",
	schema: z.object({ title: z.string(), lang: z.string(), content: z.string() }),
	transform: async (document) => ({
		name: document._meta.path,
		title: document.title,
		code: document.content.trim(),
		html: await codeToHtml(document.content.trim(), {
			lang: document.lang,
			themes: THEMES,
			defaultColor: false,
		}),
	}),
});

export default defineConfig({ content: [docs, snippets] });
