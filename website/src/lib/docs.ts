import { allDocs } from "content-collections";

export type Doc = (typeof allDocs)[number];

export const SECTIONS = [
	{ id: "tutorial", title: "Tutorial", blurb: "Step by step, from an empty folder to a working sign-in." },
	{ id: "concepts", title: "Concepts", blurb: "How the choreography works, and why every flow follows from it." },
	{ id: "guides", title: "Guides", blurb: "Recipes for one task each: React, OAuth 2.0, Workers, your own step." },
	{ id: "reference", title: "Reference", blurb: "Every export, option, route and error, by import path." },
] as const;

export type SectionId = (typeof SECTIONS)[number]["id"];

const byOrder = (a: Doc, b: Doc) => a.order - b.order || a.title.localeCompare(b.title);

export const overview = allDocs.find((d) => d.slug === "");

export function pagesOf(section: string): Doc[] {
	return allDocs.filter((d) => d.section === section).sort(byOrder);
}

/** Reading order of the whole site: the introduction, then each section in sidebar order. */
export const readingOrder: Doc[] = [...(overview ? [overview] : []), ...SECTIONS.flatMap((s) => pagesOf(s.id))];

export function findDoc(slug: string): Doc | undefined {
	return allDocs.find((d) => d.slug === slug);
}

export function sectionOf(id: string) {
	return SECTIONS.find((s) => s.id === id);
}

export function neighbours(doc: Doc) {
	const i = readingOrder.findIndex((d) => d.url === doc.url);
	return { prev: i > 0 ? readingOrder[i - 1] : undefined, next: i >= 0 ? readingOrder[i + 1] : undefined };
}
