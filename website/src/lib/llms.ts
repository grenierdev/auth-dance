import { overview, pagesOf, readingOrder, SECTIONS } from "@/lib/docs";

/** The llms.txt files follow the proposal at https://llmstxt.org. */
const SITE = "https://auth.dance";
const NAME = "Auth Dance";
const SUMMARY = "Auth Dance is an authentication library for TypeScript. You declare the steps one time, and it derives every flow from them.";

export const textResponse = (body: string) => new Response(body, { headers: { "content-type": "text/plain; charset=utf-8" } });

/** The index: the project, then one link list per section of the docs. */
export function llmsIndex() {
	const item = (d: { title: string; url: string; description: string }) => `- [${d.title}](${SITE}${d.url}): ${d.description}`;
	const lists = [
		...(overview ? [`## Overview\n\n${item(overview)}`] : []),
		...SECTIONS.map((s) => `## ${s.title}\n\n${pagesOf(s.id).map(item).join("\n")}`),
	];
	const head = `# ${NAME}\n\n> ${SUMMARY}\n\nThe full text of every page below is in one file: [llms-full.txt](${SITE}/llms-full.txt).`;
	return `${[head, ...lists].join("\n\n")}\n`;
}

/** Every documentation page as one Markdown file, in reading order. */
export function llmsFull() {
	const pages = readingOrder.map((doc) => {
		// Site-relative links become absolute, as the file is read outside the site.
		const body = doc.markdown.replace(/\]\(\/(?!\/)/g, `](${SITE}/`);
		return `# ${doc.title}\n\nSource: ${SITE}${doc.url}\n\n> ${doc.description}\n\n${body}\n`;
	});
	const head = `# ${NAME}\n\n> ${SUMMARY}\n\nThis file holds the full documentation of ${NAME}, one page after the other, in reading order.\n`;
	return [head, ...pages].join("\n---\n\n");
}
