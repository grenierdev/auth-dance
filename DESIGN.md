---
name: Auth Dance
description: Declare the dance once. Every flow follows.
colors:
  ground: "#08090a"
  panel: "#0f1011"
  panel-raised: "#1a1b1e"
  ink: "#f7f8f8"
  muted: "#8a8f98"
  faint: "#82878f"
  line: "rgb(255 255 255 / 0.08)"
  line-strong: "rgb(255 255 255 / 0.15)"
  highlight: "rgb(255 255 255 / 0.06)"
  accent: "oklch(0.565 0.21 283)"
  accent-fg: "#ffffff"
  accent-text: "oklch(0.76 0.14 285)"
  accent-wash: "oklch(0.565 0.21 283 / 0.2)"
  ground-light: "#fbfbfc"
  panel-light: "#ffffff"
  panel-raised-light: "#f1f2f4"
  ink-light: "#0d0e10"
  muted-light: "#5b606b"
  faint-light: "#6a6f7a"
  line-light: "rgb(13 14 16 / 0.09)"
  line-strong-light: "rgb(13 14 16 / 0.16)"
  highlight-light: "rgb(255 255 255 / 0.7)"
  accent-light: "oklch(0.55 0.22 281)"
  accent-text-light: "oklch(0.5 0.22 281)"
  accent-wash-light: "oklch(0.55 0.22 281 / 0.1)"
typography:
  display:
    fontFamily: "Geist Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "4.5rem"
    fontWeight: 560
    lineHeight: 1.02
    letterSpacing: "-0.035em"
    fontFeature: "\"ss01\", \"cv11\""
  headline:
    fontFamily: "Geist Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "3.25rem"
    fontWeight: 560
    lineHeight: 1.02
    letterSpacing: "-0.035em"
  statement:
    fontFamily: "Geist Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "2.4rem"
    fontWeight: 560
    lineHeight: 1.2
    letterSpacing: "-0.025em"
  page-title:
    fontFamily: "Geist Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "2.6rem"
    fontWeight: 560
    lineHeight: 1.1
    letterSpacing: "-0.035em"
  prose-heading:
    fontFamily: "Geist Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "1.5rem"
    fontWeight: 600
    lineHeight: 1.25
    letterSpacing: "-0.02em"
  lede:
    fontFamily: "Geist Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "17px"
    fontWeight: 400
    lineHeight: 1.625
  body:
    fontFamily: "Geist Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.75
  body-compact:
    fontFamily: "Geist Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.625
  label:
    fontFamily: "Geist Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "13px"
    fontWeight: 500
    lineHeight: 1.4
  code:
    fontFamily: "Geist Mono Variable, ui-monospace, SFMono-Regular, Menlo, monospace"
    fontSize: "12.5px"
    fontWeight: 400
    lineHeight: 1.7
  code-chip:
    fontFamily: "Geist Mono Variable, ui-monospace, SFMono-Regular, Menlo, monospace"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: 1
rounded:
  tag: "4px"
  chip: "5px"
  control-sm: "6px"
  control: "8px"
  sheet: "10px"
  window: "12px"
  pill: "9999px"
spacing:
  gutter: "16px"
  gutter-wide: "24px"
  bar: "44px"
  row: "16px"
  block: "56px"
  section: "128px"
  section-wide: "176px"
  frame: "76rem"
components:
  button-primary:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.ground}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    height: "44px"
    padding: "0 16px"
  button-secondary:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    height: "44px"
    padding: "0 20px"
  button-secondary-hover:
    backgroundColor: "{colors.panel-raised}"
  button-pill:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.ground}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    height: "32px"
    padding: "0 14px"
  install-command:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink}"
    typography: "{typography.code}"
    rounded: "{rounded.control}"
    height: "44px"
    padding: "0 12px 0 16px"
  window:
    backgroundColor: "{colors.panel}"
    rounded: "{rounded.window}"
  window-bar:
    textColor: "{colors.muted}"
    typography: "{typography.label}"
    height: "44px"
    padding: "0 16px"
  sheet:
    backgroundColor: "{colors.panel-raised}"
    rounded: "{rounded.sheet}"
  step-chip:
    backgroundColor: "{colors.panel-raised}"
    textColor: "{colors.ink}"
    typography: "{typography.code-chip}"
    rounded: "{rounded.chip}"
    padding: "4px 8px"
  step-chip-active:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.accent-fg}"
  step-toggle:
    textColor: "{colors.faint}"
    typography: "{typography.code-chip}"
    rounded: "{rounded.control-sm}"
    height: "32px"
    padding: "0 10px"
  step-toggle-pressed:
    backgroundColor: "{colors.accent-wash}"
    textColor: "{colors.ink}"
  nav-item:
    textColor: "{colors.muted}"
    rounded: "{rounded.control-sm}"
    padding: "6px 10px"
  nav-item-active:
    backgroundColor: "{colors.panel-raised}"
    textColor: "{colors.ink}"
---

# Design System: Auth Dance

## Overview

**Creative North Star: "The Lit Window on a Dark Floor"**

The site is a near-black floor with the product lit on it. Each idea arrives as a large application window in which the library runs: the console plays a sign-in prompt by prompt, the Composer re-derives every flow when a step is toggled, the code panes show the real server and client. Copy sits around the windows in short blocks; the windows carry the argument. The register is a modern developer tool at Linear's craft level: Geist at medium weight with tight tracking, grey-on-grey secondary text, hairline borders, one indigo-violet accent that marks state and nothing else.

Dark is the default and the design target; light is the same system inverted behind the toggle, with the same roles and the same accent hue. Density is low on the landing (sections 128 to 176px apart, one window per section) and moderate in the docs, where the article column holds 72ch beside a sidebar and an on-page index. The landing moves on a beat; the docs stay still.

The world rejects the security-vendor look (shields, padlocks, navy and green), orange, institutional branding, feature-card grids, and the square-cornered, dashed-rail, monochrome spec sheet this system replaced.

**Key Characteristics:**
- Near-black ground, panels one and two steps up, 1px white-alpha hairlines, a 1px top highlight on raised panels.
- The product shown working inside 12px-radius windows, never described in cards.
- Display type in Geist 560 at -0.035em, the claim in ink and its consequence in grey, set as one block.
- One indigo-violet accent for state: the step being performed, the step just added, the refusal, the copied command.
- The ink-filled primary button (white on dark, black on light), never an accent fill.
- Motion on a 760ms beat on the landing; no animation in the docs.

## Colors

A neutral near-black-to-white ramp with a faint cool cast, and one saturated indigo-violet used sparingly.

### Primary
- **Cue Violet** (`accent`, light `accent-light`): the fill of the step being performed, the checked mark in the Composer, the done badge in the console, the copied state of the install command, text selection. Always carries white text (`accent-fg`).
- **Cue Violet Text** (`accent-text`, light `accent-text-light`): the accent at text contrast. Used for outcomes (`→ tokens`), returned token types, the `$` prompt, the refusal's error name, and hover on links that lead into a feature.
- **Cue Wash** (`accent-wash`, light `accent-wash-light`): the translucent tint behind a pressed step toggle, a traced chip, the choice the client answered, and the ring of the chip-in entrance.

### Neutral
- **Stage Black** (`ground`, light `ground-light`): the page floor and the ink of text on the primary button.
- **Panel** (`panel`, light `panel-light`): the window surface, the install command, secondary buttons, docs cards and code frames.
- **Raised Panel** (`panel-raised`, light `panel-raised-light`): one step up. Sheets laid over a window, active sidebar and nav items, done step chips, inline code, hover on rows.
- **Ink** (`ink`, light `ink-light`): headings, the claim half of a display line, primary button fill, active chrome.
- **Wing Grey** (`muted`, light `muted-light`): the consequence half of a display line, body copy on the landing, idle nav links, window bar labels.
- **Far Grey** (`faint`, light `faint-light`): metadata. Counts, latencies, status codes, package paths, sidebar group labels, captions. In dark it sits just under Wing Grey because it is held at AA contrast on the ground; the difference is size and role, not a wide value gap.
- **Hairline** (`line`, light `line-light`): every structural border: window edges, row dividers, the header rule, the docs columns.
- **Hairline Strong** (`line-strong`, light `line-strong-light`): borders that must read at rest: the install command, secondary buttons, sheets, step chips, the timeline rail, table header rules.
- **Top Light** (`highlight`, light `highlight-light`): the 1px inset light along the top edge of windows and sheets.

### Named Rules
**The State-Only Accent Rule.** The accent marks what is happening or what just changed: the performed step, the added step, the copied command, the refused choreography, the returned token. It is never a primary button, never a section color, never a background field.

**The Inverted Twin Rule.** Light is not a second palette. Every role keeps its name and job; only the values swap, and the accent keeps its hue.

## Typography

**Display Font:** Geist Variable (with ui-sans-serif, system-ui)
**Body Font:** Geist Variable
**Label/Mono Font:** Geist Mono Variable (with ui-monospace, SFMono-Regular, Menlo)

**Character:** One grotesque family at a medium weight (560) with tight tracking for headings and regular weight for reading; its mono twin for the material the library works on. Stylistic sets ss01 and cv11 are on for the whole body.

### Hierarchy
- **Display** (560, 2.75rem mobile, 3.75rem small, 4.5rem desktop, 1.02, -0.035em): the hero line and the closing line only. Measure held to about 16ch.
- **Headline** (560, 2.25rem to 3.25rem, 1.02, -0.035em): feature block titles, always two lines with the second forced to its own line.
- **Statement** (560, 1.75rem to 2.4rem, 1.2, -0.025em): the one statement paragraph after the hero, about 30ch.
- **Page Title** (560, 2.1rem to 2.6rem, 1.1): the docs page heading, with an 18px muted description under it.
- **Prose Heading** (600, 1.5rem, 1.25, -0.02em; h3 at 1.125rem, 1.4, -0.01em): docs section heads. h2 carries a hairline above it.
- **Lede** (400, 17px, 1.625): the hero subcopy, in Wing Grey.
- **Body** (400, 1rem, 1.75, max 72ch): the docs article, set at 86% ink over the ground.
- **Body Compact** (400, 13.5 to 15px, 1.625): feature case text, sub-links, figure captions, tutorial steps. Muted.
- **Label** (500, 13 to 15px): titles inside windows, sub-link titles, footer column heads, buttons, nav.
- **Code** (Mono 400, 12.5px, 1.7; docs blocks at 13px): code panes, request bodies, the choreography line.
- **Code Chip** (Mono 400, 11.5 to 12.5px): step names, routes, package paths, RFC numbers, method badges at 10px.

### Named Rules
**The Ink and Echo Rule.** A heading states the claim in ink and its consequence in Wing Grey, in one block at one size. The grey half is never a separate subtitle.

**The Mono Is Material Rule.** Mono is for what the library reads and writes: code, step names, routes, request and response bodies, package paths, RFC numbers. Chrome labels (window titles, nav, buttons, captions, group labels) are Geist sans.

## Layout

One page column (`frame`, 76rem) centered, with 16px gutters on mobile and 24px from the small breakpoint. Landing sections open with 128px of top space, 176px from the large breakpoint; the close has more (160 to 208px above, 144 to 176px below). Inside a section the order is fixed: heading row, 56 to 64px, the window, 48px, then the sub-links row behind a hairline.

The feature block is a two-column heading row from the medium breakpoint: the two-line headline left, its case (15px muted text and one arrow link) right, aligned to the bottom. Below it the product window runs the full column width, or 48rem for the Composer. Three sub-links follow in a row of three columns from the small breakpoint, each a title and one sentence, with an arrow that appears on hover.

The hero is left-aligned: the display line, then one row with the lede left and the install command plus the primary button right (stacked below the large breakpoint). The console starts inside the first viewport, 56 to 80px below.

The tutorial is a horizontal timeline at the large breakpoint: a hairline rail at the top, an 11px dot per step (the first in accent), titles and one-sentence text under each, four columns; two columns, then one, below. The footer is a four-column grid, the mark and tagline taking the wider first column, link columns at 13px.

The docs shell is three columns at extra-large widths: a 15.5rem sticky sidebar, the article (72ch, 40 to 56px side padding), a 13rem sticky on-page index, separated by hairlines. Below the large breakpoint the sidebar folds into a sticky 44px Menu bar under the header.

Breakpoints are Tailwind's defaults (640, 768, 1024, 1280px). The console's columns appear in steps: the prompt loop alone, then the flow sidebar at medium, then the request log at large.

## Elevation & Depth

Depth is tonal first: ground, panel, raised panel, each step lighter in dark and the reverse in light. Shadows are reserved for the two raised objects: windows and the sheet laid over a window. Both carry a 1px inset top highlight so the edge reads as lit from above. Rows, chips, buttons and docs cards are flat; they change surface on hover rather than lifting.

### Shadow Vocabulary
- **Window, dark** (`box-shadow: inset 0 1px 0 rgb(255 255 255 / 0.06), 0 0 0 1px rgb(0 0 0 / 0.6), 0 40px 100px -30px rgb(0 0 0 / 0.9)`): every product window. The outer 1px black ring separates the panel from a ground of nearly the same value.
- **Window, light** (`box-shadow: inset 0 1px 0 rgb(255 255 255 / 0.7), 0 1px 2px rgb(13 14 16 / 0.05), 0 24px 60px -24px rgb(13 14 16 / 0.22)`).
- **Sheet, dark** (`box-shadow: inset 0 1px 0 rgb(255 255 255 / 0.06), 0 2px 6px rgb(0 0 0 / 0.25), 0 24px 48px -12px rgb(0 0 0 / 0.55)`): the response sheet that overlaps the console's lower edge.
- **Sheet, light** (`box-shadow: inset 0 1px 0 rgb(255 255 255 / 0.7), 0 2px 6px rgb(13 14 16 / 0.06), 0 20px 40px -12px rgb(13 14 16 / 0.2)`).
- **Beat ring** (`box-shadow: 0 0 0 6px accent-wash, 0 0 0 1px accent`, animated outward): state only, never at rest.

### Named Rules
**The One Step Up Rule.** A sheet over a window is one surface step up from it (raised panel on panel) with a stronger hairline and its own shadow. Nothing stacks a third level.

**The Window Fades Into the Floor Rule.** The hero console fades to the ground over its last 56px at large widths, so the product appears to continue below the fold.

## Shapes

Gently rounded throughout, with a fixed radius per object size: 4px for method badges and inline code in the console, 5px for step chips and docs inline code, 6px for small controls (nav items, step toggles, ship tags, icon buttons), 8px for 44px controls (buttons, the install command, the typed-answer field), 10px for sheets, code frames and callouts, 12px for windows and docs cards. Two things are round: the "Get started" pill and the console's status and step-icon discs. Borders are 1px hairlines; the docs h2 and the feature sub-link row are separated by a hairline, not by boxes.

### Named Rules
**The Dashed Means Absent Rule.** A dashed border means a step that is not on the floor: an unpressed step toggle, a not-yet-reached chip, the "+ yours" slot, the lost step in the recovery figure. Dashes are never structure, rails or dividers.

## Components

### Buttons
Quiet, high-contrast, no accent.
- **Shape:** 8px radius at 44px height; the header action is a 32px full pill.
- **Primary:** ink fill with ground-colored 14px medium text, 16 to 20px side padding, an arrow icon where it leads somewhere. Hover drops opacity to 90%; the arrow moves 2px right on the expo curve.
- **Secondary:** panel fill, strong hairline, ink text; hover steps to raised panel. An external link carries a muted up-right arrow.
- **Get started pill:** ink fill, 13px medium text, 14px side padding, the last item in the header.
- **Icon buttons:** 28 to 32px squares at 6px radius, muted icon at 1.5 stroke, raised-panel hover.
- **Focus:** a 2px ink outline at 2px offset on every focusable element.

### Install Command
The site's first action. A 44px panel button at 8px radius with a strong hairline, the command in 13px mono after an accent-text `$`, a copy icon and label at the right in Far Grey. Hover brightens the border to Wing Grey; a copy turns the border to accent and the label to "Copied" in accent text for 2.2s.

### Chips
- **Step chip:** 5px radius, 12px mono, 4px by 8px, joined by 12 to 16px hairline connectors into a path. States: idle (hairline, muted), not reached (dashed strong hairline, faint), done (raised panel, strong hairline, ink), traced (accent border on wash), performing (accent fill, white text, lifted 2px). The path ends with the outcome in accent text, which slides in when the path completes.
- **Step toggle:** 32px, 6px radius, 12px mono with a 12px check square. Unpressed is dashed and faint; pressed is accent border on wash with an accent check; the fixed first step is raised panel with a muted check. Press scales to 96%.
- **Ship tag:** 6px radius, hairline on raised panel at 60%, 12.5px mono ink.
- **Method badge:** 4px radius, raised panel, 10px mono muted (`POST`).

### Cards / Containers
- **Corner Style:** 12px for windows and docs cards, 10px for sheets and code frames.
- **Background:** panel; sidebars and the choreography strip inside a window sit on ground at 40% to recess.
- **Shadow Strategy:** windows and sheets only (see Elevation & Depth); docs cards are flat.
- **Border:** 1px hairline; sheets use the strong hairline.
- **Internal Padding:** 16px rows, 20px at small widths and up; 44px title bars.

### Window
The container for every product view. A 44px title bar (13px muted label, ink for the current item, a faint slash between levels, mono for a file name) over a hairline, then panes divided by hairlines. Lists inside a window are hairline-divided rows; grids of cells use a 1px gap on a hairline field so the gaps draw the lines.

### Inputs / Fields
There are no free-text inputs. The console's typed answer is a 44px-tall row at 8px radius, hairline on ground at 50%, 12.5px mono ink, a faint return icon at the right.

### Navigation
- **Header:** sticky, 64px, ground at 80% with backdrop blur and saturation, a hairline under it. Wordmark left; nav links at 13.5px muted, ink on hover and when active; a 16px hairline divider, GitHub and theme icon buttons, then the pill.
- **Docs sidebar:** group titles at 12px medium Far Grey, page links at 13.5px muted in 6px-radius items; hover gives a 60% raised panel, active gives the full raised panel and ink.
- **On this page:** 13px muted links, ink for the current section, h3 entries indented 12px.
- **Footer:** a hairline above, four columns, 13px medium column heads, 13px muted links that turn ink on hover, the license in 12px Far Grey.

### Hero Console
The signature window. Three panes at large widths: a 13.5rem sidebar (tenant row, choreography presets, flows with path counts), the prompt loop (flow and path in the bar with a blinking live dot, the choreography line, the path of step chips, then the exchange rows), and a 21rem request log (method badge, route, status, latency, the body truncated in Far Grey). A response sheet overlaps the lower right edge. It plays one event per 760ms beat and holds four beats on a finished path. It pauses on hover, on focus, when offscreen and when the tab is hidden, and shows the finished state under reduced motion.

### Composer
A window titled "Composer / server.ts": a row of step toggles, the choreography line on a recessed strip, then every derived flow as a label and its paths. Toggling re-derives the flows; the new step's chip unmasks left to right (chip-in, 520ms), the new token in the line flashes accent (token-in, 900ms) and the line settles from a 2px blur (code-in, 320ms). A path that proves nothing replaces the flows with the error name in accent text and the sentence the constructor raises, entering with one short shake (380ms). A 40px footer counts the flows and offers Reset.

### Line Figures
Three 280 by 180 SVG drawings in the statement row: 22px nodes at 5px radius on raised panel with strong hairlines, labels in 10px mono muted, connectors in strong hairline, the moving part in accent. Captions are a 15px medium title and 14px muted text.

### Tutorial Timeline
A hairline rail with an 11px dot per page, ringed in the ground color; titles at 15px medium turn accent text on hover.

## Do's and Don'ts

### Do:
- **Do** show each capability running inside a window, with the real API names and routes.
- **Do** set headings in Geist 560 at -0.035em, the claim in ink and its consequence in Wing Grey in the same block.
- **Do** reserve the accent for state: the performed step, the added step, the copied command, the refusal, the returned token.
- **Do** keep the primary action ink-filled (white in dark, black in light) with ground-colored text.
- **Do** use mono only for code, step names, routes, bodies, package paths and RFC numbers.
- **Do** run landing motion on the expo curve (`cubic-bezier(0.16, 1, 0.3, 1)`) and the 760ms beat, pause it on hover, focus, offscreen and hidden tab, and show the settled state under reduced motion.
- **Do** keep the docs still: color transitions on hover only, no entrances, no loops.
- **Do** design in dark first and check that light holds every role.

### Don't:
- **Don't** fill a primary button, a section or a background with the accent.
- **Don't** lay features out as a grid of cards; use the feature block and a window.
- **Don't** use shields, padlocks, navy, green, orange or institutional branding.
- **Don't** return to square corners, dashed rails or a monochrome spec-sheet layout; dashes mark an absent step only.
- **Don't** put a small label or kicker above a section heading.
- **Don't** set chrome labels, buttons or nav in mono.
- **Don't** add a third level of elevation above a sheet, or shadows on rows, chips or docs cards.
