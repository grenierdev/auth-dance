# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

The documentation site lives in `website/`: TanStack Start, Tailwind CSS, and content-collections reading Markdown from the root
`docs/` folder. It is prerendered to static assets and deployed with wrangler to `auth.dance`, the same way `demo/` deploys to
`demo.auth.dance`. The library itself is the root package (`src/`).

## Users

Two audiences, equally weighted:

- Evaluators: tech leads and senior developers comparing authentication libraries. They need the choreography idea and its
  consequences before they read any API.
- Integrators: TypeScript developers adding authentication to a server (Hono, Cloudflare Workers, Node.js) and a client (browser,
  React, CLI). They read the docs beside their editor, copy code, and come back to look up an option or a route.

## Product Purpose

Auth Dance is an authentication library for TypeScript. The developer declares one choreography, for example
`choice(sequence("email", "password"), "passkey")`, and the library derives sign-in, sign-up, enrollment, credential rotation,
account recovery, subscription and deletion from it. The same core also acts as an OAuth 2.0 authorization server (authorization
code with PKCE, refresh, client credentials, device grant, introspection, revocation, dynamic registration).

The site succeeds when an evaluator understands why one choreography replaces a set of hand-written flows, and an integrator gets a
working server and client from the getting-started tutorial, then finds any option in the API reference.

## Positioning

Other libraries hand you a set of flows to wire one by one. Auth Dance takes a single declaration of the steps and derives every
flow from it, recovery included: to recover one component, the owner signs in by a path without it. A custom factor implements one
small interface (`AuthDanceComponent`) and works in every flow.

## Operating Context

- Server: `createAuthDance(options)` returns `fetch`, `app` (Hono), `api` (state machine without HTTP) and an OpenAPI schema.
- Client: `auth-dance/client` runs a flow as a loop of prompts (`input`, `choice`, confirmation) until tokens come back.
- React: `auth-dance/react` provider, flow provider and prompt switch.
- Identity provider: `auth-dance/oauth2`, with login, consent and device pages the integrator hosts.
- Batteries: components `email`, `oauth2`, `oidc`, `otp`, `password`, `policy`, `totp`, `webauthn`; social providers `apple`,
  `facebook`, `github`, `gitlab`, `google`, `microsoft`, `x`; storage providers `memory` and `cloudflare` (D1, KV).
- A live demo runs at `demo.auth.dance`.

## Capabilities and Constraints

- Node.js 24.4 or newer; the core uses web APIs and runs on Workers.
- Tokens: RFC 9068 access tokens (`at+jwt`), refresh tokens (`rt+jwt`), asymmetric signing keys, JWKS at `/.well-known/jwks.json`.
- Every complete path of a choreography needs a step that proves control; `choice("email", "passkey")` fails at startup.
- Version 0.1.0 release candidate. Undecided: versioned docs, search provider, i18n of the docs.

## Brand Commitments

- Name: Auth Dance. Domain: auth.dance. License: MIT.
- Vocabulary from modern dance is the product's own language: choreography, dance, step, sequence, choice. The site may extend the
  metaphor, but API terms keep their exact names.
- Voice: plain, short, declarative sentences, close to Simplified Technical English, as in the README. No hype.
- The user asked for a somewhat serious brand with dynamic elements drawn from modern dance.
- Standing preference (2026-11-03, after two re-rolled direction rounds): the modern developer-SaaS register. Peers that set the
  craft bar: Better Auth, Vercel / Geist docs, Linear. The landing carries motion and play (the hero console, the Composer playground); docs stay still.
- Standing preference (2026-11-03): no UQAT branding and no orange. The accent is one modern SaaS indigo-violet. The landing should feel dynamic and personal, not like a manual or a spec sheet.
- Standing preference (2026-11-03): the site is pinned to linear.app's register: dark-first (light kept behind the toggle), large
  app windows that show the product working, Linear's section grammar. It reaches the docs chrome too.
- Avoid: playful or funky treatments, the security-vendor look (shields, padlocks, navy and green).

## Evidence on Hand

- `README.md`: the source text for the tutorial and reference content.
- `src/*.test.ts`: the behavioral reference for every module.
- `demo/`: a working TanStack Start demo of the dance, the OAuth 2.0 server and the device grant.
- No testimonials, users, benchmarks, adoption numbers or logos exist. Do not invent them.

## Product Principles

1. One declaration, every flow: each page should show how a feature follows from the choreography, not stand apart from it.
2. Code first: every concept arrives with a runnable snippet that uses the real API.
3. Say what it does, in plain words: no hype, no claims the tests do not back.
4. Security rules are stated, not buried: proof-of-control, rate-limit addresses, key rotation and token lifetimes are visible.

## Accessibility & Inclusion

WCAG 2.2 AA. Motion respects `prefers-reduced-motion`; code blocks stay readable in light and dark themes.
