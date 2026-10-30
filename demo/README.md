# Auth Dance demo

A working tour of Auth Dance, with no server: a TanStack Start single-page app with shadcn/ui, and the Auth Dance
backend running in a service worker of the same page, on Hono, with IndexedDB storage.

```sh
cd demo
npm install
npm run dev        # builds the library in the parent folder and the worker, then watches both
```

Open http://localhost:5173. Use `localhost`, not `127.0.0.1`: the passkeys, the issuer and the redirect URIs all name
that origin.

## What it shows

| Page                  | What happens                                                                                                  |
| --------------------- | ------------------------------------------------------------------------------------------------------------- |
| `/login`              | Sign-in and sign-up on `choice(sequence("email", "password", "otp"), "passkey")`, on the login-05 block        |
| `/recover`            | Recovery of the password or the passkey, through the branch that does without it                              |
| `/account`            | Sessions, sign-out everywhere, enroll, rotate and remove each method, subscribe channels, grants, delete       |
| `/playground`         | Dance Notes, an OAuth 2.0 client: authorization code with PKCE, login page, consent screen, refresh, revoke    |
| `/tv`                 | Dance TV, the device authorization grant (RFC 8628): a user code, the device page, consent, polling            |
| `/idp/*`              | The `ui.login`, `ui.consent` and `ui.device` pages of the authorization server                                 |

Mail goes nowhere: every code lands in the demo inbox, at the bottom right of each page. Every record lives in IndexedDB,
in this browser: the worker draws its secrets, its signing key and the two clients on its first start, and finds them
again each time the browser restarts it. Clear the site data to start over. The device grant runs between two tabs of
one browser, since the backend lives in it.

`npm run build` writes a static site to `dist/client`, and `npm run preview` serves it. A static host must answer every
page path with the SPA shell.

## Layout

- `src/backend/app.ts` builds the core with `createAuthDance` under `/auth`, the authorization server with
  `createAuthDanceOauth2` under `/oauth2`, the two demo clients, and the `/api` routes the pages need: the inbox and the
  server side of the login, consent and device pages. `src/backend/storage.ts` holds the IndexedDB providers.
- `src/backend/sw.ts` is the service worker. It answers `/auth`, `/oauth2`, `/.well-known` and `/api`, navigations
  included, so the OAuth 2.0 redirects run as against a real host. `vite.sw.config.ts` bundles it into `public/sw.js`.
- `src/lib/backend.ts` registers the worker, and the root route waits until it controls the page.
- `src/components/dance-form.tsx` runs any flow with `useAuthDanceFlow`: it renders the field of each prompt type
  (`email`, `password`, `otp` with the input-otp component, `webauthn`, `webauthn-create`, `confirmation`) inside the
  login-05 frame of `src/components/login-form.tsx`, with the "Or" separator between the branches of a choice.
