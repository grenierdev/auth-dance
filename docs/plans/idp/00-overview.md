# Auth Dance as an OAuth 2.0 authorization server

This is the index of the plans that make Auth Dance an OAuth 2.0 authorization server, and the decisions they all build on.

| Plan                                       | Delivers                                                                            | Depends on |
| ------------------------------------------ | ----------------------------------------------------------------------------------- | ---------- |
| [01 Signing keys](01-signing-keys.md)      | Asymmetric token signing in the core, a JWKS, a required URL issuer. Breaking.      | —          |
| [02 Foundation](02-foundation.md)          | The `auth-dance/idp` module, the client storage, the error model, RFC 8414 metadata | 01         |
| [03 RFC 6749](03-rfc6749.md)               | `/authorize` with Hydra-style challenges, `/token`, PKCE, refresh, client credentials | 02       |
| [04 RFC 7662](04-rfc7662-introspection.md) | `/introspect`                                                                       | 03         |
| [05 RFC 7009](05-rfc7009-revocation.md)    | `/revoke`                                                                           | 03         |
| [06 RFC 7591](06-rfc7591-registration.md)  | `/register`                                                                         | 02, 03     |

04, 05 and 06 do not depend on each other once 03 lands. OpenID Connect (ID tokens, `/userinfo`, `openid-configuration`,
RP-initiated logout) gets a plan of its own after these. Plans 02 and 03 leave room for it, and they say where.

## The shape

```
Third-party app ──/authorize──▶ AuthDanceProviderApp ──redirect──▶ Login app (integrator hosts it)
                                        │                                │ runs the dance with AuthDanceClient
                                        │                                │ against the existing AuthDanceApp
                                        │◀──acceptLoginRequest(challenge, access_token)
                                        │
Third-party app ◀──code──────── AuthDanceProviderApp
Third-party app ──/token, /introspect, /revoke, /register──▶ AuthDanceProviderApp (JSON, no UI)
```

- `AuthDanceProviderApi` holds the protocol logic, with no HTTP. It wraps one `AuthDanceApi` and does not duplicate it:
  it verifies the access token of a dance with `api.verifyAccessToken`, and it reaches the KV store through
  `api.storage`.
- `AuthDanceProviderApp` is a Hono app, like `AuthDanceApp`. It binds `idp: AuthDanceProviderApi` the way the core app
  binds `api`.
- `AuthDanceClientStorage` holds the registered clients behind a `AuthDanceClientProvider` adapter, with memory and
  Cloudflare D1 implementations.
- `createAuthDanceProvider(options)` builds all three and returns `{ idp, app, fetch, generateOpenAPISchema }`, the
  way `createAuthDance` does.

## Decisions

1. **The Hydra model handles every step that shows UI.** `/authorize` never renders a page, with one exception: an
   invalid `client_id` or `redirect_uri`, where RFC 6749 §4.1.2.1 forbids a redirect. It hands off to `ui.login` and
   `ui.consent`, two URLs the integrator hosts, each with a challenge id. The integrator answers through
   `accept*Request` and `reject*Request`. These are in-process methods, and they are also admin routes when
   `admin.authorize` is given.
2. **Only the authorization code grant with PKCE, plus `refresh_token` and `client_credentials`.** The implicit grant
   and the password grant answer `unsupported_response_type` and `unsupported_grant_type`. RFC 6749 lets a server
   leave a grant out, and RFC 9700 (OAuth 2.0 Security BCP) deprecates both. PKCE (RFC 7636) is required for every
   client, and only with `S256`.
3. **Access tokens are JWTs (RFC 9068, `typ: at+jwt`) signed with asymmetric keys.** A resource server checks them
   on its own through the JWKS, and calls `/introspect` when it needs to know about a revocation. Refresh tokens and
   authorization codes are opaque random values that only the server reads. The store holds them as SHA-256 hashes.
4. **A grant is the unit of revocation.** Every code, access token and refresh token belongs to one grant
   (`gnt_` ksuid). Revoking any token of a grant revokes the whole grant, which RFC 7009 §2.1 allows. Access
   tokens carry the grant id as `gid`, so introspection sees the revocation before `exp`.
5. **By default a grant lives no longer than the Auth Dance session that created it.** The grant keeps `sessionId`.
   The refresh exchange and introspection check that the session still exists. A sign-out, a delete or a
   credential reset in the core therefore ends every downstream grant, with no new hook. Offline access waits for
   the OIDC plan (`offline_access`).
6. **The IdP errors are RFC errors.** The provider app answers `{ error, error_description? }` with the RFC status
   codes. It does not answer the `{ error: CODE }` 500 of the core app. Plan 02 defines the error classes.
7. **Breaking changes are accepted.** Plan 01 changes the core token format and makes `tokens.issuer` required.
   Nothing keeps the HS256 tokens working.

## Files

```
src/idp.ts                  entry of auth-dance/idp, re-exports src/idp/*
src/idp/api.ts              AuthDanceProviderApi, createAuthDanceProviderApi
src/idp/app.ts              AuthDanceProviderApp, createAuthDanceProviderApp
src/idp/client.ts           AuthDanceRegisteredClient, its valibot schema, redirect URI rules
src/idp/storage.ts          AuthDanceClientProvider, AuthDanceClientStorage
src/idp/records.ts          challenge, code, grant, consent records over api.storage KV
src/idp/error.ts            OAuth error classes
src/idp/pkce.ts             S256 verification
src/idp/client-auth.ts      client_secret_basic, client_secret_post, none
src/keys.ts                 signing keys and JWKS (core, plan 01)
src/providers/memory.ts     + MemoryClientProvider
src/providers/cloudflare.ts + CloudflareD1ClientProvider
src/providers/sqlite.sql    + "client" table
src/provider.test.ts        + shared client provider suite
```

`package.json` gets a `./idp` export.

## Naming to settle before plan 02

- `AuthDanceClient` is already the HTTP SDK in `src/client.ts`. The registered OAuth client is therefore
  `AuthDanceRegisteredClient`, and its adapter is `AuthDanceClientProvider`. The other option is to rename the SDK to
  `AuthDanceDanceClient` or similar, which is also a breaking change.
- In this codebase "provider" already means a storage adapter (`MemoryKvProvider`). `createAuthDanceProviderApi`
  uses it for the identity provider. The plans keep the names you asked for, and the docs call the adapters
  "adapters" to keep the two apart.

## Interop testing

Add `oauth4webapi` as a dev dependency and run each flow from its relying-party side against the in-process
`fetch`. It enforces PKCE, `iss` in the authorization response (RFC 9207) and the RFC error formats, so it catches
spec drift that tests written against our own code miss.
