# Plan 04: Token introspection (RFC 7662)

`POST /introspect` lets a resource server ask whether a token is active, and see what it carries.

## Request (§2.1)

- `POST`, `application/x-www-form-urlencoded`.
- `token`: required.
- `token_type_hint`: `access_token` or `refresh_token`. It is a hint only. When the lookup by hint finds nothing, the
  server tries the other type (§2.1). An unknown hint value is ignored.

## Who may call

§2.1 requires the endpoint to be protected, so it cannot be used to probe tokens. The caller authenticates with the
client authentication of plan 03 (`client_secret_basic` or `client_secret_post`). A public client is refused with
`invalid_client`.

An authenticated client may introspect:

- tokens issued to itself (`client_id` of the token equals the caller), and
- any token, when the server-side flag `introspect: true` is set on the client (resource servers). `/register` can
  never set this flag.

A token the caller may not see answers `{ "active": false }`, exactly like an invalid token (§2.2, §4).

## Lookup

- **Access token**: verify the JWT (signature, `typ: at+jwt`, `iss`, `exp`, `nbf`). Then load `idp/grant/<gid>`.
  The token is active only when the grant exists and is not revoked, and when its session still exists (if it has
  one).
- **Refresh token**: split `<gid>.<random>`, load the grant, and compare the hash with `refresh.current`. The previous
  token is never active. Check the session the same way.
- A core Auth Dance token (`aud: <issuer>`) is never active here.

## Response (§2.2)

Active:

```json
{
	"active": true,
	"scope": "a b",
	"client_id": "cli_…",
	"username": "…",
	"token_type": "Bearer",
	"exp": 0,
	"iat": 0,
	"nbf": 0,
	"sub": "id_…",
	"aud": "cli_…",
	"iss": "https://…",
	"jti": "…"
}
```

- `username` is left out by default. An option `introspection.username(identity)` fills it, from `email` for
  example.
- `token_type` is `Bearer` for an access token and `refresh_token` for a refresh token.
- Extension members: `auth_time`, `gid`. §2.2 allows extensions.

Inactive: `{ "active": false }` and nothing else. The answer is always HTTP 200 for a well-formed request, whether the
token is valid or not.

Errors: a missing `token` is `invalid_request` 400. A failed client authentication is `invalid_client` 401.

Headers: `Cache-Control: no-store`. The answer depends on revocation state, so a cache would make revocation late.

## Rate limiting

An address bucket `introspect`, and a per-client bucket `introspect:<client_id>`. §4 names token scanning as the
threat.

## API

```ts
introspect(caller: AuthDanceRegisteredClient, token: string, hint?: "access_token" | "refresh_token"):
	Promise<AuthDanceIntrospection>;
```

The route only authenticates the client and calls this.

## Metadata

Add `introspection_endpoint` and `introspection_endpoint_auth_methods_supported` to the RFC 8414 document.

## Steps

1. `introspect` in `api.ts`, with unit tests: an active access token, an expired token, a revoked grant, an ended
   session, a token of another client (with and without `introspect: true`), refresh current vs previous, a core
   token, and garbage.
2. `/introspect` route with client authentication and buckets.
3. Interop test: `oauth4webapi.introspectionRequest` + `processIntrospectionResponse`.

## Out of scope

JWT-formatted introspection responses (RFC 9701).
