# Plan 05: Token revocation (RFC 7009)

`POST /revoke` lets a client tell the server it no longer needs a token.

## Request (§2.1)

- `POST`, `application/x-www-form-urlencoded`.
- `token`: required.
- `token_type_hint`: `access_token` or `refresh_token`, a hint only. The server also looks the token up as the other
  type (§2.1).
- Client authentication as in plan 03. A confidential client must authenticate. A public client sends its
  `client_id` (§2.1, "the client also includes its authentication credentials").

## Behaviour

1. Authenticate the client. A failure is `invalid_client` 401.
2. Find the grant of the token:
   - access token: verify the JWT signature and `iss`, and read `gid`. **An expired access token still resolves**,
     because revoking it is harmless.
   - refresh token: `<gid>.<random>` matched against `refresh.current` or `refresh.previous`.
3. The token belongs to another client: do nothing and answer 200 (§2.1: "the authorization server … verifies whether
   the token was issued to the client"). Telling the caller would leak that the token exists.
4. Revoke the grant: delete `idp/grant/<gid>` and `idp/grants/<identityId>/<gid>`, and call `onGrantRevoked`.
   - Revoking a refresh token revokes the whole grant and its access tokens (§2.1, "SHOULD").
   - Revoking an access token also revokes the grant (§2.1, "MAY"). It is the only way to make a self-contained JWT
     inactive before `exp`, and it keeps one model.
5. Answer 200 with an empty body. An invalid, unknown or already-revoked token also gets 200 (§2.2).

`unsupported_token_type` (§2.2.1) is never raised, since both types are supported. The error class exists for
completeness.

## What revocation does not reach

A resource server that only checks the JWT signature keeps accepting the access token until `exp`, which is 300 s by
default. The README states this, and points to `/introspect` or `verifyAccessToken(token, { grant: true })` for
resource servers that need immediate revocation. This is the same trade-off as `session: true` in the core.

## CORS (§5)

Browser clients revoke on sign-out. The route answers CORS preflight for the origins of the registered
`redirect_uris` of public clients, like `/token`.

## Revocation by the identity and by the admin

Outside RFC 7009, but the same code path:

```ts
listGrants(identityId): Promise<AuthDanceGrantPublic[]>;   // "apps with access to your account"
revokeGrant(grantId): Promise<void>;
revokeClientGrants(identityId, clientId): Promise<void>;  // also deletes the remembered consent
```

`deleteClient` in the client storage does not reach the grants. The provider api's `deleteClient` revokes every
grant of the client first. That needs an index `idp/client-grants/<cid>/<gid>`, so add it to `records.ts` in this
plan.

## Metadata

Add `revocation_endpoint` and `revocation_endpoint_auth_methods_supported` to the RFC 8414 document.

## Steps

1. `revoke` in `api.ts`, with tests: refresh current, refresh previous, an access token (live and expired), a token
   of another client, garbage, and twice in a row.
2. After revocation, refresh fails with `invalid_grant` and introspection answers `active: false`.
3. `/revoke` route, CORS, address bucket.
4. `listGrants`, `revokeGrant`, `revokeClientGrants`, and the client index.
5. Interop test: `oauth4webapi.revocationRequest`.
