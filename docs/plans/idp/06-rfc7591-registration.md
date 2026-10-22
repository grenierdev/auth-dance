# Plan 06: Dynamic client registration (RFC 7591)

`POST /register` lets a client register itself and receive a `client_id`.

## Is the endpoint open?

§3 allows open registration, or registration protected by an initial access token. The option:

```ts
registration?:
	| false // default: no /register route, no registration_endpoint in the metadata
	| {
			/** Checks the bearer token of the request. Without it, registration is open to anyone. */
			authorize?: (initialAccessToken: string, c: Context) => boolean | Promise<boolean>;
			/** Can rewrite or refuse metadata before it is stored. Throw an AuthDanceOAuthError to refuse. */
			policy?: (metadata: AuthDanceClientMetadata) => AuthDanceClientMetadata | Promise<AuthDanceClientMetadata>;
			/** The ceiling of `scope` for a dynamic client. @defaultValue every scope in `scopes` */
			scope?: string[];
			/** Lifetime of an issued secret, in seconds. 0 = never expires. @defaultValue 0 */
			secret_lifetime?: number;
	  };
```

Recommended default for deployments: `authorize` set. Open registration with a consent step stays safe for
authorization code clients, because the user still sees `client_name` and consents. It still allows phishing with a
plausible name, so the README spells this out.

## Request (§3.1)

`POST`, `Content-Type: application/json`, body = client metadata (§2). Accepted members:

| Member                        | Rule                                                                                   |
| ----------------------------- | -------------------------------------------------------------------------------------- |
| `redirect_uris`               | Required when `grant_types` has `authorization_code`. Each passes `validateRedirectUri`. |
| `token_endpoint_auth_method`  | `client_secret_basic` (default, §2), `client_secret_post`, `none`                       |
| `grant_types`                 | Default `["authorization_code"]`. Subset of the three supported ones                    |
| `response_types`              | Default `["code"]`. Only `code`                                                         |
| `scope`                       | Intersected with `registration.scope`. Default is that ceiling                          |
| `client_name`, `client_uri`, `logo_uri`, `tos_uri`, `policy_uri` | Strings. The URIs must be `https:`                    |
| `contacts`                    | Array of strings                                                                        |
| `software_id`, `software_version` | Strings, stored as given                                                          |
| `name#lang` variants (§2.2)   | For `client_name`, `client_uri`, `logo_uri`, `tos_uri`, `policy_uri`. BCP 47 tag       |
| `jwks`, `jwks_uri`            | Refused with `invalid_client_metadata`. `private_key_jwt` is not supported              |
| `software_statement`          | Refused with `unapproved_software_statement` unless a verifier option is added later    |

Consistency checks (§2.1):

- `authorization_code` in `grant_types` ⇔ `code` in `response_types`. A mismatch is `invalid_client_metadata`.
- `refresh_token` without `authorization_code` is `invalid_client_metadata`.
- `client_credentials` with `none` is `invalid_client_metadata`.

The server may replace a value it does not accept (§3.2.1). This plan narrows `scope` silently and refuses everything
else, so a client never gets settings it did not ask for without seeing them in the response.

Server-side fields (`skip_consent`, `introspect`, `registered_by`) are never read from the body. A body that names
them is not an error: the server ignores the member and sets `registered_by: "dynamic"`.

## Response (§3.2.1)

`201 Created`, `Cache-Control: no-store`, JSON:

```json
{
	"client_id": "cli_…",
	"client_secret": "…",
	"client_id_issued_at": 0,
	"client_secret_expires_at": 0,
	"redirect_uris": ["…"],
	"token_endpoint_auth_method": "client_secret_basic",
	"grant_types": ["authorization_code", "refresh_token"],
	"response_types": ["code"],
	"scope": "a b",
	"client_name": "…",
	"client_name#fr-CA": "…"
}
```

- `client_secret` and `client_secret_expires_at` only when the method is not `none`. `client_secret_expires_at` is
  required whenever a secret is issued (§3.2.1).
- Every registered metadata member is returned, including the defaults the server applied.

## Errors (§3.2.2)

HTTP 400 with `{ error, error_description }`: `invalid_redirect_uri`, `invalid_client_metadata`,
`invalid_software_statement`, `unapproved_software_statement`. A missing or refused initial access token is 401
with `WWW-Authenticate: Bearer error="invalid_token"` (RFC 6750 §3).

## Consent and display

The consent page shows `client_name` in the user's language (`client_name#<lang>`, then `client_name`, then the
`client_id`), and the host of the redirect URI. A dynamic client is never `skip_consent`.

## Rate limiting

An address bucket `register` that is tight by default (10 per hour). Spam registrations fill the client store.

## API

```ts
registerClient(metadata: unknown, options?: { registered_by: "dynamic" | "admin" }):
	Promise<AuthDanceClientRegistration>;
```

The admin path (a setup script, a seed) calls the same validation with `registered_by: "admin"`, and can set the
server-side fields.

## Metadata

`registration_endpoint` in the RFC 8414 document, only when `registration` is enabled.

## Steps

1. `AuthDanceClientMetadata` input schema in `client.ts` (valibot), the language-tag parser, and the consistency
   checks. Unit tests for each rule in the tables.
2. `registerClient` in `api.ts` on top of `AuthDanceClientStorage.createClient`.
3. `/register` route, the `authorize` and `policy` hooks, the bucket, and `onClientRegistered`.
4. End-to-end: register with `oauth4webapi.dynamicClientRegistrationRequest`, then run the full code flow from
   plan 03 with the new client.

## Out of scope

RFC 7592 (read, update and delete through `registration_client_uri` and `registration_access_token`). The response
leaves out both members, so adding them later breaks nothing. Software statements and `private_key_jwt` are out of
scope too.
