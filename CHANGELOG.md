# Changelog

## 0.1.0-rc.5 (unreleased)

### Breaking changes

- **Password records use a random salt (H1).** `PasswordHasher` is now an object with `hash`, `verify` and `needsRehash`, not a
  function. `pbkdf2PasswordHasher` writes `pbkdf2-sha256:<iterations>:<salt>:<digest>` with 16 random bytes of salt. It still verifies
  the `<iterations>:<salt>:<digest>` record of earlier versions, and a sign-in rewrites that record into the new form. A custom
  `PasswordHasher` function no longer compiles: a hasher that gives the same string for the same value is the bug.
- **The password pepper has a floor (H1).** `PasswordAuthDanceComponent` throws a `TypeError` for a pepper that is not a string or
  holds fewer than 16 bytes. An unset `process.env.PASSWORD_PEPPER` now fails at startup. Make a pepper with
  `openssl rand -base64 32`.
- **Only `true` or an identity id accepts a step (M1).** A sign-in step whose `verifyPrompt` answers anything else, `undefined`
  included, raises `INVALID_PROMPT_VALUE`. So does an identity id that names no stored identity. A component that answered
  `undefined` for success now fails; it also accepted every wrong value.
- **Every path needs a step that proves control (H3).** `AuthDanceComponent` gains `proves?: boolean`. A challenge proves by
  default, an identification does not. `EmailAuthDanceComponent` sets `proves = false` and `WebAuthnAuthDanceComponent` sets
  `proves = true`. The `AuthDanceApi` constructor raises the new `InvalidChoreographyError` (`INVALID_CHOREOGRAPHY`) for a complete
  path with no proving step, for example `choice("email", "passkey")`, and `UnknownComponentError` for an undeclared step. Sign in
  by address and code with `sequence("email", "otp")`, where `otp` is the `challenge` name of the email component. A sign-up now
  completes through that choreography.
- **Recovery is a sign-in without the recovered component (H2).** The recovery dance of a component is every complete path of the
  choreography that holds it, with the component removed. A path stays when it starts with an identification and holds a step that
  proves control. With `sequence("email", "password", "totp")`, a password reset needs the address, its one-time code and the TOTP
  code; the inbox alone no longer resets anything. A component that another path can do without, such as the passkey of
  `choice(sequence("email", "password"), "passkey")`, is no longer recoverable. The new `AuthDanceApiOptions.recovery` option marks a
  component `false`, or gives it a recovery choreography of its own: `{ password: sequence("email") }` restores the old behavior for
  the password. The constructor raises `INVALID_CHOREOGRAPHY` for an entry it cannot run.
- **The recover state changed shape (H2).** `identification` is gone; `path` and `proving` are new. A recover state issued before
  the upgrade raises `INVALID_STATE`. The state lives 5 minutes.
- **A WebAuthn recovery step runs one ceremony (H2).** It proves control with its own signature, so the second ceremony is gone.
- **`TotpAuthDanceComponent` asks for a code in a recovery step (H2).** In a `recover` flow, a prompt built without an identity has
  the type `totp`; the reset still collects a key with `totp-key`.
- **Refresh tokens work one time (M3).** Each exchange replaces the refresh token, and the session keeps a record of the current one
  at `session/<id>/refresh`. An exchange of the token just replaced, inside `durations.refresh_leeway` (default 10 seconds), raises
  `INVALID_REFRESH_TOKEN` and keeps the session. Any other exchange of an old token deletes the session and fires
  `onSessionDeleted` with the new flow `reuse`. A client that keeps the refresh token it gets from each exchange, as
  `AuthDanceClient` does, sees no change. On Workers KV the detection works inside one location only.
- **`verifyAccessToken` takes `{ session: true }` (M3).** With it, a token whose session ended raises `SESSION_NOT_FOUND`. Without
  it, the check stays stateless, and a token stays valid for up to `durations.access` after a sign-out. `/list-sessions` and
  `/list-components` now pass `session: true`.
- **A reset signs out the other sessions (M5).** A completed `rotate` deletes every other session of the identity, and a completed
  `recover` deletes every session. `onSessionDeleted` fires for each, with the new flows `rotate` and `recover`, after
  `onIdentityUpdated`. Set `revokeSessionsOnReset: false` to keep them. Rotating an email address signs out the other devices too.
- **`AuthDanceStorage.deleteSession` also deletes the refresh record (M3).** `AuthDanceStorage` gains `getRefreshRecord` and
  `setRefreshRecord`.
- **The default caller address is the last `x-forwarded-for` entry (M2).** It was the first, which the client writes. The new
  `AuthDanceAppOptions.address` resolver picks the source; `cloudflareAddress` and `forwardedAddress(hops)` ship with the library. A
  deployment behind two proxies sees all traffic under the inner proxy until it passes `forwardedAddress(2)`. The default still
  reads `cf-connecting-ip` first, which a client writes off Cloudflare: pass a resolver there.
- **Requests with no address share one bucket (M2).** They skipped the per-address buckets before. In-process use with
  `auth.fetch` lands in that shared bucket (300 requests a minute by default).
- **Sign-up steps are rate limited (M2).** A sign-up keys the `verify` and `send` buckets on the identity id its state carries, so a
  replay of the state keeps the count.
- **New `recipient` bucket (M2).** `limits.identity.recipient` (default 5 messages in 15 minutes) counts every message to one
  recipient, across states and identities. The key holds a SHA-256 of the channel and the recipient, never the address.
- **Email addresses are normalized (L2).** `EmailAuthDanceComponent` stores and looks up each address trimmed, in NFC, and in lower
  case, the local part included. `Victim@Example.com` and `victim@example.com` now name one identity. Set `preserveLocalCase: true`
  for a mail system where the local part depends on its case. A value that is not one address raises `INVALID_PROMPT_VALUE`; it
  became the empty address before. The new `normalizeEmailAddress` is exported from `auth-dance/components/email`. Stored
  mixed-case addresses stop matching: run `normalizeEmailIdentifications(storage, "email")` once. It rewrites every address it can
  and reports, without touching them, the identities that would collide.
- **`subscribe` validates the recipient (M4).** The library refuses a recipient that is not a string of 1 to 320 characters, or
  that holds a control character, then calls `getIdentityChannel` of the channel and stores the record it returns. A third-party
  channel must now implement `getIdentityChannel` properly: validate and normalize the recipient, and throw
  `InvalidPromptValueError` for one it cannot deliver to. Any other error becomes `INVALID_PROMPT_VALUE`.
  `CloudflareSendMailAuthDanceChannel` normalizes the address and refuses a stored recipient with a line break, and a mail channel
  under a name other than `email` now delivers to its subscribed recipient. `MemoryAuthDanceChannel` refuses a non-string.
