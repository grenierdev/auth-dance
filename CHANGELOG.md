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
