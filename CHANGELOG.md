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
