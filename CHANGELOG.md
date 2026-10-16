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
