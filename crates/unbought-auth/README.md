# unbought-auth

A framework-independent Rust relying-party library for the **Unbought OIDC
contract**, built on `openidconnect`, `reqwest` and `jsonwebtoken`. It implements
authorization-code login with PKCE, ID-token validation, refresh, bounded session
revalidation and signed back-channel logout validation.

Requires Rust 1.99 or newer and a Tokio runtime for async network operations.
HTTPS is required for issuer and callback URLs, except HTTP loopback URLs for
local development. The client does not follow HTTP redirects and bounds each
HTTP request to five seconds.

## Configuration

```rust
use unbought_auth::{Configuration, RelyingParty};

fn configure() -> Result<RelyingParty, Box<dyn std::error::Error>> {
    Ok(RelyingParty::new(Configuration {
        issuer: std::env::var("OIDC_ISSUER")?,
        client_id: std::env::var("OIDC_CLIENT_ID")?,
        client_secret: std::env::var("OIDC_CLIENT_SECRET")?,
        redirect_uri: std::env::var("OIDC_REDIRECT_URI")?,
    })?)
}
```

Constructing a client does not contact a service. Applications using local
authentication do not need to construct a client or run Unbought Accounts.
This crate is a library compiled into the consumer, not a separate service.

## Consumer responsibilities

Implement `LoginStore::insert` and `LoginStore::consume` using durable storage.
`consume` must atomically match issuer, client ID, hashed state, hashed browser
secret and expiry, delete the transaction, and return it at most once. A
PostgreSQL `DELETE ... RETURNING` transaction is suitable. A failed match or an
expired transaction returns `None`; database failures return an error.

The consumer owns HTTP routes, secure cookies, CSRF protection, session storage,
rate limits, account linking, membership and game authorization. Do not use
email or username as the immutable identity key: use `(issuer, subject)`.
Keep `Tokens` server-side; their serialized representation includes credentials.

- `RelyingParty::begin` saves a ten-minute login transaction and returns the
  provider authorization URL. Bind the browser secret to the initiating browser.
- `RelyingParty::callback` checks the response issuer, consumes the transaction,
  and revalidates its local return path before exchanging the code. It returns
  `Tokens` and the saved local return path.
- `RelyingParty::refresh` refreshes tokens while preserving identity continuity.
- `RelyingParty::revalidate` reuses an unexpired snapshot for less than 60 seconds;
  otherwise it refreshes. Call this before admitting authenticated game commands.
  Deny commands on validation failure while allowing the simulation to continue.
- `RelyingParty::logout` validates a signed back-channel logout token. Consumers
  must atomically deduplicate its `jti` and revoke local sessions for the matching
  issuer and `sid`; this crate does not persist logout events.
- `require_verified` is an explicit policy helper. Email verification is not
  automatically required by the login flow.

`safe_return_path` accepts local absolute paths, rejecting scheme-relative URLs,
backslashes and all ASCII control characters, including tabs that browsers remove
when parsing URLs. Pass the validated path directly as the saved local destination;
do not turn it into an external URL by decoding or rewriting it afterward.

## Provider contract

This release is tested against the Unbought contract, not arbitrary OIDC
providers. In addition to standard ID-token claims, it requires
`preferred_username` (3–30 lowercase ASCII letters, digits or underscores) and
`sid`. An absent `email_verified` means false; a present value must be boolean.
The optional `session_expires_at` claim caps the local identity's expiry.

Login requests `openid`, `profile`, `email` and `offline_access` scopes.
The callback must supply the provider's response issuer. Refresh responses must
include an ID token. A returned refresh nonce, when present, must match the
original login nonce.

Back-channel logout uses RS256, a `logout+jwt` header type, a matching signing
key ID, issuer and audience, and nonempty `sid` and `jti` claims. The
`http://schemas.openid.net/event/backchannel-logout` event must be an empty
object. A nonce claim is forbidden, including JSON null. Consumers must retain
the replay-protection records for the token's possible acceptance window.

## Verification and license

Run `make check` from the workspace root. Unit and contract tests are offline.
The accounts service retains its separate full-system protocol acceptance suite.
The public API and runtime implementation are preserved from the initial
Unbought accounts integration.

Licensed under MIT. Copyright (c) 2026 Unbought Games, LLC and contributors.

## Token endpoint failures

Version 0.1.2 preserves transient failures during both authorization-code exchange
and refresh: HTTP 429, HTTP 5xx, network failures, and OAuth `server_error` or
`temporarily_unavailable` return `Error::Unavailable`. HTTP status is checked before
parsing the response body, so Accounts' message-only 429 and proxy HTML outages
are classified correctly. Invalid grants/client credentials, malformed successful
responses, account-action errors, and failed identity checks remain invalid.

No automatic retry or session acceptance is added. Callback transactions remain
single-use; consumers should offer a fresh login after a transient callback
failure. Orbit already maps `Unavailable` to HTTP 503. The library does not forward
provider retry headers; callers should use backoff for unavailable responses.
Publish this patch through the repository release procedure, then update consumers'
registry pins and lockfiles in their own reviewed release.
