# Unbought Rust libraries

Public Rust libraries shared by Unbought games. This repository is a Cargo
workspace; each package has its own version and release. Game-specific crates
stay in their game repositories.

| Package | Purpose |
| --- | --- |
| [unbought-auth](crates/unbought-auth/README.md) | Framework-independent client for the Unbought OIDC contract |

The libraries are MIT-licensed; see [LICENSE](LICENSE). The auth library was
originally developed by Ethan Mick for Unbought Games, LLC in the accounts
project. This repository contains the extracted library and its tests, not the
accounts service.

## Development

Install Rust 1.99.0 with rustfmt and Clippy; `rust-toolchain.toml` pins the
toolchain. Run `make check`. The tests use no running account service, database,
email provider or private repository.

## Releases

Versions belong to individual packages. Keep the package version and lockfile
current, run `make check`, and inspect `make package-list`. The packaged source
must include the license, README, code and tests and no credentials or unrelated
service files.

`make publish-dry-run` verifies the package without publishing it.
`make publish` publishes the selected version of `unbought-auth` to crates.io
using the operator's Cargo credentials. Publication is a deliberate release
operation; pull request CI has no publishing credentials.

After verifying the registry package, tag its source commit
`unbought-auth-v<VERSION>` and push that tag. Consumers depend on a crates.io
version and commit their application lockfile. Temporary local Cargo overrides
can be used for coordinated development, but must not enter release manifests.

Use company-maintained crates.io owners and narrowly scoped publishing access.
GitHub organization membership does not itself confer crates.io ownership.
