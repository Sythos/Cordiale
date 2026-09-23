# Security Policy

Cordiale is a native desktop client for Grappa. It stores credentials via
the OS-native credential store when available (Windows Credential
Manager/DPAPI, macOS Keychain, Linux Secret Service), with an explicitly
non-secure
fallback documented in code and never presented as real protection — see
`crates/cordiale-core/src/credentials.rs`.

## Supported versions

Cordiale is alpha software (0.1.x releases). Only the `main` branch is
supported: fixes land there and ship in the next tagged release, and older
releases are not maintained.

## Reporting a vulnerability

This repository's private reporting channel accepts submissions only for
security vulnerabilities in Cordiale itself. For security issues in the Grappa
server, please report them directly through
[Grappa's Security page](https://github.com/vjt/grappa-irc/security). Cordiale
has no automatic link or forwarding mechanism for Grappa reports, so reports
submitted here will not be routed to the Grappa maintainers.

If you find a security issue in Cordiale, please open a private report
through GitHub's [Security Advisories](https://github.com/Sythos/Cordiale/security/advisories)
for this repository rather than a public issue. Include:

- a description of the issue and its potential impact;
- steps to reproduce, if applicable;
- the Cordiale commit or version affected.

Please do not disclose the issue publicly until it has been triaged and,
where applicable, fixed.

## Scope notes

- Cordiale never invents server-side capabilities (e.g. guest/visitor
  access, admin privileges) beyond what the Grappa server's documented
  client protocol and actual behavior grant — see `docs/protocol-notes.md`.
- Secrets (passwords, per-client tokens) are never logged or written to
  `settings.json`/`servers.json` in plain text.
- Build, test and packaging run only in GitHub Actions; no release artifact
  is produced on a local development machine.

## Automated scanning

CI runs Clippy, `cargo audit` (RustSec advisory database) and CodeQL for
Rust on every push to `main` and on every pull request. No dedicated static analysis or security
scanner exists for Slint `.slint` files today; Slint markup is still
compiled and type-checked as part of `cargo check`/`cargo build`. A generic
secret scanner (e.g. `gitleaks`) is under consideration but not yet added.
