# Security Policy

Cordiale is a native desktop client for Grappa. It stores credentials via
the OS-native credential store when available (Windows Credential
Manager/DPAPI, Linux Secret Service), with an explicitly non-secure
fallback documented in code and never presented as real protection — see
`crates/cordiale-core/src/credentials.rs`.

## Supported versions

Cordiale is pre-release (Phase 1 of the roadmap in `MEMORY.md`). Until a
first tagged release exists, only the `main` branch is supported; there are
no maintained older versions.

## Reporting a vulnerability

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
Rust on every push to `main`. No dedicated static analysis or security
scanner exists for Slint `.slint` files today; Slint markup is still
compiled and type-checked as part of `cargo check`/`cargo build`. A generic
secret scanner (e.g. `gitleaks`) is under consideration but not yet added —
see `MEMORY.md`.
