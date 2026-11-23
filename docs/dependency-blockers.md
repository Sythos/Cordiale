# Blocked dependency updates

This file records the Cargo packages that stay behind their newest release.
A parent crate prevents each update. No patch or override forces a newer version.

Check date: 14 November 2026. Command: `cargo update --dry-run`. Result: 0 packages to update.

## Direct dependencies

All direct requirements allow the newest release:

- `ffmpeg-next` `^9` (lockfile: `ffmpeg-sys-next` 9.1.1)
- `resvg` `^0.49` (must match the `resvg` of `slint` 1.19.0, which requires `^0.49.0`; `resvg` 0.50.0 exists but `slint` cannot use it)
- `rusty_vp9` `^0.2`
- `sysinfo` `^0.40.3`

## Blocked paths

Each parent crate below is at its newest release on crates.io.
The rows for `slint` were checked on 14 November 2026 against `slint` 1.18.1.
Cordiale now uses `slint` 1.19.0, so check those rows again before you act on them.

| Parent crate (version) | Constraint that blocks | Blocked packages |
| --- | --- | --- |
| `slint` 1.18.1 | `i-slint-core` 1.18.1 requires `accesskit` 0.24 and `parley` 0.11 | `accesskit*`, `parley*`, `fontique`, `skrifa`, `read-fonts`, `taffy`, `femtovg` and other packages of the Slint graph |
| `slint` 1.18.1 | `i-slint-backend-winit` 1.18.1 requires `winit` 0.30.13 and `accesskit_winit` 0.33 | `smithay-client-toolkit`, `sctk-adwaita`, `x11rb*`, `zbus*`, `atspi*`, `muda` and the other platform packages of `winit` 0.30 |
| `windows` 0.62.2 | No `windows` 0.100 release exists | `windows-*` 0.100, `windows_*` 0.53, `windows-targets` 0.53 |
| `reqwest` 0.13.5 | Requires `tower-http` `^0.6` | `tower-http` 0.7.1 |
| `vodozemac` 0.11.2 | Requires `hpke` 0.14 | `hpke` 0.15.1 |
| `rodio` 0.23.0 | `cpal` 0.18.2 requires `alsa` 0.11 and `alsa-sys` 0.4 | `alsa` 0.12.1, `alsa-sys` 0.6.1 |
| `wiremock` 0.6.5 (dev only) | Requires `deadpool` 0.12 | `deadpool` 0.13.1, `deadpool-runtime` 0.3.1 |
| `rodio` 0.23.0, `rusty_av1d` 1.3.0, `keyring` 4.2.0 | `num-rational` 0.4 (through `rodio` and `av-data`) and `num` 0.4 (through `secret-service`) require `num-bigint` 0.4 | `num-bigint` 0.5.1 |
| `slint` 1.18.1 | `glutin` 0.32.3 build script requires `gl_generator` 0.14, which requires `xml-rs` 0.8 | `xml-rs` 1.0.0 |

The newest `winit` is 0.31.0-beta.4.
Cordiale needs the `unstable-winit-030` feature of `slint`, so a beta release does not replace 0.30.

## Duplicate `base64`, `unicode-width` and `windows-sys` versions

Check date: 23 November 2026, with `slint` 1.19.0.
Command: `cargo tree --target all --all-features -e normal,build,dev -d`.
`resvg` and `usvg` have one version each (0.49.0), the version that `slint` 1.19.0 requires.
The other crates below keep an older version because of a parent crate.

| Old version | Dependency path | Required range |
| --- | --- | --- |
| `base64` 0.22.1 | `wiremock` 0.6.5 (dev only, newest release) | `^0.22` |
| `unicode-width` 0.1.14 | `ctap-hid-fido2` 3.6.1 (newest, feature `ctap-hid`) -> `pad` 0.1.6 (newest) | `^0.1` |
| `windows-sys` 0.52.0 | `slint` -> `i-slint-backend-winit` -> `winit` 0.30.13, `glutin` 0.32.3, `glutin_egl_sys` 0.7.1 | `^0.52` |
| `windows-sys` 0.59.0 | `slint` -> `i-slint-backend-winit` -> `winit` 0.30.13 -> `rustix` 0.38.44 (through `calloop` 0.13) | `^0.59` |
| `windows-sys` 0.48.0 | `slint` optional `libinput` backend -> `input` 0.10 -> `udev` 0.9.3 -> `io-lifetimes` 1.0.11 | `^0.48` |

`windows-sys` 0.48.0 is in `Cargo.lock` only.
No enabled feature of Cordiale builds it.

Safe options:

- Keep `slint` 1.19.0 (the newest release) until a `slint` release uses a `winit` that needs `windows-sys` 0.61.
- Use `winit` 0.31 only when `slint` supports it with a stable release.
- Replace `wiremock` in the dev tests only if a replacement keeps the same test behaviour.
- Wait for a release of `ctap-hid-fido2` or `pad` that uses `unicode-width` 0.2.

Do not use a patch or a lockfile edit to force a newer version on these parent crates.

## Other parent crates at their newest release

Each crate below is locked to its newest stable release on crates.io (checked on 14 November 2026).
No newer release allows the remaining targets:
`slint` 1.18.1, `reqwest` 0.13.5, `vodozemac` 0.11.2, `wiremock` 0.6.5, `symphonia` 0.6.1,
`image` 0.25.10, `rusty_h264-decoder` 0.17.2, `keyring` 4.2.0, `dark-light` 3.0.0,
`arboard` 3.7.0, `rusty_av1d` 1.3.0, `rodio` 0.23.0, `cpal` 0.18.2 and `dirs` 7.0.0.

Do not raise a version past a break point of the chain.
A newer child crate stays blocked until its parent crate allows it.

## How to continue

1. Run `cargo update --dry-run` and `cargo info <crate>` for each parent crate.
2. When a parent crate has a new release, raise its requirement in the manifest.
3. Run `cargo update` to regenerate `Cargo.lock`.
4. Run `cargo metadata --locked`.
5. Remove the resolved row from this file.
