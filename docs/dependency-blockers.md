# Blocked dependency updates

This file records the Cargo packages that stay behind their newest release.
A parent crate prevents each update. No patch or override forces a newer version.

Check date: 14 November 2026. Command: `cargo update --dry-run`. Result: 0 packages to update.

## Direct dependencies

All direct requirements allow the newest release:

- `ffmpeg-next` `^9` (lockfile: `ffmpeg-sys-next` 9.1.1)
- `resvg` `^0.50`
- `rusty_vp9` `^0.2`
- `sysinfo` `^0.40.3`

## Blocked paths

Each parent crate below is at its newest release on crates.io.

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
