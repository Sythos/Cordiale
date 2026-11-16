# Known warnings in GitHub Actions

This file lists the warnings that stay in the CI and package logs.
Each warning has a source and a reason to keep it.
Do not use broad suppression to hide them.

Check date: 16 November 2026.

## macOS linker warnings

### `QTKit.framework/QTKit.tbd` does not declare arm64

- Source: `build.rs` of `ffmpeg-sys-next` 9.1.1.
  The script links the `QTKit` framework on every static macOS build.
- Cause: the macOS SDK stub for `QTKit` does not declare arm64.
  The linker ignores the stub for the arm64 link.
- Where: the macOS hardware decoding jobs in `.github/workflows/packages.yml`.
- Impact: none. FFmpeg does not use `QTKit` at run time. The package job passes.
- Action: keep the warning. Cordiale cannot change the build script of a dependency.
  Do not remove FFmpeg or hardware decoding.

### FFmpeg archive objects have no platform load command

- Source: object files in the static FFmpeg libraries from vcpkg
  (`arm64-osx` and `x64-osx` triplets).
- Cause: the objects do not record a target platform.
  The linker assumes macOS. This is the target of both macOS package jobs.
- Where: the macOS hardware decoding jobs in `.github/workflows/packages.yml`.
- Impact: none. The package job passes and the executable starts.
- Action: keep the warning. The log does not name the objects.
  The exact files are not traced.

### `__eh_frame` section too large

- Source: the macOS link of a large `cordiale-ui` test binary.
  The binary contains the Slint generated code and the media dependencies.
- Cause: the section is larger than 16 MB. The linker cannot use the compact unwind table.
- Where: the macOS jobs in `.github/workflows/ci.yml`.
- Impact: the linker uses the slower DWARF lookup to unwind an exception.
  The tests pass. The release binary is a separate link and is not part of this check.
- Action: keep the warning visible. The exact object files are not traced.
  Do not add a linker flag that hides it.

## Other warnings

| Warning | Source | Action |
| --- | --- | --- |
| `RUSTSEC-2024-0436` (`paste` 1.0.15) | Path: `cordiale-ui` to `rusty_av1d` 1.3.0 to `paste`. | Allowed in the audit step of `.github/workflows/ci.yml`. Remove the flag when `rusty_av1d` drops `paste`. |
| Git default branch hint | Runner output of Git helper commands. | Keep. No Cordiale command controls it. |
