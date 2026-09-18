# Installing Cordiale

Every release artifact is built and published by the `packages.yml` GitHub
Actions workflow — never on a local machine — and is **unsigned**. Windows
SmartScreen and some Linux package managers may warn about that; it's
expected for an unsigned, community-built app, not a sign of tampering.

Each artifact ships with a `SHA256SUMS` file (per platform/architecture
bundle) and a [build provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds),
verifiable with:

```bash
gh attestation verify <downloaded-file> -R Sythos/Cordiale
```

## Windows (x64 / ARM64)

Download `Cordiale_Windows_x64.exe` or `Cordiale_Windows_arm64.exe` and run
it. It installs to `Program Files\Cordiale` and adds a Start Menu shortcut
(admin rights required). Prefer a portable copy instead? Grab the matching
`cordiale-windows-*.zip` and run `cordiale-ui.exe` directly, no install
step.

## Debian 13 / Ubuntu 26.04 (x64 / ARM64)

```bash
sudo apt install ./Cordiale_Debian_13_<amd64|arm64>.deb
# or, on Ubuntu:
sudo apt install ./Cordiale_Ubuntu_26.04_<amd64|arm64>.deb
```

(`apt install ./file.deb` resolves dependencies; plain `dpkg -i` doesn't.)

## AlmaLinux / other RHEL-based distros (x64 / ARM64)

```bash
sudo dnf install ./Cordiale_AlmaLinux_10_<x86_64|aarch64>.rpm
```

## Arch Linux (x64 / ARM64)

```bash
sudo pacman -U Cordiale_Arch_rolling_<x86_64|aarch64>.pkg.tar.zst
```

## Any other Linux distro (x64 / ARM64)

```bash
tar -xzf cordiale-linux-<amd64|arm64>-<version>.tar.gz
./cordiale-ui
```

No installer, no package manager integration — just the binary. Requires
fontconfig, Mesa/OpenGL, XCB and xkbcommon to already be on the system
(present on effectively any desktop Linux install).

## macOS (universal: x64 + Apple Silicon)

Download `Cordiale_macOS_universal.dmg`, open it, drag `Cordiale.app` to
`Applications`. Since the app is unsigned and not notarized, the first
launch will be blocked by Gatekeeper. To allow it: try opening the app,
then go to **System Settings → Privacy & Security**, scroll down, click
**"Open Anyway"** next to the Cordiale warning, and confirm **Open** in the
dialog that reappears. Right-click (or Control-click) the app and choose
**Open** is the older equivalent, also still offered on most macOS
versions.

Prefer a plain binary? Grab `cordiale-macos-universal-<version>.tar.gz`
instead and run `./cordiale-ui` from a terminal.

## Building from source

Every release also ships `Cordiale_src.tar.gz`: a plain snapshot of the
tagged source tree (via `git archive`, so it's exactly what's on GitHub for
that tag — no build artifacts, no `.git` history). To build it yourself:

```bash
tar -xzf Cordiale_src.tar.gz
cd cordiale-<version>
cargo build --release --package cordiale-ui
./target/release/cordiale-ui
```

Requires a stable Rust toolchain ([rustup.rs](https://rustup.rs)) and, on
Linux, the same system packages listed in `.github/workflows/ci.yml`
(`libfontconfig1-dev`, `libgl1-mesa-dev`, `libxcb1-dev`,
`libxcb-render0-dev`, `libxcb-shape0-dev`, `libxcb-xfixes0-dev`,
`libxkbcommon-dev`, `libxkbcommon-x11-dev` — names as they appear in Debian
Trixie/Ubuntu Resolute's `apt`; adjust for your distro's package manager).
Windows and macOS need nothing beyond the Rust toolchain itself. This is
also just `git clone` plus the same two commands if you'd rather build
straight from `main` instead of a tagged release.
