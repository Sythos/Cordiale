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
