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

The package depends on the libraries Cordiale needs (see the table under
"Any other Linux distro" for what each one is for): `libasound2t64` (or
`libasound2` on releases that predate the rename), `libfontconfig1`,
`libgcc-s1`, `libxkbcommon0`, `libxkbcommon-x11-0`, `libxcb1`, `libx11-6`,
`libx11-xcb1`, `libxcursor1`, `libxi6`, `libgl1`, `libegl1`,
`libwayland-client0` and `libwayland-egl1`. `apt install ./file.deb`
installs whatever of them is missing; plain `dpkg -i` doesn't.

## AlmaLinux / other RHEL-based distros (x64 / ARM64)

```bash
sudo dnf install ./Cordiale_AlmaLinux_10_<x86_64|aarch64>.rpm
```

`dnf` pulls in the packages the `.rpm` requires: `alsa-lib`, `fontconfig`,
`libgcc`, `libxkbcommon`, `libxkbcommon-x11`, `libxcb`, `libX11`,
`libX11-xcb`, `libXcursor`, `libXi`, `libglvnd-glx`, `libglvnd-egl`,
`libwayland-client` and `libwayland-egl`.

## Arch Linux (x64 / ARM64)

```bash
sudo pacman -U Cordiale_Arch_rolling_<x86_64|aarch64>.pkg.tar.zst
```

`pacman` installs the packages the file depends on: `alsa-lib`,
`fontconfig`, `gcc-libs`, `libxkbcommon`, `libxkbcommon-x11`, `libxcb`,
`libx11`, `libxcursor`, `libxi`, `libglvnd` and `wayland`.

## Any other Linux distro (x64 / ARM64)

```bash
tar -xzf cordiale-linux-<amd64|arm64>-<version>.tar.gz
./cordiale-ui
```

No installer, no package manager integration — just the binary, so nothing
installs its libraries for you. These have to be on the system already:

| Library | Debian / Ubuntu | AlmaLinux / RHEL | Arch | Used for |
|-|-|-|-|-|
| `libasound.so.2` | `libasound2t64` (`libasound2` before the rename) | `alsa-lib` | `alsa-lib` | radio player audio |
| `libfontconfig.so.1` | `libfontconfig1` | `fontconfig` | `fontconfig` | finding system fonts |
| `libgcc_s.so.1` | `libgcc-s1` | `libgcc` | `gcc-libs` | Rust runtime |
| `libxkbcommon.so.0`, `libxkbcommon-x11.so.0` | `libxkbcommon0`, `libxkbcommon-x11-0` | `libxkbcommon`, `libxkbcommon-x11` | `libxkbcommon`, `libxkbcommon-x11` | keyboard layouts |
| `libxcb.so.1`, `libX11.so.6`, `libX11-xcb.so.1`, `libXcursor.so.1`, `libXi.so.6` | `libxcb1`, `libx11-6`, `libx11-xcb1`, `libxcursor1`, `libxi6` | `libxcb`, `libX11`, `libX11-xcb`, `libXcursor`, `libXi` | `libxcb`, `libx11`, `libxcursor`, `libxi` | the window on X11 |
| `libwayland-client.so.0`, `libwayland-egl.so.1` | `libwayland-client0`, `libwayland-egl1` | `libwayland-client`, `libwayland-egl` | `wayland` | the window on Wayland |
| `libGL.so.1`, `libEGL.so.1` | `libgl1`, `libegl1` | `libglvnd-glx`, `libglvnd-egl` | `libglvnd` | OpenGL rendering |

`libasound` and `libfontconfig` are linked when the program is built, so
without them it won't start at all. The others are loaded at run time,
when the window system and OpenGL are set up, so they don't stop the binary
from loading but a missing one breaks the window. You also need a working
OpenGL driver, normally Mesa, which any desktop install has. The same list,
with the packages each distro's `.deb`, `.rpm` and `.pkg.tar.zst` declare,
lives in `packaging/check-linux-deps.sh`; CI fails when the binary links a
library that list doesn't cover.

## macOS (Apple Silicon and Intel)

Download `Cordiale_macOS_arm64.dmg` on an Apple Silicon Mac (M1 and later)
or `Cordiale_macOS_x64.dmg` on an Intel Mac, open it, drag `Cordiale.app` to
`Applications`. Since the app is unsigned and not notarized, the first
launch will be blocked by Gatekeeper. To allow it: try opening the app,
then go to **System Settings → Privacy & Security**, scroll down, click
**"Open Anyway"** next to the Cordiale warning, and confirm **Open** in the
dialog that reappears. Right-click (or Control-click) the app and choose
**Open** is the older equivalent, also still offered on most macOS
versions.

Prefer a plain binary? Grab `cordiale-macos-arm64-<version>.tar.gz` (or
`cordiale-macos-x64-<version>.tar.gz` on Intel) instead and run
`./cordiale-ui` from a terminal.

## Where Cordiale keeps its files

Cordiale uses each platform's standard folders (on Linux they follow
`XDG_CONFIG_HOME`, `XDG_DATA_HOME` and `XDG_STATE_HOME` when set):

| | Settings and servers | Credentials fallback (only without a keyring) | Log |
|-|-|-|-|
| Linux | `~/.config/cordiale` | `~/.local/share/cordiale` | `~/.local/state/cordiale` |
| Windows | `%APPDATA%\Cordiale` | `%LOCALAPPDATA%\Cordiale` | `%LOCALAPPDATA%\Cordiale` |
| macOS | `~/Library/Application Support/Cordiale` | `~/Library/Application Support/Cordiale` | `~/Library/Logs/Cordiale` |

The files are `settings.json` and `servers.json`, `credentials.json`, and
`cordiale.log` plus `cordiale.log.1` (the log is capped at about 1 MiB and
the previous one is kept). The **Debug** page shows these locations and has an
Open data folder button. Older versions kept everything in `~/.cordiale`;
Cordiale moves those files to the folders above the first time it starts, and
keeps using `~/.cordiale` (and says so on the Debug page) if that fails.

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
(`libasound2-dev`, `libfontconfig1-dev`, `libgl1-mesa-dev`, `libxcb1-dev`,
`libxcb-render0-dev`, `libxcb-shape0-dev`, `libxcb-xfixes0-dev`,
`libxkbcommon-dev`, `libxkbcommon-x11-dev` — names as they appear in Debian
Trixie/Ubuntu Resolute's `apt`; adjust for your distro's package manager).
Windows and macOS need nothing beyond the Rust toolchain itself. This is
also just `git clone` plus the same two commands if you'd rather build
straight from `main` instead of a tagged release.

## Grappa upstream references

Cordiale is a native client for Grappa. Its server integration follows the
upstream client contract; the Grappa server implementation remains the final
authority if documentation and behavior differ. These links intentionally
target the original `main` branch, not a release branch:

- **Original Grappa repository and server source:**
  <https://github.com/vjt/grappa-irc/tree/main>.
- **Authoritative REST and Phoenix Channels client protocol:**
  <https://github.com/vjt/grappa-irc/blob/main/docs/CLIENT_PROTOCOL.md>.
- **Cicchetto reference client** (functional comparison only):
  <https://github.com/vjt/grappa-irc/tree/main/cicchetto>.
