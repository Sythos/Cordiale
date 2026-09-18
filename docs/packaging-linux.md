# Packaging Linux

Note per gli artefatti Linux di Cordiale. Target x64 e ARM64 per ciascuna
distribuzione, tutti unsigned (mai dichiarato nel nome file):

- Debian 13 Trixie → `.deb`.
- Ubuntu 26.04 "Resolute Raccoon" → `.deb`.
- Arch Linux (rolling release, nessuna versione OS distinta) → pacchetto
  pacman (`.pkg.tar.zst`), via AUR.
- RHEL rpm-based, rappresentato da AlmaLinux 10 (ultima major stable a
  2026-09-18; AlmaLinux 9.x resta mantenuta in parallelo ma non è il target
  di riferimento) → `.rpm`.
- `.tar.gz` standalone generico x64/ARM64, non legato a una distribuzione.

Convenzione di naming vincolante per i pacchetti distro-specifici:
`Cordiale_<NomeDistro>_<VersioneDistro>_<arch>.<estensione>`, con `<arch>`
nella convenzione nativa dell'ecosistema pacchetti (`amd64`/`arm64` per
`.deb`, `x86_64`/`aarch64` per `.rpm` e per il pacchetto Arch — pacman non
usa mai `amd64`/`arm64`). Per Arch, che non ha una versione OS, il segmento
`<VersioneDistro>` usa `rolling` come placeholder (nessuna convenzione
ufficiale trovata per citare una "versione distro" nel nome di un pacchetto
di terze parti su Arch — vedi `MEMORY.md` §4).

Immagini Docker ufficiali confermate per la build multi-distro su runner
Ubuntu: `ubuntu:26.04`, `almalinux:9`/`almalinux:10`, `archlinux:latest`
(o `archlinux:base-devel` per una toolchain di build completa).

La compilazione e il packaging devono avvenire nel workflow GitHub Actions
`packages.yml`, mai nella macchina di sviluppo.
