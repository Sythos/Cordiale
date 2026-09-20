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
di terze parti su Arch).

Immagini Docker ufficiali confermate per la build multi-distro su runner
Ubuntu: `ubuntu:26.04`, `almalinux:9`/`almalinux:10`, `archlinux:latest`
(o `archlinux:base-devel` per una toolchain di build completa).

La compilazione e il packaging devono avvenire nel workflow GitHub Actions
`packages.yml`, mai nella macchina di sviluppo.

## Runner di build vs. compatibilità glibc

Il binario Linux viene compilato UNA sola volta per architettura (nessuna
build separata per distro dentro un container) e poi impacchettato tale
e quale in `.deb` (Debian 13 E Ubuntu 26.04, stesso file copiato),
`.rpm` e `.pkg.tar.zst` — quindi il floor di glibc del runner di build
diventa il floor di compatibilità di TUTTI i pacchetti Linux distribuiti.
Versioni glibc verificate (2026-09-19): Ubuntu 24.04 → 2.39, Debian 13
Trixie → 2.41, Ubuntu 26.04 → 2.43. I job `linux-x64`/`linux-arm64` di
`build-and-package` restano quindi pinnati a `ubuntu-24.04` (il floor più
basso, compatibile all'indietro con Debian 13 e Ubuntu 26.04) anche dopo
il pin generale di `ci.yml`/`codeql.yml` a `ubuntu-26.04` — costruire lì
su `ubuntu-26.04` alzerebbe il requisito glibc minimo sopra quello di
Debian 13 Trixie, rompendo quel pacchetto. I job `source-archive` e
`create-release` non compilano nulla, quindi possono restare su
`ubuntu-26.04` senza rischio.

## Fonti upstream Grappa (`vjt/grappa-irc`, branch `main`)

Questa guida riguarda il packaging di Cordiale; il contratto tra il client e
il server Grappa va verificato sulle fonti upstream originali:

- **Repository e codice server:**
  <https://github.com/vjt/grappa-irc/tree/main>.
- **Contratto client REST/Phoenix Channels:**
  <https://github.com/vjt/grappa-irc/blob/main/docs/CLIENT_PROTOCOL.md>.
- **Cicchetto**, solo riferimento funzionale:
  <https://github.com/vjt/grappa-irc/tree/main/cicchetto>.
