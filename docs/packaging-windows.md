# Packaging Windows

Installer unsigned NSIS 3 per Windows x64 e ARM64, prodotto da
`packaging/windows/installer.nsi` nel workflow GitHub Actions
`packages.yml`, mai nella macchina di sviluppo.

**NSIS 3, non NSIS 2** (deciso in autonomia il 2026-09-18): NSIS 2.51
(2016) non è più mantenuto su alcun package manager, l'unica via per
ottenerlo in CI sarebbe un installer non
verificabile scaricato da SourceForge. NSIS 3.10 è già preinstallato sul
runner `windows-latest`, nessuno step di installazione necessario. Nessuna
differenza pratica per questo progetto: l'installer generato è comunque un
unico eseguibile x86 che gira su ARM64 via emulazione Windows in entrambi
i casi.

Output: `Cordiale_Windows_x64.exe` e `Cordiale_Windows_arm64.exe`, oltre
agli archivi `.zip` generici già esistenti.

La versione testuale è `<tag>.<GITHUB_RUN_ID>`; il workflow DEV aggiunge
anche il suffisso `-dev`. Il quarto campo numerico delle risorse Windows è il
run ID ridotto sotto `65535` sottraendo ripetutamente `65535` (il workflow
usa il resto equivalente per evitare iterazioni inutilmente lunghe). I campi
`FileVersion`, `ProductVersion`, `DisplayVersion` e `BuildID` conservano il
run ID completo; `BuildAttempt` identifica un eventuale rilancio della stessa
esecuzione. Il tag resta la versione di release del progetto.

Il bundle macOS mantiene il tag in `CFBundleShortVersionString`; Apple limita
`CFBundleVersion` a tre componenti numeriche con ampiezza `4/2/2`, quindi il
workflow vi scrive una codifica compatta valida e conserva il run ID completo
nei campi `CordialeBuildID` e `CordialeBuildVersion`. I pacchetti Linux usano
direttamente il run ID come quarto componente della versione.

## Fonti upstream Grappa (`vjt/grappa-irc`, branch `main`)

Questa guida descrive il packaging del client nativo Cordiale; per il
contratto server/client e il comportamento Grappa valgono le fonti upstream:

- **Repository e codice server originali:**
  <https://github.com/vjt/grappa-irc/tree/main>.
- **Contratto client REST/Phoenix Channels:**
  <https://github.com/vjt/grappa-irc/blob/main/docs/CLIENT_PROTOCOL.md>.
- **Cicchetto**, solo riferimento funzionale e non architetturale:
  <https://github.com/vjt/grappa-irc/tree/main/cicchetto>.
