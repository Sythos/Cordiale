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
