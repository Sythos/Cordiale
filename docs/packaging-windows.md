# Packaging Windows

Spazio riservato all'installer unsigned NSIS 2 per Windows x64 e ARM64.

La compilazione e il packaging devono avvenire nel workflow GitHub Actions
`packages.yml`, mai nella macchina di sviluppo. La matrice iniziale produce
un archivio Windows; l'installer NSIS 2 verrà aggiunto quando sarà fissata
la toolchain NSIS esatta del runner.
