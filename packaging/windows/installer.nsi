; Minimal unsigned NSIS installer for Cordiale.
;
; Built with the NSIS 3.10 toolchain preinstalled on GitHub's windows-latest
; runner (see docs/packaging-windows.md). Command-line defines expected:
;   /DBIN_PATH=<path to the built cordiale-ui.exe>
;   /DOUT_FILE=<path to write the installer to>
;   /DVERSION=<version string shown to the user>

!ifndef BIN_PATH
  !error "BIN_PATH must be defined on the command line (/DBIN_PATH=...)"
!endif
!ifndef OUT_FILE
  !error "OUT_FILE must be defined on the command line (/DOUT_FILE=...)"
!endif
!ifndef VERSION
  !define VERSION "0.0.0"
!endif

!define APP_NAME "Cordiale"
!define APP_EXE "cordiale-ui.exe"
!define COMPANY "Sythos"

Name "${APP_NAME}"
OutFile "${OUT_FILE}"
InstallDir "$PROGRAMFILES64\${APP_NAME}"
RequestExecutionLevel admin
VIProductVersion "0.0.0.0"
VIAddVersionKey "ProductName" "${APP_NAME}"
VIAddVersionKey "CompanyName" "${COMPANY}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"

Page directory
Page instfiles

UninstPage uninstConfirm
UninstPage instfiles

Section "Install"
  SetOutPath "$INSTDIR"
  File /oname=${APP_EXE} "${BIN_PATH}"

  CreateDirectory "$SMPROGRAMS\${APP_NAME}"
  CreateShortcut "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}"
  CreateShortcut "$SMPROGRAMS\${APP_NAME}\Uninstall ${APP_NAME}.lnk" "$INSTDIR\uninstall.exe"

  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\${APP_EXE}"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  Delete "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk"
  Delete "$SMPROGRAMS\${APP_NAME}\Uninstall ${APP_NAME}.lnk"
  RMDir "$SMPROGRAMS\${APP_NAME}"
SectionEnd
