; Minimal unsigned NSIS installer for Cordiale.
;
; Built with the NSIS 3.10 toolchain preinstalled on GitHub's windows-latest
; runner (see docs/packaging-windows.md). Command-line defines expected:
;   /DBIN_PATH=<path to the built cordiale-ui.exe>
;   /DOUT_FILE=<path to write the installer to>
;   /DVERSION=<version string shown to the user>
;   /DICON_PATH=<path to the cordiale.ico file>

!ifndef BIN_PATH
  !error "BIN_PATH must be defined on the command line (/DBIN_PATH=...)"
!endif
!ifndef OUT_FILE
  !error "OUT_FILE must be defined on the command line (/DOUT_FILE=...)"
!endif
!ifndef ICON_PATH
  !error "ICON_PATH must be defined on the command line (/DICON_PATH=...)"
!endif
!ifndef VERSION
  !define VERSION "0.0.0"
!endif

!include "FileFunc.nsh"

!define APP_NAME "Cordiale"
!define APP_EXE "cordiale-ui.exe"
!define COMPANY "Sythos"
; Where Windows Settings > Apps / Control Panel > Programs and Features
; reads installed-app entries from — nothing here means Cordiale is
; installed and uninstallable via uninstall.exe, but invisible to both.
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}"

Name "${APP_NAME}"
OutFile "${OUT_FILE}"
Icon "${ICON_PATH}"
UninstallIcon "${ICON_PATH}"
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

  ; Registers Cordiale with Windows Settings > Apps / Control Panel >
  ; Programs and Features — without this the app is installed and
  ; uninstallable via uninstall.exe, but doesn't show up there at all.
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayName" "${APP_NAME}"
  WriteRegStr HKLM "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegStr HKLM "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\${APP_EXE}"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINST_KEY}" "Publisher" "${COMPANY}"
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  WriteRegDWORD HKLM "${UNINST_KEY}" "EstimatedSize" $0
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\${APP_EXE}"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  Delete "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk"
  Delete "$SMPROGRAMS\${APP_NAME}\Uninstall ${APP_NAME}.lnk"
  RMDir "$SMPROGRAMS\${APP_NAME}"

  DeleteRegKey HKLM "${UNINST_KEY}"
SectionEnd
