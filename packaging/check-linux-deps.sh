#!/usr/bin/env bash
# Checks the run-time library dependencies of a Linux Cordiale binary.
#
# Usage: bash packaging/check-linux-deps.sh <binary> [debian|ubuntu|almalinux|arch]
#
# Reads the DT_NEEDED entries of <binary> with readelf (binutils) and fails,
# naming the soname, if one of them is neither a glibc base library nor in
# the table below. With a distro it also prints that distro's package list on
# stdout, one package per line, ready for `fpm --depends`; every message goes
# to stderr. `ubuntu` uses the Debian names.
#
# Two kinds of libraries are in the table:
#   needed  linked at build time, so they show up in DT_NEEDED: the check
#           above fails if a new one appears that the table doesn't know.
#   dlopen  loaded when the window system or GL is initialised (winit, glutin,
#           xkbcommon-dl and wayland-sys all dlopen them), so readelf cannot
#           see them. They are always declared as dependencies; the binary's
#           strings are scanned for other sonames and any hit is only a note.
set -euo pipefail

# soname;kind;Debian/Ubuntu;AlmaLinux/RHEL;Arch
rows() {
  sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' <<'TABLE'
libasound.so.2;needed;libasound2t64 | libasound2;alsa-lib;alsa-lib
libfontconfig.so.1;needed;libfontconfig1;fontconfig;fontconfig
libgcc_s.so.1;needed;libgcc-s1;libgcc;gcc-libs
libxkbcommon.so.0;dlopen;libxkbcommon0;libxkbcommon;libxkbcommon
libxkbcommon-x11.so.0;dlopen;libxkbcommon-x11-0;libxkbcommon-x11;libxkbcommon-x11
libxcb.so.1;dlopen;libxcb1;libxcb;libxcb
libX11.so.6;dlopen;libx11-6;libX11;libx11
libX11-xcb.so.1;dlopen;libx11-xcb1;libX11-xcb;libx11
libXcursor.so.1;dlopen;libxcursor1;libXcursor;libxcursor
libXi.so.6;dlopen;libxi6;libXi;libxi
libGL.so.1;dlopen;libgl1;libglvnd-glx;libglvnd
libEGL.so.1;dlopen;libegl1;libglvnd-egl;libglvnd
libwayland-client.so.0;dlopen;libwayland-client0;libwayland-client;wayland
libwayland-egl.so.1;dlopen;libwayland-egl1;libwayland-egl;wayland
TABLE
}

usage() {
  echo "usage: $0 <binary> [debian|ubuntu|almalinux|arch]" >&2
  exit 2
}

# Libraries that ship with glibc: present on every system the binary runs on.
is_base() {
  case "$1" in
    libc.so.6 | libm.so.6 | libdl.so.2 | libpthread.so.0 | librt.so.1 | libutil.so.1 | ld-linux-*.so.*) return 0 ;;
  esac
  return 1
}

[[ $# -ge 1 && $# -le 2 ]] || usage
bin="$1"
distro="${2:-}"
case "${distro}" in
  "" | debian | ubuntu | almalinux | arch) ;;
  *) usage ;;
esac
[[ -f "${bin}" ]] || { echo "error: no such file: ${bin}" >&2; exit 2; }
command -v readelf > /dev/null || { echo "error: readelf not found (install binutils)" >&2; exit 2; }

known="$(rows | cut -d';' -f1)"
failed=0

# The table itself must name a package for every distro.
while IFS=';' read -r soname kind deb rpm arch; do
  for pkg in "${deb}" "${rpm}" "${arch}"; do
    if [[ -z "${pkg}" ]]; then
      echo "error: table row for ${soname} has an empty package column" >&2
      failed=1
    fi
  done
done < <(rows)

dynamic="$(readelf -d "${bin}" 2>&1)" || { echo "error: readelf failed on ${bin}: ${dynamic}" >&2; exit 2; }
needed="$(sed -n 's/.*(NEEDED).*\[\(.*\)\]$/\1/p' <<< "${dynamic}")"
if [[ -z "${needed}" ]]; then
  echo "error: no DT_NEEDED entries in ${bin}: not a dynamically linked ELF binary" >&2
  exit 2
fi

echo "DT_NEEDED of ${bin}:" >&2
while IFS= read -r soname; do
  if is_base "${soname}"; then
    echo "  ${soname} (glibc, always present)" >&2
  elif grep -Fxq -- "${soname}" <<< "${known}"; then
    echo "  ${soname}" >&2
  else
    echo "  ${soname}  <-- NOT COVERED" >&2
    echo "error: ${soname} is linked but has no package in packaging/check-linux-deps.sh" >&2
    failed=1
  fi
done <<< "${needed}"

# Informational: sonames embedded as strings that are probably dlopen targets.
strings_found="$({ grep -aoE 'lib[A-Za-z0-9_+-]+\.so(\.[0-9]+)+' "${bin}" || true; } | sort -u)"
while IFS= read -r soname; do
  [[ -n "${soname}" ]] || continue
  is_base "${soname}" && continue
  grep -Fxq -- "${soname}" <<< "${known}" && continue
  echo "note: ${soname} appears in the binary but is not in the table (dlopen target?)" >&2
done <<< "${strings_found}"

[[ "${failed}" -eq 0 ]] || exit 1

case "${distro}" in
  debian | ubuntu) column=3 ;;
  almalinux) column=4 ;;
  arch) column=5 ;;
  *) exit 0 ;;
esac
rows | cut -d';' -f"${column}" | awk '!seen[$0]++'
