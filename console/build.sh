#!/bin/bash
# RootLayer console - standalone build (no make required).
#
# Portable: every path is derived from this script's folder and the toolchain is
# looked up through PATH / MINGW_PREFIX, like the repository's own build.sh.
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RELEASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$RELEASE_DIR/build/bin/Server"

find_toolchain() {
    local dir
    dir="$(dirname "$(command -v g++ 2>/dev/null)" 2>/dev/null)"
    if [ -n "$dir" ] && [ "$dir" != "." ] && { [ -x "$dir/g++.exe" ] || [ -x "$dir/g++" ]; }; then
        echo "$dir"
        return 0
    fi
    for dir in "${MINGW_PREFIX:-}/bin" /d/App/msys64/mingw64/bin /c/msys64/mingw64/bin \
               /mingw64/bin /usr/bin; do
        [ -n "$dir" ] || continue
        if [ -x "$dir/g++.exe" ] || [ -x "$dir/g++" ]; then
            echo "$dir"
            return 0
        fi
    done
    return 1
}

TOOLCHAIN="$(find_toolchain)"
if [ -z "$TOOLCHAIN" ]; then
    echo "ERROR: g++ not found. Use an MSYS2 mingw64 shell or set MINGW_PREFIX."
    exit 1
fi

COMPILER="$TOOLCHAIN/g++"
[ -x "$COMPILER" ] || COMPILER="$TOOLCHAIN/g++.exe"
WINDRES="$TOOLCHAIN/windres"
[ -x "$WINDRES" ] || WINDRES="$TOOLCHAIN/windres.exe"

mkdir -p "$BIN_DIR" "$RELEASE_DIR/build/obj"

cd "$SCRIPT_DIR" || exit 1

# Embedded icon (console.rc -> RT_ICON/RT_GROUP_ICON in the executable).
"$WINDRES" -J rc -O coff -i console.rc -o "$RELEASE_DIR/build/obj/console.res"
if [ $? -ne 0 ]; then
    echo "ERROR: console.rc (icon) could not be compiled!"
    exit 1
fi

"$COMPILER" -Wall -Wextra -std=c++17 -I. \
    -o "$BIN_DIR/console.exe" \
    main.cpp \
    core/text.cpp core/files.cpp core/config.cpp core/options.cpp core/output.cpp \
    net/admin_client.cpp \
    commands/registry.cpp commands/name_commands.cpp commands/tld_commands.cpp \
    commands/cert_commands.cpp commands/server_commands.cpp \
    "$RELEASE_DIR/build/obj/console.res" \
    -lws2_32

status=$?
if [ $status -ne 0 ]; then
    echo "ERROR: console build failed!"
    exit $status
fi

echo "console built: build/bin/Server/console.exe"
