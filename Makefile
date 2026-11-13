# Makefile for MinGW64 TUN/TAP RootLayer P2P Client and Signaling Server
# Project name: RootLayer (exe description: "Root Layer", author: levent INAN).
# Build artifacts are placed in build/ so the source tree stays clean.

BUILD = build
BIN = $(BUILD)/bin
OBJ = $(BUILD)/obj
CC = gcc
CXX = g++
WINDRES = windres
CXXFLAGS = -Wall -Wextra -std=c++17 -I.
SERVER_CXXFLAGS = $(CXXFLAGS) -Iserver
CLIENT_CXXFLAGS = $(CXXFLAGS) -Iclient
LDFLAGS = -lws2_32 -liphlpapi -lsetupapi -lnetapi32 -lshell32 -ladvapi32 -lgdiplus -lgdi32 -lole32

# Server (uses SQLite to remember identity -> IP assignments).
# server.rc embeds resources/icons/exe_server.ico as the file icon.
# The server is split into categorized folders:
#   core/ globals, config, utils | db/ client_ips store | arpa/ domain.db
#   dns/ name server | session/ sessions + IP assignment | gateway/ TAP
#   net/ relay + signaling | main.cpp startup + accept loop
SERVER_SRCS = server/main.cpp \
              server/core/globals.cpp server/core/config.cpp server/core/utils.cpp \
              server/db/store.cpp server/db/write_queue.cpp \
              server/arpa/arpa.cpp \
              server/dns/dns.cpp \
              server/session/session.cpp \
              server/gateway/gateway.cpp \
              server/ca/ca.cpp \
              server/admin/admin.cpp \
              server/net/net.cpp

server: $(SERVER_SRCS) server/sqlite/sqlite3.c server/resources/server.rc server/resources/server.manifest
	@mkdir -p $(BIN) $(OBJ)
	$(CC) -O2 -c server/sqlite/sqlite3.c -o $(OBJ)/sqlite3.o
	$(WINDRES) -J rc -O coff server/resources/server.rc $(OBJ)/server.res
	$(CXX) $(SERVER_CXXFLAGS) -o $(BIN)/server.exe $(SERVER_SRCS) $(OBJ)/sqlite3.o $(OBJ)/server.res $(LDFLAGS) -lcrypto -lcrypt32

# Client
# NOTE: the executable is named client.exe (project: RootLayer).
# client.rc embeds the two tray PNG icons, the file icon and the
# requireAdministrator manifest, so resources/ is only needed for the TAP driver.
#
# The status panel is Qt 6 Widgets (MSYS2: pacman -S mingw-w64-x86_64-qt6-base).
# QT_DIR is detected from qmake6 so a stock MSYS2 mingw64 shell works unchanged.
# qmake6 first, then the usual MSYS2 mingw64 prefixes: the project can live
# anywhere, only the toolchain location matters.
QT_DIR ?= $(shell qmake6 -query QT_INSTALL_PREFIX 2>/dev/null || \
             for d in $(MINGW_PREFIX) /d/App/msys64/mingw64 /c/msys64/mingw64; do \
               [ -d $$d/include/qt6/QtWidgets ] && echo $$d && break; done)
QT_CFLAGS = -I$(QT_DIR)/include/qt6 -I$(QT_DIR)/include/qt6/QtCore \
            -I$(QT_DIR)/include/qt6/QtGui -I$(QT_DIR)/include/qt6/QtWidgets
QT_LIBS = -L$(QT_DIR)/lib -lQt6Widgets -lQt6Gui -lQt6Core

# The client is split into categorized folders:
#   core/ state, helpers, JSON events | tap/ driver + adapter config
#   net/ signaling, tunnel, resolve   | ui/ tray + Win32 status panel + Qt panel
CLIENT_SRCS = client/client.cpp \
              client/core/state.cpp client/core/utils.cpp client/core/json.cpp \
              client/tap/tap_driver.cpp client/tap/tap_config.cpp \
              client/net/signaling.cpp client/net/tunnel.cpp client/net/resolve.cpp \
              client/net/auto_secure.cpp \
              client/ui/tray.cpp client/ui/panel.cpp \
              client/ui/ui_panel_qt.cpp
CLIENT_HDRS = $(wildcard client/core/*.h client/tap/*.h client/net/*.h client/ui/*.h)

client: $(CLIENT_SRCS) $(CLIENT_HDRS) client/client.rc client/client.manifest
	@mkdir -p $(BIN) $(OBJ)
	$(WINDRES) -J rc -O coff client/client.rc $(OBJ)/client.res
	$(CXX) $(CLIENT_CXXFLAGS) $(QT_CFLAGS) -o $(BIN)/client.exe $(CLIENT_SRCS) $(OBJ)/client.res $(LDFLAGS) $(QT_LIBS) -lcrypto -lcrypt32 -mwindows
	@mkdir -p $(BIN)/resources; cp -r resources/. $(BIN)/resources/; rm -f $(BIN)/resources/icons/*.psd

# Copy the Qt runtime next to the executable so it starts without MSYS2 on PATH.
deploy-client: client
	windeployqt6 --no-translations --no-system-d3d-compiler --no-opengl-sw $(BIN)/client.exe

clean:
	rm -f $(BIN)/server.exe $(BIN)/client.exe $(BIN)/p2p_client.exe
	rm -f $(OBJ)/sqlite3.o $(OBJ)/server.res $(OBJ)/client.res
	rm -f $(BIN)/Qt6*.dll
	rm -f $(BIN)/server.db $(BIN)/domain.db

.PHONY: server client clean