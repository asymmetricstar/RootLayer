# RootLayer console - separate project, built on its own.
#   make          -> ../build/bin/Server/console.exe
#   make clean
CXX = g++
WINDRES = windres
CXXFLAGS = -Wall -Wextra -std=c++17 -I.
LDFLAGS = -lws2_32

SRCS = main.cpp \
       core/text.cpp core/files.cpp core/config.cpp core/options.cpp core/output.cpp \
       net/admin_client.cpp \
       commands/registry.cpp commands/name_commands.cpp commands/tld_commands.cpp \
       commands/cert_commands.cpp commands/server_commands.cpp
HDRS = $(wildcard core/*.h net/*.h commands/*.h)

BIN_DIR = ../build/bin/Server
OBJ_DIR = ../build/obj
RES = $(OBJ_DIR)/console.res
ICON = ../resources/icons/exe_console.ico

console: $(SRCS) $(HDRS) console.rc console.manifest version.h $(ICON)
	@mkdir -p $(BIN_DIR) $(OBJ_DIR)
	$(WINDRES) -J rc -O coff -i console.rc -o $(RES)
	$(CXX) $(CXXFLAGS) -o $(BIN_DIR)/console.exe $(SRCS) $(RES) $(LDFLAGS)

clean:
	rm -f $(BIN_DIR)/console.exe $(RES)

.PHONY: console clean
