// console/core/exit_codes.h
//
// Process exit codes: a script can tell a usage mistake from a server refusal
// and from an unreachable server.
#ifndef ROOTLAYER_CONSOLE_EXIT_CODES_H
#define ROOTLAYER_CONSOLE_EXIT_CODES_H

const int kExitOk = 0;          // command executed
const int kExitUsage = 1;       // wrong arguments / unknown command
const int kExitServer = 2;      // server refused or failed the command
const int kExitConnection = 3;  // server not reachable

#endif  // ROOTLAYER_CONSOLE_EXIT_CODES_H
