// console/core/files.h
//
// The only place the console touches the file system: writing the certificate
// files and locating its own folder.
#ifndef ROOTLAYER_CONSOLE_FILES_H
#define ROOTLAYER_CONSOLE_FILES_H

#include <string>

// Folder console.exe lives in (used to find server.ini).
std::string exe_dir();

std::string join_path(const std::string& directory, const std::string& name);

// Creates the directory and every missing parent. True when it exists after.
bool ensure_directory(const std::string& path);

// Writes (or overwrites) a file. True on success.
bool write_file(const std::string& path, const std::string& data);

#endif  // ROOTLAYER_CONSOLE_FILES_H
