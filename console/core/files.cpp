// console/core/files.cpp
#include "core/files.h"

#include <windows.h>

#include <fstream>

std::string exe_dir() {
    char buffer[MAX_PATH] = {0};
    const DWORD length = GetModuleFileNameA(NULL, buffer, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) return ".";

    std::string path(buffer, length);
    const size_t slash = path.find_last_of("\\/");
    if (slash == std::string::npos) return ".";
    return path.substr(0, slash);
}

std::string join_path(const std::string& directory, const std::string& name) {
    if (directory.empty()) return name;
    const char last = directory[directory.size() - 1];
    if (last == '\\' || last == '/') return directory + name;
    return directory + "\\" + name;
}

bool ensure_directory(const std::string& path) {
    if (path.empty()) return false;
    if (CreateDirectoryA(path.c_str(), NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
        return true;
    }

    // Create the parents first, walking the separators.
    std::string partial;
    for (size_t i = 0; i < path.size(); ++i) {
        partial.push_back(path[i]);
        const bool separator = path[i] == '\\' || path[i] == '/';
        if (!separator && i + 1 != path.size()) continue;

        std::string candidate = partial;
        while (!candidate.empty() &&
               (candidate.back() == '\\' || candidate.back() == '/')) {
            candidate.pop_back();
        }
        // "C:" alone is a drive, not a directory to create.
        if (candidate.empty() || (candidate.size() == 2 && candidate[1] == ':')) continue;
        if (!CreateDirectoryA(candidate.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
            return false;
        }
    }
    return true;
}

bool write_file(const std::string& path, const std::string& data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) return false;
    out.write(data.data(), (std::streamsize)data.size());
    out.close();
    return out.good();
}
