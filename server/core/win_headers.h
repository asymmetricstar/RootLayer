// server/core/win_headers.h
//
// Common Windows + STL includes for every server translation unit.
// winsock2.h MUST be included before windows.h.
#ifndef ROOTLAYER_SERVER_WIN_HEADERS_H
#define ROOTLAYER_SERVER_WIN_HEADERS_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <setupapi.h>
#include <netioapi.h>
#include <shellapi.h>
#include <aclapi.h>
#include <gdiplus.h>
#include <objbase.h>
#include <cwchar>
#include <atomic>
#include <random>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <ctime>
#include <fstream>
#include <set>
#include <deque>
#include <memory>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstdlib>

#include "sqlite3.h"

#endif  // ROOTLAYER_SERVER_WIN_HEADERS_H
