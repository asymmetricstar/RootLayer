
// client/core/win_headers.h
//
// Common Windows + STL includes for every client translation unit.
// winsock2.h MUST be included before windows.h, otherwise the winsock1
// declarations collide and the build fails.
#ifndef ROOTLAYER_WIN_HEADERS_H
#define ROOTLAYER_WIN_HEADERS_H

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

#endif  // ROOTLAYER_WIN_HEADERS_H
