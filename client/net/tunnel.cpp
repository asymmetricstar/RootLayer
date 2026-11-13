// client/net/tunnel.cpp - TAP <-> UDP frame pump threads.
#include "core/win_headers.h"
#include "core/state.h"
#include "core/json.h"
#include "net/tunnel.h"

void tap_to_udp_thread() {
    char buffer[65535];
    DWORD bytes_read = 0;
    int consecutive_failures = 0;

    OVERLAPPED ov;
    ZeroMemory(&ov, sizeof(ov));
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (ov.hEvent == NULL) {
        json_event("error", "\"code\":\"tap_read_event_failed\",\"win_error\":" + std::to_string(GetLastError()));
        return;
    }

    while (tap_device != INVALID_HANDLE_VALUE && udp_sock != INVALID_SOCKET) {
        ResetEvent(ov.hEvent);
        ov.Offset = 0;
        ov.OffsetHigh = 0;
        bytes_read = 0;

        if (!ReadFile(tap_device, buffer, sizeof(buffer), &bytes_read, &ov)) {
            DWORD error = GetLastError();

            if (g_shutdown || tap_device == INVALID_HANDLE_VALUE || udp_sock == INVALID_SOCKET) {
                break;
            }

            if (error == ERROR_IO_PENDING) {
                // Wait in slices so shutdown and adapter reconfiguration are
                // noticed while the read is still in flight.
                bool cancelled = false;
                for (;;) {
                    if (WaitForSingleObject(ov.hEvent, 500) == WAIT_OBJECT_0) break;
                    if (g_shutdown || tap_device == INVALID_HANDLE_VALUE ||
                        udp_sock == INVALID_SOCKET) {
                        CancelIo(tap_device);
                        cancelled = true;
                        break;
                    }
                }
                if (cancelled) break;
                if (!GetOverlappedResult(tap_device, &ov, &bytes_read, FALSE)) {
                    error = GetLastError();
                } else {
                    error = ERROR_SUCCESS;
                }
            } else {
                bytes_read = 0;
            }

            if (error != ERROR_SUCCESS) {
                // Assigning the adapter address or changing its media status
                // aborts a pending read with ERROR_OPERATION_ABORTED. The device
                // stays usable, so retry instead of tearing the tunnel down.
                if (error == ERROR_OPERATION_ABORTED || error == ERROR_NOT_READY) {
                    ++consecutive_failures;
                    if (consecutive_failures == 20) {
                        json_event("warning", "\"code\":\"tap_read_retrying\",\"win_error\":" + std::to_string(error));
                    }
                    Sleep(100);
                    continue;
                }

                json_event("error", "\"code\":\"tap_read_failed\",\"win_error\":" + std::to_string(error));
                break;
            }
        }

        consecutive_failures = 0;

        if (bytes_read > 0) {
            sockaddr_in target;
            {
                std::lock_guard<std::mutex> lock(tunnel_mutex);
                if (!peer_valid) {
                    if (fallback_target_valid) {
                        target = fallback_target;  // probe the relay until peer is known
                    } else {
                        continue;  // no target at all, drop the packet
                    }
                } else {
                    target = peer_addr;
                }
            }
            sendto(udp_sock, buffer, bytes_read, 0, (sockaddr*)&target, sizeof(target));
            frames_from_tap++;
        }
    }
    CloseHandle(ov.hEvent);
}

void udp_to_tap_thread() {
    char buffer[65535];
    sockaddr_in sender_addr;
    int sender_addr_len = sizeof(sender_addr);

    OVERLAPPED wov;
    ZeroMemory(&wov, sizeof(wov));
    wov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (wov.hEvent == NULL) {
        json_event("error", "\"code\":\"tap_write_event_failed\",\"win_error\":" + std::to_string(GetLastError()));
        return;
    }

    while (tap_device != INVALID_HANDLE_VALUE && udp_sock != INVALID_SOCKET) {
        sender_addr_len = sizeof(sender_addr);
        int bytes_received = recvfrom(udp_sock, buffer, sizeof(buffer), 0, (sockaddr*)&sender_addr, &sender_addr_len);
        if (bytes_received > 0) {
            // The relay is the only sender on this socket. Follow its source
            // address in case a NAT rewrote the port.
            {
                std::lock_guard<std::mutex> lock(tunnel_mutex);
                peer_addr = sender_addr;
                peer_valid = true;
            }

            ResetEvent(wov.hEvent);
            wov.Offset = 0;
            wov.OffsetHigh = 0;
            DWORD bytes_written = 0;
            BOOL written = WriteFile(tap_device, buffer, (DWORD)bytes_received, &bytes_written, &wov);
            DWORD win_error = written ? ERROR_SUCCESS : GetLastError();
            if (!written && win_error == ERROR_IO_PENDING) {
                if (WaitForSingleObject(wov.hEvent, 5000) == WAIT_OBJECT_0 &&
                    GetOverlappedResult(tap_device, &wov, &bytes_written, FALSE)) {
                    written = TRUE;
                } else {
                    win_error = GetLastError();
                    CancelIo(tap_device);
                }
            }
            if (!written) {
                // A reconfiguration aborts the pending write; the frame is lost
                // but the tunnel stays up.
                if (win_error == ERROR_OPERATION_ABORTED || win_error == ERROR_NOT_READY) {
                    continue;
                }
                json_event("error", "\"code\":\"tap_write_failed\",\"win_error\":" + std::to_string(win_error));
                break;
            }
            frames_to_tap++;
        } else {
            if (g_shutdown || udp_sock == INVALID_SOCKET) {
                break;
            }
            // A UDP socket can report transient errors (for example
            // WSAECONNRESET after an ICMP port unreachable); keep listening.
            Sleep(10);
        }
    }
    CloseHandle(wov.hEvent);
}
