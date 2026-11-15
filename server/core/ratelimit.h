// server/core/ratelimit.h
//
// Byte token bucket used for the per-client bandwidth cap. One instance limits
// one direction of one session; a rate of 0 means unlimited.
//
// Not internally locked: every path that touches it already holds the session
// registry mutex (sessions_mutex), which is what serialises the relay thread and
// the gateway writer thread.
#ifndef ROOTLAYER_SERVER_RATELIMIT_H
#define ROOTLAYER_SERVER_RATELIMIT_H

#include "core/win_headers.h"

#include <algorithm>

class RateLimit {
public:
    // bytes_per_sec <= 0 disables the limit.
    void set_rate(double bytes_per_sec) {
        const double rate = bytes_per_sec > 0.0 ? bytes_per_sec : 0.0;
        rate_ = rate;
        // One second of burst, but never less than a couple of MTU-sized
        // frames: a 32 kbit/s cap must still let a 1400 byte packet through.
        burst_ = rate > 0.0 ? std::max<double>(rate, 3200.0) : 0.0;
        if (tokens_ > burst_) {
            tokens_ = burst_;
        }
        if (rate <= 0.0) {
            tokens_ = 0.0;
            last_ms_ = 0;
        }
    }

    double rate() const { return rate_; }
    bool unlimited() const { return rate_ <= 0.0; }

    // True when `bytes` may pass now; the bucket is charged either way, so a
    // bursty sender pays for it with the silence that follows.
    bool allow(size_t bytes) {
        if (rate_ <= 0.0) {
            return true;
        }
        const unsigned long long now = GetTickCount64();
        if (last_ms_ == 0) {
            last_ms_ = now;
            tokens_ = burst_;
        }
        const double elapsed = (double)(now - last_ms_) / 1000.0;
        last_ms_ = now;
        tokens_ = std::min(burst_, tokens_ + elapsed * rate_);
        tokens_ -= (double)bytes;
        // A little debt is tolerated so one oversized frame cannot stall the
        // stream; a sustained overrun still drives the bucket negative.
        return tokens_ >= -(double)burst_;
    }

private:
    double rate_ = 0.0;
    double burst_ = 0.0;
    double tokens_ = 0.0;
    unsigned long long last_ms_ = 0;
};

#endif  // ROOTLAYER_SERVER_RATELIMIT_H
