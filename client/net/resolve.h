
// client/net/resolve.h
//
// One-shot ARPA name resolution (--resolve <name>, headless JSON output) and
// the background probe that feeds the "Zone Network" pill in the panel.
#ifndef ROOTLAYER_RESOLVE_H
#define ROOTLAYER_RESOLVE_H

#include "core/win_headers.h"

int run_arpa_resolve(const std::string& name);

// Background thread: asks the root server's name service (ARPA) for "root"
// over the signaling port every ~15 s and publishes the answer through
// panel_zone_status (1 = zone answering, 2 = zone down).
void zone_worker_thread();

#endif  // ROOTLAYER_RESOLVE_H
