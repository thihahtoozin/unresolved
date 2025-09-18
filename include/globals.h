#ifndef GLOBAL_H
#define GLOBAL_H

#include <stdint.h>
#include "dns.h"

extern uint16_t txid_counter;
// extern uint16_t upstream_txid;
extern pending_query_t pending_queries[MAX_PENDINGS];

#endif
