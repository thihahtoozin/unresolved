#include <globals.h>
#include "dns.h"

uint16_t txid_counter = 1;
// uint16_t upstream_txid = 1;
pending_query_t pending_queries[MAX_PENDINGS];

