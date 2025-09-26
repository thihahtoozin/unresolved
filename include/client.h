#ifndef CLIENT_H
#define CLIENT_H

#include <netinet/in.h>
#include "dns.h"

typedef enum { REQ_LOC, REQ_EXT } client_req_t;

typedef struct{

    /* Address */
    char ip[INET_ADDRSTRLEN];
    unsigned short port;
    struct sockaddr_in addr;

    /* DNS Query */
    dns_t req;

    /* Request Type */
    client_req_t req_loc;

}client_t;

#endif

