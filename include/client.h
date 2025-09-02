#ifndef CLIENT_H
#define CLIENT_H

#include <netinet/in.h>
#include "dns.h"

typedef struct{
    char ip[INET_ADDRSTRLEN];
    unsigned short port;
    struct sockaddr_in addr;
    dns_t req;
}client_t;

#endif
