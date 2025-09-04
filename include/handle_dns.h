#ifndef HANDLE_DNS_H
#define HANDLE_DNS_H

#include <sys/socket.h>

void read_request(const char *buffer, client_t *client);

void write_response(const char *buffer, ssize_t bytes_recv, int serv_sock, client_t *client, zone_t zone, socklen_t addr_len, struct sockaddr_in ext_serv_addr);

int parse_question(const char *buffer, int offset, dns_query_t *query);

#endif
