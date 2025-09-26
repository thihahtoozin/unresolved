#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#include "dns.h"
#include "client.h"
#include "zoneloader.h"
#include "handle_dns.h"
#include "config.h"

#define BUFFER_SIZE 1232
#define MAX_EVENTS 64

int make_socket_nonblocking(int fd){
    int flags = fcntl(fd, F_GETFL, 0);
    if(flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void log_msg(client_t client){
    /* Print log messages in a format */
    char time_fmt_str[32], loc_str[32];
    time_t now = time(NULL);
    struct tm *loctime = localtime(&now);
 
    strftime(time_fmt_str, sizeof(time_fmt_str), "%Y-%m-%d %H:%M:%S", loctime);                 // Time
    snprintf(loc_str, sizeof(loc_str), "%s", client.req_loc == REQ_LOC ? "Local" : "Remote");   // Local | Remote

    printf("[%s]\t%s:%d\t%s\t[%s]\n", time_fmt_str, client.ip, client.port, client.req.query.question, loc_str);
}

int main(int argc, char **argv){
    // Resolving arguments
    if(argc != 3){
        fprintf(stderr, "Usage:\n\t%s <ip> <port>\n", argv[0]);
        return EXIT_SUCCESS;
    }
    const char *serv_ip = argv[1];
    unsigned short serv_port = atoi(argv[2]);
    const char *ext_serv_ip = EXT_SERV;
    unsigned short ext_serv_port = EXT_SERV_PORT;

    // Creating server socket
    int serv_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(serv_sock == -1){
        perror("Failed to create server socket");
        exit(EXIT_FAILURE);
    }

    // Setting socket option
    int opt = 1;
    if (setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        exit(EXIT_FAILURE);
    }
 
    // Creating the socket of making upstream request
    int upstream_sock = socket(AF_INET, SOCK_DGRAM, 0);

    make_socket_nonblocking(serv_sock);
    make_socket_nonblocking(upstream_sock);

    /* ADDRESS STRUCTURE */
    // Create the Address Structure for server
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(serv_port);
    inet_pton(AF_INET, serv_ip, &serv_addr.sin_addr);

    if(bind(serv_sock, (const struct sockaddr *) &serv_addr, (socklen_t) sizeof(serv_addr)) < 0){
        perror("bind() failed");
        exit(EXIT_FAILURE);
    }

    // Create the Address Structure for external server
    struct sockaddr_in ext_serv_addr;
    memset(&ext_serv_addr, 0, sizeof(ext_serv_addr));
    ext_serv_addr.sin_family = AF_INET;
    ext_serv_addr.sin_port = htons(ext_serv_port);
    inet_pton(AF_INET, ext_serv_ip, &ext_serv_addr.sin_addr);

    /* EPOLL */
    struct epoll_event tmp_ev, ep_events[MAX_EVENTS];
    int epfd = epoll_create1(0);
    tmp_ev.events = EPOLLIN;
    tmp_ev.data.fd = serv_sock;
    epoll_ctl(epfd, EPOLL_CTL_ADD, serv_sock, &tmp_ev);

    tmp_ev.data.fd = upstream_sock;
    epoll_ctl(epfd, EPOLL_CTL_ADD, upstream_sock, &tmp_ev);

    /* Reading ZONE FILE */
    zone_t zone;
    parse_zone_file(ZONE_FILE, &zone);

    /* Display TTL and Origin */
    printf("zone.ttl\t%u\n", zone.ttl);
    printf("zone.origin\t%s\n", zone.origin);

    /* Display SOA */
    printf("SOA Rrecord\n");
    printf("MNAME   : %s\n", zone.soa.mname);
    printf("RNAME   : %s\n", zone.soa.rname); 
    printf("Serial  : %u\n", zone.soa.serial);
    printf("Refresh : %u\n", zone.soa.refresh);
    printf("Retry   : %u\n", zone.soa.retry);
    printf("Expire  : %u\n", zone.soa.expire);
    printf("Min TTL : %u\n", zone.soa.min_ttl);

    /* Display records */
    printf("Records\n");
    for(size_t i = 0; i < zone.n_records; i++){
        printf("%s\t%s\t%s\t%s\n", zone.records[i].name, zone.records[i].rec_class, zone.records[i].type, zone.records[i].value);
    }

    /* MAIN LOOP */
    for(;;){
        char buffer[BUFFER_SIZE];
        int nfds = epoll_wait(epfd, ep_events, MAX_EVENTS, -1);

        /* Temporary Client Instance */
        /*
        * Since we are using UDP, we are not tracking each client unless it is in the pending (forwarding)
        * state and waiting for the response. Otherwise, we will respond the client immediately and forgets
        * it.
        */
        client_t client;

        for(int i = 0; i < nfds; i++){
            int fd = ep_events[i].data.fd;
            if(fd == serv_sock){

                socklen_t addr_len = sizeof(client.addr);
                ssize_t bytes_recv = recvfrom(serv_sock, buffer, sizeof(buffer), 0, (struct sockaddr *) &client.addr, &addr_len);
                if(bytes_recv < 0){
                    perror("recvfrom()");
                    close(serv_sock);
                    exit(EXIT_FAILURE);
                }
                read_request(buffer, &client);
                client.port = client.addr.sin_port;
                inet_ntop(AF_INET, &client.addr.sin_addr, client.ip, INET_ADDRSTRLEN);

                int found = handle_dns(buffer, bytes_recv, serv_sock, upstream_sock, &client, &zone, addr_len, ext_serv_addr);
                client.req_loc = found == 1 ? REQ_LOC : REQ_EXT;
                log_msg(client);

            }else if(fd == upstream_sock){
                /* Handle downstream response */
                forward_downstream(serv_sock, upstream_sock);

            }else{
                fprintf(stderr, "fd is neither server serv_sock nor upstream_sock\n");
            }
        }
    }

    close(serv_sock);

    return EXIT_SUCCESS;
}

