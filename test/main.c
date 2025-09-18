#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#define PORT 1337
#define BUFFER_SIZE 256
#define MAX_CONN 10
#define MAX_EVENTS 10

int make_socket_nonblocking(int fd){
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int main(void){
    char buffer[BUFFER_SIZE];
    // socket
    int serv_fd, cli_fd_tmp, nfds;
    struct sockaddr_in addr, cli_addr;

    serv_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(serv_fd == -1) { perror("serv_fd"); exit(1); }

    int opt = 1;
    setsockopt(serv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(serv_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("bind"); exit(1);
    }

    if (listen(serv_fd, MAX_CONN) == -1) {
        perror("listen"); exit(1);
    }
    
    make_socket_nonblocking(serv_fd);

    // epoll
    struct epoll_event tmp_event, ep_events[MAX_EVENTS];
    int epfd = epoll_create1(0);

    tmp_event.events = EPOLLIN;          // Level Triggered
    tmp_event.data.fd = serv_fd;

    if(epoll_ctl(epfd, EPOLL_CTL_ADD, serv_fd, &tmp_event) == -1){
        perror("epoll_ctl"); exit(1);
    }

    socklen_t cli_addr_len = sizeof(cli_addr);
    for(;;){
        nfds = epoll_wait(epfd, ep_events, MAX_EVENTS, -1);
        for(int i = 0; i < nfds; ++i){
            if(ep_events[i].data.fd == serv_fd){
                printf("servfd\n");
                cli_fd_tmp = accept(serv_fd, (struct sockaddr *) &cli_addr, &cli_addr_len); // like `read()`, `accept()` can also return EAGAIN.
                if(cli_fd_tmp == -1 && errno == EAGAIN) continue;                           // continue the loop on EAGAIN

                // Add client to epoll instance
                tmp_event.events = EPOLLIN | EPOLLET;
                tmp_event.data.fd = cli_fd_tmp;
                epoll_ctl(epfd, EPOLL_CTL_ADD, cli_fd_tmp, &tmp_event);

                // Make client socket non-blocking
                make_socket_nonblocking(cli_fd_tmp);
                
                char client_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &cli_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
                printf("Client's addr : %s\n", client_ip);
                printf("Client's port : %hu\n", ntohs(cli_addr.sin_port));

            }else{
                cli_fd_tmp = ep_events[i].data.fd;
                // printf("client_fd : %d\n", cli_fd_tmp);
                while(1){
                    int n_read = read(cli_fd_tmp, buffer, BUFFER_SIZE);
                    if(n_read == -1){
                        if(errno == EAGAIN || errno == EWOULDBLOCK){
                            printf("no more data for now\n");
                            break; // no more data for now
                        }else{
                            exit(1);
                            break;
                        }
                    }
                    printf("n_read : %d\n", n_read);
                    buffer[n_read] = '\0';
                    printf("%s\n", buffer);
                    fflush(stdout);
                    break;
                }
            }
        }
    }

    return 0;
}

