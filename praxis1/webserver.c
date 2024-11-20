#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#define BACKLOG 10
#define BUFFER_SIZE 8192


static struct sockaddr_in derive_sockaddr(const char* host, const char* port);
void *get_in_addr(struct sockaddr *sa);
void sigchld_handler(int s);

int main(int argc, char *argv[]) {
    // printf("ADDR: %s\n", argv[1]);
    // printf("PORT: %s\n", argv[2]);

    int status, sockfd;
    int optval = 1;
    struct addrinfo hints, *res;
    struct sockaddr_storage their_addr;
    struct sigaction sa;
    char s[INET6_ADDRSTRLEN];
    
    memset(&hints, 0, sizeof hints); // make sure the struct is empty
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
    hints.ai_flags = AI_PASSIVE;     // fill in my IP for me
    
    
    if ((status = getaddrinfo(argv[1], argv[2], &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        exit(1);
    }

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    
    // struct sockaddr_in _sockaddr = derive_sockaddr(argv[1], argv[2]);
    // printf("PARSED ADDR: %d\n", _sockaddr.sin_addr.s_addr);
    // printf("PARSED PORT: %d\n", _sockaddr.sin_port);
    
    bind(sockfd, res->ai_addr, res->ai_addrlen);

    // set SO_REUSEADDR on a socket to true (1):
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);

    printf("Listen Status: %d\n", listen(sockfd, BACKLOG));

    printf("Listening on port %s...\n", argv[2]);

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    socklen_t addr_size = sizeof their_addr;
    int new_fd;

    while(1) {  // main accept() loop
        addr_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &addr_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
        printf("server: got connection from %s\n", s);

        if (!fork()) { // this is the child process
            close(sockfd); // child doesn't need the listener

            char buffer[BUFFER_SIZE];
            int bytes_received;
            char *msg = "Reply\r\n\r\n";
            int len, bytes_sent;
            len = strlen(msg);

            while (1) {
                // Receive data from the client
                memset(buffer, 0, sizeof(buffer));
                bytes_received = recv(new_fd, buffer, sizeof(buffer) - 1, 0);

                if (bytes_received <= 0) {
                    if (bytes_received == 0) {
                        printf("Client disconnected.\n");
                    } else {
                        perror("recv failed");
                    }
                    break; 
                }

                if (bytes_received == 2 && buffer[0] == '\r' && buffer[1] == '\n') {
                    printf("Packet end detected.\n");
                    break;
                }

                printf("Received %d bytes: %s\n", bytes_received, buffer);

                // Send a reply for the current request
            
                int bytes_sent = send(new_fd, msg, len, 0);
                if (bytes_sent < 0) {
                    perror("send failed");
                    break; // Exit the loop
                }
                printf("sent %s\n", msg);
            }

            close(new_fd);
            exit(0);
        }
        close(new_fd);  // parent doesn't need this
    }

    return 0;
}

static struct sockaddr_in derive_sockaddr(const char* host, const char* port) {
    struct addrinfo hints = {
    .ai_family = AF_INET,
    };
    struct addrinfo *result_info;

    // Resolve the host (IP address or hostname) into a list of possible addresses.
    int returncode = getaddrinfo(host, port, &hints, &result_info);
    if (returncode) {
        fprintf(stderr, "Error␣parsing␣host/port");
        exit(EXIT_FAILURE);
    }

    // Copy the sockaddr_in structure from the first address in the list
    struct sockaddr_in result = *((struct sockaddr_in*) result_info->ai_addr);

    // Free the allocated memory for the result_info
    freeaddrinfo(result_info);
    return result;
}


void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}