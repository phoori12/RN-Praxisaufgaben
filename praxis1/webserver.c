#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define BACKLOG 10
#define BUFFER_SIZE 1024


static struct sockaddr_in derive_sockaddr(const char* host, const char* port);

int main(int argc, char *argv[]) {
    printf("ADDR: %s\n", argv[1]);
    printf("PORT: %s\n", argv[2]);

    int status, sockfd;
    int optval = 1;
    struct addrinfo hints, *res;
    struct sockaddr_storage their_addr;
    
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

    socklen_t addr_size = sizeof their_addr;
    int new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &addr_size);

    // char buffer[BUFFER_SIZE];
    // int bytes_received;
    // memset(buffer, 0, BUFFER_SIZE); // Clear the buffer
    // bytes_received = recv(new_fd, buffer, BUFFER_SIZE - 1, 0); // Read data
    // printf("%s\n", bytes_received);

    char *msg = "Reply";
    int len, bytes_sent;
    len = strlen(msg);
    bytes_sent = send(new_fd, msg, len, 0);

    close(sockfd);
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