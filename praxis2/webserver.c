#include <pthread.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "data.h"
#include "http.h"
#include "util.h"

#define MAX_RESOURCES 100
#define MAX_REQUESTS 10

struct tuple resources[MAX_RESOURCES] = {
    {"/static/foo", "Foo", sizeof "Foo" - 1},   // "/static/foo" 44834
    {"/static/bar", "Bar", sizeof "Bar" - 1},   // "/static/bar" 45104
    {"/static/baz", "Baz", sizeof "Baz" - 1}};  // "/static/baz" 43056

struct message {
    uint8_t message_type;           // 1 byte
    uint16_t hash_id;               // 2 bytes
    uint16_t node_id;               // 2 bytes
    struct in_addr ip_address;      // 4 bytes 
    uint16_t node_port;             // 2 bytes
} __attribute__((packed));

struct lookup_request {
    uint16_t hash_id;               // Unique identifier for the request
    char node_ip[INET_ADDRSTRLEN];  // Node IP (IPv4 as string, e.g., "127.0.0.1")
    uint16_t node_port;             // Node port
};

struct tcp_thread_args {
    int server_socket;      // TCP server socket
    int datagram_socket;    // UDP socket
};

int request_count = 0;      // Tracks the number of stored requests
struct lookup_request requests[MAX_REQUESTS];

char *PRED_ID, *PRED_IP, *PRED_PORT, *SUCC_ID, *SUCC_IP, *SUCC_PORT, *ID, *IP, *PORT;

void send_reply(int conn, struct request *request, int udp_socket);
size_t process_packet(int conn, char *buffer, size_t n, int udp_socket);
static void connection_setup(struct connection_state *state, int sock);
char *buffer_discard(char *buffer, size_t discard, size_t keep);
bool handle_connection(struct connection_state *state, int udp_socket);
static struct sockaddr_in derive_sockaddr(const char *host, const char *port);
static int setup_server_socket(struct sockaddr_in addr);
static int setup_datagram_socket(const char *host, const char *port);
void send_udp_message(int socket ,uint8_t message_type, uint16_t hash_id, uint16_t node_id, char* ip_address, uint16_t node_port, struct in_addr send_ip, uint16_t send_port);
void add_request(struct lookup_request new_request);
int has_request(uint16_t hash_id);
void find_and_write(uint16_t hash_id, char* ip, char* port);
int fetch_req_index(uint16_t hash_id, uint16_t current_id);
int normal_fetch_index(uint16_t hash_id);
void *tcp_thread_function(void *arg);
void *udp_thread_function(void *arg);
void print_lookup_requests(struct lookup_request* requests, size_t count);

void *tcp_thread_function(void *args) {
    struct tcp_thread_args *thread_args = (struct tcp_thread_args *)args;
    int server_socket = thread_args->server_socket;
    int datagram_socket = thread_args->datagram_socket;
    // Create an array of pollfd structures to monitor sockets.
    struct pollfd sockets[2] = {
        {.fd = server_socket, .events = POLLIN},
    };

    struct connection_state state = {0};

    while (true) {
        int ready = poll(sockets, sizeof(sockets) / sizeof(sockets[0]), -1);
        if (ready == -1) {
            perror("poll");
            exit(EXIT_FAILURE);
        }

        // Process events on the monitored sockets.
        for (size_t i = 0; i < sizeof(sockets) / sizeof(sockets[0]); i += 1) {
            if (sockets[i].revents != POLLIN) {
                // If there are no POLLIN events on the socket, continue to the
                // next iteration.
                continue;
            }
            int s = sockets[i].fd;

            if (s == server_socket) {

                // If the event is on the server_socket, accept a new connection
                // from a client.
                int connection = accept(server_socket, NULL, NULL);
                if (connection == -1 && errno != EAGAIN &&
                    errno != EWOULDBLOCK) {
                    close(server_socket);
                    perror("accept");
                    exit(EXIT_FAILURE);
                } else {
                    connection_setup(&state, connection);

                    // limit to one connection at a time
                    sockets[0].events = 0;
                    sockets[1].fd = connection;
                    sockets[1].events = POLLIN;
                }
            } else {
                assert(s == state.sock);

                // Call the 'handle_connection' function to process the incoming
                // data on the socket.
                bool cont = handle_connection(&state, datagram_socket);
                if (!cont) { // get ready for a new connection
                    sockets[0].events = POLLIN;
                    sockets[1].fd = -1;
                    sockets[1].events = 0;
                }
            }
        }
    }
    return NULL;
}

void *udp_thread_function(void *arg) {
    int datagram_socket = *(int *)arg;

    while (true) {
        // Handle message forwarding and reply logic
        char buffer[1024];
        struct sockaddr_in sender_addr;
        socklen_t addr_len = sizeof(sender_addr);

        ssize_t num_bytes = recvfrom(datagram_socket, buffer, sizeof(buffer), 0,
                                    (struct sockaddr *)&sender_addr, &addr_len);
        if (num_bytes == -1) {
            // perror("recvfrom");
            continue;
        }

        if (num_bytes < (ssize_t)sizeof(struct message)) {
            fprintf(stderr, "Received message is too short to unpack\n");
            continue;
        }

        // Cast the buffer to a pointer to your struct message
        struct message *received_msg = (struct message *)buffer;

        // Access the fields of the unpacked struct
        // printf("Received UDP message:\n");
        // printf("  Message Type: %u\n", received_msg->message_type);
        // printf("  PRED ID: %u\n", atoi(PRED_ID)); 
        // printf("  CURR ID: %u\n", atoi(ID)); 
        // printf("  Hash ID: %u\n", ntohs(received_msg->hash_id));  // Convert from network to host byte order
        // printf("  SUCC ID: %u\n", atoi((SUCC_ID))); 
        // printf("  Node ID: %u\n", ntohs(received_msg->node_id));  // Convert from network to host byte order
        // char ip_str[INET_ADDRSTRLEN];
        // inet_ntop(AF_INET, &received_msg->ip_address, ip_str, sizeof(ip_str)); // Convert IP to string
        // printf("  IP Address: %s\n", ip_str);
        // printf("  Node Port: %u\n", ntohs(received_msg->node_port)); 
        // printf("  SUCC IP: %s\n", SUCC_IP);
        // printf("  SUCC Port: %s\n", SUCC_PORT); 

        if (received_msg->message_type == 0) {
           
            if ((ntohs(received_msg->hash_id) > atoi(ID) && ntohs(received_msg->hash_id) < atoi(SUCC_ID))
            || (atoi(ID) > atoi(SUCC_ID) && received_msg->hash_id < atoi(ID) && ntohs(received_msg->hash_id) <= atoi(SUCC_ID))
            || (atoi(ID) > atoi(SUCC_ID) && received_msg->hash_id > atoi(ID) && ntohs(received_msg->hash_id) >= atoi(SUCC_ID))) { // Successor responsible
                send_udp_message(datagram_socket , 1, htons(atoi(ID)), htons(atoi(SUCC_ID)), SUCC_IP, htons(atoi(SUCC_PORT)), 
                received_msg->ip_address, received_msg->node_port);
            } 
            else { // forward lookup
                struct sockaddr_in udp_addr;
                memset(&udp_addr, 0, sizeof(udp_addr));
                udp_addr.sin_family = AF_INET;
                udp_addr.sin_port = htons(atoi(SUCC_PORT));         
                inet_pton(AF_INET, SUCC_IP, &udp_addr.sin_addr); 

                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &received_msg->ip_address, ip_str, sizeof(ip_str));
                send_udp_message(datagram_socket , received_msg->message_type, received_msg->hash_id, received_msg->node_id, 
                ip_str, received_msg->node_port, udp_addr.sin_addr, udp_addr.sin_port);    

            }
            
            
        } else {
            // find lookup in requests[] and write
            int index = fetch_req_index(received_msg->hash_id, ntohs(received_msg->node_id));
            if (index >= 0) {
                // printf("request found overwriting...\n");
                inet_ntop(AF_INET, &received_msg->ip_address, requests[index].node_ip, sizeof(requests[index].node_ip));
                requests[index].node_port = ntohs(received_msg->node_port);
            } else {
                // printf("request not found\n");
                perror("hash not found");
            }
        }
                
    }
    return NULL;
}

/**
 *  Call as:
 *
 *  ./build/webserver self.ip self.port
 * 
 *  Or:
 * 
 *  PRED_ID=49152 PRED_IP=127.0.0.1 PRED_PORT=2002 SUCC_ID=49152 SUCC_IP=127.0.0.1 SUCC_PORT=2002 ./build/webserver 127.0.0.1 2001 16384
 *  
 */
int main(int argc, char **argv) {
    // uint16_t h1 = pseudo_hash("/static/foo", sizeof "/static/foo" - 1);
    // uint16_t h2 = pseudo_hash("/static/bar", sizeof "/static/bar" - 1);
    // uint16_t h3 = pseudo_hash("/static/baz", sizeof "/static/baz" - 1);
    // printf("%d , %d, %d \n", h1,h2,h3);
    PRED_ID = getenv("PRED_ID");
    PRED_IP = getenv("PRED_IP");
    PRED_PORT = getenv("PRED_PORT");
    SUCC_ID = getenv("SUCC_ID");
    SUCC_IP = getenv("SUCC_IP");
    SUCC_PORT = getenv("SUCC_PORT");
    if (argc > 3) {
        ID = argv[3];
    } else {
        ID = "0"; 
    }
    IP = argv[1];
    PORT = argv[2];

    memset(requests, 0, sizeof(requests));
    
    // printf("PRED_ID=%s, PRED_IP=%s, PRED_PORT=%s, SUCC_ID=%s, SUCC_IP=%s, SUCC_PORT=%s, ID=%s\n", 
    // PRED_ID, PRED_IP, PRED_PORT, SUCC_ID, SUCC_IP, SUCC_PORT, ID);

    struct sockaddr_in addr = derive_sockaddr(argv[1], argv[2]);

    // Set up a server socket.
    int server_socket = setup_server_socket(addr);

    // Set up a datagram socket
    int datagram_socket = setup_datagram_socket(argv[1], argv[2]);

    struct tcp_thread_args *args = malloc(sizeof(struct tcp_thread_args));
    if (!args) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    args->server_socket = server_socket;
    args->datagram_socket = datagram_socket;


    pthread_t tcp_thread, udp_thread;
    if (pthread_create(&tcp_thread, NULL, tcp_thread_function, (void *)args) != 0) {
        perror("pthread_create (TCP)");
        free(args);
        exit(EXIT_FAILURE);
    }
    if (pthread_create(&udp_thread, NULL, udp_thread_function, &datagram_socket) != 0) {
        perror("pthread_create (UDP)");
        exit(EXIT_FAILURE);
    }

    // Wait for threads to finish (optional)
    pthread_join(tcp_thread, NULL);
    pthread_join(udp_thread, NULL);

    // Clean up
    close(server_socket);
    close(datagram_socket);

    return EXIT_SUCCESS;
   
}

/**
 * Sends an HTTP reply to the client based on the received request.
 *
 * @param conn      The file descriptor of the client connection socket.
 * @param request   A pointer to the struct containing the parsed request
 * @param upd_socket UDP Socket for DHT lookups
 * information.
 */
void send_reply(int conn, struct request *request, int udp_socket) {

    // Create a buffer to hold the HTTP reply
    char buffer[HTTP_MAX_SIZE];
    char *reply = buffer;
    size_t offset = 0;

    // fprintf(stderr, "Handling %s request for %s (%lu byte payload)\n",
    //         request->method, request->uri, request->payload_length);

    uint16_t uri_hash = pseudo_hash((const unsigned char *)request->uri, strlen(request->uri));
    
    char uri_hash_string[6];  // Buffer to hold the string representation of the number (5 digits + null terminator)
    snprintf(uri_hash_string, sizeof(uri_hash_string), "%u", uri_hash);
    printf("%s\n", uri_hash_string);

    if ((uri_hash < atoi(ID) && uri_hash >= atoi(PRED_ID)) // || (strcmp(PRED_ID, SUCC_ID) == 0 && uri_hash != atoi(ID)) 
    || (uri_hash <= atoi(ID) && uri_hash < atoi(PRED_ID) && atoi(PRED_ID) > atoi(ID))
    || (uri_hash >= atoi(ID) && uri_hash > atoi(PRED_ID) && atoi(PRED_ID) > atoi(ID))) { // nothing to look for
    //    fprintf(stderr,"responsible node found %d: %d\n", uri_hash, atoi(ID));
        // snprintf(reply, HTTP_MAX_SIZE, "HTTP/1.1 303 See Other\r\nLocation:%s:%s%s\r\nContent-Length: 0\r\n\r\n", SUCC_IP, SUCC_PORT, request->uri);
       if (strcmp(request->method, "GET") == 0) {
        // Find the resource with the given URI in the 'resources' array.
            size_t resource_length;
            const char *resource =
                get(request->uri, resources, MAX_RESOURCES, &resource_length);

            if (resource) {
                size_t payload_offset =
                    sprintf(reply, "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\n\r\n",
                            resource_length);
                memcpy(reply + payload_offset, resource, resource_length);
                offset = payload_offset + resource_length;
            } else {
                reply = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                offset = strlen(reply);
            }
        } else if (strcmp(request->method, "PUT") == 0) {
            // Try to set the requested resource with the given payload in the
            // 'resources' array.
            if (set(request->uri, request->payload, request->payload_length,
                    resources, MAX_RESOURCES)) {
                reply = "HTTP/1.1 204 No Content\r\n\r\n";
            } else {
                reply = "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
            }
            offset = strlen(reply);
        } else if (strcmp(request->method, "DELETE") == 0) {
            // Try to delete the requested resource from the 'resources' array
            if (delete (request->uri, resources, MAX_RESOURCES)) {
                reply = "HTTP/1.1 204 No Content\r\n\r\n";
            } else {
                reply = "HTTP/1.1 404 Not Found\r\n\r\n";
            }
            offset = strlen(reply);
        } else {
            reply = "HTTP/1.1 501 Method Not Supported\r\n\r\n";
            offset = strlen(reply);
        }
    } else {
        //  fprintf(stderr,"responsible node NOT found\n");
        if (!has_request(uri_hash)) {
            
            if (uri_hash > atoi(ID) && uri_hash < atoi(SUCC_ID)) {
                snprintf(reply, HTTP_MAX_SIZE, "HTTP/1.1 303 See Other\r\nLocation: http://%s:%s%s\r\nContent-Length: 0\r\n\r\n", 
                        SUCC_IP, SUCC_PORT, request->uri);
            } else {
                reply = "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\nContent-Length: 0\r\n\r\n";
                // Send the lookup request (uri_hash and uri)
                struct sockaddr_in udp_addr;
                memset(&udp_addr, 0, sizeof(udp_addr));
                udp_addr.sin_family = AF_INET;
                udp_addr.sin_port = htons(atoi(SUCC_PORT));          
                inet_pton(AF_INET, SUCC_IP, &udp_addr.sin_addr);      

                send_udp_message(udp_socket, 0, htons(uri_hash), htons(atoi(ID)), IP, htons(atoi(PORT)), udp_addr.sin_addr, udp_addr.sin_port);

                struct lookup_request new_request;
                memset(&new_request, 0, sizeof(new_request));
                new_request.hash_id = uri_hash;
                add_request(new_request);
            }
            
        } else {
            // print_lookup_requests(requests, request_count);
            int index = normal_fetch_index(uri_hash); 
            // printf("index: %d\n", index);
            if (requests[index].node_ip == NULL) {
                reply = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            } else {
                char port_str[6]; // Enough to hold a 5-digit port number and a null terminator
                snprintf(port_str, sizeof(port_str), "%u", requests[index].node_port);
                
                snprintf(reply, HTTP_MAX_SIZE, "HTTP/1.1 303 See Other\r\nLocation: http://%s:%s%s\r\nContent-Length: 0\r\n\r\n", 
                        requests[index].node_ip, port_str, request->uri);
            }
            
        }
        offset = strlen(reply);
    }
    
    // Send the reply back to the client
    if (send(conn, reply, offset, 0) == -1) {
        perror("send");
        close(conn);
    }
}

/**
 * Processes an incoming packet from the client.
 *
 * @param conn The socket descriptor representing the connection to the client.
 * @param buffer A pointer to the incoming packet's buffer.
 * @param n The size of the incoming packet.
 *
 * @return Returns the number of bytes processed from the packet.
 *         If the packet is successfully processed and a reply is sent, the
 * return value indicates the number of bytes processed. If the packet is
 * malformed or an error occurs during processing, the return value is -1.
 *
 */
size_t process_packet(int conn, char *buffer, size_t n, int udp_socket) {
    struct request request = {
        .method = NULL, .uri = NULL, .payload = NULL, .payload_length = -1};
    ssize_t bytes_processed = parse_request(buffer, n, &request);

    if (bytes_processed > 0) {
        send_reply(conn, &request, udp_socket);

        // Check the "Connection" header in the request to determine if the
        // connection should be kept alive or closed.
        const string connection_header = get_header(&request, "Connection");
        if (connection_header && strcmp(connection_header, "close")) {
            return -1;
        }
    } else if (bytes_processed == -1) {
        // If the request is malformed or an error occurs during processing,
        // send a 400 Bad Request response to the client.
        const string bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(conn, bad_request, strlen(bad_request), 0);
        printf("Received malformed request, terminating connection.\n");
        close(conn);
        return -1;
    }

    return bytes_processed;
}

/**
 * Sets up the connection state for a new socket connection.
 *
 * @param state A pointer to the connection_state structure to be initialized.
 * @param sock The socket descriptor representing the new connection.
 *
 */
static void connection_setup(struct connection_state *state, int sock) {
    // Set the socket descriptor for the new connection in the connection_state
    // structure.
    state->sock = sock;

    // Set the 'end' pointer of the state to the beginning of the buffer.
    state->end = state->buffer;

    // Clear the buffer by filling it with zeros to avoid any stale data.
    memset(state->buffer, 0, HTTP_MAX_SIZE);
}

/**
 * Discards the front of a buffer
 *
 * @param buffer A pointer to the buffer to be modified.
 * @param discard The number of bytes to drop from the front of the buffer.
 * @param keep The number of bytes that should be kept after the discarded
 * bytes.
 *
 * @return Returns a pointer to the first unused byte in the buffer after the
 * discard.
 * @example buffer_discard(ABCDEF0000, 4, 2):
 *          ABCDEF0000 ->  EFCDEF0000 -> EF00000000, returns pointer to first 0.
 */
char *buffer_discard(char *buffer, size_t discard, size_t keep) {
    memmove(buffer, buffer + discard, keep);
    memset(buffer + keep, 0, discard); // invalidate buffer
    return buffer + keep;
}

/**
 * Handles incoming connections and processes data received over the socket.
 *
 * @param state A pointer to the connection_state structure containing the
 * connection state.
 * @return Returns true if the connection and data processing were successful,
 * false otherwise. If an error occurs while receiving data from the socket, the
 * function exits the program.
 */
bool handle_connection(struct connection_state *state, int udp_socket) {
    // Calculate the pointer to the end of the buffer to avoid buffer overflow
    const char *buffer_end = state->buffer + HTTP_MAX_SIZE;

    // Check if an error occurred while receiving data from the socket
    ssize_t bytes_read =
        recv(state->sock, state->end, buffer_end - state->end, 0);
    if (bytes_read == -1) {
        perror("recv");
        close(state->sock);
        exit(EXIT_FAILURE);
    } else if (bytes_read == 0) {
        return false;
    }

    char *window_start = state->buffer;
    char *window_end = state->end + bytes_read;

    ssize_t bytes_processed = 0;
    while ((bytes_processed = process_packet(state->sock, window_start,
                                             window_end - window_start, udp_socket)) > 0) {
        window_start += bytes_processed;
    }
    if (bytes_processed == -1) {
        return false;
    }

    state->end = buffer_discard(state->buffer, window_start - state->buffer,
                                window_end - window_start);
    return true;
}

/**
 * Derives a sockaddr_in structure from the provided host and port information.
 *
 * @param host The host (IP address or hostname) to be resolved into a network
 * address.
 * @param port The port number to be converted into network byte order.
 *
 * @return A sockaddr_in structure representing the network address derived from
 * the host and port.
 */
static struct sockaddr_in derive_sockaddr(const char *host, const char *port) {
    struct addrinfo hints = {
        .ai_family = AF_INET,
    };
    struct addrinfo *result_info;

    // Resolve the host (IP address or hostname) into a list of possible
    // addresses.
    int returncode = getaddrinfo(host, port, &hints, &result_info);
    if (returncode) {
        fprintf(stderr, "Error parsing host/port");
        exit(EXIT_FAILURE);
    }

    // Copy the sockaddr_in structure from the first address in the list
    struct sockaddr_in result = *((struct sockaddr_in *)result_info->ai_addr);

    // Free the allocated memory for the result_info
    freeaddrinfo(result_info);
    return result;
}

/**
 * Sets up a TCP server socket and binds it to the provided sockaddr_in address.
 *
 * @param addr The sockaddr_in structure representing the IP address and port of
 * the server.
 *
 * @return The file descriptor of the created TCP server socket.
 */
static int setup_server_socket(struct sockaddr_in addr) {
    const int enable = 1;
    const int backlog = 1;

    // Create a socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Avoid dead lock on connections that are dropped after poll returns but
    // before accept is called
    if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
        perror("fcntl");
        exit(EXIT_FAILURE);
    }

    // Set the SO_REUSEADDR socket option to allow reuse of local addresses
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) ==
        -1) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Bind socket to the provided address
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Start listening on the socket with maximum backlog of 1 pending
    // connection
    if (listen(sock, backlog)) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    return sock;
}

static int setup_datagram_socket(const char *host, const char *port) {
    struct addrinfo hints, *servinfo, *p;
    const int enable = 1;
    int rv, sock;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; 
    hints.ai_socktype = SOCK_DGRAM;

    if ((rv = getaddrinfo(host, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        exit(EXIT_FAILURE);
    }
    
    struct sockaddr_in result = *((struct sockaddr_in *)servinfo->ai_addr);

    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sock = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("talker: socket");
            continue;
        }

        break;
    }

    if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
        perror("fcntl");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) ==
        -1) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    if (p == NULL) {
        fprintf(stderr, "talker: failed to create socket\n");
        freeaddrinfo(servinfo);
        exit(EXIT_FAILURE);
    }

    if (bind(sock, (struct sockaddr *)&result, sizeof(result)) == -1) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(servinfo);
    return sock;
}

void send_udp_message(int socket ,uint8_t message_type, uint16_t hash_id, uint16_t node_id, char* ip_address, uint16_t node_port, struct in_addr send_ip, uint16_t send_port) {
    struct message udp_message;
    udp_message.message_type = message_type;
    udp_message.hash_id = hash_id; 
    udp_message.node_id = node_id;
    inet_pton(AF_INET, ip_address, &udp_message.ip_address); // Convert IP address to binary format
    udp_message.node_port = node_port;      // Convert port to network byte order

    // Define the UDP address
    struct sockaddr_in udp_addr;
    memset(&udp_addr, 0, sizeof(udp_addr));
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_port = send_port;          // UDP port (already in network byte order)
    udp_addr.sin_addr = send_ip;
    // inet_pton(AF_INET, send_ip, &udp_addr.sin_addr); 

    // Send the message over UDP
    if (sendto(socket, &udp_message, sizeof(udp_message), 0,
            (struct sockaddr*)&udp_addr, sizeof(udp_addr)) < 0) {
        perror("Failed to send UDP message");
    } 
}

void add_request(struct lookup_request new_request) {
    // If the list is full, overwrite the oldest request
    if (request_count >= MAX_REQUESTS) {
        request_count = 0; // Reset to the start of the array
    }
    requests[request_count] = new_request;
    (request_count)++;
}

int has_request(uint16_t hash_id) {
    for (int i = 0;i < MAX_REQUESTS;i++) {
        if (requests[i].hash_id == hash_id) return 1;
    }
    return 0;
}

void find_and_write(uint16_t hash_id, char* ip, char* port) {
    for (int i = 0; i < MAX_REQUESTS; i++) {
        if (requests[i].hash_id == hash_id) {
            // Safely copy the IP string
            strncpy(requests[i].node_ip, ip, INET_ADDRSTRLEN);
            requests[i].node_ip[INET_ADDRSTRLEN - 1] = '\0'; // Ensure null-termination
            
            // Convert the port from string to uint16_t and assign
            requests[i].node_port = (uint16_t)atoi(port);
            return;
        }
    }
}


int fetch_req_index(uint16_t hash_id, uint16_t current_id) {
    for (int i = 0;i < request_count;i++) {
        if ((requests[i].hash_id >= hash_id && requests[i].hash_id < current_id)
        || (hash_id > current_id && requests[i].hash_id < hash_id && requests[i].hash_id <= current_id)
        || (hash_id > current_id && requests[i].hash_id > hash_id && requests[i].hash_id >= current_id)) return i;
    }
    return -1;
}

int normal_fetch_index(uint16_t hash_id) {
    for (int i = 0;i < request_count;i++) {
        if (requests[i].hash_id == hash_id) return i;
    }
    return -1;
}

void print_lookup_requests(struct lookup_request* requests, size_t count) {
    if (requests == NULL || count == 0) {
        printf("No lookup requests to print.\n");
        return;
    }

    printf("Lookup Requests:\n");
    for (size_t i = 0; i < count; i++) {
        printf("Request %zu:\n", i + 1);
        printf("  Hash ID: %u\n", requests[i].hash_id);
        printf("  Node IP: %s\n", requests[i].node_ip ? requests[i].node_ip : "N/A");
        printf("  Node Port: %u\n", requests[i].node_port);
    }
}
