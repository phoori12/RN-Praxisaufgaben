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

#define MAX_HEADER 40
#define HEADER_SIZE 256
#define CONTENT_SIZE 256

#define METHOD_SIZE 10
#define URI_SIZE 256
#define HTTP_VERSION_SIZE 20

#define MAX_DYNAMIC_PATH 100
#define MAX_PATH_DATA 296

#define BAD_REQUEST "HTTP/1.1 400 Bad Request\r\n\r\n"
#define ETC_REQUEST "HTTP/1.1 501 ETC Request\r\n\r\n"
#define FORBIDDEN_REQUEST "HTTP/1.1 403 Forbidden Request\r\n\r\n"


static struct sockaddr_in derive_sockaddr(const char* host, const char* port);
void *get_in_addr(struct sockaddr *sa);
void sigchld_handler(int s);
char* validate_first_token(const char *token);
int validate_key_value_token(const char *token);
char* path_extract(const char *token, char dynamic_paths[MAX_DYNAMIC_PATH][MAX_PATH_DATA]);
char* db_query(const char *path, const char *content, char dynamic_paths[MAX_DYNAMIC_PATH][MAX_PATH_DATA], uint8_t mode);

int main(int argc, char *argv[]) {
    // printf("ADDR: %s\n", argv[1]);
    // printf("PORT: %s\n", argv[2]);

    int status, sockfd, new_fd;
    int optval = 1;
    struct addrinfo hints, *res, *p;
    struct sockaddr_storage their_addr;
    struct sigaction sa;
    char s[INET6_ADDRSTRLEN];
    socklen_t addr_size = sizeof their_addr;
    char dynamic_paths[MAX_DYNAMIC_PATH][MAX_PATH_DATA];
    int dynamic_path_index = 0;

    memset(dynamic_paths, '\0', sizeof(dynamic_paths));
    
    memset(&hints, 0, sizeof hints); // make sure the struct is empty
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
    hints.ai_flags = AI_PASSIVE;     // fill in my IP for me
    
    
    if ((status = getaddrinfo(argv[1], argv[2], &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        exit(1);
    }

    // loop through all the results and bind to the first we can
    for(p = res; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    // struct sockaddr_in _sockaddr = derive_sockaddr(argv[1], argv[2]);
    // printf("PARSED ADDR: %d\n", _sockaddr.sin_addr.s_addr);
    // printf("PARSED PORT: %d\n", _sockaddr.sin_port);

    freeaddrinfo(res);

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    // Main accept() loop //
    while(1) {  
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
                    // printf("Packet end detected.\n");
                    break;
                }

                // printf("Received %d bytes: %s\n", bytes_received, buffer);

                // Parse request

                char *token;
                char tokens[MAX_HEADER][HEADER_SIZE];
                int token_count = 0;
                char* request_method = NULL;

                // Use strtok to split the string
                token = strtok(buffer, "\r\n");
                while (token != NULL && token_count < MAX_HEADER) {
                    strncpy(tokens[token_count], token, HEADER_SIZE - 1);
                    tokens[token_count][HEADER_SIZE - 1] = '\0'; // Ensure null-termination
                    token_count++;
                    token = strtok(NULL, "\r\n");
                }
                // printf("Got %d tokens\n", token_count);
                // Start Line 
                // printf("Checking request\n");

                request_method = validate_first_token(tokens[0]);
                // printf("First line request type: %d\n", request_status);
                // printf("First line request type: %d\n", validate_first_token(tokens[0]));

                // Header and keys (rest)
                for (int i = 1;i < token_count-1;i++) {
                    if (validate_key_value_token(tokens[i]) == 0) {
                        request_method = NULL;
                    }
                }
                // printf("Rest request type: %d\n", request_status);

                // Print the resulting tokens
                // printf("Split tokens:\n");
                // for (int i = 0; i < token_count; i++) {
                //     printf("Token %d: %s\n", i + 1, tokens[i]);
                // }

                // Send a reply for the current request
                // printf("Server got request: %s\n", request_method);
                char msg[BUFFER_SIZE];

                if (request_method == NULL) {
                    strcpy(msg, BAD_REQUEST);
                } else if (strcmp(request_method, "GET") == 0) {
                    char *content = path_extract(tokens[0], dynamic_paths); 
                    // printf("extracted content: %s\n", content);
                    if (content == NULL) {
                        snprintf(msg, BUFFER_SIZE, "HTTP/1.1 404 GET Request\r\nContent-Length: 0\r\n\r\n");
                    } else {
                        snprintf(msg, BUFFER_SIZE, "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n%s", strlen(content), content);
                    }
                } else if (strcmp(request_method, "PUT") == 0) {                   
                    char method[METHOD_SIZE], uri[URI_SIZE], http_version[HTTP_VERSION_SIZE];
                    sscanf(tokens[0], "%s %s %s", method, uri, http_version);
                    // printf("extracted path: %s\n", uri);
                    char *path = strtok(uri, "/");
                    path = strtok(NULL, "/");
                    char* query_status = db_query(path, tokens[token_count-1], dynamic_paths, 0);
                    // printf("Query status: %s\n", query_status);
                    if (query_status == NULL) {
                        snprintf(msg, BUFFER_SIZE, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
                    } else {
                        snprintf(msg, BUFFER_SIZE, "HTTP/1.1 201 Created\r\nContent-Length: %zu\r\n\r\n%s", strlen(query_status), query_status);
                    }


                } else if (strcmp(request_method, "DELETE") == 0) {
                    char method[METHOD_SIZE], uri[URI_SIZE], http_version[HTTP_VERSION_SIZE];
                    sscanf(tokens[0], "%s %s %s", method, uri, http_version);
                    // printf("extracted path: %s\n", uri);
                    char *path = strtok(uri, "/");
                    path = strtok(NULL, "/");
                    char* query_status = db_query(path, tokens[token_count-1], dynamic_paths, 1);
                    // printf("Query status: %s\n", query_status);
                    if (query_status == NULL) {
                        snprintf(msg, BUFFER_SIZE, "HTTP/1.1 404 GET Request\r\nContent-Length: 0\r\n\r\n");
                    } else {
                        snprintf(msg, BUFFER_SIZE, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
                    }
                }else {
                    strcpy(msg, ETC_REQUEST);
                }
        
                // printf("sending %s\n", msg);
                int len;
                len = strlen(msg);
                int bytes_sent = send(new_fd, msg, len, 0);
                if (bytes_sent < 0) {
                    perror("send failed");
                    break; 
                }
                // printf("sent %s\n", msg);
            }

            close(new_fd);
            exit(0);
        }
        close(new_fd);
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

char* validate_first_token(const char *token) {
    char method[METHOD_SIZE], uri[URI_SIZE], http_version[HTTP_VERSION_SIZE];

    int num_parts = sscanf(token, "%s %s %s", method, uri, http_version);

    // Validate the HTTP Method
    if (strcmp(method, "GET") != 0 && strcmp(method, "POST") != 0 &&
        strcmp(method, "HEAD") != 0 && strcmp(method, "PUT") != 0 &&
        strcmp(method, "DELETE") != 0 && strcmp(method, "OPTIONS") != 0 &&
        strcmp(method, "PATCH") != 0) {
        return NULL; // Unsupported or invalid method BAD REQUEST
    }

    // Validate the HTTP Version
    if (strcmp(http_version, "HTTP/1.0") != 0 && strcmp(http_version, "HTTP/1.1") != 0) {
        return NULL; // Invalid HTTP version BAD REQUEST
    }

    // All checks passed
    char *validated_method = malloc(strlen(method) + 1);
    if (validated_method) {
        strcpy(validated_method, method);
    }
    return validated_method;
}

int validate_key_value_token(const char *token) {
    const char *colon_pos = strchr(token, ':');
    if (!colon_pos) {
        return 0; 
    }

    if (*(colon_pos + 1) != ' ') {
        return 0; 
    }

    if (colon_pos == token) {
        return 0; 
    }

    if (strlen(colon_pos + 2) == 0) {
        return 0; 
    }

    return 1;
}

char* path_extract(const char *token, char dynamic_paths[MAX_DYNAMIC_PATH][MAX_PATH_DATA]) {
    char method[METHOD_SIZE], uri[URI_SIZE], http_version[HTTP_VERSION_SIZE];
    
    if (sscanf(token, "%s %s %s", method, uri, http_version) != 3) {
        return NULL; // Invalid request format
    }

    char *path = strtok(uri, "/");
    if (path == NULL) return NULL; // No "static" path or token is empty

    // dynamic paths
    if (strcmp(path, "dynamic") == 0) {
        path = strtok(NULL, "/");
        // printf("Searching dynamic paths for path %s ...\n", path);
        
        for (int i = 0; i < MAX_DYNAMIC_PATH;i++) {
            char temp[MAX_PATH_DATA];
            strncpy(temp, dynamic_paths[i], MAX_PATH_DATA); // Copy dynamic path to avoid modifying the array
            temp[MAX_PATH_DATA - 1] = '\0'; // Ensure null-termination
            // printf("DATA %s\n", temp);
            char *data = strtok(temp, ": "); 
            // printf("DATA %s\n", data);
            if (data == NULL) {
                continue;
            } else if (strcmp(data, path) == 0) {
                data = strtok(NULL, ": ");
                // printf("FOUND %s\n", data);
                char* result = malloc(strlen(data) + 1);
                if (result) {
                    strcpy(result, data); // Copy the string to the allocated memory
                }
                return result;
            }
        }
    } else if (strcmp(path, "static") == 0) {
        // printf("Searching static paths ...\n");
        // static paths
        while ((path = strtok(NULL, "/")) != NULL) {
            if (strcmp(path, "foo") == 0) {
                return "Foo";
            } else if (strcmp(path, "bar") == 0) {
                return "Bar";
            } else if (strcmp(path, "baz") == 0) {
                return "Baz";
            }
        }
    }

    // printf("Content not found\n");
    return NULL; 
}

// PUT and DELETE Implemention // Mode 0 = PUT, Mode 1 = DELETE
char* db_query(const char *path, const char *content, char dynamic_paths[MAX_DYNAMIC_PATH][MAX_PATH_DATA], uint8_t mode) {
    if (mode == 0) {
        int index = 0;
        // printf("PUTTING %s: %s\n", path, content);
        // search for duplicates
        for (int i = 0; i < MAX_DYNAMIC_PATH;i++) {
            char temp[MAX_PATH_DATA];
            strncpy(temp, dynamic_paths[i], MAX_PATH_DATA); // Copy dynamic path to avoid modifying the array
            temp[MAX_PATH_DATA - 1] = '\0'; // Ensure null-termination
            
            char *data = strtok(temp, ": "); 
            // printf("DATA %s\n", data);
            if (data == NULL) {
                continue;
            } else if (strcmp(data, path) == 0) {
                // printf("found %s\n", data);
                return NULL; // Match found
            }
        }

        // printf("No duplicates found, performing PUT\n");
        for (int i = 0;i < MAX_DYNAMIC_PATH;i++) {
            if (dynamic_paths[i][0] == '\0') {
                char data[MAX_PATH_DATA];
                snprintf(data, MAX_PATH_DATA, "%s: %s", path, content);
                // printf("PUTTING DATA: %s\n", data);
                strncpy(dynamic_paths[i], data, MAX_PATH_DATA);
                dynamic_paths[i][MAX_PATH_DATA - 1] = '\0';
                
                // Allocate memory for the return value
                char* result = malloc(strlen(data) + 1);
                if (result) {
                    strcpy(result, data); // Copy the string to the allocated memory
                }
                return result;
            }
        }
    } else {
        int index = 0;
        // printf("DELETING %s: %s\n", path, content);
        // search for duplicates
        for (int i = 0; i < MAX_DYNAMIC_PATH;i++) {
            char temp[MAX_PATH_DATA];
            strncpy(temp, dynamic_paths[i], MAX_PATH_DATA); // Copy dynamic path to avoid modifying the array
            temp[MAX_PATH_DATA - 1] = '\0'; // Ensure null-termination
            
            char *data = strtok(temp, ": "); 
            // printf("DATA %s\n", data);
            if (data == NULL) {
                continue;
            } else if (strcmp(data, path) == 0) {
                // printf("found %s\n", data);
                dynamic_paths[i][0] = '\0';
                return "DELETED"; // Return the cleared path
            }
        }
    }

    return NULL;
}   
