#include "zhelpers.h"
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include "data.h"
#include <ctype.h>


void read_file_in_chunks(FILE *file, size_t limit, QueueList** queue);

int main(int argc, char **argv) {
    printf("fdasikfhiosdajfas\n");
    char *filename = argv[1];

    int num_workers = argc - 2;

    QueueList* msg_queue = NULL;

    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }
    read_file_in_chunks(file, MAX_PAYLOAD_LEN, &msg_queue);
    fclose(file);
    
    // print_queue(msg_queue);

    void *context = zmq_ctx_new();
    void *workers[num_workers];
    zmq_pollitem_t poll_items[num_workers];

    // Create REQ sockets and connect to workers
    for (int i = 0; i < num_workers; i++) {
        workers[i] = zmq_socket(context, ZMQ_REQ);
        char endpoint[50];
        snprintf(endpoint, sizeof(endpoint), "tcp://127.0.0.1:%s", argv[i+2]);
        printf("Distributor publishing on %s\n", endpoint);
        zmq_connect(workers[i], endpoint);
        poll_items[i].socket = workers[i];
        poll_items[i].events = ZMQ_POLLIN;
    }

    // Send initial request to all workers
    for (int i = 0; i < num_workers; i++) {
        char request[MAX_MSG_LEN];
        snprintf(request, sizeof(request), "map%s", msg_queue->msg);
        delete_from_queue(&msg_queue);
        zmq_send(workers[i], request, strlen(request), 0);
    }

    // Poll for responses
    int active_workers = num_workers;
    while (active_workers > 0) {
        zmq_poll(poll_items, num_workers, -1); // Wait indefinitely

        for (int i = 0; i < num_workers; i++) {
            if (poll_items[i].revents & ZMQ_POLLIN) {
                char response[256];
                zmq_recv(workers[i], response, sizeof(response) - 1, 0);
                response[255] = '\0';
                printf("Received from worker %d: %s\n", i, response);

               if (strcmp(response, "rip") == 0) {  // If worker signals termination
                    zmq_close(workers[i]);  // Close its socket
                    poll_items[i].socket = NULL; // Remove from polling
                    active_workers--;  // Decrease active count
                    printf("Worker %d disconnected. Remaining: %d\n", i, active_workers);
                } else {
                    if (msg_queue != NULL) {
                        char request[MAX_MSG_LEN];
                        snprintf(request, sizeof(request), "map%s", msg_queue->msg);
                        delete_from_queue(&msg_queue);
                        s_send(workers[i], request);
                    } else {
                        s_send(workers[i], "rip");
                    }
                }
                
            }
        }
    }

    // Cleanup
    for (int i = 0; i < num_workers; i++) {
        zmq_close(workers[i]);
    }
    zmq_ctx_destroy(context);

    return 0;
}

void read_file_in_chunks(FILE *file, size_t limit, QueueList** queue) {
    char line[MAX_MSG_LEN];

    // Read each line from the file
    while (fgets(line, sizeof(line), file)) {
        size_t len = strlen(line);

        // Remove the trailing newline character if it exists
        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
            len--;
        }

        size_t i = 0;
        while (i < len) {
            // Ensure we don't exceed the limit
            size_t chunk_len = (len - i < limit) ? len - i : limit;

            // Check if the chunk cuts a word (by checking the next character)
            if (i + chunk_len < len && line[i + chunk_len] != ' ' && isalnum(line[i + chunk_len])) {
                // Find the last space in the chunk to avoid word clipping
                size_t last_space = i + chunk_len;
                while (last_space > i && line[last_space] != ' ') {
                    last_space--;
                }

                if (last_space > i) {
                    chunk_len = last_space - i; // Adjust chunk length to the last space
                }
            }
            add_to_queue(queue, line + i);

            // Print the current chunk
            // char chunk[MAX_MSG_LEN + 1];
            // strncpy(chunk, line + i, chunk_len);
            // chunk[chunk_len] = '\0'; // Null-terminate the chunk
            // printf("Chunk: '%s'\n", chunk);

            // Move to the next chunk
            i += chunk_len;

            // Skip over any spaces that separate words
            while (line[i] == ' ' && i < len) {
                i++;
            }
        }
    }
}