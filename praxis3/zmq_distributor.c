#include "zhelpers.h"
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include "data.h"
#include <ctype.h>

enum jobState {
    MAP,
    RED,
    IDLE
};

void read_file_in_chunks(FILE *file, size_t limit, QueueList** queue);
void split_and_store(const char* input, HashMap** hashmap);

int main(int argc, char **argv) {
    char *filename = argv[1];

    int num_workers = argc - 2;

    QueueList* worker_queue[num_workers];
    for (int i = 0; i < num_workers;i++) {
        worker_queue[i] = NULL;
    }
    QueueList* msg_queue = NULL;
    HashMap* words[HASH_SIZE*4] = {NULL};
    Tree *node = NULL;

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
    enum jobState workers_states[num_workers];
    zmq_pollitem_t poll_items[num_workers];

    int workers_job[num_workers];

    // distribute jobs to each worker queue
    while (msg_queue != NULL) {
        for (int i = 0; i < num_workers;i++) {
            char msg[MAX_PAYLOAD_LEN];
            poll_from_queue(&msg_queue, msg, sizeof(msg)); 
            add_to_queue(&worker_queue[i], msg);
        }
    }
    

    // int sndhwm = 1500;  // Set HWM above your expected message size
    // int sndbuf = 1500;  // Set buffer size above your expected message size
    
    // Create REQ sockets and connect to workers
    for (int i = 0; i < num_workers; i++) {
        workers[i] = zmq_socket(context, ZMQ_REQ);
        // zmq_setsockopt(workers[i], ZMQ_SNDBUF, &sndbuf, sizeof(sndbuf));
        // zmq_setsockopt(workers[i], ZMQ_SNDHWM, &sndhwm, sizeof(sndhwm));
        char endpoint[50];
        snprintf(endpoint, sizeof(endpoint), "tcp://127.0.0.1:%s", argv[i+2]);
        // printf("Distributor publishing on %s\n", endpoint);
        zmq_connect(workers[i], endpoint);
        poll_items[i].socket = workers[i];
        poll_items[i].events = ZMQ_POLLIN;
        workers_job[i] = 0;
    }

    // Send initial request to all workers
    for (int i = 0; i < num_workers; i++) {
        char request[MAX_MSG_LEN];
        char msg[MAX_PAYLOAD_LEN];
        poll_from_queue(&worker_queue[i], msg, sizeof(msg)); 
        snprintf(request, sizeof(request), "map%s", msg);
        zmq_send(workers[i], request, strlen(request) + 1, 0);
        workers_states[i] = MAP;
        workers_job[i]++;
    }

    // Poll for responses
    int active_workers = num_workers;
    int next_worker = 0;
    while (active_workers > 0) {
        zmq_poll(poll_items, num_workers, -1); // Wait indefinitely
        

        for (int i = 0; i < num_workers; i++) {
            if (poll_items[i].revents & ZMQ_POLLIN) {
                char response[MAX_MSG_LEN];
                zmq_recv(workers[i], response, sizeof(response) - 1, 0);
                response[MAX_MSG_LEN-1] = '\0';
                // printf("Received from worker %d: %s\n", i, response);


                if (strcmp(response, "rip") == 0) {  // If worker signals termination
                    // printf("recieved rip cmd\n");
                    // s_send(workers[i], "rip");
                    poll_items[i].socket = NULL; // Remove from polling
                    active_workers--;  // Decrease active count
                    // printf("Worker %d disconnected. Remaining: %d\n", i, active_workers);
                } else {
                    if (workers_states[i] == MAP) {
                        // send RED command
                        // printf("sending reduce cmd\n");
                        char request[MAX_MSG_LEN];
                        snprintf(request, sizeof(request), "red%s", response);
                        zmq_send(workers[i], request, strlen(request) + 1, 0);
                        workers_states[i] = RED;
                        workers_job[i]++;
                    } else if (workers_states[i] == RED) {
                        // saves key,values
                        split_and_store(response, &words);
                        
                        workers_states[i] = IDLE;

                        if (worker_queue[i] != NULL) {
                            // saves key,values to tree and send next map
                            // printf("sending another map cmd\n");
                            char request[MAX_MSG_LEN];
                            char msg[MAX_PAYLOAD_LEN];
                            poll_from_queue(&worker_queue[i], msg, sizeof(msg)); 
                            snprintf(request, sizeof(request), "map%s", msg);
                            zmq_send(workers[i], request, strlen(request) + 1, 0);
                            workers_states[i] = MAP;
                            workers_job[i]++;
                        } else {
                            // save key
                            // printf("sending rip2 cmd\n");
                            char* result = "rip\0";
                            zmq_send (workers[i], result, strlen (result) + 1, 0);
                        }
                    }
                } 
                
            }
        }
    }

    // printf("cleaning up\n");
    // Cleanup
    for (int i = 0; i < num_workers; i++) {
        zmq_close(workers[i]);
    }

    // printf("clearing context\n");

    
    zmq_ctx_destroy(context);

    // print tree
    printf("word,frequency\n");
    node = hashmap_to_tree(&words, node);

    traverseDescending(node);

    // for (int i = 0;i < num_workers;i++) {
    //     printf("worker %d : %d\n", i, workers_job[i]);
    // }

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

void split_and_store(const char* input, HashMap** hashmap) {
    int i = 0, j = 0;
    char word[MAX_WORD_LEN];
    char number[MAX_WORD_LEN];

    while (input[i] != '\0') {
        // Extract the word
        j = 0;
        while (input[i] != '\0' && isalpha(input[i])) {
            word[j++] = input[i++];
        }
        word[j] = '\0';

        // Extract the number
        j = 0;
        while (input[i] != '\0' && isdigit(input[i])) {
            number[j++] = input[i++];
        }
        number[j] = '\0';

        // Insert into hashmap if valid
        if (word[0] != '\0' && number[0] != '\0') {
            insert_normal(word, atoi(number), hashmap);
        }
    }
}
