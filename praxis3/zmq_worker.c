#include "zhelpers.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include "data.h"


typedef struct {
    void *context;
    char *port;
} worker_args_t;

char* map(char *text) {
    static char result[MAX_MSG_LEN];
    result[0] = '\0';  // Initialize empty result

    // Hashmap (array of pointers to linked lists)
    HashMap *hashmap[HASH_SIZE] = {NULL};
    QueueList* word_order = NULL;

    char *token = strtok(text, " .,\n"); // TODO: FIX DELIMITERS
    while (token != NULL) {
        to_lowercase(token);
        insert_word(token, &hashmap, &word_order);
        token = strtok(NULL, " .,\n"); // TODO: FIX DELIMITERS
    }

    // // Build result string using word order array
    while (word_order != NULL) {
        char word[MAX_WORD_LEN];
        poll_from_queue(&word_order, word, sizeof(word)); // poll like this to prevent memory leakss
        int hash = hash_function(word);
        HashMap *node = hashmap[hash];

        // Find the correct node
        while (node && strcmp(node->word, word) != 0) {
            node = node->next;
        }

        if (node) {
            strcat(result, node->word);
            for (int j = 0; j < node->count; j++) {
                strcat(result, "1");
            }
        }
    }

    result[strlen(result)] = '\0';
    free_hashmap(hashmap);
    return result;

}

char* reduce(const char* text) {
    static char result[MAX_MSG_LEN];  // Ensure MAX_MSG_LEN is defined
    result[0] = '\0';  

    int i = 0, j = 0, sum = 0;
    int in_number = 0;  // Flag to track if we are currently in a numeric sequence

    while (text[i] != '\0') {
        if (isdigit(text[i])) {
            sum = sum + (text[i] - '0'); // Accumulate number
            in_number = 1;
        } else {
            if (in_number) {  // If we were in a number sequence, store the sum
                j += sprintf(result + j, "%d", sum);
                sum = 0;
                in_number = 0;
            }
            if (j < MAX_MSG_LEN - 1) { // Ensure we don't overflow
                result[j++] = text[i]; // Copy non-digit character
            }
        }
        i++;
    }

    // If the string ends with a number, append the final sum
    if (in_number) {
        j += sprintf(result + j, "%d", sum);
    }

    result[j] = '\0'; // Null-terminate the output string
    return result;  
}

static void *worker_routine (void *arg) {
    worker_args_t *args = (worker_args_t *)arg;
    void *worker = zmq_socket(args->context, ZMQ_REP);

    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "tcp://127.0.0.1:%s", args->port);

    if (zmq_bind(worker, endpoint) != 0) {
        perror("zmq_bind failed");
        return NULL;
    }

    printf("Worker listening on %s\n", endpoint);

    while (1) {
        char *string = s_recv(worker);
        printf ("Received request: [%s]\n", string);


        if (strncmp(string, "map", 3) == 0) {
            char* result = map(string+3);
            zmq_send (worker, result, strlen (result) + 1, 0);
        } else if (strncmp(string, "red", 3) == 0) {
            char* result = reduce(string+3);
            zmq_send (worker, result, strlen (result) + 1, 0);
        } else if (strcmp(string, "rip") == 0) {
            char* result = "rip\0";
            zmq_send (worker, result, strlen (result) + 1, 0);
            free(string);
            break;
        } 
        
        free(string);
    }

    zmq_close(worker);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc <= 1) {
        return 0;
    }

    int worker_procs = argc-1;
    void *context = zmq_ctx_new();

    pthread_t workers[worker_procs];
    worker_args_t args[worker_procs];

    // Create worker threads
    for (int i = 1; i < argc; i++) {
        args[i - 1].context = context;
        args[i - 1].port = argv[i];
        pthread_create(&workers[i - 1], NULL, worker_routine, &args[i - 1]);
    }

    // Join threads
    for (int i = 0; i < argc - 1; i++) {
        pthread_join(workers[i], NULL);
    }

    zmq_ctx_destroy(context);

    // char map_message[] = "mapInteroperability test. Test uses python distributor. Test interoperability again.\0";

    // char *map_result, *red_result;

    // char *actual_message = map_message + 3; 

    // map_result = map(actual_message);

    // printf("%s \n", map_result);

    // red_result = reduce(map_result);

    // printf("%s \n", red_result);

    // for (int i = 0; i < strlen(map_result) + 1; i++) {
    //     printf("'%c' (%d)\n", map_result[i], map_result[i]);
    // }
    // printf("'%c' (%d)\n", map_result[strlen(map_result)], map_result[strlen(map_result)]);

    return 0;
}