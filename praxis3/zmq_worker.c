#include "zhelpers.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>

typedef struct {
    void *context;
    char *port;
} worker_args_t;

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

        if (strcmp(string, "rip") == 0) {
            s_send(worker, "rip");
            break;
        } else {
            s_send(worker, "");
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
    // printf("worker processes: %d\n", worker_procs);
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
    return 0;
}