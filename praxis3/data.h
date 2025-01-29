#pragma once

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_MSG_LEN 1500
#define MAX_PAYLOAD_LEN 1497

typedef struct QueueList QueueList; // FIFO QUEUE
struct QueueList {
    char msg[MAX_PAYLOAD_LEN];
    QueueList* next;
};

// Function to add a message to the queue (FIFO)
void add_to_queue(QueueList** head, const char* message);
// Function to delete a message from the queue (FIFO)
void delete_from_queue(QueueList** head);
// Function to print the queue (for debugging purposes)
void print_queue(QueueList* head);