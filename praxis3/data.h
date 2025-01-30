#pragma once

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_MSG_LEN 1500
#define MAX_PAYLOAD_LEN 1497
#define MAX_WORD_LEN 50
#define HASH_SIZE 1500

// FIFO QUEUE
typedef struct QueueList {
    char msg[MAX_PAYLOAD_LEN];
    struct QueueList* next;
} QueueList;

typedef struct HashMap {
    char word[MAX_WORD_LEN];
    int count;
    struct HashMap *next;
} HashMap;

// Function to add a message to the queue (FIFO)
void add_to_queue(QueueList** head, const char* message);
// Get the oldest message from queue and deletes it 
void poll_from_queue(QueueList** head, char* buffer, size_t bufsize);
// Function to delete a message from the queue (FIFO)
void delete_from_queue(QueueList** head);
// Function to print the queue (for debugging purposes)
void print_queue(QueueList* head);

// Hash function (simple sum of characters)
int hash_function(const char *word);
// Converts a string to lowercase
void to_lowercase(char *str);
// Inserts or updates word in hashmap
void insert_word(const char *word, HashMap** hashmap, QueueList** word_order);
// Free hashmap memory
void free_hashmap(HashMap** hashmap);